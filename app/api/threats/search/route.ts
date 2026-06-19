/**
 * Advanced Threat Search API
 * POST - Search threats with advanced filters
 * GET - Quick search with query params
 *
 * Reads from `email_verdicts` (the live detection pipeline's source of truth),
 * consistent with the rest of the threat-management screens. `status` and
 * `threat_type` are not native email_verdicts columns, so they are derived in
 * SQL (mirroring lib/detection/storage.ts deriveThreatStatus / deriveThreatType)
 * so the WHERE clause, the COUNT query, and the facets all agree. The legacy
 * `integrationType` filter is dropped — email_verdicts has no provider column.
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

interface SearchFilters {
  query?: string;              // Free text search
  status?: string[];           // quarantined, released, deleted (derived)
  verdict?: string[];          // suspicious, quarantine, block
  threatTypes?: string[];      // phishing, malware, spam, bec (derived from signals)
  senders?: string[];          // Sender email addresses
  senderDomains?: string[];    // Sender domain names
  recipients?: string[];       // Recipient emails
  scoreMin?: number;           // Minimum threat score
  scoreMax?: number;           // Maximum threat score
  dateFrom?: string;           // ISO date string
  dateTo?: string;             // ISO date string
  hasSignal?: string;          // Signal type to filter by
  integrationType?: string;    // DEPRECATED — email_verdicts has no provider column; ignored
  sortBy?: 'date' | 'score' | 'sender' | 'subject';
  sortOrder?: 'asc' | 'desc';
  page?: number;
  limit?: number;
}

// Only threatening verdicts surface on the threat screens (mirrors
// getThreatsForManagement), so the search is scoped the same way — otherwise
// benign 'pass' rows in email_verdicts would pollute "threat" results.
const THREATENING_VERDICTS = `ev.verdict IN ('suspicious', 'quarantine', 'block')`;

// Mirrors lib/detection/storage.ts deriveThreatStatus. Kept in SQL (not JS) so
// the status filter, COUNT, and status facet all agree.
const STATUS_EXPR = `CASE
  WHEN ev.action_taken IN ('released', 'delivered') THEN 'released'
  WHEN ev.action_taken = 'deleted' THEN 'deleted'
  WHEN ev.user_feedback = 'false_positive' THEN 'released'
  WHEN ev.verdict IN ('quarantine', 'block') THEN 'quarantined'
  ELSE 'quarantined'
END`;

// Mirrors lib/detection/storage.ts deriveThreatType (signal priority cascade).
const THREAT_TYPE_EXPR = `CASE
  WHEN ev.signals @> '[{"type":"credential_request"}]'::jsonb THEN 'phishing'
  WHEN ev.signals @> '[{"type":"financial_request"}]'::jsonb
    OR ev.signals @> '[{"type":"bec_detected"}]'::jsonb
    OR ev.signals @> '[{"type":"bec_impersonation"}]'::jsonb THEN 'bec'
  WHEN ev.signals @> '[{"type":"executable"}]'::jsonb
    OR ev.signals @> '[{"type":"macro_enabled"}]'::jsonb
    OR ev.signals @> '[{"type":"dangerous_attachment"}]'::jsonb THEN 'malware'
  WHEN ev.signals @> '[{"type":"homoglyph"}]'::jsonb
    OR ev.signals @> '[{"type":"display_name_spoof"}]'::jsonb
    OR ev.signals @> '[{"type":"dangerous_url"}]'::jsonb
    OR ev.signals @> '[{"type":"ip_url"}]'::jsonb THEN 'phishing'
  WHEN ev.signals @> '[{"type":"spam"}]'::jsonb
    OR ev.signals @> '[{"type":"bulk_sender"}]'::jsonb THEN 'spam'
  ELSE 'phishing'
END`;

/**
 * POST - Advanced search with complex filters
 */
export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const filters: SearchFilters = await request.json();

    const results = await executeSearch(tenantId, filters);

    return NextResponse.json(results);
  } catch (error) {
    console.error('Threat search error:', error);
    return NextResponse.json(
      { error: 'Search failed' },
      { status: 500 }
    );
  }
}

/**
 * GET - Quick search with query params
 */
export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const searchParams = request.nextUrl.searchParams;

    const filters: SearchFilters = {
      query: searchParams.get('q') || undefined,
      status: searchParams.get('status')?.split(','),
      verdict: searchParams.get('verdict')?.split(','),
      threatTypes: searchParams.get('types')?.split(','),
      senderDomains: searchParams.get('domains')?.split(','),
      scoreMin: searchParams.get('scoreMin') ? parseInt(searchParams.get('scoreMin')!) : undefined,
      scoreMax: searchParams.get('scoreMax') ? parseInt(searchParams.get('scoreMax')!) : undefined,
      dateFrom: searchParams.get('from') || undefined,
      dateTo: searchParams.get('to') || undefined,
      // integrationType intentionally not mapped — email_verdicts has no provider
      // column. See SearchFilters.integrationType.
      sortBy: (searchParams.get('sortBy') as SearchFilters['sortBy']) || 'date',
      sortOrder: (searchParams.get('sortOrder') as 'asc' | 'desc') || 'desc',
      page: parseInt(searchParams.get('page') || '1'),
      limit: Math.min(parseInt(searchParams.get('limit') || '25'), 100),
    };

    const results = await executeSearch(tenantId, filters);

    return NextResponse.json(results);
  } catch (error) {
    console.error('Threat search error:', error);
    return NextResponse.json(
      { error: 'Search failed' },
      { status: 500 }
    );
  }
}

async function executeSearch(tenantId: string, filters: SearchFilters) {
  const page = filters.page || 1;
  const limit = Math.min(filters.limit || 25, 100);
  const offset = (page - 1) * limit;

  // Build WHERE conditions. Base scope: tenant + threatening verdicts only.
  const conditions: string[] = [`ev.tenant_id = $1`, THREATENING_VERDICTS];
  const params: unknown[] = [tenantId];
  let paramIndex = 2;

  // Free text search (subject, sender, explanation)
  if (filters.query) {
    conditions.push(`(
      ev.subject ILIKE $${paramIndex}
      OR ev.from_address ILIKE $${paramIndex}
      OR ev.from_display_name ILIKE $${paramIndex}
      OR COALESCE(ev.explanation, ev.llm_explanation) ILIKE $${paramIndex}
    )`);
    params.push(`%${filters.query}%`);
    paramIndex++;
  }

  // Status filter (derived — mirrors deriveThreatStatus)
  if (filters.status && filters.status.length > 0) {
    conditions.push(`(${STATUS_EXPR}) = ANY($${paramIndex})`);
    params.push(filters.status);
    paramIndex++;
  }

  // Verdict filter
  if (filters.verdict && filters.verdict.length > 0) {
    conditions.push(`ev.verdict = ANY($${paramIndex})`);
    params.push(filters.verdict);
    paramIndex++;
  }

  // Threat type filter (derived from signals — mirrors deriveThreatType)
  if (filters.threatTypes && filters.threatTypes.length > 0) {
    conditions.push(`(${THREAT_TYPE_EXPR}) = ANY($${paramIndex})`);
    params.push(filters.threatTypes);
    paramIndex++;
  }

  // Sender email filter
  if (filters.senders && filters.senders.length > 0) {
    conditions.push(`ev.from_address = ANY($${paramIndex})`);
    params.push(filters.senders);
    paramIndex++;
  }

  // Sender domain filter
  if (filters.senderDomains && filters.senderDomains.length > 0) {
    conditions.push(`SPLIT_PART(ev.from_address, '@', 2) = ANY($${paramIndex})`);
    params.push(filters.senderDomains);
    paramIndex++;
  }

  // Recipient filter (to_addresses is a jsonb array of {address, ...})
  if (filters.recipients && filters.recipients.length > 0) {
    conditions.push(`EXISTS (
      SELECT 1 FROM jsonb_array_elements(COALESCE(ev.to_addresses, '[]'::jsonb)) AS r
      WHERE r->>'address' = ANY($${paramIndex})
    )`);
    params.push(filters.recipients);
    paramIndex++;
  }

  // Score range
  if (filters.scoreMin !== undefined) {
    conditions.push(`ev.score >= $${paramIndex}`);
    params.push(filters.scoreMin);
    paramIndex++;
  }
  if (filters.scoreMax !== undefined) {
    conditions.push(`ev.score <= $${paramIndex}`);
    params.push(filters.scoreMax);
    paramIndex++;
  }

  // Date range (email_verdicts uses created_at, not quarantined_at)
  if (filters.dateFrom) {
    conditions.push(`ev.created_at >= $${paramIndex}`);
    params.push(filters.dateFrom);
    paramIndex++;
  }
  if (filters.dateTo) {
    conditions.push(`ev.created_at <= $${paramIndex}`);
    params.push(filters.dateTo);
    paramIndex++;
  }

  // Signal type filter (searches the jsonb signals array)
  if (filters.hasSignal) {
    conditions.push(`ev.signals @> $${paramIndex}::jsonb`);
    params.push(JSON.stringify([{ type: filters.hasSignal }]));
    paramIndex++;
  }

  // integration_type: unsupported on email_verdicts (no provider column) — was a
  // threats-schema-only filter. Intentionally not applied; see SearchFilters.

  // Build ORDER BY (date maps to created_at on email_verdicts)
  const orderMap: Record<string, string> = {
    date: 'ev.created_at',
    score: 'ev.score',
    sender: 'ev.from_address',
    subject: 'ev.subject',
  };
  const orderColumn = orderMap[filters.sortBy || 'date'] || 'ev.created_at';
  const orderDirection = filters.sortOrder === 'asc' ? 'ASC' : 'DESC';

  const whereClause = conditions.join(' AND ');

  // Execute count query
  const countQuery = `
    SELECT COUNT(*)::int as total
    FROM email_verdicts ev
    WHERE ${whereClause}
  `;
  const countResult = await sql.transaction([
    sql([countQuery, ...params] as unknown as TemplateStringsArray),
  ]);
  const total = countResult[0][0]?.total || 0;

  // Execute search query
  const searchQuery = `
    SELECT
      ev.message_id,
      ev.subject,
      ev.from_address AS sender_email,
      ev.from_display_name AS sender_name,
      COALESCE(ev.to_addresses->0->>'address', '') AS recipient_email,
      ${THREAT_TYPE_EXPR} AS threat_type,
      ev.verdict,
      ev.score,
      ${STATUS_EXPR} AS status,
      CAST(NULL AS text) AS integration_type,
      ev.created_at AS quarantined_at,
      COALESCE(ev.explanation, ev.llm_explanation) AS explanation,
      COALESCE(jsonb_array_length(ev.signals), 0) AS signal_count
    FROM email_verdicts ev
    WHERE ${whereClause}
    ORDER BY ${orderColumn} ${orderDirection}
    LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
  `;
  params.push(limit, offset);

  const result = await sql.transaction([
    sql([searchQuery, ...params] as unknown as TemplateStringsArray),
  ]);
  const rows = (result[0] ?? []) as Array<Record<string, unknown>>;

  // Shape ids to match getThreatsForManagement: the detail route keys on the
  // URL-encoded message_id, so encode it here for clickable results.
  const threats = rows.map((row) => ({
    ...row,
    id: encodeURIComponent(String(row.message_id ?? '')),
  }));

  // Tenant-wide facets (unfiltered by the active search, matching prior behavior)
  const aggregations = await getSearchAggregations(tenantId);

  return {
    threats,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      hasMore: page * limit < total,
    },
    aggregations,
    filters: {
      applied: Object.keys(filters).filter(
        (k) => k !== 'integrationType' && filters[k as keyof SearchFilters] !== undefined
      ).length,
    },
  };
}

async function getSearchAggregations(tenantId: string) {
  // Tenant-wide facet distributions over threatening email_verdicts. status and
  // threat_type are derived in SQL (see STATUS_EXPR / THREAT_TYPE_EXPR above) so
  // the facets match what the search results can actually surface.

  try {
    const base = `FROM email_verdicts ev WHERE ev.tenant_id = $1 AND ${THREATENING_VERDICTS}`;

    const statusAgg = await sql.transaction([
      sql(
        [`SELECT (${STATUS_EXPR}) AS status, COUNT(*)::int AS count ${base} GROUP BY status`, tenantId] as unknown as TemplateStringsArray
      ),
    ]);

    const verdictAgg = await sql.transaction([
      sql(
        [`SELECT verdict, COUNT(*)::int AS count ${base} GROUP BY verdict`, tenantId] as unknown as TemplateStringsArray
      ),
    ]);

    const typeAgg = await sql.transaction([
      sql(
        [`SELECT (${THREAT_TYPE_EXPR}) AS threat_type, COUNT(*)::int AS count ${base} GROUP BY threat_type ORDER BY count DESC LIMIT 10`, tenantId] as unknown as TemplateStringsArray
      ),
    ]);

    const domainAgg = await sql.transaction([
      sql(
        [`SELECT SPLIT_PART(ev.from_address, '@', 2) AS domain, COUNT(*)::int AS count ${base} GROUP BY domain ORDER BY count DESC LIMIT 10`, tenantId] as unknown as TemplateStringsArray
      ),
    ]);

    const scoreAgg = await sql.transaction([
      sql(
        [`SELECT
        CASE
          WHEN ev.score < 40 THEN 'low'
          WHEN ev.score < 70 THEN 'medium'
          WHEN ev.score < 90 THEN 'high'
          ELSE 'critical'
        END AS severity,
        COUNT(*)::int AS count
        ${base} GROUP BY severity`, tenantId] as unknown as TemplateStringsArray
      ),
    ]);

    return {
      statuses: statusAgg[0],
      verdicts: verdictAgg[0],
      threatTypes: typeAgg[0],
      domains: domainAgg[0],
      severities: scoreAgg[0],
    };
  } catch {
    return null;
  }
}
