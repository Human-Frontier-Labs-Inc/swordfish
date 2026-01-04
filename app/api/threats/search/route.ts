/**
 * Advanced Threat Search API
 * POST - Search threats with advanced filters
 * GET - Quick search with query params
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

interface SearchFilters {
  query?: string;              // Free text search
  status?: string[];           // quarantined, released, deleted, dismissed
  verdict?: string[];          // quarantine, block
  threatTypes?: string[];      // phishing, malware, spam, bec
  senders?: string[];          // Email addresses
  senderDomains?: string[];    // Domain names
  recipients?: string[];       // Recipient emails
  scoreMin?: number;           // Minimum threat score
  scoreMax?: number;           // Maximum threat score
  dateFrom?: string;           // ISO date string
  dateTo?: string;             // ISO date string
  hasSignal?: string;          // Signal type to filter by
  integrationType?: string;    // o365, gmail
  sortBy?: 'date' | 'score' | 'sender' | 'subject';
  sortOrder?: 'asc' | 'desc';
  page?: number;
  limit?: number;
}

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
      integrationType: searchParams.get('integration') || undefined,
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

  // Build WHERE conditions
  const conditions: string[] = ['t.tenant_id = $1'];
  const params: unknown[] = [tenantId];
  let paramIndex = 2;

  // Free text search (subject, sender, explanation)
  if (filters.query) {
    conditions.push(`(
      t.subject ILIKE $${paramIndex}
      OR t.sender_email ILIKE $${paramIndex}
      OR t.sender_name ILIKE $${paramIndex}
      OR t.explanation ILIKE $${paramIndex}
    )`);
    params.push(`%${filters.query}%`);
    paramIndex++;
  }

  // Status filter
  if (filters.status && filters.status.length > 0) {
    conditions.push(`t.status = ANY($${paramIndex})`);
    params.push(filters.status);
    paramIndex++;
  }

  // Verdict filter
  if (filters.verdict && filters.verdict.length > 0) {
    conditions.push(`t.verdict = ANY($${paramIndex})`);
    params.push(filters.verdict);
    paramIndex++;
  }

  // Threat type filter
  if (filters.threatTypes && filters.threatTypes.length > 0) {
    conditions.push(`t.threat_type = ANY($${paramIndex})`);
    params.push(filters.threatTypes);
    paramIndex++;
  }

  // Sender email filter
  if (filters.senders && filters.senders.length > 0) {
    conditions.push(`t.sender_email = ANY($${paramIndex})`);
    params.push(filters.senders);
    paramIndex++;
  }

  // Sender domain filter
  if (filters.senderDomains && filters.senderDomains.length > 0) {
    conditions.push(`SPLIT_PART(t.sender_email, '@', 2) = ANY($${paramIndex})`);
    params.push(filters.senderDomains);
    paramIndex++;
  }

  // Recipient filter
  if (filters.recipients && filters.recipients.length > 0) {
    conditions.push(`t.recipient_email = ANY($${paramIndex})`);
    params.push(filters.recipients);
    paramIndex++;
  }

  // Score range
  if (filters.scoreMin !== undefined) {
    conditions.push(`t.score >= $${paramIndex}`);
    params.push(filters.scoreMin);
    paramIndex++;
  }
  if (filters.scoreMax !== undefined) {
    conditions.push(`t.score <= $${paramIndex}`);
    params.push(filters.scoreMax);
    paramIndex++;
  }

  // Date range
  if (filters.dateFrom) {
    conditions.push(`t.quarantined_at >= $${paramIndex}`);
    params.push(filters.dateFrom);
    paramIndex++;
  }
  if (filters.dateTo) {
    conditions.push(`t.quarantined_at <= $${paramIndex}`);
    params.push(filters.dateTo);
    paramIndex++;
  }

  // Signal type filter (searches in JSONB)
  if (filters.hasSignal) {
    conditions.push(`t.signals @> $${paramIndex}::jsonb`);
    params.push(JSON.stringify([{ type: filters.hasSignal }]));
    paramIndex++;
  }

  // Integration type
  if (filters.integrationType) {
    conditions.push(`t.integration_type = $${paramIndex}`);
    params.push(filters.integrationType);
    paramIndex++;
  }

  // Build ORDER BY
  const orderMap: Record<string, string> = {
    date: 't.quarantined_at',
    score: 't.score',
    sender: 't.sender_email',
    subject: 't.subject',
  };
  const orderColumn = orderMap[filters.sortBy || 'date'] || 't.quarantined_at';
  const orderDirection = filters.sortOrder === 'asc' ? 'ASC' : 'DESC';

  // Execute count query
  const countQuery = `
    SELECT COUNT(*)::int as total
    FROM threats t
    WHERE ${conditions.join(' AND ')}
  `;
  const countResult = await sql.transaction([
    sql([countQuery, ...params] as unknown as TemplateStringsArray),
  ]);
  const total = countResult[0][0]?.total || 0;

  // Execute search query
  const searchQuery = `
    SELECT
      t.id,
      t.message_id,
      t.subject,
      t.sender_email,
      t.sender_name,
      t.recipient_email,
      t.threat_type,
      t.verdict,
      t.score,
      t.status,
      t.integration_type,
      t.quarantined_at,
      t.explanation,
      COALESCE(jsonb_array_length(t.signals), 0) as signal_count
    FROM threats t
    WHERE ${conditions.join(' AND ')}
    ORDER BY ${orderColumn} ${orderDirection}
    LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
  `;
  params.push(limit, offset);

  const threats = await sql.transaction([
    sql([searchQuery, ...params] as unknown as TemplateStringsArray),
  ]);

  // Get aggregations for faceted search
  const aggregations = await getSearchAggregations(tenantId, conditions.slice(1), params.slice(1, -2));

  return {
    threats: threats[0],
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      hasMore: page * limit < total,
    },
    aggregations,
    filters: {
      applied: Object.keys(filters).filter(k => filters[k as keyof SearchFilters] !== undefined).length,
    },
  };
}

async function getSearchAggregations(
  tenantId: string,
  additionalConditions: string[],
  additionalParams: unknown[]
) {
  // Get aggregations for faceted search
  const baseCondition = `tenant_id = $1`;
  const params = [tenantId, ...additionalParams];

  try {
    // Status distribution
    const statusAgg = await sql`
      SELECT status, COUNT(*)::int as count
      FROM threats
      WHERE tenant_id = ${tenantId}
      GROUP BY status
    `;

    // Verdict distribution
    const verdictAgg = await sql`
      SELECT verdict, COUNT(*)::int as count
      FROM threats
      WHERE tenant_id = ${tenantId}
      GROUP BY verdict
    `;

    // Threat type distribution
    const typeAgg = await sql`
      SELECT threat_type, COUNT(*)::int as count
      FROM threats
      WHERE tenant_id = ${tenantId}
      AND threat_type IS NOT NULL
      GROUP BY threat_type
      ORDER BY count DESC
      LIMIT 10
    `;

    // Top sender domains
    const domainAgg = await sql`
      SELECT
        SPLIT_PART(sender_email, '@', 2) as domain,
        COUNT(*)::int as count
      FROM threats
      WHERE tenant_id = ${tenantId}
      GROUP BY SPLIT_PART(sender_email, '@', 2)
      ORDER BY count DESC
      LIMIT 10
    `;

    // Score distribution
    const scoreAgg = await sql`
      SELECT
        CASE
          WHEN score < 40 THEN 'low'
          WHEN score < 70 THEN 'medium'
          WHEN score < 90 THEN 'high'
          ELSE 'critical'
        END as severity,
        COUNT(*)::int as count
      FROM threats
      WHERE tenant_id = ${tenantId}
      GROUP BY severity
    `;

    return {
      statuses: statusAgg,
      verdicts: verdictAgg,
      threatTypes: typeAgg,
      domains: domainAgg,
      severities: scoreAgg,
    };
  } catch {
    return null;
  }
}
