/**
 * Rewritten URLs Database Module
 *
 * Handles all database operations for the URL rewriting system:
 * - URL ID generation (short, unguessable)
 * - URL mapping storage and retrieval
 * - Expiration handling
 * - Click tracking
 * - Statistics and analytics
 */

import { createHash, randomBytes } from 'crypto';
import { sql } from '@/lib/db';

// ============================================================================
// Types
// ============================================================================

export interface RewrittenUrlRecord {
  id: string;
  tenantId: string;
  emailId: string;
  originalUrl: string;
  expandedUrl: string | null;
  createdAt: Date;
  clickedAt: Date | null;
  expiresAt: Date;
  clickCount: number;
  clickVerdict: 'safe' | 'suspicious' | 'malicious' | 'blocked' | 'unknown' | null;
  metadata: Record<string, unknown> | null;
}

export interface UrlLookupResult {
  found: boolean;
  expired: boolean;
  originalUrl: string | null;
  expandedUrl: string | null;
  tenantId: string | null;
  emailId: string | null;
  clickCount: number;
  clickVerdict: string | null;
  metadata: Record<string, unknown> | null;
}

export interface RewriteStats {
  period: string;
  totalUrlsRewritten: number;
  totalClicks: number;
  uniqueUrlsClicked: number;
  maliciousClicks: number;
  suspiciousClicks: number;
  blockedClicks: number;
  safeClicks: number;
  avgClicksPerUrl: number;
  topClickedDomains: Array<{ domain: string; clicks: number }>;
  clicksByDay: Array<{ date: string; clicks: number }>;
  expiringUrlsCount: number;
}

export interface ExclusionUpdate {
  addDomains?: string[];
  removeDomains?: string[];
  addPatterns?: string[];
  removePatterns?: string[];
}

export interface BatchStoreResult {
  stored: number;
  skipped: number;
  errors: Array<{ url: string; error: string }>;
}

// ============================================================================
// URL ID Generation
// ============================================================================

/**
 * Generate a short, unguessable URL ID
 *
 * Format: [timestamp-base36][random-hex][hash-prefix]
 * Total length: ~30 characters
 *
 * Properties:
 * - Unguessable: 8 bytes of cryptographic randomness
 * - Unique: Timestamp + random + content hash
 * - Short: Base36 encoding for timestamp, hex for random
 * - URL-safe: Only alphanumeric characters
 */
export function generateUrlId(
  originalUrl: string,
  emailId: string,
  tenantId: string
): string {
  // Timestamp component (6 chars in base36)
  const timestamp = Date.now().toString(36);

  // Random component (16 chars hex = 8 bytes)
  const random = randomBytes(8).toString('hex');

  // Hash component for uniqueness (8 chars from SHA-256)
  const hash = createHash('sha256')
    .update(`${originalUrl}|${emailId}|${tenantId}|${timestamp}|${random}`)
    .digest('hex')
    .substring(0, 8);

  // Combine: timestamp(6) + random(16) + hash(8) = 30 chars
  return `${timestamp}${random}${hash}`;
}

/**
 * Generate a shorter URL ID for high-volume scenarios
 * Less collision-resistant but more compact
 */
export function generateShortUrlId(
  originalUrl: string,
  emailId: string
): string {
  const random = randomBytes(6).toString('hex'); // 12 chars
  const hash = createHash('sha256')
    .update(`${originalUrl}|${emailId}|${random}`)
    .digest('hex')
    .substring(0, 8);

  return `${random}${hash}`; // 20 chars total
}

/**
 * Validate URL ID format
 */
export function isValidUrlId(id: string): boolean {
  // Must be alphanumeric and between 20-40 characters
  return /^[a-z0-9]{20,40}$/i.test(id);
}

// ============================================================================
// Database Operations
// ============================================================================

/**
 * Store a single rewritten URL mapping
 */
export async function storeRewrittenUrl(params: {
  id: string;
  tenantId: string;
  emailId: string;
  originalUrl: string;
  expandedUrl?: string | null;
  expiryDays?: number;
  metadata?: Record<string, unknown>;
}): Promise<boolean> {
  try {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + (params.expiryDays ?? 30));

    await sql`
      INSERT INTO rewritten_urls (
        id, tenant_id, email_id, original_url, expanded_url,
        created_at, expires_at, click_count, metadata
      )
      VALUES (
        ${params.id},
        ${params.tenantId},
        ${params.emailId},
        ${params.originalUrl},
        ${params.expandedUrl || null},
        NOW(),
        ${expiresAt.toISOString()},
        0,
        ${JSON.stringify(params.metadata || {})}::jsonb
      )
      ON CONFLICT (id) DO NOTHING
    `;

    return true;
  } catch (error) {
    console.error('[RewrittenUrls] Failed to store URL:', error);
    return false;
  }
}

/**
 * Store multiple rewritten URL mappings in batch
 */
export async function batchStoreRewrittenUrls(
  urls: Array<{
    id: string;
    tenantId: string;
    emailId: string;
    originalUrl: string;
    expandedUrl?: string | null;
    metadata?: Record<string, unknown>;
  }>,
  expiryDays: number = 30
): Promise<BatchStoreResult> {
  const result: BatchStoreResult = {
    stored: 0,
    skipped: 0,
    errors: [],
  };

  if (urls.length === 0) {
    return result;
  }

  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + expiryDays);

  // Process in batches of 100 to avoid query size limits
  const batchSize = 100;
  for (let i = 0; i < urls.length; i += batchSize) {
    const batch = urls.slice(i, i + batchSize);

    try {
      // Build values for batch insert
      for (const url of batch) {
        try {
          const insertResult = await sql`
            INSERT INTO rewritten_urls (
              id, tenant_id, email_id, original_url, expanded_url,
              created_at, expires_at, click_count, metadata
            )
            VALUES (
              ${url.id},
              ${url.tenantId},
              ${url.emailId},
              ${url.originalUrl},
              ${url.expandedUrl || null},
              NOW(),
              ${expiresAt.toISOString()},
              0,
              ${JSON.stringify(url.metadata || {})}::jsonb
            )
            ON CONFLICT (id) DO NOTHING
            RETURNING id
          `;

          if (insertResult.length > 0) {
            result.stored++;
          } else {
            result.skipped++; // Already exists
          }
        } catch (urlError) {
          result.errors.push({
            url: url.originalUrl,
            error: urlError instanceof Error ? urlError.message : 'Unknown error',
          });
        }
      }
    } catch (batchError) {
      console.error('[RewrittenUrls] Batch insert failed:', batchError);
      // Mark all in this batch as errors
      for (const url of batch) {
        result.errors.push({
          url: url.originalUrl,
          error: batchError instanceof Error ? batchError.message : 'Batch error',
        });
      }
    }
  }

  return result;
}

/**
 * Lookup original URL from rewritten URL ID
 */
export async function lookupOriginalUrl(urlId: string): Promise<UrlLookupResult> {
  try {
    const result = await sql`
      SELECT
        id, tenant_id, email_id, original_url, expanded_url,
        created_at, clicked_at, expires_at, click_count,
        click_verdict, metadata
      FROM rewritten_urls
      WHERE id = ${urlId}
      LIMIT 1
    `;

    if (result.length === 0) {
      return {
        found: false,
        expired: false,
        originalUrl: null,
        expandedUrl: null,
        tenantId: null,
        emailId: null,
        clickCount: 0,
        clickVerdict: null,
        metadata: null,
      };
    }

    const row = result[0];
    const isExpired = new Date(row.expires_at) < new Date();

    return {
      found: true,
      expired: isExpired,
      originalUrl: row.original_url,
      expandedUrl: row.expanded_url,
      tenantId: row.tenant_id,
      emailId: row.email_id,
      clickCount: row.click_count,
      clickVerdict: row.click_verdict,
      metadata: row.metadata,
    };
  } catch (error) {
    console.error('[RewrittenUrls] Lookup failed:', error);
    return {
      found: false,
      expired: false,
      originalUrl: null,
      expandedUrl: null,
      tenantId: null,
      emailId: null,
      clickCount: 0,
      clickVerdict: null,
      metadata: null,
    };
  }
}

/**
 * Record a click on a rewritten URL
 */
export async function recordUrlClick(
  urlId: string,
  verdict?: 'safe' | 'suspicious' | 'malicious' | 'blocked' | 'unknown',
  metadata?: Record<string, unknown>
): Promise<{
  success: boolean;
  originalUrl: string | null;
  expandedUrl: string | null;
  isFirstClick: boolean;
}> {
  try {
    const result = await sql`
      UPDATE rewritten_urls
      SET
        clicked_at = COALESCE(clicked_at, NOW()),
        click_count = click_count + 1,
        click_verdict = COALESCE(${verdict || null}, click_verdict),
        metadata = CASE
          WHEN ${metadata ? JSON.stringify(metadata) : null}::jsonb IS NOT NULL THEN
            COALESCE(metadata, '{}'::jsonb) || ${metadata ? JSON.stringify(metadata) : '{}'}::jsonb
          ELSE metadata
        END
      WHERE id = ${urlId}
        AND expires_at > NOW()
      RETURNING original_url, expanded_url, (click_count = 1) as is_first_click
    `;

    if (result.length === 0) {
      return {
        success: false,
        originalUrl: null,
        expandedUrl: null,
        isFirstClick: false,
      };
    }

    return {
      success: true,
      originalUrl: result[0].original_url,
      expandedUrl: result[0].expanded_url,
      isFirstClick: result[0].is_first_click,
    };
  } catch (error) {
    console.error('[RewrittenUrls] Record click failed:', error);
    return {
      success: false,
      originalUrl: null,
      expandedUrl: null,
      isFirstClick: false,
    };
  }
}

/**
 * Get rewritten URL record by ID
 */
export async function getRewrittenUrl(urlId: string): Promise<RewrittenUrlRecord | null> {
  try {
    const result = await sql`
      SELECT
        id, tenant_id, email_id, original_url, expanded_url,
        created_at, clicked_at, expires_at, click_count,
        click_verdict, metadata
      FROM rewritten_urls
      WHERE id = ${urlId}
      LIMIT 1
    `;

    if (result.length === 0) {
      return null;
    }

    const row = result[0];
    return {
      id: row.id,
      tenantId: row.tenant_id,
      emailId: row.email_id,
      originalUrl: row.original_url,
      expandedUrl: row.expanded_url,
      createdAt: new Date(row.created_at),
      clickedAt: row.clicked_at ? new Date(row.clicked_at) : null,
      expiresAt: new Date(row.expires_at),
      clickCount: row.click_count,
      clickVerdict: row.click_verdict,
      metadata: row.metadata,
    };
  } catch (error) {
    console.error('[RewrittenUrls] Get URL failed:', error);
    return null;
  }
}

/**
 * Get all rewritten URLs for an email
 */
export async function getRewrittenUrlsForEmail(
  emailId: string,
  tenantId: string
): Promise<RewrittenUrlRecord[]> {
  try {
    const result = await sql`
      SELECT
        id, tenant_id, email_id, original_url, expanded_url,
        created_at, clicked_at, expires_at, click_count,
        click_verdict, metadata
      FROM rewritten_urls
      WHERE email_id = ${emailId}
        AND tenant_id = ${tenantId}
      ORDER BY created_at ASC
    `;

    return result.map((row) => ({
      id: row.id,
      tenantId: row.tenant_id,
      emailId: row.email_id,
      originalUrl: row.original_url,
      expandedUrl: row.expanded_url,
      createdAt: new Date(row.created_at),
      clickedAt: row.clicked_at ? new Date(row.clicked_at) : null,
      expiresAt: new Date(row.expires_at),
      clickCount: row.click_count,
      clickVerdict: row.click_verdict,
      metadata: row.metadata,
    }));
  } catch (error) {
    console.error('[RewrittenUrls] Get URLs for email failed:', error);
    return [];
  }
}

// ============================================================================
// Expiration Handling
// ============================================================================

/**
 * Delete expired URL mappings
 */
export async function cleanupExpiredUrls(): Promise<{
  deletedCount: number;
  freedBytes: number;
}> {
  try {
    const result = await sql`
      DELETE FROM rewritten_urls
      WHERE expires_at < NOW()
      RETURNING id
    `;

    return {
      deletedCount: result.length,
      freedBytes: 0, // Actual space requires VACUUM
    };
  } catch (error) {
    console.error('[RewrittenUrls] Cleanup failed:', error);
    return { deletedCount: 0, freedBytes: 0 };
  }
}

/**
 * Extend expiration for active URLs
 */
export async function extendUrlExpiration(
  urlIds: string[],
  additionalDays: number = 30
): Promise<number> {
  if (urlIds.length === 0) return 0;

  try {
    const result = await sql`
      UPDATE rewritten_urls
      SET expires_at = expires_at + ${`${additionalDays} days`}::interval
      WHERE id = ANY(${urlIds})
        AND expires_at > NOW()
      RETURNING id
    `;

    return result.length;
  } catch (error) {
    console.error('[RewrittenUrls] Extend expiration failed:', error);
    return 0;
  }
}

/**
 * Get URLs expiring soon (for notification/cleanup)
 */
export async function getExpiringUrls(
  tenantId: string,
  daysUntilExpiry: number = 7
): Promise<RewrittenUrlRecord[]> {
  try {
    const result = await sql`
      SELECT
        id, tenant_id, email_id, original_url, expanded_url,
        created_at, clicked_at, expires_at, click_count,
        click_verdict, metadata
      FROM rewritten_urls
      WHERE tenant_id = ${tenantId}
        AND expires_at > NOW()
        AND expires_at < NOW() + ${`${daysUntilExpiry} days`}::interval
        AND click_count > 0
      ORDER BY expires_at ASC
      LIMIT 100
    `;

    return result.map((row) => ({
      id: row.id,
      tenantId: row.tenant_id,
      emailId: row.email_id,
      originalUrl: row.original_url,
      expandedUrl: row.expanded_url,
      createdAt: new Date(row.created_at),
      clickedAt: row.clicked_at ? new Date(row.clicked_at) : null,
      expiresAt: new Date(row.expires_at),
      clickCount: row.click_count,
      clickVerdict: row.click_verdict,
      metadata: row.metadata,
    }));
  } catch (error) {
    console.error('[RewrittenUrls] Get expiring URLs failed:', error);
    return [];
  }
}

// ============================================================================
// Statistics & Analytics
// ============================================================================

/**
 * Get rewrite statistics for a tenant
 */
export async function getRewriteStats(
  tenantId: string,
  period: 'day' | 'week' | 'month' | '90days' = 'month'
): Promise<RewriteStats> {
  const intervalMap = {
    day: '1 day',
    week: '7 days',
    month: '30 days',
    '90days': '90 days',
  };
  const interval = intervalMap[period];

  try {
    // Get totals
    const totalsResult = await sql`
      SELECT
        COUNT(*) as total_urls,
        COALESCE(SUM(click_count), 0) as total_clicks,
        COUNT(*) FILTER (WHERE click_count > 0) as unique_urls_clicked,
        COUNT(*) FILTER (WHERE click_verdict = 'malicious') as malicious_clicks,
        COUNT(*) FILTER (WHERE click_verdict = 'suspicious') as suspicious_clicks,
        COUNT(*) FILTER (WHERE click_verdict = 'blocked') as blocked_clicks,
        COUNT(*) FILTER (WHERE click_verdict = 'safe') as safe_clicks,
        COALESCE(AVG(click_count) FILTER (WHERE click_count > 0), 0) as avg_clicks
      FROM rewritten_urls
      WHERE tenant_id = ${tenantId}
        AND created_at >= NOW() - ${interval}::interval
    `;

    // Get top clicked domains
    const domainsResult = await sql`
      SELECT
        SUBSTRING(original_url FROM '://([^/]+)') as domain,
        SUM(click_count) as clicks
      FROM rewritten_urls
      WHERE tenant_id = ${tenantId}
        AND created_at >= NOW() - ${interval}::interval
        AND click_count > 0
      GROUP BY domain
      ORDER BY clicks DESC
      LIMIT 10
    `;

    // Get clicks by day
    const dailyResult = await sql`
      SELECT
        DATE(clicked_at) as date,
        COUNT(*) as clicks
      FROM rewritten_urls
      WHERE tenant_id = ${tenantId}
        AND clicked_at IS NOT NULL
        AND clicked_at >= NOW() - ${interval}::interval
      GROUP BY DATE(clicked_at)
      ORDER BY date ASC
    `;

    // Get expiring count
    const expiringResult = await sql`
      SELECT COUNT(*) as count
      FROM rewritten_urls
      WHERE tenant_id = ${tenantId}
        AND expires_at > NOW()
        AND expires_at < NOW() + '7 days'::interval
        AND click_count > 0
    `;

    const totals = totalsResult[0] || {};

    return {
      period,
      totalUrlsRewritten: Number(totals.total_urls || 0),
      totalClicks: Number(totals.total_clicks || 0),
      uniqueUrlsClicked: Number(totals.unique_urls_clicked || 0),
      maliciousClicks: Number(totals.malicious_clicks || 0),
      suspiciousClicks: Number(totals.suspicious_clicks || 0),
      blockedClicks: Number(totals.blocked_clicks || 0),
      safeClicks: Number(totals.safe_clicks || 0),
      avgClicksPerUrl: Number(totals.avg_clicks || 0),
      topClickedDomains: domainsResult.map((row) => ({
        domain: row.domain || 'unknown',
        clicks: Number(row.clicks),
      })),
      clicksByDay: dailyResult.map((row) => ({
        date: row.date instanceof Date ? row.date.toISOString().split('T')[0] : String(row.date),
        clicks: Number(row.clicks),
      })),
      expiringUrlsCount: Number(expiringResult[0]?.count || 0),
    };
  } catch (error) {
    console.error('[RewrittenUrls] Get stats failed:', error);
    return {
      period,
      totalUrlsRewritten: 0,
      totalClicks: 0,
      uniqueUrlsClicked: 0,
      maliciousClicks: 0,
      suspiciousClicks: 0,
      blockedClicks: 0,
      safeClicks: 0,
      avgClicksPerUrl: 0,
      topClickedDomains: [],
      clicksByDay: [],
      expiringUrlsCount: 0,
    };
  }
}

// ============================================================================
// Exclusion Management
// ============================================================================

/**
 * Get excluded domains for a tenant
 */
export async function getExcludedDomains(tenantId: string): Promise<string[]> {
  try {
    const result = await sql`
      SELECT value
      FROM policies
      WHERE tenant_id = ${tenantId}
        AND type = 'allowlist'
        AND target = 'domain'
        AND is_active = true
    `;

    return result.map((row) => row.value.toLowerCase());
  } catch (error) {
    console.error('[RewrittenUrls] Get excluded domains failed:', error);
    return [];
  }
}

/**
 * Get excluded URL patterns for a tenant
 */
export async function getExcludedPatterns(tenantId: string): Promise<string[]> {
  try {
    const result = await sql`
      SELECT value
      FROM policies
      WHERE tenant_id = ${tenantId}
        AND type = 'allowlist'
        AND target = 'pattern'
        AND is_active = true
    `;

    return result.map((row) => row.value);
  } catch (error) {
    console.error('[RewrittenUrls] Get excluded patterns failed:', error);
    return [];
  }
}

/**
 * Update exclusions for a tenant
 */
export async function updateExclusions(
  tenantId: string,
  update: ExclusionUpdate,
  userId?: string
): Promise<{
  domainsAdded: number;
  domainsRemoved: number;
  patternsAdded: number;
  patternsRemoved: number;
}> {
  const result = {
    domainsAdded: 0,
    domainsRemoved: 0,
    patternsAdded: 0,
    patternsRemoved: 0,
  };

  try {
    // Add domains
    if (update.addDomains && update.addDomains.length > 0) {
      for (const domain of update.addDomains) {
        const insertResult = await sql`
          INSERT INTO policies (
            tenant_id, type, target, value, action, priority, is_active, created_by
          )
          VALUES (
            ${tenantId}, 'allowlist', 'domain', ${domain.toLowerCase()},
            'allow', 100, true, ${userId || null}
          )
          ON CONFLICT DO NOTHING
          RETURNING id
        `;
        if (insertResult.length > 0) {
          result.domainsAdded++;
        }
      }
    }

    // Remove domains
    if (update.removeDomains && update.removeDomains.length > 0) {
      const deleteResult = await sql`
        DELETE FROM policies
        WHERE tenant_id = ${tenantId}
          AND type = 'allowlist'
          AND target = 'domain'
          AND LOWER(value) = ANY(${update.removeDomains.map((d) => d.toLowerCase())})
        RETURNING id
      `;
      result.domainsRemoved = deleteResult.length;
    }

    // Add patterns
    if (update.addPatterns && update.addPatterns.length > 0) {
      for (const pattern of update.addPatterns) {
        const insertResult = await sql`
          INSERT INTO policies (
            tenant_id, type, target, value, action, priority, is_active, created_by
          )
          VALUES (
            ${tenantId}, 'allowlist', 'pattern', ${pattern},
            'allow', 100, true, ${userId || null}
          )
          ON CONFLICT DO NOTHING
          RETURNING id
        `;
        if (insertResult.length > 0) {
          result.patternsAdded++;
        }
      }
    }

    // Remove patterns
    if (update.removePatterns && update.removePatterns.length > 0) {
      const deleteResult = await sql`
        DELETE FROM policies
        WHERE tenant_id = ${tenantId}
          AND type = 'allowlist'
          AND target = 'pattern'
          AND value = ANY(${update.removePatterns})
        RETURNING id
      `;
      result.patternsRemoved = deleteResult.length;
    }

    return result;
  } catch (error) {
    console.error('[RewrittenUrls] Update exclusions failed:', error);
    return result;
  }
}

// ============================================================================
// Search & Query
// ============================================================================

/**
 * Search rewritten URLs
 */
export async function searchRewrittenUrls(params: {
  tenantId: string;
  query?: string;
  verdict?: string;
  emailId?: string;
  startDate?: Date;
  endDate?: Date;
  limit?: number;
  offset?: number;
}): Promise<{
  urls: RewrittenUrlRecord[];
  total: number;
}> {
  const {
    tenantId,
    query,
    verdict,
    emailId,
    startDate,
    endDate,
    limit = 50,
    offset = 0,
  } = params;

  try {
    let urls;
    let countResult;

    // Build query based on filters
    if (query && verdict && emailId) {
      urls = await sql`
        SELECT
          id, tenant_id, email_id, original_url, expanded_url,
          created_at, clicked_at, expires_at, click_count,
          click_verdict, metadata
        FROM rewritten_urls
        WHERE tenant_id = ${tenantId}
          AND original_url ILIKE ${'%' + query + '%'}
          AND click_verdict = ${verdict}
          AND email_id = ${emailId}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
      countResult = await sql`
        SELECT COUNT(*) as total
        FROM rewritten_urls
        WHERE tenant_id = ${tenantId}
          AND original_url ILIKE ${'%' + query + '%'}
          AND click_verdict = ${verdict}
          AND email_id = ${emailId}
      `;
    } else if (query && verdict) {
      urls = await sql`
        SELECT
          id, tenant_id, email_id, original_url, expanded_url,
          created_at, clicked_at, expires_at, click_count,
          click_verdict, metadata
        FROM rewritten_urls
        WHERE tenant_id = ${tenantId}
          AND original_url ILIKE ${'%' + query + '%'}
          AND click_verdict = ${verdict}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
      countResult = await sql`
        SELECT COUNT(*) as total
        FROM rewritten_urls
        WHERE tenant_id = ${tenantId}
          AND original_url ILIKE ${'%' + query + '%'}
          AND click_verdict = ${verdict}
      `;
    } else if (query) {
      urls = await sql`
        SELECT
          id, tenant_id, email_id, original_url, expanded_url,
          created_at, clicked_at, expires_at, click_count,
          click_verdict, metadata
        FROM rewritten_urls
        WHERE tenant_id = ${tenantId}
          AND original_url ILIKE ${'%' + query + '%'}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
      countResult = await sql`
        SELECT COUNT(*) as total
        FROM rewritten_urls
        WHERE tenant_id = ${tenantId}
          AND original_url ILIKE ${'%' + query + '%'}
      `;
    } else if (verdict) {
      urls = await sql`
        SELECT
          id, tenant_id, email_id, original_url, expanded_url,
          created_at, clicked_at, expires_at, click_count,
          click_verdict, metadata
        FROM rewritten_urls
        WHERE tenant_id = ${tenantId}
          AND click_verdict = ${verdict}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
      countResult = await sql`
        SELECT COUNT(*) as total
        FROM rewritten_urls
        WHERE tenant_id = ${tenantId}
          AND click_verdict = ${verdict}
      `;
    } else if (emailId) {
      urls = await sql`
        SELECT
          id, tenant_id, email_id, original_url, expanded_url,
          created_at, clicked_at, expires_at, click_count,
          click_verdict, metadata
        FROM rewritten_urls
        WHERE tenant_id = ${tenantId}
          AND email_id = ${emailId}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
      countResult = await sql`
        SELECT COUNT(*) as total
        FROM rewritten_urls
        WHERE tenant_id = ${tenantId}
          AND email_id = ${emailId}
      `;
    } else {
      urls = await sql`
        SELECT
          id, tenant_id, email_id, original_url, expanded_url,
          created_at, clicked_at, expires_at, click_count,
          click_verdict, metadata
        FROM rewritten_urls
        WHERE tenant_id = ${tenantId}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
      countResult = await sql`
        SELECT COUNT(*) as total
        FROM rewritten_urls
        WHERE tenant_id = ${tenantId}
      `;
    }

    return {
      urls: urls.map((row) => ({
        id: row.id,
        tenantId: row.tenant_id,
        emailId: row.email_id,
        originalUrl: row.original_url,
        expandedUrl: row.expanded_url,
        createdAt: new Date(row.created_at),
        clickedAt: row.clicked_at ? new Date(row.clicked_at) : null,
        expiresAt: new Date(row.expires_at),
        clickCount: row.click_count,
        clickVerdict: row.click_verdict,
        metadata: row.metadata,
      })),
      total: Number(countResult[0]?.total || 0),
    };
  } catch (error) {
    console.error('[RewrittenUrls] Search failed:', error);
    return { urls: [], total: 0 };
  }
}

// ============================================================================
// Exports
// ============================================================================

export default {
  generateUrlId,
  generateShortUrlId,
  isValidUrlId,
  storeRewrittenUrl,
  batchStoreRewrittenUrls,
  lookupOriginalUrl,
  recordUrlClick,
  getRewrittenUrl,
  getRewrittenUrlsForEmail,
  cleanupExpiredUrls,
  extendUrlExpiration,
  getExpiringUrls,
  getRewriteStats,
  getExcludedDomains,
  getExcludedPatterns,
  updateExclusions,
  searchRewrittenUrls,
};
