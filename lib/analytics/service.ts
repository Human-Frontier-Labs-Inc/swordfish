/**
 * Analytics Service
 * Aggregates and analyzes email security data for reporting
 */

import { sql } from '@/lib/db';

export interface TimeSeriesPoint {
  date: string;
  value: number;
}

export interface VerdictBreakdown {
  pass: number;
  suspicious: number;
  quarantine: number;
  block: number;
}

export interface ThreatCategory {
  category: string;
  count: number;
  percentage: number;
}

export interface SenderStats {
  email: string;
  domain: string;
  threatCount: number;
  avgScore: number;
  lastSeen: Date;
}

export interface DashboardStats {
  summary: {
    totalEmails: number;
    threatsBlocked: number;
    quarantined: number;
    passRate: number;
    avgProcessingTime: number;
  };
  trends: {
    emailsToday: number;
    emailsYesterday: number;
    threatsToday: number;
    threatsYesterday: number;
    changePercent: number;
  };
  verdictBreakdown: VerdictBreakdown;
  topThreats: ThreatCategory[];
  recentActivity: TimeSeriesPoint[];
}

/**
 * Get comprehensive dashboard statistics
 */
export async function getDashboardStats(
  tenantId: string,
  daysBack: number = 7
): Promise<DashboardStats> {
  // Run queries in parallel for performance
  const [summary, trends, breakdown, categories, timeSeries] = await Promise.all([
    getSummaryStats(tenantId, daysBack),
    getTrendComparison(tenantId),
    getVerdictBreakdown(tenantId, daysBack),
    getTopThreatCategories(tenantId, daysBack),
    getEmailTimeSeries(tenantId, daysBack),
  ]);

  return {
    summary,
    trends,
    verdictBreakdown: breakdown,
    topThreats: categories,
    recentActivity: timeSeries,
  };
}

/**
 * Get summary statistics for a time period
 */
export async function getSummaryStats(
  tenantId: string,
  daysBack: number = 7
): Promise<DashboardStats['summary']> {
  const results = await sql`
    SELECT
      COUNT(*)::int as total_emails,
      COUNT(*) FILTER (WHERE verdict = 'block')::int as threats_blocked,
      COUNT(*) FILTER (WHERE verdict = 'quarantine')::int as quarantined,
      ROUND(
        (COUNT(*) FILTER (WHERE verdict = 'pass')::float / NULLIF(COUNT(*), 0) * 100)::numeric, 1
      ) as pass_rate,
      ROUND(AVG(processing_time_ms)::numeric, 0) as avg_processing_time
    FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND created_at >= NOW() - INTERVAL '1 day' * ${daysBack}
  `;

  const row = results[0] || {};
  return {
    totalEmails: Number(row.total_emails) || 0,
    threatsBlocked: Number(row.threats_blocked) || 0,
    quarantined: Number(row.quarantined) || 0,
    passRate: Number(row.pass_rate) || 0,
    avgProcessingTime: Number(row.avg_processing_time) || 0,
  };
}

/**
 * Get trend comparison (today vs yesterday)
 */
export async function getTrendComparison(
  tenantId: string
): Promise<DashboardStats['trends']> {
  const results = await sql`
    SELECT
      COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE)::int as emails_today,
      COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE - INTERVAL '1 day' AND created_at < CURRENT_DATE)::int as emails_yesterday,
      COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE AND verdict IN ('block', 'quarantine'))::int as threats_today,
      COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE - INTERVAL '1 day' AND created_at < CURRENT_DATE AND verdict IN ('block', 'quarantine'))::int as threats_yesterday
    FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND created_at >= CURRENT_DATE - INTERVAL '2 days'
  `;

  const row = results[0] || {};
  const emailsToday = Number(row.emails_today) || 0;
  const emailsYesterday = Number(row.emails_yesterday) || 0;
  const changePercent = emailsYesterday > 0
    ? Math.round(((emailsToday - emailsYesterday) / emailsYesterday) * 100)
    : 0;

  return {
    emailsToday,
    emailsYesterday,
    threatsToday: Number(row.threats_today) || 0,
    threatsYesterday: Number(row.threats_yesterday) || 0,
    changePercent,
  };
}

/**
 * Get verdict breakdown for pie chart
 */
export async function getVerdictBreakdown(
  tenantId: string,
  daysBack: number = 7
): Promise<VerdictBreakdown> {
  const results = await sql`
    SELECT
      COUNT(*) FILTER (WHERE verdict = 'pass')::int as pass,
      COUNT(*) FILTER (WHERE verdict = 'suspicious')::int as suspicious,
      COUNT(*) FILTER (WHERE verdict = 'quarantine')::int as quarantine,
      COUNT(*) FILTER (WHERE verdict = 'block')::int as block
    FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND created_at >= NOW() - INTERVAL '1 day' * ${daysBack}
  `;

  const row = results[0] || {};
  return {
    pass: Number(row.pass) || 0,
    suspicious: Number(row.suspicious) || 0,
    quarantine: Number(row.quarantine) || 0,
    block: Number(row.block) || 0,
  };
}

/**
 * Get top threat categories
 */
export async function getTopThreatCategories(
  tenantId: string,
  daysBack: number = 7,
  limit: number = 5
): Promise<ThreatCategory[]> {
  // Extract categories from signals JSONB
  const results = await sql`
    WITH signal_categories AS (
      SELECT
        jsonb_array_elements(signals)->>'category' as category
      FROM email_verdicts
      WHERE tenant_id = ${tenantId}
      AND created_at >= NOW() - INTERVAL '1 day' * ${daysBack}
      AND verdict IN ('suspicious', 'quarantine', 'block')
    ),
    category_counts AS (
      SELECT
        COALESCE(category, 'unknown') as category,
        COUNT(*) as count
      FROM signal_categories
      WHERE category IS NOT NULL
      GROUP BY category
      ORDER BY count DESC
      LIMIT ${limit}
    ),
    total AS (
      SELECT SUM(count)::float as total FROM category_counts
    )
    SELECT
      cc.category,
      cc.count::int,
      ROUND((cc.count::float / NULLIF(t.total, 0) * 100)::numeric, 1) as percentage
    FROM category_counts cc, total t
  `;

  return results.map((r: Record<string, unknown>) => ({
    category: String(r.category),
    count: Number(r.count) || 0,
    percentage: Number(r.percentage) || 0,
  }));
}

/**
 * Get email volume time series for charts
 */
export async function getEmailTimeSeries(
  tenantId: string,
  daysBack: number = 7
): Promise<TimeSeriesPoint[]> {
  const results = await sql`
    SELECT
      DATE(created_at) as date,
      COUNT(*)::int as value
    FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND created_at >= NOW() - INTERVAL '1 day' * ${daysBack}
    GROUP BY DATE(created_at)
    ORDER BY date
  `;

  return results.map((r: Record<string, unknown>) => ({
    date: new Date(r.date as string).toISOString().split('T')[0],
    value: Number(r.value) || 0,
  }));
}

/**
 * Get threat time series (threats per day)
 */
export async function getThreatTimeSeries(
  tenantId: string,
  daysBack: number = 30
): Promise<TimeSeriesPoint[]> {
  const results = await sql`
    SELECT
      DATE(created_at) as date,
      COUNT(*)::int as value
    FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND created_at >= NOW() - INTERVAL '1 day' * ${daysBack}
    AND verdict IN ('suspicious', 'quarantine', 'block')
    GROUP BY DATE(created_at)
    ORDER BY date
  `;

  return results.map((r: Record<string, unknown>) => ({
    date: new Date(r.date as string).toISOString().split('T')[0],
    value: Number(r.value) || 0,
  }));
}

/**
 * Get score distribution histogram
 */
export async function getScoreDistribution(
  tenantId: string,
  daysBack: number = 7
): Promise<Array<{ range: string; count: number }>> {
  const results = await sql`
    SELECT
      CASE
        WHEN score >= 0 AND score < 20 THEN '0-19'
        WHEN score >= 20 AND score < 40 THEN '20-39'
        WHEN score >= 40 AND score < 60 THEN '40-59'
        WHEN score >= 60 AND score < 80 THEN '60-79'
        WHEN score >= 80 THEN '80-100'
      END as range,
      COUNT(*)::int as count
    FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND created_at >= NOW() - INTERVAL '1 day' * ${daysBack}
    GROUP BY range
    ORDER BY range
  `;

  return results.map((r: Record<string, unknown>) => ({
    range: String(r.range),
    count: Number(r.count) || 0,
  }));
}

/**
 * Get top threat senders
 */
export async function getTopThreatSenders(
  tenantId: string,
  daysBack: number = 30,
  limit: number = 10
): Promise<SenderStats[]> {
  const results = await sql`
    SELECT
      t.sender_email as email,
      SPLIT_PART(t.sender_email, '@', 2) as domain,
      COUNT(*)::int as threat_count,
      ROUND(AVG(t.score)::numeric, 0) as avg_score,
      MAX(t.quarantined_at) as last_seen
    FROM threats t
    WHERE t.tenant_id = ${tenantId}
    AND t.quarantined_at >= NOW() - INTERVAL '1 day' * ${daysBack}
    GROUP BY t.sender_email
    ORDER BY threat_count DESC, avg_score DESC
    LIMIT ${limit}
  `;

  return results.map((r: Record<string, unknown>) => ({
    email: String(r.email),
    domain: String(r.domain),
    threatCount: Number(r.threat_count) || 0,
    avgScore: Number(r.avg_score) || 0,
    lastSeen: new Date(r.last_seen as string),
  }));
}

/**
 * Get top threat domains
 */
export async function getTopThreatDomains(
  tenantId: string,
  daysBack: number = 30,
  limit: number = 10
): Promise<Array<{ domain: string; count: number; avgScore: number }>> {
  const results = await sql`
    SELECT
      SPLIT_PART(sender_email, '@', 2) as domain,
      COUNT(*)::int as count,
      ROUND(AVG(score)::numeric, 0) as avg_score
    FROM threats
    WHERE tenant_id = ${tenantId}
    AND quarantined_at >= NOW() - INTERVAL '1 day' * ${daysBack}
    GROUP BY SPLIT_PART(sender_email, '@', 2)
    ORDER BY count DESC
    LIMIT ${limit}
  `;

  return results.map((r: Record<string, unknown>) => ({
    domain: String(r.domain),
    count: Number(r.count) || 0,
    avgScore: Number(r.avg_score) || 0,
  }));
}

/**
 * Get hourly distribution (for heatmap)
 */
export async function getHourlyDistribution(
  tenantId: string,
  daysBack: number = 7
): Promise<Array<{ hour: number; day: number; count: number }>> {
  const results = await sql`
    SELECT
      EXTRACT(HOUR FROM created_at)::int as hour,
      EXTRACT(DOW FROM created_at)::int as day,
      COUNT(*)::int as count
    FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND created_at >= NOW() - INTERVAL '1 day' * ${daysBack}
    AND verdict IN ('suspicious', 'quarantine', 'block')
    GROUP BY hour, day
    ORDER BY day, hour
  `;

  return results.map((r: Record<string, unknown>) => ({
    hour: Number(r.hour),
    day: Number(r.day),
    count: Number(r.count) || 0,
  }));
}

/**
 * Get detection performance metrics
 */
export async function getDetectionPerformance(
  tenantId: string,
  daysBack: number = 7
): Promise<{
  avgLatency: number;
  p95Latency: number;
  p99Latency: number;
  llmUsageRate: number;
  avgTokensPerLLM: number;
}> {
  const results = await sql`
    SELECT
      ROUND(AVG(processing_time_ms)::numeric, 0) as avg_latency,
      ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY processing_time_ms)::numeric, 0) as p95_latency,
      ROUND(PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY processing_time_ms)::numeric, 0) as p99_latency,
      ROUND(
        (COUNT(*) FILTER (WHERE llm_tokens_used > 0)::float / NULLIF(COUNT(*), 0) * 100)::numeric, 1
      ) as llm_usage_rate,
      ROUND(AVG(llm_tokens_used) FILTER (WHERE llm_tokens_used > 0)::numeric, 0) as avg_tokens
    FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND created_at >= NOW() - INTERVAL '1 day' * ${daysBack}
  `;

  const row = results[0] || {};
  return {
    avgLatency: Number(row.avg_latency) || 0,
    p95Latency: Number(row.p95_latency) || 0,
    p99Latency: Number(row.p99_latency) || 0,
    llmUsageRate: Number(row.llm_usage_rate) || 0,
    avgTokensPerLLM: Number(row.avg_tokens) || 0,
  };
}

/**
 * Get policy effectiveness metrics
 */
export async function getPolicyEffectiveness(
  tenantId: string,
  daysBack: number = 30
): Promise<{
  allowlistHits: number;
  blocklistHits: number;
  customPolicyHits: number;
  falsePositives: number;
  falseNegatives: number;
}> {
  const [policyHits, feedback] = await Promise.all([
    sql`
      SELECT
        COUNT(*) FILTER (WHERE signals::text LIKE '%allowlist%')::int as allowlist_hits,
        COUNT(*) FILTER (WHERE signals::text LIKE '%blocklist%')::int as blocklist_hits,
        COUNT(*) FILTER (WHERE signals::text LIKE '%policy%')::int as custom_policy_hits
      FROM email_verdicts
      WHERE tenant_id = ${tenantId}
      AND created_at >= NOW() - INTERVAL '1 day' * ${daysBack}
    `,
    sql`
      SELECT
        COUNT(*) FILTER (WHERE feedback_type = 'false_positive')::int as false_positives,
        COUNT(*) FILTER (WHERE feedback_type = 'false_negative')::int as false_negatives
      FROM feedback
      WHERE tenant_id = ${tenantId}
      AND created_at >= NOW() - INTERVAL '1 day' * ${daysBack}
    `,
  ]);

  const policyRow = policyHits[0] || {};
  const feedbackRow = feedback[0] || {};

  return {
    allowlistHits: Number(policyRow.allowlist_hits) || 0,
    blocklistHits: Number(policyRow.blocklist_hits) || 0,
    customPolicyHits: Number(policyRow.custom_policy_hits) || 0,
    falsePositives: Number(feedbackRow.false_positives) || 0,
    falseNegatives: Number(feedbackRow.false_negatives) || 0,
  };
}

/**
 * Generate executive summary report data
 */
export async function generateExecutiveSummary(
  tenantId: string,
  daysBack: number = 30
): Promise<{
  period: { start: Date; end: Date };
  summary: DashboardStats['summary'];
  verdictBreakdown: VerdictBreakdown;
  topThreats: ThreatCategory[];
  topSenders: SenderStats[];
  performance: Awaited<ReturnType<typeof getDetectionPerformance>>;
  policyEffectiveness: Awaited<ReturnType<typeof getPolicyEffectiveness>>;
}> {
  const endDate = new Date();
  const startDate = new Date(endDate.getTime() - daysBack * 24 * 60 * 60 * 1000);

  const [summary, verdictBreakdown, topThreats, topSenders, performance, policyEffectiveness] =
    await Promise.all([
      getSummaryStats(tenantId, daysBack),
      getVerdictBreakdown(tenantId, daysBack),
      getTopThreatCategories(tenantId, daysBack, 10),
      getTopThreatSenders(tenantId, daysBack, 10),
      getDetectionPerformance(tenantId, daysBack),
      getPolicyEffectiveness(tenantId, daysBack),
    ]);

  return {
    period: { start: startDate, end: endDate },
    summary,
    verdictBreakdown,
    topThreats,
    topSenders,
    performance,
    policyEffectiveness,
  };
}
