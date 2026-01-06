/**
 * MSP Admin Reports API
 * GET - Generate comprehensive threat analytics and reports
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgRole } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check MSP admin access
    const currentUser = await sql`
      SELECT is_msp_user, role FROM users
      WHERE clerk_user_id = ${userId}
      LIMIT 1
    `;

    const user = currentUser[0];
    const hasAccess = orgRole === 'org:admin' || user?.is_msp_user || user?.role === 'msp_admin';

    if (!hasAccess) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const searchParams = request.nextUrl.searchParams;
    const reportType = searchParams.get('type') || 'overview';
    const period = searchParams.get('period') || '30d';
    const tenantId = searchParams.get('tenantId');
    const format = searchParams.get('format') || 'json';

    // Calculate date range
    const periodDays = period === '7d' ? 7 : period === '30d' ? 30 : period === '90d' ? 90 : 30;

    if (reportType === 'overview') {
      return await getOverviewReport(periodDays, tenantId);
    } else if (reportType === 'trends') {
      return await getTrendsReport(periodDays, tenantId);
    } else if (reportType === 'tenants') {
      return await getTenantComparisonReport(periodDays);
    } else if (reportType === 'threats') {
      return await getThreatBreakdownReport(periodDays, tenantId);
    } else if (reportType === 'export') {
      return await getExportData(periodDays, tenantId, format);
    }

    return NextResponse.json({ error: 'Invalid report type' }, { status: 400 });
  } catch (error) {
    console.error('Admin reports error:', error);
    return NextResponse.json(
      { error: 'Failed to generate report' },
      { status: 500 }
    );
  }
}

async function getOverviewReport(periodDays: number, tenantId: string | null) {
  // Summary stats
  const summary = await sql`
    SELECT
      COUNT(*)::int as total_threats,
      COUNT(*) FILTER (WHERE verdict = 'malicious')::int as malicious,
      COUNT(*) FILTER (WHERE verdict = 'phishing')::int as phishing,
      COUNT(*) FILTER (WHERE verdict = 'suspicious')::int as suspicious,
      COUNT(*) FILTER (WHERE status = 'quarantined')::int as quarantined,
      COUNT(*) FILTER (WHERE status = 'released')::int as released,
      COUNT(*) FILTER (WHERE status = 'deleted')::int as deleted,
      ROUND(AVG(score)::numeric, 1) as avg_score,
      COUNT(DISTINCT tenant_id)::int as affected_tenants
    FROM threats
    WHERE created_at >= NOW() - INTERVAL '1 day' * ${periodDays}
    ${tenantId ? sql`AND tenant_id = ${tenantId}` : sql``}
  `;

  // Comparison with previous period
  const previousPeriod = await sql`
    SELECT COUNT(*)::int as total_threats
    FROM threats
    WHERE created_at >= NOW() - INTERVAL '1 day' * ${periodDays * 2}
      AND created_at < NOW() - INTERVAL '1 day' * ${periodDays}
    ${tenantId ? sql`AND tenant_id = ${tenantId}` : sql``}
  `;

  const currentTotal = summary[0]?.total_threats || 0;
  const previousTotal = previousPeriod[0]?.total_threats || 0;
  const changePercent = previousTotal > 0
    ? Math.round(((currentTotal - previousTotal) / previousTotal) * 100)
    : 0;

  // Top threat sources
  const topSources = await sql`
    SELECT
      sender_email,
      COUNT(*)::int as threat_count,
      ROUND(AVG(score)::numeric, 1) as avg_score
    FROM threats
    WHERE created_at >= NOW() - INTERVAL '1 day' * ${periodDays}
    ${tenantId ? sql`AND tenant_id = ${tenantId}` : sql``}
    GROUP BY sender_email
    ORDER BY threat_count DESC
    LIMIT 10
  `;

  // Most targeted recipients
  const topTargets = await sql`
    SELECT
      recipient_email,
      COUNT(*)::int as threat_count
    FROM threats
    WHERE created_at >= NOW() - INTERVAL '1 day' * ${periodDays}
      AND recipient_email IS NOT NULL
    ${tenantId ? sql`AND tenant_id = ${tenantId}` : sql``}
    GROUP BY recipient_email
    ORDER BY threat_count DESC
    LIMIT 10
  `;

  return NextResponse.json({
    reportType: 'overview',
    period: `${periodDays}d`,
    generatedAt: new Date().toISOString(),
    summary: {
      totalThreats: currentTotal,
      changeFromPrevious: changePercent,
      byVerdict: {
        malicious: summary[0]?.malicious || 0,
        phishing: summary[0]?.phishing || 0,
        suspicious: summary[0]?.suspicious || 0,
      },
      byStatus: {
        quarantined: summary[0]?.quarantined || 0,
        released: summary[0]?.released || 0,
        deleted: summary[0]?.deleted || 0,
      },
      averageScore: summary[0]?.avg_score || 0,
      affectedTenants: summary[0]?.affected_tenants || 0,
    },
    topSources: topSources.map((s: Record<string, unknown>) => ({
      email: s.sender_email,
      count: s.threat_count,
      avgScore: s.avg_score,
    })),
    topTargets: topTargets.map((t: Record<string, unknown>) => ({
      email: t.recipient_email,
      count: t.threat_count,
    })),
  });
}

async function getTrendsReport(periodDays: number, tenantId: string | null) {
  // Daily threat counts
  const dailyTrends = await sql`
    SELECT
      DATE(created_at) as date,
      COUNT(*)::int as total,
      COUNT(*) FILTER (WHERE verdict = 'malicious')::int as malicious,
      COUNT(*) FILTER (WHERE verdict = 'phishing')::int as phishing,
      COUNT(*) FILTER (WHERE verdict = 'suspicious')::int as suspicious
    FROM threats
    WHERE created_at >= NOW() - INTERVAL '1 day' * ${periodDays}
    ${tenantId ? sql`AND tenant_id = ${tenantId}` : sql``}
    GROUP BY DATE(created_at)
    ORDER BY date ASC
  `;

  // Hourly distribution (for pattern detection)
  const hourlyDistribution = await sql`
    SELECT
      EXTRACT(HOUR FROM created_at)::int as hour,
      COUNT(*)::int as count
    FROM threats
    WHERE created_at >= NOW() - INTERVAL '1 day' * ${periodDays}
    ${tenantId ? sql`AND tenant_id = ${tenantId}` : sql``}
    GROUP BY EXTRACT(HOUR FROM created_at)
    ORDER BY hour
  `;

  // Day of week distribution
  const weekdayDistribution = await sql`
    SELECT
      EXTRACT(DOW FROM created_at)::int as day_of_week,
      COUNT(*)::int as count
    FROM threats
    WHERE created_at >= NOW() - INTERVAL '1 day' * ${periodDays}
    ${tenantId ? sql`AND tenant_id = ${tenantId}` : sql``}
    GROUP BY EXTRACT(DOW FROM created_at)
    ORDER BY day_of_week
  `;

  const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

  return NextResponse.json({
    reportType: 'trends',
    period: `${periodDays}d`,
    generatedAt: new Date().toISOString(),
    daily: dailyTrends.map((d: Record<string, unknown>) => ({
      date: (d.date as Date).toISOString().split('T')[0],
      total: d.total,
      malicious: d.malicious,
      phishing: d.phishing,
      suspicious: d.suspicious,
    })),
    hourlyDistribution: hourlyDistribution.map((h: Record<string, unknown>) => ({
      hour: h.hour,
      count: h.count,
    })),
    weekdayDistribution: weekdayDistribution.map((w: Record<string, unknown>) => ({
      day: dayNames[w.day_of_week as number],
      dayIndex: w.day_of_week,
      count: w.count,
    })),
  });
}

async function getTenantComparisonReport(periodDays: number) {
  // Per-tenant threat stats
  const tenantStats = await sql`
    SELECT
      t.tenant_id,
      ten.name as tenant_name,
      COUNT(*)::int as total_threats,
      COUNT(*) FILTER (WHERE t.verdict = 'malicious')::int as malicious,
      COUNT(*) FILTER (WHERE t.verdict = 'phishing')::int as phishing,
      COUNT(*) FILTER (WHERE t.status = 'quarantined')::int as quarantined,
      ROUND(AVG(t.score)::numeric, 1) as avg_score
    FROM threats t
    LEFT JOIN tenants ten ON t.tenant_id = ten.clerk_org_id OR t.tenant_id = ten.id::text
    WHERE t.created_at >= NOW() - INTERVAL '1 day' * ${periodDays}
    GROUP BY t.tenant_id, ten.name
    ORDER BY total_threats DESC
  `;

  // Calculate risk scores
  const tenantsWithRisk = tenantStats.map((t: Record<string, unknown>) => {
    const total = t.total_threats as number;
    const malicious = t.malicious as number;
    const phishing = t.phishing as number;
    const avgScore = t.avg_score as number || 0;

    // Risk score formula: weighted average of threat severity
    const riskScore = total > 0
      ? Math.round((malicious * 3 + phishing * 2 + (total - malicious - phishing)) / total * avgScore / 3)
      : 0;

    return {
      tenantId: t.tenant_id,
      tenantName: t.tenant_name || 'Unknown',
      totalThreats: total,
      malicious,
      phishing,
      quarantined: t.quarantined,
      avgScore,
      riskScore: Math.min(100, riskScore),
      riskLevel: riskScore >= 70 ? 'high' : riskScore >= 40 ? 'medium' : 'low',
    };
  });

  return NextResponse.json({
    reportType: 'tenants',
    period: `${periodDays}d`,
    generatedAt: new Date().toISOString(),
    tenants: tenantsWithRisk,
    summary: {
      totalTenants: tenantsWithRisk.length,
      highRisk: tenantsWithRisk.filter(t => t.riskLevel === 'high').length,
      mediumRisk: tenantsWithRisk.filter(t => t.riskLevel === 'medium').length,
      lowRisk: tenantsWithRisk.filter(t => t.riskLevel === 'low').length,
    },
  });
}

async function getThreatBreakdownReport(periodDays: number, tenantId: string | null) {
  // By category
  const categoryBreakdown = await sql`
    SELECT
      unnest(categories) as category,
      COUNT(*)::int as count
    FROM threats
    WHERE created_at >= NOW() - INTERVAL '1 day' * ${periodDays}
      AND categories IS NOT NULL
    ${tenantId ? sql`AND tenant_id = ${tenantId}` : sql``}
    GROUP BY unnest(categories)
    ORDER BY count DESC
    LIMIT 20
  `;

  // By signal type
  const signalBreakdown = await sql`
    SELECT
      unnest(signals) as signal,
      COUNT(*)::int as count
    FROM threats
    WHERE created_at >= NOW() - INTERVAL '1 day' * ${periodDays}
      AND signals IS NOT NULL
    ${tenantId ? sql`AND tenant_id = ${tenantId}` : sql``}
    GROUP BY unnest(signals)
    ORDER BY count DESC
    LIMIT 20
  `;

  // Score distribution
  const scoreDistribution = await sql`
    SELECT
      CASE
        WHEN score >= 90 THEN 'Critical (90-100)'
        WHEN score >= 70 THEN 'High (70-89)'
        WHEN score >= 50 THEN 'Medium (50-69)'
        WHEN score >= 30 THEN 'Low (30-49)'
        ELSE 'Minimal (0-29)'
      END as range,
      COUNT(*)::int as count
    FROM threats
    WHERE created_at >= NOW() - INTERVAL '1 day' * ${periodDays}
    ${tenantId ? sql`AND tenant_id = ${tenantId}` : sql``}
    GROUP BY range
    ORDER BY
      CASE range
        WHEN 'Critical (90-100)' THEN 1
        WHEN 'High (70-89)' THEN 2
        WHEN 'Medium (50-69)' THEN 3
        WHEN 'Low (30-49)' THEN 4
        ELSE 5
      END
  `;

  // By integration type
  const integrationBreakdown = await sql`
    SELECT
      COALESCE(integration_type, 'Unknown') as integration,
      COUNT(*)::int as count
    FROM threats
    WHERE created_at >= NOW() - INTERVAL '1 day' * ${periodDays}
    ${tenantId ? sql`AND tenant_id = ${tenantId}` : sql``}
    GROUP BY integration_type
    ORDER BY count DESC
  `;

  return NextResponse.json({
    reportType: 'threats',
    period: `${periodDays}d`,
    generatedAt: new Date().toISOString(),
    categories: categoryBreakdown.map((c: Record<string, unknown>) => ({
      category: c.category,
      count: c.count,
    })),
    signals: signalBreakdown.map((s: Record<string, unknown>) => ({
      signal: s.signal,
      count: s.count,
    })),
    scoreDistribution: scoreDistribution.map((s: Record<string, unknown>) => ({
      range: s.range,
      count: s.count,
    })),
    integrations: integrationBreakdown.map((i: Record<string, unknown>) => ({
      type: i.integration,
      count: i.count,
    })),
  });
}

async function getExportData(periodDays: number, tenantId: string | null, format: string) {
  const threats = await sql`
    SELECT
      t.id,
      t.tenant_id,
      ten.name as tenant_name,
      t.subject,
      t.sender_email,
      t.recipient_email,
      t.verdict,
      t.score,
      t.status,
      t.categories,
      t.signals,
      t.created_at
    FROM threats t
    LEFT JOIN tenants ten ON t.tenant_id = ten.clerk_org_id OR t.tenant_id = ten.id::text
    WHERE t.created_at >= NOW() - INTERVAL '1 day' * ${periodDays}
    ${tenantId ? sql`AND t.tenant_id = ${tenantId}` : sql``}
    ORDER BY t.created_at DESC
    LIMIT 10000
  `;

  if (format === 'csv') {
    const headers = ['ID', 'Tenant', 'Subject', 'Sender', 'Recipient', 'Verdict', 'Score', 'Status', 'Categories', 'Date'];
    const rows = threats.map((t: Record<string, unknown>) => [
      t.id,
      t.tenant_name || t.tenant_id,
      `"${((t.subject as string) || '').replace(/"/g, '""')}"`,
      t.sender_email,
      t.recipient_email || '',
      t.verdict,
      t.score,
      t.status,
      `"${((t.categories as string[]) || []).join(', ')}"`,
      (t.created_at as Date).toISOString(),
    ].join(','));

    const csv = [headers.join(','), ...rows].join('\n');

    return new NextResponse(csv, {
      headers: {
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename=threats-export-${new Date().toISOString().split('T')[0]}.csv`,
      },
    });
  }

  return NextResponse.json({
    exportType: 'json',
    period: `${periodDays}d`,
    generatedAt: new Date().toISOString(),
    recordCount: threats.length,
    data: threats.map((t: Record<string, unknown>) => ({
      id: t.id,
      tenantId: t.tenant_id,
      tenantName: t.tenant_name || 'Unknown',
      subject: t.subject,
      senderEmail: t.sender_email,
      recipientEmail: t.recipient_email,
      verdict: t.verdict,
      score: t.score,
      status: t.status,
      categories: t.categories || [],
      signals: t.signals || [],
      createdAt: (t.created_at as Date).toISOString(),
    })),
  });
}
