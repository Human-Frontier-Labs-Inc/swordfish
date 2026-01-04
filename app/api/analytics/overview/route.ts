/**
 * Analytics Overview API
 * GET - Get comprehensive analytics data
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const range = request.nextUrl.searchParams.get('range') || '30d';

    // Calculate date range
    const days = range === '7d' ? 7 : range === '90d' ? 90 : 30;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    // Overview stats
    const overview = await sql`
      SELECT
        COUNT(*)::int as total_emails,
        COUNT(*) FILTER (WHERE verdict = 'block')::int as threats_blocked,
        COUNT(*) FILTER (WHERE verdict = 'quarantine')::int as quarantined,
        COUNT(*) FILTER (WHERE user_feedback = 'false_positive')::int as false_positives
      FROM email_verdicts
      WHERE (tenant_id::text = ${tenantId} OR tenant_id::uuid = (SELECT id FROM tenants WHERE clerk_org_id = ${tenantId} LIMIT 1))
      AND created_at >= ${startDate.toISOString()}::timestamp
    `;

    const totalEmails = overview[0]?.total_emails || 0;
    const threatsBlocked = overview[0]?.threats_blocked || 0;
    const quarantined = overview[0]?.quarantined || 0;
    const falsePositives = overview[0]?.false_positives || 0;
    const detectionRate = totalEmails > 0 ? ((threatsBlocked + quarantined) / totalEmails) * 100 : 0;

    // Daily trends
    const trends = await sql`
      SELECT
        DATE(created_at) as date,
        COUNT(*)::int as emails,
        COUNT(*) FILTER (WHERE verdict IN ('block', 'quarantine'))::int as threats,
        COUNT(*) FILTER (WHERE verdict = 'quarantine')::int as quarantined
      FROM email_verdicts
      WHERE (tenant_id::text = ${tenantId} OR tenant_id::uuid = (SELECT id FROM tenants WHERE clerk_org_id = ${tenantId} LIMIT 1))
      AND created_at >= ${startDate.toISOString()}::timestamp
      GROUP BY DATE(created_at)
      ORDER BY date
    `;

    // Threat types distribution
    const threatTypes = await sql`
      SELECT
        COALESCE(ml_classification, 'unknown') as type,
        COUNT(*)::int as count
      FROM email_verdicts
      WHERE (tenant_id::text = ${tenantId} OR tenant_id::uuid = (SELECT id FROM tenants WHERE clerk_org_id = ${tenantId} LIMIT 1))
      AND verdict IN ('block', 'quarantine')
      AND created_at >= ${startDate.toISOString()}::timestamp
      GROUP BY ml_classification
      ORDER BY count DESC
      LIMIT 10
    `;

    const totalThreats = threatTypes.reduce((sum: number, t: Record<string, unknown>) => sum + (t.count as number), 0);

    // Top threat senders
    const topSenders = await sql`
      SELECT
        from_address as email,
        SPLIT_PART(from_address, '@', 2) as domain,
        COUNT(*)::int as threat_count
      FROM email_verdicts
      WHERE (tenant_id::text = ${tenantId} OR tenant_id::uuid = (SELECT id FROM tenants WHERE clerk_org_id = ${tenantId} LIMIT 1))
      AND verdict IN ('block', 'quarantine')
      AND created_at >= ${startDate.toISOString()}::timestamp
      GROUP BY from_address
      ORDER BY threat_count DESC
      LIMIT 10
    `;

    // Verdict distribution
    const verdictDistribution = await sql`
      SELECT
        verdict,
        COUNT(*)::int as count
      FROM email_verdicts
      WHERE (tenant_id::text = ${tenantId} OR tenant_id::uuid = (SELECT id FROM tenants WHERE clerk_org_id = ${tenantId} LIMIT 1))
      AND created_at >= ${startDate.toISOString()}::timestamp
      GROUP BY verdict
      ORDER BY count DESC
    `;

    const totalVerdicts = verdictDistribution.reduce((sum: number, v: Record<string, unknown>) => sum + (v.count as number), 0);

    // Response metrics
    const metrics = await sql`
      SELECT
        AVG(processing_time_ms)::int as avg_processing_time
      FROM email_verdicts
      WHERE (tenant_id::text = ${tenantId} OR tenant_id::uuid = (SELECT id FROM tenants WHERE clerk_org_id = ${tenantId} LIMIT 1))
      AND created_at >= ${startDate.toISOString()}::timestamp
    `;

    const releaseMetrics = await sql`
      SELECT
        AVG(EXTRACT(EPOCH FROM (released_at - created_at)) / 60)::int as avg_release_time
      FROM quarantine
      WHERE tenant_id::text = ${tenantId}
      AND status = 'released'
      AND created_at >= ${startDate.toISOString()}::timestamp
    `;

    return NextResponse.json({
      overview: {
        totalEmails,
        threatsBlocked,
        quarantined,
        falsePositives,
        detectionRate,
      },
      trends: trends.map((t: Record<string, unknown>) => ({
        date: (t.date as Date).toISOString(),
        emails: t.emails,
        threats: t.threats,
        quarantined: t.quarantined,
      })),
      threatTypes: threatTypes.map((t: Record<string, unknown>) => ({
        type: t.type,
        count: t.count,
        percentage: totalThreats > 0 ? ((t.count as number) / totalThreats) * 100 : 0,
      })),
      topSenders: topSenders.map((s: Record<string, unknown>) => ({
        email: s.email,
        domain: s.domain,
        threatCount: s.threat_count,
      })),
      verdictDistribution: verdictDistribution.map((v: Record<string, unknown>) => ({
        verdict: v.verdict,
        count: v.count,
        percentage: totalVerdicts > 0 ? ((v.count as number) / totalVerdicts) * 100 : 0,
      })),
      responseMetrics: {
        avgProcessingTime: metrics[0]?.avg_processing_time || 0,
        avgReleaseTime: releaseMetrics[0]?.avg_release_time || 0,
        autoQuarantineRate: quarantined > 0 && totalEmails > 0 ? (quarantined / totalEmails) * 100 : 0,
      },
    });
  } catch (error) {
    console.error('Analytics overview error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch analytics' },
      { status: 500 }
    );
  }
}
