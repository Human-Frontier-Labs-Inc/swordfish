/**
 * Dashboard Stats API
 * Real-time statistics for the security dashboard
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { getVerdictStats } from '@/lib/detection/storage';
import { getThreatStats } from '@/lib/quarantine/service';

/**
 * GET - Get dashboard statistics
 */
export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const searchParams = request.nextUrl.searchParams;
    const period = searchParams.get('period') || '7d';

    // Calculate days from period
    const daysMap: Record<string, number> = {
      '24h': 1,
      '7d': 7,
      '30d': 30,
      '90d': 90,
    };
    const days = daysMap[period] || 7;

    // Get verdict stats
    const verdictStats = await getVerdictStats(tenantId, days);

    // Get threat stats
    const threatStats = await getThreatStats(tenantId);

    // Get email processing timeline
    const timeline = await sql`
      SELECT
        DATE_TRUNC('day', created_at) as date,
        COUNT(*)::int as total,
        COUNT(*) FILTER (WHERE verdict = 'pass')::int as passed,
        COUNT(*) FILTER (WHERE verdict IN ('suspicious', 'quarantine', 'block'))::int as threats
      FROM email_verdicts
      WHERE tenant_id = ${tenantId}
      AND created_at >= NOW() - INTERVAL '1 day' * ${days}
      GROUP BY DATE_TRUNC('day', created_at)
      ORDER BY date ASC
    `;

    // Get top threat types
    const topThreats = await sql`
      SELECT
        signal_type,
        COUNT(*)::int as count,
        AVG(score)::float as avg_score
      FROM (
        SELECT
          jsonb_array_elements(signals)->>'type' as signal_type,
          score
        FROM email_verdicts
        WHERE tenant_id = ${tenantId}
        AND verdict IN ('suspicious', 'quarantine', 'block')
        AND created_at >= NOW() - INTERVAL '1 day' * ${days}
      ) signals
      GROUP BY signal_type
      ORDER BY count DESC
      LIMIT 10
    `;

    // Get top senders by threat score
    const topSenders = await sql`
      SELECT
        signals->0->>'sender' as sender,
        COUNT(*)::int as email_count,
        AVG(score)::float as avg_score,
        MAX(score)::int as max_score
      FROM email_verdicts
      WHERE tenant_id = ${tenantId}
      AND verdict IN ('suspicious', 'quarantine', 'block')
      AND created_at >= NOW() - INTERVAL '1 day' * ${days}
      GROUP BY signals->0->>'sender'
      HAVING signals->0->>'sender' IS NOT NULL
      ORDER BY avg_score DESC
      LIMIT 10
    `;

    // Get integration status
    const integrations = await sql`
      SELECT
        provider,
        status,
        email,
        updated_at as last_sync
      FROM provider_connections
      WHERE tenant_id = ${tenantId}
    `;

    // Calculate summary metrics
    const summary = {
      totalEmails: verdictStats.total,
      passedEmails: verdictStats.passed,
      threatsDetected: verdictStats.suspicious + verdictStats.quarantined + verdictStats.blocked,
      quarantined: verdictStats.quarantined,
      blocked: verdictStats.blocked,
      avgThreatScore: Math.round(verdictStats.avgScore),
      avgProcessingTime: Math.round(verdictStats.avgProcessingTime),
      detectionRate: verdictStats.total > 0
        ? ((verdictStats.suspicious + verdictStats.quarantined + verdictStats.blocked) / verdictStats.total * 100).toFixed(1)
        : '0',
      activeQuarantined: threatStats.quarantinedCount,
      last24Hours: threatStats.last24Hours,
    };

    return NextResponse.json({
      summary,
      timeline,
      topThreats,
      topSenders,
      integrations,
      quarantine: threatStats,
      period,
    });
  } catch (error) {
    console.error('Stats API error:', error);
    return NextResponse.json(
      { error: 'Failed to get stats' },
      { status: 500 }
    );
  }
}
