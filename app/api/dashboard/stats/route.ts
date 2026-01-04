/**
 * Dashboard Statistics API
 * GET /api/dashboard/stats
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getVerdictStats } from '@/lib/detection/storage';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const tenantId = orgId || `personal_${userId}`;

    // Get days parameter from query (default 7)
    const searchParams = request.nextUrl.searchParams;
    const days = parseInt(searchParams.get('days') || '7');

    const stats = await getVerdictStats(tenantId, days);

    // Calculate detection rate
    const threatCount = stats.suspicious + stats.quarantined + stats.blocked;
    const detectionRate = stats.total > 0 ? (threatCount / stats.total) * 100 : 0;

    return NextResponse.json({
      emailsScanned: stats.total,
      threatsBlocked: threatCount,
      quarantined: stats.quarantined,
      detectionRate: Math.round(detectionRate * 10) / 10,
      avgProcessingTimeMs: Math.round(stats.avgProcessingTime),
      breakdown: {
        passed: stats.passed,
        suspicious: stats.suspicious,
        quarantined: stats.quarantined,
        blocked: stats.blocked,
      },
      period: `${days}d`,
    });

  } catch (error) {
    console.error('Stats API error:', error);

    // Return zeros for new tenants without data
    return NextResponse.json({
      emailsScanned: 0,
      threatsBlocked: 0,
      quarantined: 0,
      detectionRate: 0,
      avgProcessingTimeMs: 0,
      breakdown: {
        passed: 0,
        suspicious: 0,
        quarantined: 0,
        blocked: 0,
      },
      period: '7d',
    });
  }
}
