/**
 * Performance Analytics API
 * GET - Get detection performance metrics
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import {
  getDetectionPerformance,
  getPolicyEffectiveness,
  getTopThreatSenders,
  getTopThreatDomains,
} from '@/lib/analytics/service';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const searchParams = request.nextUrl.searchParams;
    const daysBack = parseInt(searchParams.get('days') || '7');

    const [performance, policyEffectiveness, topSenders, topDomains] = await Promise.all([
      getDetectionPerformance(tenantId, daysBack),
      getPolicyEffectiveness(tenantId, daysBack),
      getTopThreatSenders(tenantId, daysBack, 10),
      getTopThreatDomains(tenantId, daysBack, 10),
    ]);

    return NextResponse.json({
      performance,
      policyEffectiveness,
      topSenders,
      topDomains,
    });
  } catch (error) {
    console.error('Performance analytics error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch performance data' },
      { status: 500 }
    );
  }
}
