/**
 * Time Series Analytics API
 * GET - Get time series data for charts
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import {
  getEmailTimeSeries,
  getThreatTimeSeries,
  getScoreDistribution,
  getHourlyDistribution,
} from '@/lib/analytics/service';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const searchParams = request.nextUrl.searchParams;
    const type = searchParams.get('type') || 'emails';
    const daysBack = parseInt(searchParams.get('days') || '7');

    let data;
    switch (type) {
      case 'emails':
        data = await getEmailTimeSeries(tenantId, daysBack);
        break;
      case 'threats':
        data = await getThreatTimeSeries(tenantId, daysBack);
        break;
      case 'scores':
        data = await getScoreDistribution(tenantId, daysBack);
        break;
      case 'hourly':
        data = await getHourlyDistribution(tenantId, daysBack);
        break;
      default:
        data = await getEmailTimeSeries(tenantId, daysBack);
    }

    return NextResponse.json({ data, type, daysBack });
  } catch (error) {
    console.error('Time series error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch time series' },
      { status: 500 }
    );
  }
}
