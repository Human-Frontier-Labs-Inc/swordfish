/**
 * Threats API
 * GET - List quarantined threats
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getThreatsForManagement } from '@/lib/detection/storage';
import { getVerdictStats } from '@/lib/detection/storage';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const searchParams = request.nextUrl.searchParams;
    const status = (searchParams.get('status') as 'quarantined' | 'released' | 'deleted' | 'all') || 'all';
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');
    const includeStats = searchParams.get('stats') === 'true';

    // Read from email_verdicts (the source the live detection pipeline writes to),
    // so the Threats page mirrors the dashboard + Emails pages.
    const threats = await getThreatsForManagement(tenantId, {
      status,
      limit,
      offset,
    });

    let stats = null;
    if (includeStats) {
      stats = await getVerdictStats(tenantId);
    }

    return NextResponse.json({
      threats,
      stats,
      pagination: {
        limit,
        offset,
        hasMore: threats.length === limit,
      },
    });
  } catch (error) {
    console.error('List threats error:', error);
    // Degrade gracefully so the page renders an empty state instead of an error.
    return NextResponse.json({
      threats: [],
      stats: null,
      pagination: { limit: 50, offset: 0, hasMore: false },
    });
  }
}
