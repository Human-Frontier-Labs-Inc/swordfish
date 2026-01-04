/**
 * Threats API
 * GET - List quarantined threats
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getQuarantinedThreats, getThreatStats } from '@/lib/quarantine/service';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const searchParams = request.nextUrl.searchParams;
    const status = searchParams.get('status') as 'quarantined' | 'released' | 'deleted' | 'all' || 'quarantined';
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');
    const includeStats = searchParams.get('stats') === 'true';

    const threats = await getQuarantinedThreats(tenantId, {
      status,
      limit,
      offset,
    });

    let stats = null;
    if (includeStats) {
      stats = await getThreatStats(tenantId);
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
    return NextResponse.json(
      { error: 'Failed to list threats' },
      { status: 500 }
    );
  }
}
