/**
 * Release Threat API
 * POST - Release email from quarantine
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { releaseEmail, reportFalsePositive } from '@/lib/quarantine/service';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const { id } = await params;
    const body = await request.json();

    const { addToAllowlist = false, isFalsePositive = false, notes } = body;

    let result;
    if (isFalsePositive) {
      result = await reportFalsePositive(tenantId, id, userId, notes);
    } else {
      result = await releaseEmail(tenantId, id, userId, addToAllowlist);
    }

    if (!result.success) {
      return NextResponse.json(
        { error: result.error },
        { status: 400 }
      );
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Release threat error:', error);
    return NextResponse.json(
      { error: 'Failed to release threat' },
      { status: 500 }
    );
  }
}
