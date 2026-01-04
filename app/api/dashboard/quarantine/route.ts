/**
 * Quarantine Management API
 * GET /api/dashboard/quarantine - List quarantined emails
 * POST /api/dashboard/quarantine - Release or delete email
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getQuarantinedEmails, releaseFromQuarantine } from '@/lib/detection/storage';
import { logAuditEvent } from '@/lib/db/audit';

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

    // Get parameters
    const searchParams = request.nextUrl.searchParams;
    const status = (searchParams.get('status') || 'quarantined') as 'quarantined' | 'released' | 'deleted';
    const limit = parseInt(searchParams.get('limit') || '50');

    const quarantined = await getQuarantinedEmails(tenantId, status, limit);

    return NextResponse.json({
      emails: quarantined,
      total: quarantined.length,
      status,
    });

  } catch (error) {
    console.error('Quarantine API error:', error);

    return NextResponse.json({
      emails: [],
      total: 0,
      status: 'quarantined',
    });
  }
}

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const tenantId = orgId || `personal_${userId}`;

    const body = await request.json();
    const { quarantineId, action } = body;

    if (!quarantineId || !action) {
      return NextResponse.json(
        { error: 'Missing quarantineId or action' },
        { status: 400 }
      );
    }

    if (action === 'release') {
      await releaseFromQuarantine(tenantId, quarantineId, userId);

      // Log audit event
      await logAuditEvent({
        tenantId,
        actorId: userId,
        actorEmail: null,
        action: 'quarantine.release',
        resourceType: 'quarantine',
        resourceId: quarantineId,
        afterState: { releasedBy: userId },
      });

      return NextResponse.json({
        success: true,
        action: 'released',
        quarantineId,
      });
    }

    if (action === 'delete') {
      // TODO: Implement delete functionality
      return NextResponse.json(
        { error: 'Delete not yet implemented' },
        { status: 501 }
      );
    }

    return NextResponse.json(
      { error: 'Invalid action. Use "release" or "delete"' },
      { status: 400 }
    );

  } catch (error) {
    console.error('Quarantine action error:', error);

    return NextResponse.json(
      { error: 'Failed to process quarantine action' },
      { status: 500 }
    );
  }
}
