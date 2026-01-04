/**
 * Bulk Threat Actions API
 * POST - Bulk release/delete threats
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { releaseEmail, deleteQuarantinedEmail } from '@/lib/quarantine/service';
import { logAuditEvent } from '@/lib/db/audit';

interface BulkActionRequest {
  threatIds: string[];
  action: 'release' | 'delete';
  addToAllowlist?: boolean;
}

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const body: BulkActionRequest = await request.json();

    const { threatIds, action, addToAllowlist = false } = body;

    if (!threatIds || threatIds.length === 0) {
      return NextResponse.json(
        { error: 'threatIds array is required' },
        { status: 400 }
      );
    }

    if (threatIds.length > 100) {
      return NextResponse.json(
        { error: 'Maximum 100 threats per request' },
        { status: 400 }
      );
    }

    if (!['release', 'delete'].includes(action)) {
      return NextResponse.json(
        { error: 'action must be "release" or "delete"' },
        { status: 400 }
      );
    }

    let successCount = 0;
    const errors: string[] = [];

    for (const threatId of threatIds) {
      try {
        let result;
        if (action === 'release') {
          result = await releaseEmail(tenantId, threatId, userId, addToAllowlist);
        } else {
          result = await deleteQuarantinedEmail(tenantId, threatId, userId);
        }

        if (result.success) {
          successCount++;
        } else {
          errors.push(`${threatId}: ${result.error}`);
        }
      } catch (error) {
        errors.push(`${threatId}: ${error instanceof Error ? error.message : 'Failed'}`);
      }
    }

    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: `threat.bulk_${action}`,
      resourceType: 'threat',
      resourceId: 'bulk',
      afterState: {
        count: threatIds.length,
        successful: successCount,
        errors: errors.length,
        addToAllowlist: action === 'release' ? addToAllowlist : undefined,
      },
    });

    return NextResponse.json({
      success: true,
      processed: threatIds.length,
      successful: successCount,
      errors: errors.length > 0 ? errors.slice(0, 10) : undefined,
    });
  } catch (error) {
    console.error('Bulk threat action error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Bulk action failed' },
      { status: 500 }
    );
  }
}
