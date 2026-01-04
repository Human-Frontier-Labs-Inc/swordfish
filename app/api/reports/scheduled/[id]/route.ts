/**
 * Individual Scheduled Report API
 * PATCH - Update scheduled report
 * DELETE - Delete scheduled report
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import {
  updateScheduledReport,
  deleteScheduledReport,
} from '@/lib/analytics/scheduled';
import { logAuditEvent } from '@/lib/db/audit';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function PATCH(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const { id } = await params;
    const body = await request.json();

    const { name, frequency, recipients, enabled, config } = body;

    await updateScheduledReport(tenantId, id, {
      name,
      frequency,
      recipients,
      enabled,
      config,
    });

    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'scheduled_report.update',
      resourceType: 'scheduled_report',
      resourceId: id,
      afterState: { updates: Object.keys(body) },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Update scheduled report error:', error);
    return NextResponse.json(
      { error: 'Failed to update report' },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const { id } = await params;

    await deleteScheduledReport(tenantId, id);

    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'scheduled_report.delete',
      resourceType: 'scheduled_report',
      resourceId: id,
      afterState: {},
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Delete scheduled report error:', error);
    return NextResponse.json(
      { error: 'Failed to delete report' },
      { status: 500 }
    );
  }
}
