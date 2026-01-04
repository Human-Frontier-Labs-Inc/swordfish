/**
 * Scheduled Reports API
 * GET - List scheduled reports
 * POST - Create scheduled report
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import {
  getScheduledReports,
  createScheduledReport,
  type ReportType,
  type ReportFrequency,
} from '@/lib/analytics/scheduled';
import { logAuditEvent } from '@/lib/db/audit';

export async function GET() {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const reports = await getScheduledReports(tenantId);

    return NextResponse.json({ reports });
  } catch (error) {
    console.error('List scheduled reports error:', error);
    return NextResponse.json(
      { error: 'Failed to list reports' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const body = await request.json();

    const { name, type, frequency, recipients, config } = body;

    if (!name || !type || !frequency || !recipients || recipients.length === 0) {
      return NextResponse.json(
        { error: 'name, type, frequency, and recipients are required' },
        { status: 400 }
      );
    }

    const validTypes: ReportType[] = ['executive_summary', 'threat_report', 'audit_report'];
    if (!validTypes.includes(type)) {
      return NextResponse.json(
        { error: 'Invalid report type' },
        { status: 400 }
      );
    }

    const validFrequencies: ReportFrequency[] = ['daily', 'weekly', 'monthly'];
    if (!validFrequencies.includes(frequency)) {
      return NextResponse.json(
        { error: 'Invalid frequency' },
        { status: 400 }
      );
    }

    const reportId = await createScheduledReport({
      tenantId,
      name,
      type,
      frequency,
      recipients,
      config,
      createdBy: userId,
    });

    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'scheduled_report.create',
      resourceType: 'scheduled_report',
      resourceId: reportId,
      afterState: { name, type, frequency, recipientCount: recipients.length },
    });

    return NextResponse.json({ success: true, id: reportId });
  } catch (error) {
    console.error('Create scheduled report error:', error);
    return NextResponse.json(
      { error: 'Failed to create report' },
      { status: 500 }
    );
  }
}
