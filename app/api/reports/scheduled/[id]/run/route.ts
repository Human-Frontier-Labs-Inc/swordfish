/**
 * Run Scheduled Report Now
 * POST - Trigger immediate execution of a scheduled report
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id } = await params;
    const tenantId = orgId || `personal_${userId}`;

    // Get the scheduled report
    const reports = await sql`
      SELECT * FROM scheduled_reports
      WHERE id = ${id}::uuid AND tenant_id = ${tenantId}
      LIMIT 1
    `;

    if (reports.length === 0) {
      return NextResponse.json({ error: 'Report not found' }, { status: 404 });
    }

    const report = reports[0];

    // Queue the report for generation
    // In production, this would trigger a background job
    await sql`
      INSERT INTO report_jobs (
        scheduled_report_id,
        tenant_id,
        status,
        triggered_by,
        created_at
      ) VALUES (
        ${id}::uuid,
        ${tenantId},
        'pending',
        ${userId},
        NOW()
      )
    `;

    // Update last run timestamp
    await sql`
      UPDATE scheduled_reports
      SET last_run_at = NOW()
      WHERE id = ${id}::uuid
    `;

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'report.triggered',
      resourceType: 'scheduled_report',
      resourceId: id,
      afterState: { name: report.name, type: report.type },
    });

    return NextResponse.json({
      success: true,
      message: 'Report generation queued',
    });
  } catch (error) {
    console.error('Run report error:', error);
    return NextResponse.json(
      { error: 'Failed to run report' },
      { status: 500 }
    );
  }
}
