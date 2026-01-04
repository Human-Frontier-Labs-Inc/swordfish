/**
 * Export Jobs API
 * GET - List export history
 * POST - Create new export job
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

export async function GET() {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    const exports = await sql`
      SELECT
        id,
        type,
        format,
        status,
        filters,
        file_url,
        file_size,
        error_message,
        expires_at,
        created_at,
        completed_at
      FROM export_jobs
      WHERE tenant_id = ${tenantId}
      ORDER BY created_at DESC
      LIMIT 50
    `;

    return NextResponse.json({
      exports: exports.map((e: Record<string, unknown>) => ({
        id: e.id,
        type: e.type,
        format: e.format,
        status: e.status,
        filters: e.filters || {},
        fileUrl: e.file_url,
        fileSize: e.file_size,
        errorMessage: e.error_message,
        expiresAt: e.expires_at ? (e.expires_at as Date).toISOString() : null,
        createdAt: (e.created_at as Date).toISOString(),
        completedAt: e.completed_at ? (e.completed_at as Date).toISOString() : null,
      })),
    });
  } catch (error) {
    console.error('List exports error:', error);
    return NextResponse.json(
      { error: 'Failed to list exports' },
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
    const { type, format, filters } = body;

    if (!type || !format) {
      return NextResponse.json(
        { error: 'Type and format are required' },
        { status: 400 }
      );
    }

    const validTypes = ['threats', 'quarantine', 'audit', 'analytics', 'custom'];
    const validFormats = ['csv', 'pdf', 'xlsx', 'json'];

    if (!validTypes.includes(type)) {
      return NextResponse.json({ error: 'Invalid export type' }, { status: 400 });
    }

    if (!validFormats.includes(format)) {
      return NextResponse.json({ error: 'Invalid format' }, { status: 400 });
    }

    const exportJob = await sql`
      INSERT INTO export_jobs (
        tenant_id,
        type,
        format,
        filters,
        status,
        requested_by,
        created_at
      ) VALUES (
        ${tenantId},
        ${type},
        ${format},
        ${JSON.stringify(filters || {})}::jsonb,
        'pending',
        ${userId},
        NOW()
      )
      RETURNING id, type, format, status, created_at
    `;

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'export.requested',
      resourceType: 'export',
      resourceId: exportJob[0].id as string,
      afterState: { type, format },
    });

    // In production, queue background job to generate export
    // await queueExportJob(exportJob[0].id);

    return NextResponse.json({
      export: {
        id: exportJob[0].id,
        type: exportJob[0].type,
        format: exportJob[0].format,
        status: exportJob[0].status,
        createdAt: (exportJob[0].created_at as Date).toISOString(),
      },
    }, { status: 201 });
  } catch (error) {
    console.error('Create export error:', error);
    return NextResponse.json(
      { error: 'Failed to create export' },
      { status: 500 }
    );
  }
}
