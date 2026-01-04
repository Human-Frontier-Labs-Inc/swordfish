/**
 * List Entry API
 * GET - Get entry details
 * PATCH - Update entry
 * DELETE - Delete entry
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const { id } = await params;

    const entries = await sql`
      SELECT * FROM list_entries
      WHERE id = ${id}
      AND tenant_id = ${tenantId}
    `;

    if (entries.length === 0) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 });
    }

    const e = entries[0];
    return NextResponse.json({
      entry: {
        id: e.id,
        listType: e.list_type,
        entryType: e.entry_type,
        value: e.value,
        reason: e.reason,
        expiresAt: e.expires_at,
        createdAt: e.created_at,
        createdBy: e.created_by,
      },
    });
  } catch (error) {
    console.error('Get list entry error:', error);
    return NextResponse.json({ error: 'Failed to get entry' }, { status: 500 });
  }
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

    const { reason, expiresAt } = body;

    const result = await sql`
      UPDATE list_entries
      SET
        reason = COALESCE(${reason}, reason),
        expires_at = ${expiresAt || null}
      WHERE id = ${id}
      AND tenant_id = ${tenantId}
      RETURNING id
    `;

    if (result.length === 0) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 });
    }

    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'list.update',
      resourceType: 'list_entry',
      resourceId: id,
      afterState: { updates: Object.keys(body) },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Update list entry error:', error);
    return NextResponse.json({ error: 'Failed to update entry' }, { status: 500 });
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

    const result = await sql`
      DELETE FROM list_entries
      WHERE id = ${id}
      AND tenant_id = ${tenantId}
      RETURNING id, list_type, entry_type, value
    `;

    if (result.length === 0) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 });
    }

    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: `list.${result[0].list_type}.remove`,
      resourceType: 'list_entry',
      resourceId: id,
      afterState: {
        entryType: result[0].entry_type,
        value: result[0].value,
      },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Delete list entry error:', error);
    return NextResponse.json({ error: 'Failed to delete entry' }, { status: 500 });
  }
}
