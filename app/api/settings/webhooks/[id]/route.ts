/**
 * Webhook Detail API
 * GET - Get webhook details
 * PATCH - Update webhook
 * DELETE - Delete webhook
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

    const { id } = await params;
    const tenantId = orgId || `personal_${userId}`;

    const webhooks = await sql`
      SELECT *
      FROM webhooks
      WHERE id = ${id}::uuid AND tenant_id = ${tenantId}
      LIMIT 1
    `;

    if (webhooks.length === 0) {
      return NextResponse.json({ error: 'Webhook not found' }, { status: 404 });
    }

    const w = webhooks[0];
    return NextResponse.json({
      webhook: {
        id: w.id,
        name: w.name,
        url: w.url,
        events: w.events,
        secret: w.secret,
        isActive: w.is_active,
        lastTriggeredAt: w.last_triggered_at ? (w.last_triggered_at as Date).toISOString() : null,
        lastStatus: w.last_status,
        failureCount: w.failure_count || 0,
        createdAt: (w.created_at as Date).toISOString(),
      },
    });
  } catch (error) {
    console.error('Get webhook error:', error);
    return NextResponse.json(
      { error: 'Failed to get webhook' },
      { status: 500 }
    );
  }
}

export async function PATCH(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id } = await params;
    const tenantId = orgId || `personal_${userId}`;
    const body = await request.json();
    const { name, url, events, isActive } = body;

    // Verify ownership
    const existing = await sql`
      SELECT * FROM webhooks
      WHERE id = ${id}::uuid AND tenant_id = ${tenantId}
      LIMIT 1
    `;

    if (existing.length === 0) {
      return NextResponse.json({ error: 'Webhook not found' }, { status: 404 });
    }

    const webhook = await sql`
      UPDATE webhooks SET
        name = COALESCE(${name}, name),
        url = COALESCE(${url}, url),
        events = COALESCE(${events ? JSON.stringify(events) : null}::jsonb, events),
        is_active = COALESCE(${isActive}, is_active),
        updated_at = NOW()
      WHERE id = ${id}::uuid AND tenant_id = ${tenantId}
      RETURNING id, name, url, events, is_active, created_at
    `;

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'webhook.updated',
      resourceType: 'webhook',
      resourceId: id,
      beforeState: { name: existing[0].name, isActive: existing[0].is_active },
      afterState: { name: webhook[0].name, isActive: webhook[0].is_active },
    });

    return NextResponse.json({
      webhook: {
        id: webhook[0].id,
        name: webhook[0].name,
        url: webhook[0].url,
        events: webhook[0].events,
        isActive: webhook[0].is_active,
        createdAt: (webhook[0].created_at as Date).toISOString(),
      },
    });
  } catch (error) {
    console.error('Update webhook error:', error);
    return NextResponse.json(
      { error: 'Failed to update webhook' },
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

    const { id } = await params;
    const tenantId = orgId || `personal_${userId}`;

    // Verify ownership
    const existing = await sql`
      SELECT name FROM webhooks
      WHERE id = ${id}::uuid AND tenant_id = ${tenantId}
      LIMIT 1
    `;

    if (existing.length === 0) {
      return NextResponse.json({ error: 'Webhook not found' }, { status: 404 });
    }

    await sql`
      DELETE FROM webhooks
      WHERE id = ${id}::uuid AND tenant_id = ${tenantId}
    `;

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'webhook.deleted',
      resourceType: 'webhook',
      resourceId: id,
      beforeState: { name: existing[0].name },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Delete webhook error:', error);
    return NextResponse.json(
      { error: 'Failed to delete webhook' },
      { status: 500 }
    );
  }
}
