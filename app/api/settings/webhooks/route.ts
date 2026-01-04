/**
 * Webhooks API
 * GET - List configured webhooks
 * POST - Create new webhook
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';
import crypto from 'crypto';

export async function GET() {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    const webhooks = await sql`
      SELECT
        id,
        name,
        url,
        events,
        is_active,
        last_triggered_at,
        last_status,
        failure_count,
        created_at
      FROM webhooks
      WHERE tenant_id = ${tenantId}
      ORDER BY created_at DESC
    `;

    return NextResponse.json({
      webhooks: webhooks.map((w: Record<string, unknown>) => ({
        id: w.id,
        name: w.name,
        url: w.url,
        events: w.events || [],
        isActive: w.is_active ?? true,
        lastTriggeredAt: w.last_triggered_at ? (w.last_triggered_at as Date).toISOString() : null,
        lastStatus: w.last_status,
        failureCount: w.failure_count || 0,
        createdAt: (w.created_at as Date).toISOString(),
      })),
    });
  } catch (error) {
    console.error('List webhooks error:', error);
    return NextResponse.json(
      { error: 'Failed to list webhooks' },
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
    const { name, url, events } = body;

    if (!name || !url) {
      return NextResponse.json(
        { error: 'Name and URL are required' },
        { status: 400 }
      );
    }

    if (!events || events.length === 0) {
      return NextResponse.json(
        { error: 'At least one event must be selected' },
        { status: 400 }
      );
    }

    // Validate URL
    try {
      new URL(url);
    } catch {
      return NextResponse.json(
        { error: 'Invalid URL format' },
        { status: 400 }
      );
    }

    // Generate signing secret
    const secret = crypto.randomBytes(32).toString('hex');

    const webhook = await sql`
      INSERT INTO webhooks (
        tenant_id,
        name,
        url,
        events,
        secret,
        is_active,
        created_at,
        updated_at
      ) VALUES (
        ${tenantId},
        ${name},
        ${url},
        ${JSON.stringify(events)}::jsonb,
        ${secret},
        true,
        NOW(),
        NOW()
      )
      RETURNING id, name, url, events, secret, is_active, created_at
    `;

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'webhook.created',
      resourceType: 'webhook',
      resourceId: webhook[0].id as string,
      afterState: { name, url, events },
    });

    return NextResponse.json({
      webhook: {
        id: webhook[0].id,
        name: webhook[0].name,
        url: webhook[0].url,
        events: webhook[0].events,
        secret: webhook[0].secret,
        isActive: webhook[0].is_active,
        createdAt: (webhook[0].created_at as Date).toISOString(),
      },
    }, { status: 201 });
  } catch (error) {
    console.error('Create webhook error:', error);
    return NextResponse.json(
      { error: 'Failed to create webhook' },
      { status: 500 }
    );
  }
}
