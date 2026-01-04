/**
 * Policy Item API
 * GET - Get policy details
 * PATCH - Update policy
 * DELETE - Delete policy
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

    const policies = await sql`
      SELECT * FROM policies
      WHERE id = ${id}
      AND tenant_id = ${tenantId}
    `;

    if (policies.length === 0) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 });
    }

    const p = policies[0];
    return NextResponse.json({
      policy: {
        id: p.id,
        name: p.name,
        description: p.description,
        type: p.type,
        status: p.status,
        priority: p.priority,
        rules: p.rules || [],
        scope: p.scope,
        createdAt: p.created_at,
        updatedAt: p.updated_at,
      },
    });
  } catch (error) {
    console.error('Get policy error:', error);
    return NextResponse.json({ error: 'Failed to get policy' }, { status: 500 });
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

    // Build update query dynamically
    const updates: string[] = [];
    const values: unknown[] = [];

    if (body.name !== undefined) {
      updates.push('name');
      values.push(body.name);
    }
    if (body.description !== undefined) {
      updates.push('description');
      values.push(body.description);
    }
    if (body.status !== undefined) {
      updates.push('status');
      values.push(body.status);
    }
    if (body.priority !== undefined) {
      updates.push('priority');
      values.push(body.priority);
    }
    if (body.rules !== undefined) {
      updates.push('rules');
      values.push(JSON.stringify(body.rules));
    }
    if (body.scope !== undefined) {
      updates.push('scope');
      values.push(JSON.stringify(body.scope));
    }

    if (updates.length === 0) {
      return NextResponse.json({ error: 'No updates provided' }, { status: 400 });
    }

    // Use raw SQL for dynamic update
    const result = await sql`
      UPDATE policies
      SET
        name = COALESCE(${body.name}, name),
        description = COALESCE(${body.description}, description),
        status = COALESCE(${body.status}, status),
        priority = COALESCE(${body.priority}, priority),
        rules = COALESCE(${body.rules ? JSON.stringify(body.rules) : null}::jsonb, rules),
        scope = COALESCE(${body.scope ? JSON.stringify(body.scope) : null}::jsonb, scope),
        updated_by = ${userId},
        updated_at = NOW()
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
      action: 'policy.update',
      resourceType: 'policy',
      resourceId: id,
      afterState: { updates: Object.keys(body) },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Update policy error:', error);
    return NextResponse.json({ error: 'Failed to update policy' }, { status: 500 });
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
      DELETE FROM policies
      WHERE id = ${id}
      AND tenant_id = ${tenantId}
      RETURNING id, name
    `;

    if (result.length === 0) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 });
    }

    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'policy.delete',
      resourceType: 'policy',
      resourceId: id,
      afterState: { name: result[0].name },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Delete policy error:', error);
    return NextResponse.json({ error: 'Failed to delete policy' }, { status: 500 });
  }
}
