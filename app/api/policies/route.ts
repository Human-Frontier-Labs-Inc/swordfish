/**
 * Policies API
 * GET - List policies
 * POST - Create policy
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';
import type { Policy, PolicyRule } from '@/lib/policies/types';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const searchParams = request.nextUrl.searchParams;
    const type = searchParams.get('type');
    const status = searchParams.get('status');

    let policies;

    if (type && status) {
      policies = await sql`
        SELECT * FROM policies
        WHERE tenant_id = ${tenantId}
        AND type = ${type}
        AND status = ${status}
        ORDER BY priority DESC, created_at DESC
      `;
    } else if (type) {
      policies = await sql`
        SELECT * FROM policies
        WHERE tenant_id = ${tenantId}
        AND type = ${type}
        ORDER BY priority DESC, created_at DESC
      `;
    } else if (status) {
      policies = await sql`
        SELECT * FROM policies
        WHERE tenant_id = ${tenantId}
        AND status = ${status}
        ORDER BY priority DESC, created_at DESC
      `;
    } else {
      policies = await sql`
        SELECT * FROM policies
        WHERE tenant_id = ${tenantId}
        ORDER BY priority DESC, created_at DESC
      `;
    }

    const formatted = policies.map((p: Record<string, unknown>) => ({
      id: p.id,
      name: p.name || p.value, // Fallback for old schema
      description: p.description,
      type: p.type,
      status: p.status || (p.is_active ? 'active' : 'inactive'),
      priority: p.priority || 'medium',
      rules: p.rules || [],
      scope: p.scope,
      createdAt: p.created_at,
      updatedAt: p.updated_at,
    }));

    return NextResponse.json({ policies: formatted });
  } catch (error) {
    console.error('List policies error:', error);
    return NextResponse.json({ policies: [] });
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

    const {
      name,
      description,
      type,
      status = 'active',
      priority = 'medium',
      rules = [],
      scope,
    } = body as Partial<Policy>;

    if (!name || !type) {
      return NextResponse.json(
        { error: 'Name and type are required' },
        { status: 400 }
      );
    }

    const result = await sql`
      INSERT INTO policies (
        tenant_id, name, description, type, status, priority, rules, scope, created_by
      ) VALUES (
        ${tenantId},
        ${name},
        ${description || null},
        ${type},
        ${status},
        ${priority},
        ${JSON.stringify(rules)}::jsonb,
        ${scope ? JSON.stringify(scope) : null}::jsonb,
        ${userId}
      )
      RETURNING id
    `;

    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'policy.create',
      resourceType: 'policy',
      resourceId: result[0].id as string,
      afterState: { name, type },
    });

    return NextResponse.json({
      success: true,
      id: result[0].id,
    });
  } catch (error) {
    console.error('Create policy error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to create policy' },
      { status: 500 }
    );
  }
}
