/**
 * Policies API
 * GET - List policies
 * POST - Create policy
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql, withTenant } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';
import type { Policy, PolicyRule, PolicyPriority } from '@/lib/policies/types';

// Priority mapping: string <-> integer for database storage
const PRIORITY_TO_INT: Record<PolicyPriority, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const INT_TO_PRIORITY: Record<number, PolicyPriority> = {
  0: 'critical',
  1: 'high',
  2: 'medium',
  3: 'low',
};

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

    // RLS-protected queries
    // Priority is stored as INTEGER: 0=critical, 1=high, 2=medium, 3=low
    // Lower number = higher priority, so ORDER BY priority ASC
    const policies = await withTenant(tenantId, async () => {
      if (type && status) {
        return sql`
          SELECT * FROM policies
          WHERE type = ${type}
          AND status = ${status}
          ORDER BY priority ASC, created_at DESC
        `;
      } else if (type) {
        return sql`
          SELECT * FROM policies
          WHERE type = ${type}
          ORDER BY priority ASC, created_at DESC
        `;
      } else if (status) {
        return sql`
          SELECT * FROM policies
          WHERE status = ${status}
          ORDER BY priority ASC, created_at DESC
        `;
      } else {
        return sql`
          SELECT * FROM policies
          ORDER BY priority ASC, created_at DESC
        `;
      }
    });

    const formatted = policies.map((p: Record<string, unknown>) => ({
      id: p.id,
      name: p.name || p.value, // Fallback for old schema
      description: p.description,
      type: p.type,
      status: p.status || (p.is_active ? 'active' : 'inactive'),
      // Convert integer priority back to string
      priority: INT_TO_PRIORITY[p.priority as number] || 'medium',
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

    // Convert string priority to integer for database storage
    const priorityInt = PRIORITY_TO_INT[priority as PolicyPriority] ?? 2; // default to medium (2)

    // RLS-protected insert
    const result = await withTenant(tenantId, async () => {
      return sql`
        INSERT INTO policies (
          tenant_id, name, description, type, status, priority, rules, scope, created_by
        ) VALUES (
          ${tenantId},
          ${name},
          ${description || null},
          ${type},
          ${status},
          ${priorityInt},
          ${JSON.stringify(rules)}::jsonb,
          ${scope ? JSON.stringify(scope) : null}::jsonb,
          ${userId}
        )
        RETURNING id
      `;
    });

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
