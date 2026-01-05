/**
 * Admin Tenant Detail API
 * GET - Get tenant details
 * PATCH - Update tenant
 * DELETE - Delete tenant
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
    const { userId, orgRole } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id } = await params;

    const tenants = await sql`
      SELECT
        t.id,
        t.clerk_org_id,
        t.name,
        t.domain,
        t.plan,
        t.status,
        t.settings,
        t.created_at,
        t.updated_at,
        (SELECT COUNT(*)::int FROM users WHERE tenant_id = t.clerk_org_id OR tenant_id = t.id::text) as user_count,
        COALESCE(stats.emails_processed, 0) as emails_processed,
        COALESCE(stats.threats_blocked, 0) as threats_blocked
      FROM tenants t
      LEFT JOIN LATERAL (
        SELECT
          COUNT(*)::int as emails_processed,
          COUNT(*) FILTER (WHERE verdict IN ('quarantine', 'block'))::int as threats_blocked
        FROM email_verdicts
        WHERE tenant_id = t.clerk_org_id OR tenant_id = t.id::text
        AND created_at >= NOW() - INTERVAL '30 days'
      ) stats ON true
      WHERE t.id = ${id}::uuid
      LIMIT 1
    `;

    if (tenants.length === 0) {
      return NextResponse.json({ error: 'Tenant not found' }, { status: 404 });
    }

    const t = tenants[0];
    return NextResponse.json({
      tenant: {
        id: t.id,
        clerkOrgId: t.clerk_org_id,
        name: t.name,
        domain: t.domain,
        plan: t.plan,
        status: t.status,
        settings: t.settings || {},
        userCount: t.user_count || 0,
        emailsProcessed: t.emails_processed || 0,
        threatsBlocked: t.threats_blocked || 0,
        createdAt: (t.created_at as Date).toISOString(),
        updatedAt: (t.updated_at as Date).toISOString(),
      },
    });
  } catch (error) {
    console.error('Tenant get error:', error);
    return NextResponse.json(
      { error: 'Failed to get tenant' },
      { status: 500 }
    );
  }
}

export async function PATCH(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgRole } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check MSP admin access
    const currentUser = await sql`
      SELECT is_msp_user, role, email FROM users
      WHERE clerk_user_id = ${userId}
      LIMIT 1
    `;

    const user = currentUser[0];
    const hasAccess = orgRole === 'org:admin' || user?.is_msp_user || user?.role === 'msp_admin';

    if (!hasAccess) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const { id } = await params;
    const body = await request.json();
    const { name, domain, plan, status, settings } = body;

    // Get existing tenant
    const existing = await sql`
      SELECT * FROM tenants WHERE id = ${id}::uuid LIMIT 1
    `;

    if (existing.length === 0) {
      return NextResponse.json({ error: 'Tenant not found' }, { status: 404 });
    }

    // Update tenant
    const tenant = await sql`
      UPDATE tenants SET
        name = COALESCE(${name}, name),
        domain = COALESCE(${domain}, domain),
        plan = COALESCE(${plan}, plan),
        status = COALESCE(${status}, status),
        settings = COALESCE(${settings ? JSON.stringify(settings) : null}::jsonb, settings),
        updated_at = NOW()
      WHERE id = ${id}::uuid
      RETURNING id, clerk_org_id, name, domain, plan, status, settings, created_at, updated_at
    `;

    // Audit log
    await logAuditEvent({
      tenantId: tenant[0].clerk_org_id as string,
      actorId: userId,
      actorEmail: user?.email as string || null,
      action: 'tenant.updated',
      resourceType: 'tenant',
      resourceId: id,
      beforeState: { name: existing[0].name, status: existing[0].status },
      afterState: { name: tenant[0].name, status: tenant[0].status },
    });

    return NextResponse.json({
      tenant: {
        id: tenant[0].id,
        clerkOrgId: tenant[0].clerk_org_id,
        name: tenant[0].name,
        domain: tenant[0].domain,
        plan: tenant[0].plan,
        status: tenant[0].status,
        settings: tenant[0].settings,
        createdAt: (tenant[0].created_at as Date).toISOString(),
        updatedAt: (tenant[0].updated_at as Date).toISOString(),
      },
    });
  } catch (error) {
    console.error('Tenant update error:', error);
    return NextResponse.json(
      { error: 'Failed to update tenant' },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgRole } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check MSP admin access
    const currentUser = await sql`
      SELECT is_msp_user, role, email FROM users
      WHERE clerk_user_id = ${userId}
      LIMIT 1
    `;

    const user = currentUser[0];
    const hasAccess = orgRole === 'org:admin' || user?.is_msp_user || user?.role === 'msp_admin';

    if (!hasAccess) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const { id } = await params;

    // Get tenant for audit
    const existing = await sql`
      SELECT clerk_org_id, name FROM tenants WHERE id = ${id}::uuid LIMIT 1
    `;

    if (existing.length === 0) {
      return NextResponse.json({ error: 'Tenant not found' }, { status: 404 });
    }

    // Soft delete - just mark as deleted
    await sql`
      UPDATE tenants SET
        status = 'deleted',
        updated_at = NOW()
      WHERE id = ${id}::uuid
    `;

    // Audit log
    await logAuditEvent({
      tenantId: existing[0].clerk_org_id as string,
      actorId: userId,
      actorEmail: user?.email as string || null,
      action: 'tenant.deleted',
      resourceType: 'tenant',
      resourceId: id,
      beforeState: { name: existing[0].name },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Tenant delete error:', error);
    return NextResponse.json(
      { error: 'Failed to delete tenant' },
      { status: 500 }
    );
  }
}
