/**
 * Admin Tenant Users API
 * GET - List users for a specific tenant
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgRole } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check MSP admin access
    const currentUser = await sql`
      SELECT is_msp_user, role FROM users
      WHERE clerk_user_id = ${userId}
      LIMIT 1
    `;

    const user = currentUser[0];
    const hasAccess = orgRole === 'org:admin' || user?.is_msp_user || user?.role === 'msp_admin';

    if (!hasAccess) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const { id } = await params;

    // Get tenant to verify it exists
    const tenant = await sql`
      SELECT id, clerk_org_id FROM tenants WHERE id = ${id}::uuid LIMIT 1
    `;

    if (tenant.length === 0) {
      return NextResponse.json({ error: 'Tenant not found' }, { status: 404 });
    }

    // Get users for this tenant
    const users = await sql`
      SELECT
        id,
        email,
        name,
        role,
        status,
        last_login_at
      FROM users
      WHERE tenant_id = ${id} OR tenant_id = ${tenant[0].clerk_org_id}
      ORDER BY created_at DESC
    `;

    return NextResponse.json({
      users: users.map((u: Record<string, unknown>) => ({
        id: u.id,
        email: u.email,
        name: u.name,
        role: u.role || 'viewer',
        status: u.status || 'active',
        lastLoginAt: u.last_login_at ? (u.last_login_at as Date).toISOString() : null,
      })),
    });
  } catch (error) {
    console.error('Tenant users list error:', error);
    return NextResponse.json(
      { error: 'Failed to list users' },
      { status: 500 }
    );
  }
}
