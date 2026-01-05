/**
 * Admin Users API
 * GET - List all users across tenants (MSP view)
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function GET(request: NextRequest) {
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

    const searchParams = request.nextUrl.searchParams;
    const page = parseInt(searchParams.get('page') || '1');
    const limit = Math.min(parseInt(searchParams.get('limit') || '50'), 100);
    const offset = (page - 1) * limit;

    // Filter parameters
    const search = searchParams.get('search');
    const role = searchParams.get('role');
    const tenantId = searchParams.get('tenantId');
    const status = searchParams.get('status');

    // Build query conditions
    const conditions: string[] = [];
    const params: unknown[] = [];
    let paramIndex = 1;

    if (search) {
      conditions.push(`(u.email ILIKE $${paramIndex} OR u.name ILIKE $${paramIndex})`);
      params.push(`%${search}%`);
      paramIndex++;
    }

    if (role) {
      conditions.push(`u.role = $${paramIndex}`);
      params.push(role);
      paramIndex++;
    }

    if (tenantId) {
      conditions.push(`u.tenant_id = $${paramIndex}`);
      params.push(tenantId);
      paramIndex++;
    }

    if (status) {
      conditions.push(`u.status = $${paramIndex}`);
      params.push(status);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get users with tenant info
    const users = await sql`
      SELECT
        u.id,
        u.clerk_user_id,
        u.email,
        u.name,
        u.role,
        u.tenant_id,
        t.name as tenant_name,
        u.is_msp_user,
        u.status,
        u.last_login_at,
        u.created_at
      FROM users u
      LEFT JOIN tenants t ON u.tenant_id = t.clerk_org_id OR u.tenant_id = t.id::text
      ORDER BY u.created_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `;

    // Get total count
    const countResult = await sql`
      SELECT COUNT(*)::int as total FROM users
    `;

    return NextResponse.json({
      users: users.map((u: Record<string, unknown>) => ({
        id: u.id,
        clerkUserId: u.clerk_user_id,
        email: u.email,
        name: u.name,
        role: u.role || 'viewer',
        tenantId: u.tenant_id,
        tenantName: u.tenant_name,
        isMspUser: u.is_msp_user || false,
        status: u.status || 'active',
        lastLoginAt: u.last_login_at ? (u.last_login_at as Date).toISOString() : null,
        createdAt: (u.created_at as Date).toISOString(),
      })),
      pagination: {
        page,
        limit,
        total: countResult[0]?.total || 0,
        totalPages: Math.ceil((countResult[0]?.total || 0) / limit),
      },
    });
  } catch (error) {
    console.error('Admin users list error:', error);
    return NextResponse.json(
      { error: 'Failed to list users' },
      { status: 500 }
    );
  }
}
