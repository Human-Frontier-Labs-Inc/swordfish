/**
 * Admin User Reactivate API
 * POST - Reactivate a suspended user
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function POST(request: NextRequest, { params }: RouteParams) {
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

    // Get target user
    const targetUsers = await sql`
      SELECT u.id, u.email, u.tenant_id, t.clerk_org_id
      FROM users u
      LEFT JOIN tenants t ON u.tenant_id::text = t.clerk_org_id OR u.tenant_id::uuid = t.id
      WHERE u.id = ${id}::uuid
      LIMIT 1
    `;

    if (targetUsers.length === 0) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    const targetUser = targetUsers[0];

    // Update user status
    await sql`
      UPDATE users
      SET status = 'active', updated_at = NOW()
      WHERE id = ${id}::uuid
    `;

    // Audit log
    await logAuditEvent({
      tenantId: (targetUser.clerk_org_id || targetUser.tenant_id) as string,
      actorId: userId,
      actorEmail: user?.email as string || null,
      action: 'user.reactivated',
      resourceType: 'user',
      resourceId: id,
      afterState: { email: targetUser.email, status: 'active' },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('User reactivate error:', error);
    return NextResponse.json(
      { error: 'Failed to reactivate user' },
      { status: 500 }
    );
  }
}
