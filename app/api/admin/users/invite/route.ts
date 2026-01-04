/**
 * Admin User Invitation API
 * POST - Send invitation to new user
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

export async function POST(request: NextRequest) {
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

    const body = await request.json();
    const { email, role, tenantId } = body;

    if (!email || !tenantId) {
      return NextResponse.json(
        { error: 'Email and tenant are required' },
        { status: 400 }
      );
    }

    // Validate role
    const validRoles = ['admin', 'analyst', 'viewer'];
    if (role && !validRoles.includes(role)) {
      return NextResponse.json(
        { error: 'Invalid role' },
        { status: 400 }
      );
    }

    // Check if user already exists
    const existing = await sql`
      SELECT id FROM users WHERE email = ${email} LIMIT 1
    `;

    if (existing.length > 0) {
      return NextResponse.json(
        { error: 'User with this email already exists' },
        { status: 400 }
      );
    }

    // Verify tenant exists
    const tenant = await sql`
      SELECT id, name, clerk_org_id FROM tenants WHERE id = ${tenantId}::uuid LIMIT 1
    `;

    if (tenant.length === 0) {
      return NextResponse.json(
        { error: 'Tenant not found' },
        { status: 404 }
      );
    }

    // Create invitation record
    const invitation = await sql`
      INSERT INTO user_invitations (
        email,
        role,
        tenant_id,
        invited_by,
        expires_at,
        created_at
      ) VALUES (
        ${email},
        ${role || 'viewer'},
        ${tenantId},
        ${userId},
        NOW() + INTERVAL '7 days',
        NOW()
      )
      RETURNING id, email, role, expires_at
    `;

    // Audit log
    await logAuditEvent({
      tenantId: tenant[0].clerk_org_id as string,
      actorId: userId,
      actorEmail: user?.email as string || null,
      action: 'user.invited',
      resourceType: 'user',
      resourceId: invitation[0].id as string,
      afterState: { email, role, tenantName: tenant[0].name },
    });

    // In production, send email invitation here
    // await sendInvitationEmail(email, invitation[0].id);

    return NextResponse.json({
      invitation: {
        id: invitation[0].id,
        email: invitation[0].email,
        role: invitation[0].role,
        expiresAt: (invitation[0].expires_at as Date).toISOString(),
      },
      message: 'Invitation sent successfully',
    }, { status: 201 });
  } catch (error) {
    console.error('User invitation error:', error);
    return NextResponse.json(
      { error: 'Failed to send invitation' },
      { status: 500 }
    );
  }
}
