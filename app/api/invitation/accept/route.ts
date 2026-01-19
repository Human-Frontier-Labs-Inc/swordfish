/**
 * Invitation Accept API
 * POST - Accept an invitation and create/update user account
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth, currentUser } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

export async function POST(request: NextRequest) {
  try {
    const { userId } = await auth();

    if (!userId) {
      return NextResponse.json(
        { error: 'You must be signed in to accept an invitation' },
        { status: 401 }
      );
    }

    // Get current user details from Clerk
    const clerkUser = await currentUser();
    if (!clerkUser) {
      return NextResponse.json(
        { error: 'Unable to retrieve user information' },
        { status: 401 }
      );
    }

    const body = await request.json();
    const { token } = body;

    if (!token) {
      return NextResponse.json(
        { error: 'Invitation token is required' },
        { status: 400 }
      );
    }

    // Fetch invitation with tenant details
    const invitationResult = await sql`
      SELECT
        i.id,
        i.email,
        i.role,
        i.tenant_id,
        i.expires_at,
        i.accepted_at,
        t.name as tenant_name,
        t.clerk_org_id
      FROM user_invitations i
      JOIN tenants t ON i.tenant_id::uuid = t.id
      WHERE i.id = ${token}::uuid
      LIMIT 1
    `;

    if (invitationResult.length === 0) {
      return NextResponse.json(
        { error: 'Invitation not found' },
        { status: 404 }
      );
    }

    const invitation = invitationResult[0];

    // Check if already accepted
    if (invitation.accepted_at) {
      return NextResponse.json(
        { error: 'This invitation has already been accepted' },
        { status: 400 }
      );
    }

    // Check if expired
    if (new Date(invitation.expires_at as string) < new Date()) {
      return NextResponse.json(
        { error: 'This invitation has expired' },
        { status: 400 }
      );
    }

    // Get user's primary email from Clerk
    const userEmail = clerkUser.emailAddresses.find(
      e => e.id === clerkUser.primaryEmailAddressId
    )?.emailAddress;

    // Verify email matches invitation (case-insensitive)
    if (userEmail?.toLowerCase() !== (invitation.email as string).toLowerCase()) {
      return NextResponse.json(
        {
          error: 'Email mismatch',
          detail: `This invitation was sent to ${invitation.email}. Please sign in with that email address.`
        },
        { status: 400 }
      );
    }

    // Check if user already exists in our database
    const existingUser = await sql`
      SELECT id, tenant_id, role FROM users
      WHERE clerk_user_id = ${userId}
      LIMIT 1
    `;

    let userRecord;

    if (existingUser.length > 0) {
      // User exists - update their tenant and role
      const updateResult = await sql`
        UPDATE users
        SET
          tenant_id = ${invitation.tenant_id}::uuid,
          role = ${invitation.role},
          status = 'active',
          updated_at = NOW()
        WHERE clerk_user_id = ${userId}
        RETURNING id, email, role, tenant_id
      `;
      userRecord = updateResult[0];
    } else {
      // Create new user record with invitation role
      const userName = [clerkUser.firstName, clerkUser.lastName]
        .filter(Boolean)
        .join(' ') || null;

      const insertResult = await sql`
        INSERT INTO users (
          clerk_user_id,
          email,
          name,
          role,
          tenant_id,
          status,
          is_msp_user,
          created_at,
          updated_at
        ) VALUES (
          ${userId},
          ${userEmail},
          ${userName},
          ${invitation.role},
          ${invitation.tenant_id}::uuid,
          'active',
          false,
          NOW(),
          NOW()
        )
        RETURNING id, email, role, tenant_id
      `;
      userRecord = insertResult[0];
    }

    // Mark invitation as accepted
    await sql`
      UPDATE user_invitations
      SET
        accepted_at = NOW(),
        accepted_by = ${userRecord.id}::uuid
      WHERE id = ${token}::uuid
    `;

    // Audit log
    await logAuditEvent({
      tenantId: invitation.clerk_org_id as string,
      actorId: userId,
      actorEmail: userEmail || null,
      action: 'invitation.accepted',
      resourceType: 'user',
      resourceId: userRecord.id as string,
      afterState: {
        email: userEmail,
        role: invitation.role,
        tenantName: invitation.tenant_name
      },
    });

    return NextResponse.json({
      success: true,
      user: {
        id: userRecord.id,
        email: userRecord.email,
        role: userRecord.role,
        tenantId: userRecord.tenant_id,
        tenantName: invitation.tenant_name,
      },
      message: 'Invitation accepted successfully',
    });
  } catch (error) {
    console.error('Invitation accept error:', error);
    return NextResponse.json(
      { error: 'Failed to accept invitation' },
      { status: 500 }
    );
  }
}
