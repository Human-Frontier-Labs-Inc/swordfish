/**
 * Invitation Details API
 * GET - Retrieve invitation details by token (invitation ID)
 */

import { NextRequest, NextResponse } from 'next/server';
import { sql } from '@/lib/db';

export async function GET(request: NextRequest) {
  try {
    const token = request.nextUrl.searchParams.get('token');

    if (!token) {
      return NextResponse.json(
        { error: 'Invitation token is required' },
        { status: 400 }
      );
    }

    // Fetch invitation with tenant details
    const result = await sql`
      SELECT
        i.id,
        i.email,
        i.role,
        i.tenant_id,
        i.expires_at,
        i.accepted_at,
        i.invited_by,
        t.name as tenant_name
      FROM user_invitations i
      JOIN tenants t ON i.tenant_id = t.id
      WHERE i.id = ${token}::uuid
      LIMIT 1
    `;

    if (result.length === 0) {
      return NextResponse.json(
        { error: 'Invitation not found' },
        { status: 404 }
      );
    }

    const invitation = result[0];

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

    return NextResponse.json({
      invitation: {
        id: invitation.id,
        email: invitation.email,
        role: invitation.role,
        tenantId: invitation.tenant_id,
        tenantName: invitation.tenant_name,
        expiresAt: (invitation.expires_at as Date).toISOString(),
        invitedBy: invitation.invited_by,
      },
    });
  } catch (error) {
    console.error('Invitation details error:', error);
    return NextResponse.json(
      { error: 'Failed to load invitation details' },
      { status: 500 }
    );
  }
}
