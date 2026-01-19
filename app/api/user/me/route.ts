/**
 * Current User API
 * GET - Retrieve current user's profile and role from database
 */

import { NextResponse } from 'next/server';
import { auth, currentUser } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function GET() {
  try {
    const { userId } = await auth();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Fetch user from database with tenant info
    const result = await sql`
      SELECT
        u.id,
        u.email,
        u.name,
        u.role,
        u.tenant_id,
        u.is_msp_user,
        u.status,
        t.name as tenant_name,
        t.clerk_org_id,
        t.domain,
        t.plan
      FROM users u
      LEFT JOIN tenants t ON u.tenant_id = t.id
      WHERE u.clerk_user_id = ${userId}
      LIMIT 1
    `;

    if (result.length === 0) {
      // User not in database yet - return null to signal they need to be created
      // This happens for new Clerk users who haven't accepted an invitation
      return NextResponse.json({
        user: null,
        needsSetup: true,
      });
    }

    const user = result[0];

    return NextResponse.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        tenantId: user.tenant_id,
        tenantName: user.tenant_name,
        clerkOrgId: user.clerk_org_id,
        domain: user.domain,
        plan: user.plan,
        isMspUser: user.is_msp_user,
        status: user.status,
      },
      needsSetup: false,
    });
  } catch (error) {
    console.error('Current user error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch user' },
      { status: 500 }
    );
  }
}
