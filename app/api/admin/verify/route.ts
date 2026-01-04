/**
 * Admin Verification API
 * GET - Verify if current user has MSP admin access
 */

import { NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function GET() {
  try {
    const { userId, orgId, orgRole } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check if user is an MSP admin
    // 1. Check Clerk org role
    const isOrgAdmin = orgRole === 'org:admin';

    // 2. Check database for MSP user flag
    const users = await sql`
      SELECT is_msp_user, role FROM users
      WHERE clerk_user_id = ${userId}
      LIMIT 1
    `;

    const user = users[0];
    const isMspUser = user?.is_msp_user === true;
    const isDbAdmin = user?.role === 'msp_admin';

    // 3. Check if org is an MSP organization
    let isMspOrg = false;
    if (orgId) {
      const mspOrgs = await sql`
        SELECT id FROM msp_organizations
        WHERE clerk_org_id = ${orgId}
        LIMIT 1
      `;
      isMspOrg = mspOrgs.length > 0;
    }

    const hasAccess = isOrgAdmin || isMspUser || isDbAdmin || isMspOrg;

    if (!hasAccess) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    return NextResponse.json({
      authorized: true,
      role: user?.role || 'admin',
      isMspUser: isMspUser || isMspOrg,
    });
  } catch (error) {
    console.error('Admin verify error:', error);
    return NextResponse.json(
      { error: 'Verification failed' },
      { status: 500 }
    );
  }
}
