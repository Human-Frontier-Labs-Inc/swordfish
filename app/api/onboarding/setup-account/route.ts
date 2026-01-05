import { NextRequest, NextResponse } from 'next/server';
import { auth, clerkClient } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function POST(request: NextRequest) {
  try {
    const { userId } = await auth();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const body = await request.json();
    const { organizationId, accountType, organizationName } = body;

    if (!organizationId || !accountType) {
      return NextResponse.json(
        { error: 'Organization ID and account type are required' },
        { status: 400 }
      );
    }

    const isMsp = accountType === 'msp';
    const client = await clerkClient();

    // Update organization metadata in Clerk
    await client.organizations.updateOrganization(organizationId, {
      publicMetadata: {
        isMsp,
        accountType,
        plan: isMsp ? 'enterprise' : 'starter',
        setupCompleted: false,
      },
    });

    // Create or update tenant in database
    const existingTenant = await sql`
      SELECT id FROM tenants WHERE clerk_org_id = ${organizationId}
    `;

    if (existingTenant.length === 0) {
      // Create new tenant
      await sql`
        INSERT INTO tenants (
          clerk_org_id,
          name,
          plan,
          status,
          settings,
          created_at,
          updated_at
        ) VALUES (
          ${organizationId},
          ${organizationName || 'New Organization'},
          ${isMsp ? 'enterprise' : 'starter'},
          'active',
          ${JSON.stringify({ isMsp, accountType })}::jsonb,
          NOW(),
          NOW()
        )
      `;
    } else {
      // Update existing tenant
      await sql`
        UPDATE tenants
        SET
          settings = settings || ${JSON.stringify({ isMsp, accountType })}::jsonb,
          plan = ${isMsp ? 'enterprise' : 'starter'},
          updated_at = NOW()
        WHERE clerk_org_id = ${organizationId}
      `;
    }

    // Update user record if exists
    const existingUser = await sql`
      SELECT id FROM users WHERE clerk_user_id = ${userId}
    `;

    if (existingUser.length === 0) {
      // Get user details from Clerk
      const clerkUser = await client.users.getUser(userId);

      await sql`
        INSERT INTO users (
          clerk_user_id,
          email,
          name,
          role,
          is_msp_user,
          created_at,
          updated_at
        ) VALUES (
          ${userId},
          ${clerkUser.emailAddresses[0]?.emailAddress || ''},
          ${clerkUser.firstName ? `${clerkUser.firstName} ${clerkUser.lastName || ''}`.trim() : null},
          ${isMsp ? 'msp_admin' : 'tenant_admin'},
          ${isMsp},
          NOW(),
          NOW()
        )
      `;
    } else {
      await sql`
        UPDATE users
        SET
          role = ${isMsp ? 'msp_admin' : 'tenant_admin'},
          is_msp_user = ${isMsp},
          updated_at = NOW()
        WHERE clerk_user_id = ${userId}
      `;
    }

    return NextResponse.json({
      success: true,
      isMsp,
      accountType,
      organizationId,
    });

  } catch (error) {
    console.error('Setup account error:', error);
    return NextResponse.json(
      { error: 'Failed to setup account' },
      { status: 500 }
    );
  }
}
