/**
 * Current User API
 * GET - Retrieve current user's profile and role from database
 */

import { NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

interface TenantRow {
  id: string;
  name: string | null;
  clerk_org_id: string | null;
  domain: string | null;
  plan: string | null;
}

/**
 * Resolve a tenant for a user without depending on the safe_uuid() SQL function
 * (which may not be applied in every environment) and without throwing on a
 * malformed/NULL users.tenant_id.
 *
 * Strategy, in order of preference:
 *   1. If the user row has a tenant_id that looks like a UUID, look it up by id.
 *   2. Otherwise (NULL/empty/non-UUID tenant_id, e.g. org users created by
 *      setup-account which never sets tenant_id), resolve by the Clerk org id.
 */
async function resolveTenant(
  tenantId: unknown,
  clerkOrgId: string | null
): Promise<TenantRow | null> {
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const tid = typeof tenantId === 'string' ? tenantId : null;

  try {
    if (tid && UUID_RE.test(tid)) {
      const rows = (await sql`
        SELECT id, name, clerk_org_id, domain, plan
        FROM tenants WHERE id = ${tid} LIMIT 1
      `) as TenantRow[];
      if (rows.length > 0) return rows[0];
    }

    if (clerkOrgId) {
      const rows = (await sql`
        SELECT id, name, clerk_org_id, domain, plan
        FROM tenants WHERE clerk_org_id = ${clerkOrgId} LIMIT 1
      `) as TenantRow[];
      if (rows.length > 0) return rows[0];
    }
  } catch (err) {
    // Tenant linkage is best-effort; never let it 500 the whole endpoint.
    console.error('resolveTenant error (degrading to null tenant):', err);
  }

  return null;
}

export async function GET() {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Fetch the user WITHOUT any fragile UUID cast / safe_uuid() dependency.
    const result = (await sql`
      SELECT
        u.id,
        u.email,
        u.name,
        u.role,
        u.tenant_id,
        u.is_msp_user,
        u.status
      FROM users u
      WHERE u.clerk_user_id = ${userId}
      LIMIT 1
    `) as Array<Record<string, unknown>>;

    if (result.length === 0) {
      // User not in database yet - return null to signal they need to be created.
      // This happens for new Clerk users who haven't accepted an invitation.
      return NextResponse.json({
        user: null,
        needsSetup: true,
      });
    }

    const user = result[0];

    // Resolve tenant separately and gracefully (handles NULL/non-UUID tenant_id
    // and org users created without a tenant_id link).
    const tenant = await resolveTenant(user.tenant_id, orgId ?? null);

    return NextResponse.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        tenantId: user.tenant_id ?? tenant?.id ?? null,
        tenantName: tenant?.name ?? null,
        clerkOrgId: tenant?.clerk_org_id ?? orgId ?? null,
        domain: tenant?.domain ?? null,
        plan: tenant?.plan ?? null,
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
