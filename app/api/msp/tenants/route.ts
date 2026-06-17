/**
 * MSP Tenants API
 *
 * Manages tenant CRUD operations for MSP dashboard
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { nanoid } from 'nanoid';

// GET /api/msp/tenants - List tenants the caller is authorized to see
export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const searchParams = request.nextUrl.searchParams;
    const search = searchParams.get('search');
    const plan = searchParams.get('plan');
    const status = searchParams.get('status');
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');

    // Check if user is MSP admin
    const userResult = await sql`
      SELECT is_msp_user, tenant_id
      FROM users
      WHERE clerk_user_id = ${userId}
    `;

    const user = userResult[0];
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    let tenantsQuery;
    let countQuery;
    let role: 'msp_admin' | 'tenant_admin';

    if (user.is_msp_user) {
      // SECURITY (P0-8): An MSP user is NOT god-mode. They may only see tenants
      // explicitly granted to their MSP organization via `msp_tenant_access`.
      // Resolve the MSP org from the caller's active Clerk org.
      if (!orgId) {
        // is_msp_user but not acting within an MSP org context -> nothing granted.
        return NextResponse.json({ tenants: [], total: 0, defaultTenantId: null });
      }

      const mspOrgResult = await sql`
        SELECT id FROM msp_organizations WHERE clerk_org_id = ${orgId} LIMIT 1
      `;
      const mspOrg = mspOrgResult[0];

      if (!mspOrg) {
        // The user's active org is not a registered MSP org -> no managed tenants.
        return NextResponse.json({ tenants: [], total: 0, defaultTenantId: null });
      }

      const mspOrgId = mspOrg.id;
      role = 'msp_admin';

      // Only tenants joined through msp_tenant_access for THIS msp org.
      tenantsQuery = sql`
        SELECT
          t.id, t.name, t.domain, t.plan, t.status, t.created_at,
          (SELECT COUNT(*)::int FROM users WHERE tenant_id = t.id) as user_count
        FROM tenants t
        INNER JOIN msp_tenant_access mta ON mta.tenant_id = t.id
        WHERE mta.msp_org_id = ${mspOrgId}
          AND t.status != 'deleted'
          ${search ? sql`AND (t.name ILIKE ${'%' + search + '%'} OR t.domain ILIKE ${'%' + search + '%'})` : sql``}
          ${plan ? sql`AND t.plan = ${plan}` : sql``}
          ${status ? sql`AND t.status = ${status}` : sql``}
        ORDER BY t.created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;

      countQuery = sql`
        SELECT COUNT(*)::int as count
        FROM tenants t
        INNER JOIN msp_tenant_access mta ON mta.tenant_id = t.id
        WHERE mta.msp_org_id = ${mspOrgId}
          AND t.status != 'deleted'
          ${search ? sql`AND (t.name ILIKE ${'%' + search + '%'} OR t.domain ILIKE ${'%' + search + '%'})` : sql``}
          ${plan ? sql`AND t.plan = ${plan}` : sql``}
          ${status ? sql`AND t.status = ${status}` : sql``}
      `;
    } else if (user.tenant_id) {
      // Regular users can only see their own tenant
      role = 'tenant_admin';
      tenantsQuery = sql`
        SELECT
          t.id, t.name, t.domain, t.plan, t.status, t.created_at,
          (SELECT COUNT(*)::int FROM users WHERE tenant_id = t.id) as user_count
        FROM tenants t
        WHERE t.id = ${user.tenant_id}
      `;
      countQuery = null;
    } else {
      return NextResponse.json({
        tenants: [],
        total: 0,
        defaultTenantId: null,
      });
    }

    const tenants = await tenantsQuery;
    const countResult = countQuery ? await countQuery : [{ count: tenants.length }];

    const formattedTenants = tenants.map((t: Record<string, unknown>) => ({
      id: t.id,
      name: t.name,
      domain: t.domain,
      plan: t.plan,
      status: t.status,
      createdAt: t.created_at,
      userCount: t.user_count || 0,
      role,
    }));

    return NextResponse.json({
      tenants: formattedTenants,
      total: countResult[0]?.count || 0,
      defaultTenantId: user.tenant_id || formattedTenants[0]?.id || null,
    });
  } catch (error) {
    console.error('Error fetching tenants:', error);
    return NextResponse.json(
      { error: 'Failed to fetch tenants' },
      { status: 500 }
    );
  }
}

// POST /api/msp/tenants - Create new tenant
export async function POST(request: NextRequest) {
  try {
    const { userId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check if user is MSP admin and get their UUID
    const userResult = await sql`
      SELECT id, is_msp_user FROM users WHERE clerk_user_id = ${userId}
    `;

    if (!userResult[0]?.is_msp_user) {
      return NextResponse.json({ error: 'Forbidden - MSP admin required' }, { status: 403 });
    }

    const userUuid = userResult[0].id;

    const body = await request.json();
    const {
      organizationName,
      domain,
      plan = 'pro',
      integrationType,
      adminEmail,
      adminName,
      useDefaultPolicies,
    } = body;

    // Validate required fields
    if (!organizationName?.trim()) {
      return NextResponse.json(
        { error: 'Organization name is required' },
        { status: 400 }
      );
    }

    if (!domain?.trim()) {
      return NextResponse.json(
        { error: 'Domain is required' },
        { status: 400 }
      );
    }

    // Check if domain already exists
    const existingTenant = await sql`
      SELECT id FROM tenants WHERE domain = ${domain.toLowerCase()} LIMIT 1
    `;

    if (existingTenant.length > 0) {
      return NextResponse.json(
        { error: 'A tenant with this domain already exists' },
        { status: 409 }
      );
    }

    // Create tenant with auto-generated UUID
    const clerkOrgId = `msp_tenant_${nanoid()}`; // Placeholder clerk org id for MSP-created tenants
    const settings = {
      integrationType,
      onboardingCompleted: false,
      adminEmail,
      adminName,
    };

    const newTenant = await sql`
      INSERT INTO tenants (clerk_org_id, name, domain, plan, status, settings, created_at, updated_at)
      VALUES (
        ${clerkOrgId},
        ${organizationName.trim()},
        ${domain.toLowerCase().trim()},
        ${plan},
        'pending',
        ${JSON.stringify(settings)},
        NOW(),
        NOW()
      )
      RETURNING id, clerk_org_id, name, domain, plan, status
    `;

    const tenantId = newTenant[0].id;

    // Apply default policies if selected
    if (useDefaultPolicies) {
      const defaultPolicies = [
        { type: 'blocklist', target: 'domain', value: '*', action: 'block', priority: 100 },
        { type: 'rule', target: 'pattern', value: '*.exe,*.bat,*.ps1', action: 'quarantine', priority: 90 },
      ];

      for (const policy of defaultPolicies) {
        await sql`
          INSERT INTO policies (tenant_id, type, target, value, action, priority, is_active, created_at, updated_at)
          VALUES (
            ${tenantId},
            ${policy.type},
            ${policy.target},
            ${policy.value},
            ${policy.action},
            ${policy.priority},
            true,
            NOW(),
            NOW()
          )
        `;
      }
    }

    // Log the creation
    await sql`
      INSERT INTO audit_log (tenant_id, actor_id, action, resource_type, resource_id, after_state, ip_address, user_agent, created_at)
      VALUES (
        ${tenantId},
        ${userUuid},
        'tenant.created',
        'tenant',
        ${tenantId},
        ${JSON.stringify({ name: organizationName, domain, plan, integrationType, useDefaultPolicies })},
        ${request.headers.get('x-forwarded-for') || 'unknown'},
        ${request.headers.get('user-agent') || 'unknown'},
        NOW()
      )
    `;

    return NextResponse.json({
      success: true,
      tenant: newTenant[0],
      message: 'Tenant created successfully',
    }, { status: 201 });
  } catch (error) {
    console.error('Error creating tenant:', error);
    return NextResponse.json(
      { error: 'Failed to create tenant' },
      { status: 500 }
    );
  }
}
