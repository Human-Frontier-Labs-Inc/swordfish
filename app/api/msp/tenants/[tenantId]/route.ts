/**
 * MSP Tenant Details API
 *
 * Individual tenant management endpoints
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql, withTenant } from '@/lib/db';
import { nanoid } from 'nanoid';

interface RouteParams {
  params: Promise<{ tenantId: string }>;
}

// GET /api/msp/tenants/[tenantId] - Get tenant details with stats
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { tenantId } = await params;

    // Verify user has access
    const userResult = await sql`
      SELECT is_msp_user, tenant_id, role FROM users WHERE clerk_user_id = ${userId}
    `;

    const user = userResult[0];
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    if (!user.is_msp_user && user.tenant_id !== tenantId) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    // Get tenant details
    const tenantResult = await sql`
      SELECT * FROM tenants WHERE id = ${tenantId} LIMIT 1
    `;

    const tenant = tenantResult[0];
    if (!tenant) {
      return NextResponse.json({ error: 'Tenant not found' }, { status: 404 });
    }

    // Get user count
    const userCountResult = await sql`
      SELECT COUNT(*)::int as count FROM users WHERE tenant_id = ${tenantId}
    `;

    // Get policy count
    const policyCountResult = await sql`
      SELECT COUNT(*)::int as count FROM policies WHERE tenant_id = ${tenantId}
    `;

    // Get email stats for last 30 days
    const emailStats = await sql`
      SELECT
        COUNT(*)::int as total,
        COUNT(*) FILTER (WHERE verdict IN ('quarantine', 'block'))::int as threats,
        COUNT(*) FILTER (WHERE verdict = 'quarantine')::int as quarantined
      FROM email_verdicts
      WHERE tenant_id = ${tenantId}
        AND created_at >= NOW() - INTERVAL '30 days'
    `;

    // Get recent activity
    const recentActivity = await sql`
      SELECT id, action, resource_type, after_state as details, created_at
      FROM audit_logs
      WHERE tenant_id = ${tenantId}
      ORDER BY created_at DESC
      LIMIT 10
    `;

    // Calculate health score
    const stats = emailStats[0] || { total: 0, threats: 0, quarantined: 0 };
    const threatRate = stats.total > 0 ? (stats.threats / stats.total) * 100 : 0;
    let healthScore = 100;

    if (threatRate > 10) healthScore -= 30;
    else if (threatRate > 5) healthScore -= 15;
    else if (threatRate > 2) healthScore -= 5;

    const settings = tenant.settings || {};
    const integrationStatus = settings.integrationConnected ? 'connected' :
      settings.integrationType ? 'disconnected' : 'disconnected';

    if (integrationStatus !== 'connected') healthScore -= 20;

    return NextResponse.json({
      tenant: {
        ...tenant,
        userCount: userCountResult[0]?.count || 0,
        policyCount: policyCountResult[0]?.count || 0,
        integrationStatus,
        healthScore: Math.max(0, healthScore),
      },
      stats: {
        emailsProcessed: stats.total,
        threatsBlocked: stats.threats,
        quarantinePending: stats.quarantined,
        period: '30d',
      },
      recentActivity,
      userRole: user.is_msp_user ? 'owner' : user.role,
    });
  } catch (error) {
    console.error('Error fetching tenant:', error);
    return NextResponse.json(
      { error: 'Failed to fetch tenant' },
      { status: 500 }
    );
  }
}

// PATCH /api/msp/tenants/[tenantId] - Update tenant
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { tenantId } = await params;

    // Verify admin access
    const userResult = await sql`
      SELECT is_msp_user, tenant_id, role FROM users WHERE clerk_user_id = ${userId}
    `;

    const user = userResult[0];
    if (!user?.is_msp_user && (user?.tenant_id !== tenantId || !['tenant_admin'].includes(user?.role))) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const body = await request.json();
    const { name, plan, status, settings } = body;

    // Get current tenant
    const currentTenant = await sql`
      SELECT * FROM tenants WHERE id = ${tenantId}
    `;

    if (currentTenant.length === 0) {
      return NextResponse.json({ error: 'Tenant not found' }, { status: 404 });
    }

    // Build update
    const currentSettings = currentTenant[0].settings || {};
    const newSettings = settings ? { ...currentSettings, ...settings } : currentSettings;

    const updated = await sql`
      UPDATE tenants SET
        name = COALESCE(${name}, name),
        plan = COALESCE(${plan}, plan),
        status = COALESCE(${status}, status),
        settings = ${JSON.stringify(newSettings)},
        updated_at = NOW()
      WHERE id = ${tenantId}
      RETURNING *
    `;

    // Log the update
    await sql`
      INSERT INTO audit_logs (id, tenant_id, actor_id, action, resource_type, resource_id, before_state, after_state, ip_address, user_agent, created_at)
      VALUES (
        ${nanoid()},
        ${tenantId},
        ${userId},
        'tenant.updated',
        'tenant',
        ${tenantId},
        ${JSON.stringify(currentTenant[0])},
        ${JSON.stringify(updated[0])},
        ${request.headers.get('x-forwarded-for') || 'unknown'},
        ${request.headers.get('user-agent') || 'unknown'},
        NOW()
      )
    `;

    return NextResponse.json({
      success: true,
      tenant: updated[0],
    });
  } catch (error) {
    console.error('Error updating tenant:', error);
    return NextResponse.json(
      { error: 'Failed to update tenant' },
      { status: 500 }
    );
  }
}

// DELETE /api/msp/tenants/[tenantId] - Delete tenant (soft delete)
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { tenantId } = await params;

    // Only MSP admins can delete
    const userResult = await sql`
      SELECT is_msp_user FROM users WHERE clerk_user_id = ${userId}
    `;

    if (!userResult[0]?.is_msp_user) {
      return NextResponse.json({ error: 'Forbidden - MSP admin required' }, { status: 403 });
    }

    // Soft delete
    await sql`
      UPDATE tenants SET
        status = 'deleted',
        settings = settings || '{"deleted": true}'::jsonb,
        updated_at = NOW()
      WHERE id = ${tenantId}
    `;

    // Log the deletion
    await sql`
      INSERT INTO audit_logs (id, tenant_id, actor_id, action, resource_type, resource_id, after_state, ip_address, user_agent, created_at)
      VALUES (
        ${nanoid()},
        ${tenantId},
        ${userId},
        'tenant.deleted',
        'tenant',
        ${tenantId},
        '{"softDelete": true}'::jsonb,
        ${request.headers.get('x-forwarded-for') || 'unknown'},
        ${request.headers.get('user-agent') || 'unknown'},
        NOW()
      )
    `;

    return NextResponse.json({
      success: true,
      message: 'Tenant deleted successfully',
    });
  } catch (error) {
    console.error('Error deleting tenant:', error);
    return NextResponse.json(
      { error: 'Failed to delete tenant' },
      { status: 500 }
    );
  }
}
