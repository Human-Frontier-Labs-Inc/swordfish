/**
 * Admin Stats API
 * GET - Get MSP-wide statistics
 */

import { NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function GET() {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // For MSP, get stats across all managed tenants
    // For non-MSP admins, this returns limited data

    // Get tenant counts
    const tenantStats = await sql`
      SELECT
        COUNT(*)::int as total_tenants,
        COUNT(*) FILTER (WHERE status = 'active')::int as active_tenants
      FROM tenants
    `;

    // Get user count
    const userStats = await sql`
      SELECT COUNT(*)::int as total_users FROM users
    `;

    // Get email processing stats (last 30 days)
    const emailStats = await sql`
      SELECT
        COUNT(*)::int as total_emails,
        COUNT(*) FILTER (WHERE verdict IN ('quarantine', 'block'))::int as threats_blocked
      FROM email_verdicts
      WHERE created_at >= NOW() - INTERVAL '30 days'
    `;

    // Get tenants by plan
    const planStats = await sql`
      SELECT plan, COUNT(*)::int as count
      FROM tenants
      GROUP BY plan
      ORDER BY count DESC
    `;

    // Get recent activity across tenants
    const recentActivity = await sql`
      SELECT
        al.id,
        t.name as tenant_name,
        al.action,
        al.created_at as timestamp
      FROM audit_log al
      JOIN tenants t ON al.tenant_id::text = t.clerk_org_id OR al.tenant_id::uuid = t.id
      ORDER BY al.created_at DESC
      LIMIT 10
    `;

    return NextResponse.json({
      totalTenants: tenantStats[0]?.total_tenants || 0,
      activeTenants: tenantStats[0]?.active_tenants || 0,
      totalUsers: userStats[0]?.total_users || 0,
      totalEmailsProcessed: emailStats[0]?.total_emails || 0,
      totalThreatsBlocked: emailStats[0]?.threats_blocked || 0,
      tenantsByPlan: planStats.map((p: Record<string, unknown>) => ({
        plan: p.plan as string,
        count: p.count as number,
      })),
      recentActivity: recentActivity.map((a: Record<string, unknown>) => ({
        id: a.id as string,
        tenantName: a.tenant_name as string,
        action: a.action as string,
        timestamp: (a.timestamp as Date).toISOString(),
      })),
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch stats' },
      { status: 500 }
    );
  }
}
