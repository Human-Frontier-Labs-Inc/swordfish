/**
 * Admin Audit Log API
 * GET - List audit logs across all tenants (MSP view)
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgRole } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check MSP admin access
    const users = await sql`
      SELECT is_msp_user, role FROM users
      WHERE clerk_user_id = ${userId}
      LIMIT 1
    `;

    const user = users[0];
    const hasAccess = orgRole === 'org:admin' || user?.is_msp_user || user?.role === 'msp_admin';

    if (!hasAccess) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const searchParams = request.nextUrl.searchParams;
    const page = parseInt(searchParams.get('page') || '1');
    const limit = Math.min(parseInt(searchParams.get('limit') || '50'), 100);
    const offset = (page - 1) * limit;

    // Filter parameters
    const tenantId = searchParams.get('tenantId');
    const action = searchParams.get('action');
    const resourceType = searchParams.get('resourceType');
    const actorEmail = searchParams.get('actorEmail');
    const startDate = searchParams.get('startDate');
    const endDate = searchParams.get('endDate');

    // Build query conditions
    const conditions: string[] = [];
    const params: unknown[] = [];
    let paramIndex = 1;

    if (tenantId) {
      conditions.push(`al.tenant_id = $${paramIndex}`);
      params.push(tenantId);
      paramIndex++;
    }

    if (action) {
      conditions.push(`al.action = $${paramIndex}`);
      params.push(action);
      paramIndex++;
    }

    if (resourceType) {
      conditions.push(`al.resource_type = $${paramIndex}`);
      params.push(resourceType);
      paramIndex++;
    }

    if (actorEmail) {
      conditions.push(`al.actor_email ILIKE $${paramIndex}`);
      params.push(`%${actorEmail}%`);
      paramIndex++;
    }

    if (startDate) {
      conditions.push(`al.created_at >= $${paramIndex}`);
      params.push(startDate);
      paramIndex++;
    }

    if (endDate) {
      conditions.push(`al.created_at <= $${paramIndex}::date + INTERVAL '1 day'`);
      params.push(endDate);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get audit logs with tenant names
    const logs = await sql`
      SELECT
        al.id,
        al.tenant_id,
        t.name as tenant_name,
        al.actor_id,
        al.actor_email,
        al.action,
        al.resource_type,
        al.resource_id,
        al.ip_address,
        al.user_agent,
        al.before_state,
        al.after_state,
        al.metadata,
        al.created_at
      FROM audit_log al
      LEFT JOIN tenants t ON al.tenant_id::text = t.clerk_org_id OR al.tenant_id::uuid = t.id
      ORDER BY al.created_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `;

    // Get total count
    const countResult = await sql`
      SELECT COUNT(*)::int as total FROM audit_log
    `;

    return NextResponse.json({
      logs: logs.map((log: Record<string, unknown>) => ({
        id: log.id,
        tenantId: log.tenant_id,
        tenantName: log.tenant_name,
        actorId: log.actor_id,
        actorEmail: log.actor_email,
        action: log.action,
        resourceType: log.resource_type,
        resourceId: log.resource_id,
        ipAddress: log.ip_address,
        userAgent: log.user_agent,
        beforeState: log.before_state,
        afterState: log.after_state,
        metadata: log.metadata,
        createdAt: (log.created_at as Date).toISOString(),
      })),
      pagination: {
        page,
        limit,
        total: countResult[0]?.total || 0,
        totalPages: Math.ceil((countResult[0]?.total || 0) / limit),
      },
    });
  } catch (error) {
    console.error('Admin audit log error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch audit logs' },
      { status: 500 }
    );
  }
}
