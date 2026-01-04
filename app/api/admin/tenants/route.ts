/**
 * Admin Tenants API
 * GET - List all tenants (MSP view)
 * POST - Create new tenant
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const searchParams = request.nextUrl.searchParams;
    const plan = searchParams.get('plan');
    const status = searchParams.get('status');
    const search = searchParams.get('search');
    const page = parseInt(searchParams.get('page') || '1');
    const limit = Math.min(parseInt(searchParams.get('limit') || '50'), 100);
    const offset = (page - 1) * limit;

    // Build query conditions
    const conditions: string[] = [];
    const params: unknown[] = [];
    let paramIndex = 1;

    if (plan) {
      conditions.push(`t.plan = $${paramIndex}`);
      params.push(plan);
      paramIndex++;
    }

    if (status) {
      conditions.push(`t.status = $${paramIndex}`);
      params.push(status);
      paramIndex++;
    }

    if (search) {
      conditions.push(`(t.name ILIKE $${paramIndex} OR t.domain ILIKE $${paramIndex})`);
      params.push(`%${search}%`);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get tenants with stats
    const tenants = await sql`
      SELECT
        t.id,
        t.clerk_org_id,
        t.name,
        t.domain,
        t.plan,
        t.status,
        t.created_at,
        (SELECT COUNT(*)::int FROM users WHERE tenant_id = t.id) as user_count,
        COALESCE(stats.emails_processed, 0) as emails_processed,
        COALESCE(stats.threats_blocked, 0) as threats_blocked,
        stats.last_activity_at
      FROM tenants t
      LEFT JOIN LATERAL (
        SELECT
          COUNT(*)::int as emails_processed,
          COUNT(*) FILTER (WHERE verdict IN ('quarantine', 'block'))::int as threats_blocked,
          MAX(created_at) as last_activity_at
        FROM email_verdicts
        WHERE tenant_id::text = t.clerk_org_id OR tenant_id::uuid = t.id
        AND created_at >= NOW() - INTERVAL '30 days'
      ) stats ON true
      ORDER BY t.created_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `;

    // Get total count
    const countResult = await sql`
      SELECT COUNT(*)::int as total FROM tenants
    `;

    return NextResponse.json({
      tenants: tenants.map((t: Record<string, unknown>) => ({
        id: t.id,
        clerkOrgId: t.clerk_org_id,
        name: t.name,
        domain: t.domain,
        plan: t.plan,
        status: t.status,
        userCount: t.user_count || 0,
        emailsProcessed: t.emails_processed || 0,
        threatsBlocked: t.threats_blocked || 0,
        createdAt: (t.created_at as Date).toISOString(),
        lastActivityAt: t.last_activity_at ? (t.last_activity_at as Date).toISOString() : null,
      })),
      pagination: {
        page,
        limit,
        total: countResult[0]?.total || 0,
        totalPages: Math.ceil((countResult[0]?.total || 0) / limit),
      },
    });
  } catch (error) {
    console.error('Admin tenants list error:', error);
    return NextResponse.json(
      { error: 'Failed to list tenants' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId, orgRole } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Only org admins can create tenants
    if (orgRole !== 'org:admin') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const body = await request.json();
    const { name, domain, plan = 'starter', clerkOrgId } = body;

    if (!name) {
      return NextResponse.json(
        { error: 'Name is required' },
        { status: 400 }
      );
    }

    // Check for duplicate domain
    if (domain) {
      const existing = await sql`
        SELECT id FROM tenants WHERE domain = ${domain} LIMIT 1
      `;
      if (existing.length > 0) {
        return NextResponse.json(
          { error: 'Domain already in use' },
          { status: 400 }
        );
      }
    }

    // Create tenant
    const tenant = await sql`
      INSERT INTO tenants (
        clerk_org_id,
        name,
        domain,
        plan,
        status,
        settings,
        created_at,
        updated_at
      ) VALUES (
        ${clerkOrgId || `pending_${Date.now()}`},
        ${name},
        ${domain || null},
        ${plan},
        'active',
        ${JSON.stringify({
          detection: {
            suspiciousThreshold: 40,
            quarantineThreshold: 60,
            blockThreshold: 80,
            enableLlmAnalysis: true,
            llmDailyLimit: 100,
          },
          notifications: {
            emailEnabled: true,
            severityThreshold: 'warning',
          },
          quarantine: {
            autoDeleteAfterDays: 30,
            allowUserRelease: false,
          },
        })}::jsonb,
        NOW(),
        NOW()
      )
      RETURNING id, clerk_org_id, name, domain, plan, status, created_at
    `;

    // Audit log
    await logAuditEvent({
      tenantId: tenant[0].id as string,
      actorId: userId,
      actorEmail: null,
      action: 'tenant.created',
      resourceType: 'tenant',
      resourceId: tenant[0].id as string,
      afterState: { name, domain, plan },
    });

    return NextResponse.json({
      tenant: {
        id: tenant[0].id,
        clerkOrgId: tenant[0].clerk_org_id,
        name: tenant[0].name,
        domain: tenant[0].domain,
        plan: tenant[0].plan,
        status: tenant[0].status,
        createdAt: (tenant[0].created_at as Date).toISOString(),
      },
    }, { status: 201 });
  } catch (error) {
    console.error('Admin tenant create error:', error);
    return NextResponse.json(
      { error: 'Failed to create tenant' },
      { status: 500 }
    );
  }
}
