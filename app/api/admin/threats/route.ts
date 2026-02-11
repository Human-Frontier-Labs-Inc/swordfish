/**
 * MSP Admin Threats API
 * GET - List threats across all tenants (MSP view)
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql, withMspContext, withTenant } from '@/lib/db';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgRole } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check MSP admin access
    const currentUser = await sql`
      SELECT is_msp_user, role FROM users
      WHERE clerk_user_id = ${userId}
      LIMIT 1
    `;

    const user = currentUser[0];
    const hasAccess = orgRole === 'org:admin' || user?.is_msp_user || user?.role === 'msp_admin';

    if (!hasAccess) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const searchParams = request.nextUrl.searchParams;
    const page = parseInt(searchParams.get('page') || '1');
    const limit = Math.min(parseInt(searchParams.get('limit') || '50'), 100);
    const offset = (page - 1) * limit;

    // Filter parameters
    const status = searchParams.get('status'); // quarantined, released, deleted, all
    const tenantId = searchParams.get('tenantId');
    const verdict = searchParams.get('verdict'); // malicious, phishing, suspicious
    const search = searchParams.get('search');
    const dateFrom = searchParams.get('dateFrom');
    const dateTo = searchParams.get('dateTo');
    const includeStats = searchParams.get('stats') === 'true';

    // Build dynamic WHERE clause
    const whereConditions = [];

    if (status && status !== 'all') {
      whereConditions.push(`t.status = '${status}'`);
    }

    if (tenantId) {
      whereConditions.push(`t.tenant_id = '${tenantId}'`);
    }

    if (verdict) {
      whereConditions.push(`t.verdict = '${verdict}'`);
    }

    if (search) {
      whereConditions.push(`(t.subject ILIKE '%${search}%' OR t.sender_email ILIKE '%${search}%' OR t.recipient_email ILIKE '%${search}%')`);
    }

    if (dateFrom) {
      whereConditions.push(`t.created_at >= '${dateFrom}'`);
    }

    if (dateTo) {
      whereConditions.push(`t.created_at <= '${dateTo}'`);
    }

    const whereClause = whereConditions.length > 0
      ? `WHERE ${whereConditions.join(' AND ')}`
      : '';

    // Get threats with tenant info
    const threats = await sql`
      SELECT
        t.id,
        t.tenant_id,
        ten.name as tenant_name,
        t.message_id,
        t.subject,
        t.sender_email,
        t.recipient_email,
        t.verdict,
        t.score,
        t.categories,
        t.signals,
        t.status,
        t.integration_type,
        t.received_at,
        t.created_at,
        t.released_at,
        t.released_by,
        t.deleted_at,
        t.deleted_by
      FROM threats t
      LEFT JOIN tenants ten ON t.tenant_id = ten.clerk_org_id OR t.tenant_id = ten.id::text
      ${status && status !== 'all' ? sql`WHERE t.status = ${status}` : sql``}
      ${tenantId ? sql`${status && status !== 'all' ? sql`AND` : sql`WHERE`} (t.tenant_id = ${tenantId} OR ten.id::text = ${tenantId})` : sql``}
      ORDER BY t.created_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `;

    // Get total count
    const countResult = await sql`
      SELECT COUNT(*)::int as total FROM threats t
      ${status && status !== 'all' ? sql`WHERE t.status = ${status}` : sql``}
      ${tenantId ? sql`${status && status !== 'all' ? sql`AND` : sql`WHERE`} t.tenant_id = ${tenantId}` : sql``}
    `;

    // Get stats if requested
    let stats = null;
    if (includeStats) {
      const statsResult = await sql`
        SELECT
          COUNT(*)::int as total,
          COUNT(*) FILTER (WHERE status = 'quarantined')::int as quarantined,
          COUNT(*) FILTER (WHERE status = 'released')::int as released,
          COUNT(*) FILTER (WHERE status = 'deleted')::int as deleted,
          COUNT(*) FILTER (WHERE verdict = 'malicious')::int as malicious,
          COUNT(*) FILTER (WHERE verdict = 'phishing')::int as phishing,
          COUNT(*) FILTER (WHERE verdict = 'suspicious')::int as suspicious,
          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::int as last_24h,
          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days')::int as last_7d,
          AVG(score)::int as avg_score
        FROM threats
        ${tenantId ? sql`WHERE tenant_id = ${tenantId}` : sql``}
      `;
      stats = statsResult[0];
    }

    // Get tenant breakdown for stats
    let tenantBreakdown = null;
    if (includeStats && !tenantId) {
      tenantBreakdown = await sql`
        SELECT
          t.tenant_id,
          ten.name as tenant_name,
          COUNT(*)::int as threat_count,
          COUNT(*) FILTER (WHERE t.status = 'quarantined')::int as quarantined
        FROM threats t
        LEFT JOIN tenants ten ON t.tenant_id = ten.clerk_org_id OR t.tenant_id = ten.id::text
        GROUP BY t.tenant_id, ten.name
        ORDER BY threat_count DESC
        LIMIT 10
      `;
    }

    return NextResponse.json({
      threats: threats.map((t: Record<string, unknown>) => ({
        id: t.id,
        tenantId: t.tenant_id,
        tenantName: t.tenant_name || 'Unknown Tenant',
        messageId: t.message_id,
        subject: t.subject,
        senderEmail: t.sender_email,
        recipientEmail: t.recipient_email,
        verdict: t.verdict,
        score: t.score,
        categories: t.categories || [],
        signals: t.signals || [],
        status: t.status,
        integrationType: t.integration_type,
        receivedAt: t.received_at ? (t.received_at as Date).toISOString() : null,
        createdAt: (t.created_at as Date).toISOString(),
        releasedAt: t.released_at ? (t.released_at as Date).toISOString() : null,
        releasedBy: t.released_by,
        deletedAt: t.deleted_at ? (t.deleted_at as Date).toISOString() : null,
        deletedBy: t.deleted_by,
      })),
      pagination: {
        page,
        limit,
        total: countResult[0]?.total || 0,
        totalPages: Math.ceil((countResult[0]?.total || 0) / limit),
      },
      ...(stats && { stats }),
      ...(tenantBreakdown && { tenantBreakdown }),
    });
  } catch (error) {
    console.error('Admin threats list error:', error);
    return NextResponse.json(
      { error: 'Failed to list threats' },
      { status: 500 }
    );
  }
}
