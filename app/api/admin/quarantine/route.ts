/**
 * MSP Admin Quarantine API
 * GET - List quarantined emails across all tenants
 * POST - Bulk actions on quarantined emails
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
    const tenantId = searchParams.get('tenantId');
    const verdict = searchParams.get('verdict');
    const search = searchParams.get('search');
    const scoreMin = searchParams.get('scoreMin');
    const scoreMax = searchParams.get('scoreMax');

    // Get quarantined threats (status = 'quarantined')
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
        t.integration_type,
        t.original_location,
        t.received_at,
        t.created_at
      FROM threats t
      LEFT JOIN tenants ten ON t.tenant_id = ten.clerk_org_id OR t.tenant_id = ten.id::text
      WHERE t.status = 'quarantined'
      ${tenantId ? sql`AND (t.tenant_id = ${tenantId} OR ten.id::text = ${tenantId})` : sql``}
      ${verdict ? sql`AND t.verdict = ${verdict}` : sql``}
      ${search ? sql`AND (t.subject ILIKE ${'%' + search + '%'} OR t.sender_email ILIKE ${'%' + search + '%'})` : sql``}
      ${scoreMin ? sql`AND t.score >= ${parseInt(scoreMin)}` : sql``}
      ${scoreMax ? sql`AND t.score <= ${parseInt(scoreMax)}` : sql``}
      ORDER BY t.created_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `;

    // Get total count
    const countResult = await sql`
      SELECT COUNT(*)::int as total FROM threats t
      WHERE t.status = 'quarantined'
      ${tenantId ? sql`AND t.tenant_id = ${tenantId}` : sql``}
      ${verdict ? sql`AND t.verdict = ${verdict}` : sql``}
    `;

    // Get stats
    const statsResult = await sql`
      SELECT
        COUNT(*)::int as total_quarantined,
        COUNT(*) FILTER (WHERE verdict = 'malicious')::int as malicious,
        COUNT(*) FILTER (WHERE verdict = 'phishing')::int as phishing,
        COUNT(*) FILTER (WHERE verdict = 'suspicious')::int as suspicious,
        COUNT(*) FILTER (WHERE score >= 80)::int as high_severity,
        COUNT(*) FILTER (WHERE score >= 60 AND score < 80)::int as medium_severity,
        COUNT(*) FILTER (WHERE score < 60)::int as low_severity,
        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::int as last_24h
      FROM threats
      WHERE status = 'quarantined'
      ${tenantId ? sql`AND tenant_id = ${tenantId}` : sql``}
    `;

    return NextResponse.json({
      quarantine: threats.map((t: Record<string, unknown>) => ({
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
        integrationType: t.integration_type,
        originalLocation: t.original_location,
        receivedAt: t.received_at ? (t.received_at as Date).toISOString() : null,
        quarantinedAt: (t.created_at as Date).toISOString(),
      })),
      pagination: {
        page,
        limit,
        total: countResult[0]?.total || 0,
        totalPages: Math.ceil((countResult[0]?.total || 0) / limit),
      },
      stats: statsResult[0] || {},
    });
  } catch (error) {
    console.error('Admin quarantine list error:', error);
    return NextResponse.json(
      { error: 'Failed to list quarantine' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const { userId, orgRole } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check MSP admin access
    const currentUser = await sql`
      SELECT id, is_msp_user, role, email FROM users
      WHERE clerk_user_id = ${userId}
      LIMIT 1
    `;

    const user = currentUser[0];
    const hasAccess = orgRole === 'org:admin' || user?.is_msp_user || user?.role === 'msp_admin';

    if (!hasAccess) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const body = await request.json();
    const { threatIds, action } = body;

    if (!threatIds || !Array.isArray(threatIds) || threatIds.length === 0) {
      return NextResponse.json({ error: 'threatIds array is required' }, { status: 400 });
    }

    if (!['release', 'delete'].includes(action)) {
      return NextResponse.json({ error: 'Invalid action. Use "release" or "delete"' }, { status: 400 });
    }

    if (threatIds.length > 100) {
      return NextResponse.json({ error: 'Maximum 100 threats per request' }, { status: 400 });
    }

    const userUuid = user?.id as string || null;
    const userEmail = user?.email as string || 'Unknown';
    const results = { success: 0, failed: 0, errors: [] as string[] };

    for (const threatId of threatIds) {
      try {
        if (action === 'release') {
          await sql`
            UPDATE threats SET
              status = 'released',
              released_at = NOW(),
              released_by = ${userEmail},
              updated_at = NOW()
            WHERE id = ${threatId}::uuid
            AND status = 'quarantined'
          `;
        } else if (action === 'delete') {
          await sql`
            UPDATE threats SET
              status = 'deleted',
              deleted_at = NOW(),
              deleted_by = ${userEmail},
              updated_at = NOW()
            WHERE id = ${threatId}::uuid
            AND status = 'quarantined'
          `;
        }

        // Log audit event
        await sql`
          INSERT INTO audit_log (tenant_id, actor_id, actor_email, action, resource_type, resource_id, created_at)
          SELECT
            tenant_id,
            ${userUuid},
            ${userEmail},
            ${action === 'release' ? 'threat.released' : 'threat.deleted'},
            'threat',
            ${threatId},
            NOW()
          FROM threats WHERE id = ${threatId}::uuid
        `;

        results.success++;
      } catch (err) {
        results.failed++;
        results.errors.push(`Failed to ${action} threat ${threatId}`);
      }
    }

    return NextResponse.json({
      success: true,
      results,
    });
  } catch (error) {
    console.error('Admin quarantine bulk action error:', error);
    return NextResponse.json(
      { error: 'Failed to perform bulk action' },
      { status: 500 }
    );
  }
}
