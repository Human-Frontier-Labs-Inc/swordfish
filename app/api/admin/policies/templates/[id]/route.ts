/**
 * Admin Policy Template Detail API
 * GET - Get template details
 * PUT - Update template
 * DELETE - Delete template
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgRole } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id } = await params;

    const templates = await sql`
      SELECT
        pt.id,
        pt.name,
        pt.description,
        pt.category,
        pt.settings,
        pt.is_default,
        pt.created_at,
        (
          SELECT COUNT(*)::int
          FROM tenant_policies tp
          WHERE tp.template_id = pt.id
        ) as usage_count
      FROM policy_templates pt
      WHERE pt.id = ${id}::uuid
      LIMIT 1
    `;

    if (templates.length === 0) {
      return NextResponse.json({ error: 'Template not found' }, { status: 404 });
    }

    const t = templates[0];
    return NextResponse.json({
      template: {
        id: t.id,
        name: t.name,
        description: t.description,
        category: t.category,
        settings: t.settings,
        usageCount: t.usage_count || 0,
        isDefault: t.is_default || false,
        createdAt: (t.created_at as Date).toISOString(),
      },
    });
  } catch (error) {
    console.error('Policy template get error:', error);
    return NextResponse.json(
      { error: 'Failed to get template' },
      { status: 500 }
    );
  }
}

export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgRole } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check MSP admin access
    const currentUser = await sql`
      SELECT is_msp_user, role, email FROM users
      WHERE clerk_user_id = ${userId}
      LIMIT 1
    `;

    const user = currentUser[0];
    const hasAccess = orgRole === 'org:admin' || user?.is_msp_user || user?.role === 'msp_admin';

    if (!hasAccess) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const { id } = await params;
    const body = await request.json();
    const { name, description, category, settings } = body;

    // Get existing template
    const existing = await sql`
      SELECT * FROM policy_templates WHERE id = ${id}::uuid LIMIT 1
    `;

    if (existing.length === 0) {
      return NextResponse.json({ error: 'Template not found' }, { status: 404 });
    }

    // Update template
    const template = await sql`
      UPDATE policy_templates SET
        name = COALESCE(${name}, name),
        description = COALESCE(${description}, description),
        category = COALESCE(${category}, category),
        settings = COALESCE(${settings ? JSON.stringify(settings) : null}::jsonb, settings),
        updated_at = NOW()
      WHERE id = ${id}::uuid
      RETURNING id, name, description, category, settings, is_default, created_at
    `;

    // Audit log
    await logAuditEvent({
      tenantId: 'msp',
      actorId: userId,
      actorEmail: user?.email as string || null,
      action: 'policy_template.updated',
      resourceType: 'policy_template',
      resourceId: id,
      beforeState: { name: existing[0].name },
      afterState: { name: template[0].name },
    });

    return NextResponse.json({
      template: {
        id: template[0].id,
        name: template[0].name,
        description: template[0].description,
        category: template[0].category,
        settings: template[0].settings,
        isDefault: template[0].is_default || false,
        createdAt: (template[0].created_at as Date).toISOString(),
      },
    });
  } catch (error) {
    console.error('Policy template update error:', error);
    return NextResponse.json(
      { error: 'Failed to update template' },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgRole } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check MSP admin access
    const currentUser = await sql`
      SELECT is_msp_user, role, email FROM users
      WHERE clerk_user_id = ${userId}
      LIMIT 1
    `;

    const user = currentUser[0];
    const hasAccess = orgRole === 'org:admin' || user?.is_msp_user || user?.role === 'msp_admin';

    if (!hasAccess) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const { id } = await params;

    // Check if template is default
    const existing = await sql`
      SELECT is_default, name FROM policy_templates WHERE id = ${id}::uuid LIMIT 1
    `;

    if (existing.length === 0) {
      return NextResponse.json({ error: 'Template not found' }, { status: 404 });
    }

    if (existing[0].is_default) {
      return NextResponse.json(
        { error: 'Cannot delete default template' },
        { status: 400 }
      );
    }

    // Delete template
    await sql`DELETE FROM policy_templates WHERE id = ${id}::uuid`;

    // Audit log
    await logAuditEvent({
      tenantId: 'msp',
      actorId: userId,
      actorEmail: user?.email as string || null,
      action: 'policy_template.deleted',
      resourceType: 'policy_template',
      resourceId: id,
      beforeState: { name: existing[0].name },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Policy template delete error:', error);
    return NextResponse.json(
      { error: 'Failed to delete template' },
      { status: 500 }
    );
  }
}
