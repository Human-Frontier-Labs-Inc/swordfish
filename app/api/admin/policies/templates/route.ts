/**
 * Admin Policy Templates API
 * GET - List all policy templates
 * POST - Create new policy template
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

export async function GET() {
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

    // Get templates with usage count
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
      ORDER BY pt.is_default DESC, pt.created_at DESC
    `;

    return NextResponse.json({
      templates: templates.map((t: Record<string, unknown>) => ({
        id: t.id,
        name: t.name,
        description: t.description,
        category: t.category,
        settings: t.settings,
        usageCount: t.usage_count || 0,
        isDefault: t.is_default || false,
        createdAt: (t.created_at as Date).toISOString(),
      })),
    });
  } catch (error) {
    console.error('Policy templates list error:', error);
    return NextResponse.json(
      { error: 'Failed to list templates' },
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
      SELECT is_msp_user, role, email FROM users
      WHERE clerk_user_id = ${userId}
      LIMIT 1
    `;

    const user = currentUser[0];
    const hasAccess = orgRole === 'org:admin' || user?.is_msp_user || user?.role === 'msp_admin';

    if (!hasAccess) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const body = await request.json();
    const { name, description, category, settings } = body;

    if (!name) {
      return NextResponse.json(
        { error: 'Name is required' },
        { status: 400 }
      );
    }

    // Validate category
    const validCategories = ['security', 'compliance', 'productivity', 'custom'];
    if (category && !validCategories.includes(category)) {
      return NextResponse.json(
        { error: 'Invalid category' },
        { status: 400 }
      );
    }

    // Create template
    const template = await sql`
      INSERT INTO policy_templates (
        name,
        description,
        category,
        settings,
        created_by,
        created_at,
        updated_at
      ) VALUES (
        ${name},
        ${description || ''},
        ${category || 'custom'},
        ${JSON.stringify(settings || {})}::jsonb,
        ${userId},
        NOW(),
        NOW()
      )
      RETURNING id, name, description, category, settings, is_default, created_at
    `;

    // Audit log
    await logAuditEvent({
      tenantId: 'msp',
      actorId: userId,
      actorEmail: user?.email as string || null,
      action: 'policy_template.created',
      resourceType: 'policy_template',
      resourceId: template[0].id as string,
      afterState: { name, category },
    });

    return NextResponse.json({
      template: {
        id: template[0].id,
        name: template[0].name,
        description: template[0].description,
        category: template[0].category,
        settings: template[0].settings,
        usageCount: 0,
        isDefault: template[0].is_default || false,
        createdAt: (template[0].created_at as Date).toISOString(),
      },
    }, { status: 201 });
  } catch (error) {
    console.error('Policy template create error:', error);
    return NextResponse.json(
      { error: 'Failed to create template' },
      { status: 500 }
    );
  }
}
