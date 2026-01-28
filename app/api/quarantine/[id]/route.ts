/**
 * Quarantine Item API
 * GET - Get quarantined email details
 * DELETE - Permanently delete quarantined email
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { deleteEmail } from '@/lib/workers/remediation';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const { id } = await params;

    const emails = await sql`
      SELECT
        t.*,
        ev.signals,
        ev.explanation
      FROM threats t
      LEFT JOIN email_verdicts ev ON t.message_id = ev.message_id AND t.tenant_id = ev.tenant_id
      WHERE t.id = ${id}
      AND t.tenant_id = ${tenantId}
    `;

    if (emails.length === 0) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 });
    }

    return NextResponse.json({ email: emails[0] });
  } catch (error) {
    console.error('Quarantine get error:', error);
    return NextResponse.json({ error: 'Failed to get email' }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const { id } = await params;

    // Verify the threat exists and belongs to this tenant
    const threats = await sql`
      SELECT id FROM threats
      WHERE id = ${id}
      AND tenant_id = ${tenantId}
    `;

    if (threats.length === 0) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 });
    }

    // Get user email for audit
    const users = await sql`
      SELECT email FROM users WHERE clerk_user_id = ${userId} LIMIT 1
    `;
    const actorEmail = users.length > 0 ? users[0].email as string : null;

    // Use remediation service to delete email from mailbox
    const result = await deleteEmail({
      tenantId,
      threatId: id,
      actorId: userId,
      actorEmail,
    });

    if (!result.success) {
      return NextResponse.json({
        error: 'Failed to delete email',
        details: result.error
      }, { status: 500 });
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Quarantine delete error:', error);
    return NextResponse.json({ error: 'Failed to delete' }, { status: 500 });
  }
}
