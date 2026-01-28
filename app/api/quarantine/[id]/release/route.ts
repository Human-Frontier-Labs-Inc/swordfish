/**
 * Quarantine Release API
 * POST - Release email from quarantine
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { releaseEmail } from '@/lib/workers/remediation';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const { id } = await params;

    // Get the threat details
    const threats = await sql`
      SELECT id, message_id, integration_type, original_location
      FROM threats
      WHERE id = ${id}
      AND tenant_id = ${tenantId}
      AND status = 'quarantined'
    `;

    if (threats.length === 0) {
      return NextResponse.json({ error: 'Not found or already released' }, { status: 404 });
    }

    // Get user email for audit
    const users = await sql`
      SELECT email FROM users WHERE clerk_user_id = ${userId} LIMIT 1
    `;
    const actorEmail = users.length > 0 ? users[0].email as string : null;

    // Use remediation service to release email from quarantine folder back to inbox
    const result = await releaseEmail({
      tenantId,
      threatId: id,
      actorId: userId,
      actorEmail,
    });

    if (!result.success) {
      return NextResponse.json({
        error: 'Failed to release email',
        details: result.error
      }, { status: 500 });
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Quarantine release error:', error);
    return NextResponse.json({ error: 'Failed to release' }, { status: 500 });
  }
}
