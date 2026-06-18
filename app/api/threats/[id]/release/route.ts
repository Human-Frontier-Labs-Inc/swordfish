/**
 * Release Threat API
 * POST - Release email from quarantine
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

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
    const body = await request.json().catch(() => ({}));

    const { isFalsePositive = false } = body as { isFalsePositive?: boolean };

    // `id` is the URL-encoded message_id. Threats are sourced from email_verdicts
    // (the populated table), so release/false-positive are recorded there.
    let messageId = id;
    try {
      messageId = decodeURIComponent(id);
    } catch {
      messageId = id;
    }

    const result = await sql`
      UPDATE email_verdicts
      SET
        action_taken = 'released',
        action_taken_at = NOW(),
        action_taken_by = NULL,
        user_feedback = ${isFalsePositive ? 'false_positive' : null}
      WHERE tenant_id = ${tenantId}
      AND message_id = ${messageId}
      RETURNING id
    `;

    if (result.length === 0) {
      return NextResponse.json({ error: 'Threat not found' }, { status: 404 });
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Release threat error:', error);
    return NextResponse.json(
      { error: 'Failed to release threat' },
      { status: 500 }
    );
  }
}
