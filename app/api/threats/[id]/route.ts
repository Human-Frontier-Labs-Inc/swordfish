/**
 * Individual Threat API
 * GET - Get threat details
 * DELETE - Delete threat
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { getThreatByMessageId } from '@/lib/detection/storage';

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

    // `id` is the URL-encoded message_id (message ids contain <, >, @).
    // getThreatByMessageId decodes it and reads from email_verdicts, the table
    // the live detection pipeline actually populates.
    const threat = await getThreatByMessageId(tenantId, id);

    if (!threat) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 });
    }

    return NextResponse.json({
      threat: {
        id: threat.id,
        tenantId,
        messageId: threat.message_id,
        subject: threat.subject,
        senderEmail: threat.sender_email,
        recipientEmail: threat.recipient_email,
        verdict: threat.verdict,
        score: threat.score,
        status: threat.status,
        provider: '',
        providerMessageId: '',
        quarantinedAt: threat.quarantined_at,
        releasedAt: null,
        releasedBy: null,
        signals: threat.signals,
        explanation: threat.explanation,
        recommendation: threat.recommendation,
      },
    });
  } catch (error) {
    console.error('Get threat error:', error);
    return NextResponse.json(
      { error: 'Failed to get threat' },
      { status: 500 }
    );
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

    // `id` is the URL-encoded message_id. Mark the verdict as deleted in
    // email_verdicts (the populated source). Provider-side deletion is handled
    // separately by the remediation worker.
    let messageId = id;
    try {
      messageId = decodeURIComponent(id);
    } catch {
      messageId = id;
    }

    const result = await sql`
      UPDATE email_verdicts
      SET action_taken = 'deleted', action_taken_at = NOW()
      WHERE tenant_id = ${tenantId}
      AND message_id = ${messageId}
      RETURNING id
    `;

    if (result.length === 0) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 });
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Delete threat error:', error);
    return NextResponse.json(
      { error: 'Failed to delete threat' },
      { status: 500 }
    );
  }
}
