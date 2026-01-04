/**
 * Individual Threat API
 * GET - Get threat details
 * DELETE - Delete threat
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { deleteQuarantinedEmail } from '@/lib/quarantine/service';

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

    const threats = await sql`
      SELECT t.*, v.signals, v.explanation, v.recommendation
      FROM threats t
      LEFT JOIN email_verdicts v ON t.message_id = v.message_id AND t.tenant_id = v.tenant_id
      WHERE t.id = ${id}
      AND t.tenant_id = ${tenantId}
    `;

    if (threats.length === 0) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 });
    }

    const t = threats[0];
    return NextResponse.json({
      threat: {
        id: t.id,
        tenantId: t.tenant_id,
        messageId: t.message_id,
        subject: t.subject,
        senderEmail: t.sender_email,
        recipientEmail: t.recipient_email,
        verdict: t.verdict,
        score: t.score,
        status: t.status,
        provider: t.provider,
        providerMessageId: t.provider_message_id,
        quarantinedAt: t.quarantined_at,
        releasedAt: t.released_at,
        releasedBy: t.released_by,
        signals: t.signals,
        explanation: t.explanation,
        recommendation: t.recommendation,
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

    const result = await deleteQuarantinedEmail(tenantId, id, userId);

    if (!result.success) {
      return NextResponse.json(
        { error: result.error },
        { status: 400 }
      );
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
