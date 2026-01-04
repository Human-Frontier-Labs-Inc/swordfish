/**
 * Quarantine API
 * GET - List quarantined emails
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const searchParams = request.nextUrl.searchParams;
    const search = searchParams.get('search') || '';
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');

    let emails;

    if (search) {
      emails = await sql`
        SELECT
          id,
          message_id,
          subject,
          sender_email as sender,
          recipient_email as recipient,
          verdict,
          score,
          categories,
          received_at,
          created_at as quarantined_at
        FROM threats
        WHERE tenant_id = ${tenantId}
        AND status = 'quarantined'
        AND (
          subject ILIKE ${'%' + search + '%'}
          OR sender_email ILIKE ${'%' + search + '%'}
        )
        ORDER BY created_at DESC
        LIMIT ${limit}
        OFFSET ${offset}
      `;
    } else {
      emails = await sql`
        SELECT
          id,
          message_id,
          subject,
          sender_email as sender,
          recipient_email as recipient,
          verdict,
          score,
          categories,
          received_at,
          created_at as quarantined_at
        FROM threats
        WHERE tenant_id = ${tenantId}
        AND status = 'quarantined'
        ORDER BY created_at DESC
        LIMIT ${limit}
        OFFSET ${offset}
      `;
    }

    // Map to frontend format
    const formatted = emails.map((e: Record<string, unknown>) => ({
      id: e.id,
      messageId: e.message_id,
      subject: e.subject,
      sender: e.sender,
      recipient: e.recipient,
      verdict: e.verdict,
      score: e.score,
      categories: e.categories || [],
      receivedAt: e.received_at,
      quarantinedAt: e.quarantined_at,
    }));

    return NextResponse.json({ emails: formatted });
  } catch (error) {
    console.error('Quarantine list error:', error);
    return NextResponse.json({ emails: [] });
  }
}
