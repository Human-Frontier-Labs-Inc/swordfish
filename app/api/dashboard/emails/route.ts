/**
 * Scanned Emails API
 * GET /api/dashboard/emails - List all scanned emails (not just threats)
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const tenantId = orgId || `personal_${userId}`;

    // Get query parameters
    const searchParams = request.nextUrl.searchParams;
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');
    const verdictFilter = searchParams.get('verdict'); // pass, suspicious, quarantine, block

    // Build query with optional verdict filter
    let emails;
    if (verdictFilter) {
      emails = await sql`
        SELECT
          id,
          message_id,
          subject,
          from_address,
          from_display_name,
          to_addresses,
          received_at,
          verdict,
          score,
          confidence,
          signals,
          processing_time_ms,
          created_at
        FROM email_verdicts
        WHERE tenant_id = ${tenantId}
        AND verdict = ${verdictFilter}
        ORDER BY received_at DESC
        LIMIT ${limit}
        OFFSET ${offset}
      `;
    } else {
      emails = await sql`
        SELECT
          id,
          message_id,
          subject,
          from_address,
          from_display_name,
          to_addresses,
          received_at,
          verdict,
          score,
          confidence,
          signals,
          processing_time_ms,
          created_at
        FROM email_verdicts
        WHERE tenant_id = ${tenantId}
        ORDER BY received_at DESC
        LIMIT ${limit}
        OFFSET ${offset}
      `;
    }

    // Get total count
    const countResult = await sql`
      SELECT COUNT(*)::int as total
      FROM email_verdicts
      WHERE tenant_id = ${tenantId}
      ${verdictFilter ? sql`AND verdict = ${verdictFilter}` : sql``}
    `;

    const total = countResult[0]?.total || 0;

    // Format emails for frontend
    const formattedEmails = emails.map((email: Record<string, unknown>) => {
      const signals = (email.signals as Array<{ type: string; severity: string; detail: string }>) || [];
      const primarySignal = signals.find(s => s.severity === 'critical')
        || signals.find(s => s.severity === 'warning')
        || signals[0];

      // Format sender display
      const fromDisplay = email.from_display_name
        ? `${email.from_display_name} <${email.from_address}>`
        : email.from_address || 'Unknown sender';

      return {
        id: email.id,
        messageId: email.message_id,
        subject: email.subject || '(No subject)',
        from: fromDisplay,
        fromAddress: email.from_address,
        to: email.to_addresses,
        receivedAt: email.received_at,
        verdict: email.verdict,
        score: email.score || 0,
        confidence: email.confidence || 0,
        signals: signals,
        signalCount: signals.length,
        primarySignal: primarySignal?.detail || (email.verdict === 'pass' ? 'No threats detected' : 'Unknown'),
        processingTimeMs: email.processing_time_ms || 0,
        scannedAt: email.created_at,
      };
    });

    return NextResponse.json({
      emails: formattedEmails,
      total,
      limit,
      offset,
    });

  } catch (error) {
    console.error('Emails API error:', error);
    return NextResponse.json({
      emails: [],
      total: 0,
      limit: 50,
      offset: 0,
    });
  }
}
