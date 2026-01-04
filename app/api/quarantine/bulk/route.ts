/**
 * Quarantine Bulk Actions API
 * POST - Perform bulk actions on quarantined emails
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

interface BulkActionRequest {
  action: 'release' | 'delete';
  emailIds: string[];
}

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const body: BulkActionRequest = await request.json();

    if (!body.emailIds || body.emailIds.length === 0) {
      return NextResponse.json({ error: 'No emails specified' }, { status: 400 });
    }

    if (!['release', 'delete'].includes(body.action)) {
      return NextResponse.json({ error: 'Invalid action' }, { status: 400 });
    }

    let successCount = 0;
    const errors: string[] = [];

    for (const emailId of body.emailIds) {
      try {
        // Verify ownership
        const threats = await sql`
          SELECT id, message_id FROM threats
          WHERE id = ${emailId}
          AND tenant_id = ${tenantId}
          AND status = 'quarantined'
        `;

        if (threats.length === 0) {
          errors.push(`${emailId}: Not found or already processed`);
          continue;
        }

        const threat = threats[0];

        if (body.action === 'release') {
          await sql`
            UPDATE threats
            SET status = 'released', released_at = NOW(), released_by = ${userId}
            WHERE id = ${emailId}
          `;

          await sql`
            UPDATE email_verdicts
            SET status = 'released'
            WHERE message_id = ${threat.message_id}
            AND tenant_id = ${tenantId}
          `;
        } else if (body.action === 'delete') {
          await sql`
            DELETE FROM threats
            WHERE id = ${emailId}
          `;

          await sql`
            UPDATE email_verdicts
            SET status = 'deleted'
            WHERE message_id = ${threat.message_id}
            AND tenant_id = ${tenantId}
          `;
        }

        successCount++;
      } catch (error) {
        errors.push(`${emailId}: ${error instanceof Error ? error.message : 'Failed'}`);
      }
    }

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: `quarantine.bulk_${body.action}`,
      resourceType: 'threat',
      resourceId: 'bulk',
      afterState: {
        totalRequested: body.emailIds.length,
        successCount,
        errorCount: errors.length,
      },
    });

    return NextResponse.json({
      success: true,
      processed: successCount,
      errors: errors.length > 0 ? errors.slice(0, 10) : undefined,
    });
  } catch (error) {
    console.error('Quarantine bulk action error:', error);
    return NextResponse.json({ error: 'Failed to process' }, { status: 500 });
  }
}
