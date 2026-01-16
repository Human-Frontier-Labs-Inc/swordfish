/**
 * Backfill Threats API
 * One-time migration to populate threats table from existing email_verdicts
 *
 * This fixes the issue where emails were quarantined before the autoRemediate
 * fix was deployed, so they exist in email_verdicts but not in threats table.
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    console.log(`[Backfill] Starting threats backfill for tenant: ${tenantId}`);

    // Find quarantine/block verdicts in email_verdicts that don't have a threats record
    const missingThreats = await sql`
      SELECT
        ev.tenant_id,
        ev.message_id,
        ev.subject,
        ev.from_address,
        ev.to_addresses,
        ev.verdict,
        ev.score,
        ev.signals,
        ev.explanation,
        ev.created_at,
        i.id as integration_id,
        i.type as integration_type
      FROM email_verdicts ev
      LEFT JOIN integrations i ON i.tenant_id = ev.tenant_id AND i.status = 'connected'
      WHERE ev.tenant_id = ${tenantId}
      AND ev.verdict IN ('quarantine', 'block')
      AND NOT EXISTS (
        SELECT 1 FROM threats t
        WHERE t.tenant_id = ev.tenant_id
        AND t.message_id = ev.message_id
      )
    `;

    console.log(`[Backfill] Found ${missingThreats.length} emails to backfill`);

    let inserted = 0;
    let errors = 0;

    for (const email of missingThreats) {
      try {
        // Parse to_addresses - could be JSON array or string
        let recipientEmail = '';
        if (email.to_addresses) {
          if (Array.isArray(email.to_addresses)) {
            recipientEmail = email.to_addresses[0] || '';
          } else if (typeof email.to_addresses === 'string') {
            try {
              const parsed = JSON.parse(email.to_addresses);
              recipientEmail = Array.isArray(parsed) ? parsed[0] : email.to_addresses;
            } catch {
              recipientEmail = email.to_addresses;
            }
          }
        }

        const status = email.verdict === 'block' ? 'deleted' : 'quarantined';

        await sql`
          INSERT INTO threats (
            tenant_id,
            message_id,
            subject,
            sender_email,
            recipient_email,
            verdict,
            score,
            status,
            integration_type,
            integration_id,
            signals,
            explanation,
            quarantined_at,
            created_at
          ) VALUES (
            ${email.tenant_id},
            ${email.message_id},
            ${email.subject || '(No subject)'},
            ${email.from_address || 'unknown@unknown.com'},
            ${recipientEmail},
            ${email.verdict},
            ${email.score || 0},
            ${status},
            ${email.integration_type || 'gmail'},
            ${email.integration_id || null},
            ${JSON.stringify(email.signals || [])}::jsonb,
            ${email.explanation || null},
            ${email.created_at || new Date()},
            NOW()
          )
        `;

        inserted++;
        console.log(`[Backfill] Inserted threat for message: ${email.message_id}`);
      } catch (insertError) {
        errors++;
        console.error(`[Backfill] Failed to insert threat for ${email.message_id}:`, insertError);
      }
    }

    console.log(`[Backfill] Complete: ${inserted} inserted, ${errors} errors`);

    return NextResponse.json({
      success: true,
      found: missingThreats.length,
      inserted,
      errors,
      message: `Backfilled ${inserted} threats from email_verdicts`
    });

  } catch (error) {
    console.error('[Backfill] Error:', error);
    return NextResponse.json(
      { error: 'Failed to backfill threats', details: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    );
  }
}

// Also support GET for easy browser testing
export async function GET(request: NextRequest) {
  return POST(request);
}
