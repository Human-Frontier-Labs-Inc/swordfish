/**
 * Cron: Sync Emails
 * Runs every 5 minutes to sync emails from connected providers
 */

import { NextRequest, NextResponse } from 'next/server';
import { sql } from '@/lib/db';

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

export async function GET(request: NextRequest) {
  try {
    // Verify cron secret
    const authHeader = request.headers.get('authorization');
    if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Find active integrations that need sync
    const integrations = await sql`
      SELECT
        i.id,
        i.tenant_id,
        i.type,
        i.config,
        t.name as tenant_name
      FROM integrations i
      JOIN tenants t ON i.tenant_id = t.id
      WHERE i.status = 'connected'
      AND (i.last_sync_at IS NULL OR i.last_sync_at < NOW() - INTERVAL '5 minutes')
      ORDER BY i.last_sync_at NULLS FIRST
      LIMIT 10
    `;

    let synced = 0;
    const errors: string[] = [];

    for (const integration of integrations) {
      try {
        // Update last sync attempt
        await sql`
          UPDATE integrations SET
            last_sync_at = NOW(),
            updated_at = NOW()
          WHERE id = ${integration.id}
        `;

        // TODO: Actually sync emails based on integration type
        // if (integration.type === 'o365') {
        //   await syncO365Emails(integration);
        // } else if (integration.type === 'gmail') {
        //   await syncGmailEmails(integration);
        // }

        synced++;
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Sync failed';
        errors.push(`${integration.tenant_id}: ${errorMsg}`);

        // Update integration with error
        await sql`
          UPDATE integrations SET
            error_message = ${errorMsg},
            updated_at = NOW()
          WHERE id = ${integration.id}
        `;
      }
    }

    return NextResponse.json({
      success: true,
      synced,
      total: integrations.length,
      errors: errors.length > 0 ? errors : undefined,
    });
  } catch (error) {
    console.error('Sync emails cron error:', error);
    return NextResponse.json(
      { error: 'Cron job failed' },
      { status: 500 }
    );
  }
}
