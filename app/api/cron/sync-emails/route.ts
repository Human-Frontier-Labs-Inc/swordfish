/**
 * Cron: Sync Emails
 * Runs every 5 minutes to sync emails from connected providers
 */

import { NextRequest, NextResponse } from 'next/server';
import { sql } from '@/lib/db';
import { syncIntegration, type SyncResult } from '@/lib/workers/email-sync';

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

// Cron-specific configuration
const CRON_TIMEOUT_MS = 55000; // Exit before Vercel's 60s limit
const MAX_INTEGRATIONS_PER_RUN = 5; // Process fewer integrations per cron run

interface IntegrationRecord {
  id: string;
  tenant_id: string;
  type: string;
  config: Record<string, unknown>;
  nango_connection_id: string | null;
  last_sync_at: Date | null;
  tenant_name: string;
}

export async function GET(request: NextRequest) {
  const startTime = Date.now();

  try {
    // Verify cron secret
    const authHeader = request.headers.get('authorization');
    if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    console.log('[Cron] Starting email sync job...');

    // Find active integrations that need sync
    // Only get integrations where syncEnabled is true in config
    // Use LEFT JOIN matching tenant_id against both clerk_org_id and id::text
    // Include integrations missing nango_connection_id for auto-healing
    const integrations = await sql`
      SELECT
        i.id,
        i.tenant_id::text as tenant_id,
        i.type,
        i.config,
        i.nango_connection_id,
        i.last_sync_at,
        COALESCE(t.name, i.tenant_id::text) as tenant_name
      FROM integrations i
      LEFT JOIN tenants t ON i.tenant_id::text = t.clerk_org_id OR i.tenant_id::text = t.id::text
      WHERE i.status = 'connected'
      AND (i.config->>'syncEnabled')::boolean = true
      AND (i.last_sync_at IS NULL OR i.last_sync_at < NOW() - INTERVAL '5 minutes')
      ORDER BY i.last_sync_at NULLS FIRST
      LIMIT ${MAX_INTEGRATIONS_PER_RUN}
    ` as IntegrationRecord[];

    // Auto-heal integrations missing Nango connection IDs
    const integrationsToHeal = integrations.filter(i => !i.nango_connection_id);
    if (integrationsToHeal.length > 0) {
      console.log(`[Cron] Auto-healing ${integrationsToHeal.length} integrations missing Nango connection...`);
      try {
        const nangoResponse = await fetch('https://api.nango.dev/connections', {
          headers: {
            'Authorization': `Bearer ${process.env.NANGO_SECRET_KEY}`,
          },
        });

        if (nangoResponse.ok) {
          const { connections } = await nangoResponse.json() as {
            connections: Array<{
              connection_id: string;
              provider_config_key: string;
              end_user?: { id: string };
            }>
          };

          for (const integration of integrationsToHeal) {
            const providerKey = integration.type === 'gmail' ? 'google-mail' : integration.type === 'outlook' ? 'microsoft-365' : null;
            if (!providerKey) continue;

            const match = connections.find(
              c => c.end_user?.id === integration.tenant_id && c.provider_config_key === providerKey
            );

            if (match) {
              await sql`
                UPDATE integrations
                SET nango_connection_id = ${match.connection_id},
                    updated_at = NOW()
                WHERE id = ${integration.id}
              `;
              integration.nango_connection_id = match.connection_id;
              console.log(`[Cron] Auto-healed integration ${integration.id} with Nango connection ${match.connection_id}`);
            }
          }
        }
      } catch (healError) {
        console.error('[Cron] Auto-heal error:', healError);
      }
    }

    // Filter to only integrations that now have Nango connections
    const validIntegrations = integrations.filter(i => i.nango_connection_id);

    console.log(`[Cron] Found ${validIntegrations.length} integrations to sync (${integrationsToHeal.length} auto-healed)`);

    const results: SyncResult[] = [];
    const errors: string[] = [];
    let timedOut = false;

    for (const integration of validIntegrations) {
      // Check if we're running out of time
      if (Date.now() - startTime > CRON_TIMEOUT_MS) {
        console.log('[Cron] Timeout approaching, stopping to avoid Vercel timeout');
        timedOut = true;
        break;
      }

      try {
        console.log(`[Cron] Syncing ${integration.type} for tenant ${integration.tenant_id}`);

        // Actually sync emails using the worker
        const result = await syncIntegration({
          id: integration.id,
          tenant_id: integration.tenant_id,
          type: integration.type,
          config: integration.config,
          nango_connection_id: integration.nango_connection_id,
          last_sync_at: integration.last_sync_at,
        });

        results.push(result);

        if (result.errors.length > 0) {
          errors.push(...result.errors.map(e => `${integration.tenant_id}: ${e}`));
        }

        console.log(`[Cron] Completed ${integration.type} sync: ${result.emailsProcessed} emails, ${result.threatsFound} threats`);
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Sync failed';
        errors.push(`${integration.tenant_id}: ${errorMsg}`);
        console.error(`[Cron] Sync failed for ${integration.tenant_id}:`, error);

        // Update integration with error status
        await sql`
          UPDATE integrations SET
            error_message = ${errorMsg},
            updated_at = NOW()
          WHERE id = ${integration.id}
        `;
      }
    }

    const totalDuration = Date.now() - startTime;
    const summary = {
      success: true,
      synced: results.length,
      total: validIntegrations.length,
      autoHealed: integrationsToHeal.length,
      totalEmailsProcessed: results.reduce((sum, r) => sum + r.emailsProcessed, 0),
      totalThreatsFound: results.reduce((sum, r) => sum + r.threatsFound, 0),
      duration: totalDuration,
      timedOut,
      errors: errors.length > 0 ? errors : undefined,
    };

    console.log(`[Cron] Sync complete:`, summary);

    return NextResponse.json(summary);
  } catch (error) {
    console.error('[Cron] Sync emails cron error:', error);
    return NextResponse.json(
      { error: 'Cron job failed', details: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    );
  }
}
