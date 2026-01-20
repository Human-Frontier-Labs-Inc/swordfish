/**
 * Force Register Gmail Push Watch (No Auth Required)
 * Immediately registers Gmail push notifications for ALL connected integrations
 * This fixes the root cause: push watch was never registered
 */

import { NextResponse } from 'next/server';
import { sql } from '@/lib/db';
import { getGmailAccessToken } from '@/lib/integrations/gmail';
import { createGmailSubscription } from '@/lib/webhooks/subscriptions';

export async function POST() {
  try {
    const result: any = {
      timestamp: new Date().toISOString(),
      steps: [],
    };

    // Get ALL Gmail integrations
    result.steps.push('Finding Gmail integrations...');
    const integrations = await sql`
      SELECT id, tenant_id, type, config, nango_connection_id, status
      FROM integrations
      WHERE type = 'gmail' AND status = 'connected'
    `;

    if (integrations.length === 0) {
      result.steps.push('❌ No Gmail integrations found');
      return NextResponse.json(result, { status: 404 });
    }

    result.steps.push(`✅ Found ${integrations.length} Gmail integration(s)`);
    result.integrations = [];

    for (const integration of integrations) {
      const intResult: any = {
        id: integration.id,
        tenant_id: integration.tenant_id,
      };

      const config = integration.config as Record<string, unknown>;

      // Check if push watch already active
      if (config.watchExpiration && new Date(config.watchExpiration as string) > new Date()) {
        intResult.status = 'already_active';
        intResult.expires_at = config.watchExpiration;
        result.integrations.push(intResult);
        continue;
      }

      // Ensure syncEnabled is true
      if (!config.syncEnabled) {
        result.steps.push(`  → Integration ${integration.id}: Enabling sync...`);
        await sql`
          UPDATE integrations
          SET config = config || ${JSON.stringify({ syncEnabled: true })}::jsonb,
              updated_at = NOW()
          WHERE id = ${integration.id}
        `;
      }

      if (!integration.nango_connection_id) {
        intResult.status = 'failed';
        intResult.reason = 'No Nango connection ID';
        result.integrations.push(intResult);
        continue;
      }

      try {
        result.steps.push(`  → Integration ${integration.id}: Getting access token...`);
        const accessToken = await getGmailAccessToken(integration.nango_connection_id);

        result.steps.push(`  → Integration ${integration.id}: Registering push watch...`);
        const subscription = await createGmailSubscription({
          integrationId: integration.id,
          tenantId: integration.tenant_id,
          accessToken,
        });

        intResult.status = 'registered';
        intResult.expires_at = subscription.expiresAt.toISOString();
        intResult.history_id = subscription.historyId;
        result.integrations.push(intResult);

        result.steps.push(`  ✅ Integration ${integration.id}: Push watch registered! Expires ${subscription.expiresAt.toISOString()}`);
      } catch (error) {
        intResult.status = 'failed';
        intResult.error = error instanceof Error ? error.message : String(error);
        result.integrations.push(intResult);
        result.steps.push(`  ❌ Integration ${integration.id}: Failed - ${intResult.error}`);
      }
    }

    const registered = result.integrations.filter((i: any) => i.status === 'registered').length;
    const alreadyActive = result.integrations.filter((i: any) => i.status === 'already_active').length;
    const failed = result.integrations.filter((i: any) => i.status === 'failed').length;

    result.summary = {
      total: integrations.length,
      registered,
      already_active: alreadyActive,
      failed,
    };

    result.steps.push('');
    result.steps.push('=== SUMMARY ===');
    result.steps.push(`Registered: ${registered}`);
    result.steps.push(`Already active: ${alreadyActive}`);
    result.steps.push(`Failed: ${failed}`);

    if (registered > 0) {
      result.steps.push('');
      result.steps.push('✅ Gmail push notifications now active!');
      result.steps.push('   Google will send instant notifications to the webhook.');
      result.steps.push('   Send a test email to verify it appears instantly (no 5-minute delay).');
    } else if (alreadyActive > 0 && failed === 0) {
      result.steps.push('');
      result.steps.push('✅ Push notifications already active for all integrations.');
      result.steps.push('   If emails still delayed, check webhook logs for errors.');
    }

    return NextResponse.json(result);
  } catch (error) {
    console.error('Push registration error:', error);
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      },
      { status: 500 }
    );
  }
}
