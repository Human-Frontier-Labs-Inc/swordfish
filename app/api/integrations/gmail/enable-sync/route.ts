/**
 * Enable Sync for Gmail Integration
 * PATCH - Enable syncEnabled flag and register push watch
 */

import { NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { getGmailAccessToken } from '@/lib/integrations/gmail';
import { createGmailSubscription } from '@/lib/webhooks/subscriptions';

export async function PATCH() {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    // Get Gmail integration
    const [integration] = await sql`
      SELECT id, tenant_id, config, nango_connection_id, status
      FROM integrations
      WHERE tenant_id = ${tenantId} AND type = 'gmail'
    `;

    if (!integration) {
      return NextResponse.json({ error: 'No Gmail integration found' }, { status: 404 });
    }

    if (integration.status !== 'connected') {
      return NextResponse.json({ error: 'Integration not connected' }, { status: 400 });
    }

    if (!integration.nango_connection_id) {
      return NextResponse.json({ error: 'No Nango connection ID' }, { status: 400 });
    }

    const result: any = {
      timestamp: new Date().toISOString(),
      steps: [],
    };

    // Step 1: Enable sync
    result.steps.push('Enabling sync...');
    await sql`
      UPDATE integrations
      SET config = config || ${JSON.stringify({ syncEnabled: true })}::jsonb,
          updated_at = NOW()
      WHERE id = ${integration.id}
    `;
    result.steps.push('✅ Sync enabled');

    // Step 2: Register Gmail push watch
    const config = integration.config as Record<string, unknown>;
    const watchExpiration = config.watchExpiration as string | null;
    const isWatchActive = watchExpiration && new Date(watchExpiration) > new Date();

    if (isWatchActive) {
      result.steps.push(`✅ Push watch already active (expires ${watchExpiration})`);
      result.pushWatchStatus = 'already_active';
      result.expiresAt = watchExpiration;
    } else {
      result.steps.push('Registering Gmail push watch...');
      try {
        const accessToken = await getGmailAccessToken(integration.nango_connection_id);
        const subscription = await createGmailSubscription({
          integrationId: integration.id,
          tenantId: integration.tenant_id,
          accessToken,
        });

        result.steps.push(`✅ Push watch registered! Expires ${subscription.expiresAt.toISOString()}`);
        result.pushWatchStatus = 'registered';
        result.expiresAt = subscription.expiresAt.toISOString();
        result.historyId = subscription.historyId;
      } catch (error) {
        result.steps.push(`❌ Failed to register push watch: ${error instanceof Error ? error.message : String(error)}`);
        result.pushWatchStatus = 'failed';
        result.pushWatchError = error instanceof Error ? error.message : String(error);
      }
    }

    result.summary = {
      syncEnabled: true,
      pushWatchStatus: result.pushWatchStatus,
    };

    if (result.pushWatchStatus === 'registered' || result.pushWatchStatus === 'already_active') {
      result.steps.push('');
      result.steps.push('✅ Gmail instant notifications are now active!');
      result.steps.push('   Google will send push notifications to the webhook.');
      result.steps.push('   Send a test email to verify instant processing (no 5-minute delay).');
    }

    return NextResponse.json(result);
  } catch (error) {
    console.error('Enable sync error:', error);
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      },
      { status: 500 }
    );
  }
}
