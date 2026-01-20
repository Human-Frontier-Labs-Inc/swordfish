/**
 * Comprehensive Webhook Diagnostic
 * Shows exactly why webhooks aren't working
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { nango, getNangoIntegrationKey } from '@/lib/nango/client';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const diagnostic: any = {
      tenantId,
      timestamp: new Date().toISOString(),
      steps: [],
    };

    // Step 1: Get Gmail integration
    diagnostic.steps.push('Step 1: Looking for Gmail integration...');
    const integrations = await sql`
      SELECT id, tenant_id, type, status, config, nango_connection_id, created_at, last_sync_at
      FROM integrations
      WHERE tenant_id = ${tenantId} AND type = 'gmail'
      LIMIT 1
    `;

    if (integrations.length === 0) {
      diagnostic.steps.push('❌ PROBLEM: No Gmail integration found');
      diagnostic.problem = 'NO_INTEGRATION';
      return NextResponse.json(diagnostic);
    }

    const integration = integrations[0];
    diagnostic.integration = {
      id: integration.id,
      status: integration.status,
      nango_connection_id: integration.nango_connection_id,
      config: integration.config,
      created_at: integration.created_at,
      last_sync_at: integration.last_sync_at,
    };
    diagnostic.steps.push('✅ Found Gmail integration');

    // Step 2: Check email in config
    diagnostic.steps.push('Step 2: Checking if email is in config...');
    const configEmail = integration.config?.email;
    if (!configEmail) {
      diagnostic.steps.push('❌ PROBLEM: Email NOT in config');
      diagnostic.steps.push('   Webhook searches for: config->>\'email\' = incoming_email');
      diagnostic.steps.push('   Your config: ' + JSON.stringify(integration.config));
      diagnostic.steps.push('   This is why webhook returns "No active integration found"');
      diagnostic.problem = 'EMAIL_NOT_IN_CONFIG';
      diagnostic.emailInConfig = null;
    } else {
      diagnostic.steps.push(`✅ Email in config: ${configEmail}`);
      diagnostic.emailInConfig = configEmail;
    }

    // Step 3: Check Nango connection
    diagnostic.steps.push('Step 3: Checking Nango connection...');
    if (!integration.nango_connection_id) {
      diagnostic.steps.push('❌ PROBLEM: No Nango connection ID');
      diagnostic.problem = 'NO_NANGO_CONNECTION';
      return NextResponse.json(diagnostic);
    }

    try {
      const providerKey = getNangoIntegrationKey('gmail');
      diagnostic.steps.push(`   Using provider key: ${providerKey}`);

      const connection = await nango.getConnection(providerKey, integration.nango_connection_id);

      diagnostic.nangoConnection = {
        id: connection.id,
        provider_config_key: connection.provider_config_key,
        end_user: connection.end_user,
        connection_config: connection.connection_config,
      };

      diagnostic.steps.push('✅ Nango connection found');

      // Step 4: Get email from Nango
      diagnostic.steps.push('Step 4: Getting email from Nango...');
      const nangoEmail = connection.connection_config?.email || connection.end_user?.email;

      if (!nangoEmail) {
        diagnostic.steps.push('⚠️  WARNING: No email in Nango connection');
        diagnostic.steps.push('   Checked: connection_config.email and end_user.email');
        diagnostic.emailInNango = null;
      } else {
        diagnostic.steps.push(`✅ Email in Nango: ${nangoEmail}`);
        diagnostic.emailInNango = nangoEmail;
      }

      // Step 5: Compare and diagnose
      diagnostic.steps.push('');
      diagnostic.steps.push('=== DIAGNOSIS ===');

      if (!configEmail && nangoEmail) {
        diagnostic.steps.push('❌ ROOT CAUSE: Email is in Nango but NOT in config');
        diagnostic.steps.push('   Webhook flow:');
        diagnostic.steps.push('   1. Webhook receives notification for: ' + nangoEmail);
        diagnostic.steps.push('   2. Searches: WHERE config->>\'email\' = \'' + nangoEmail + '\'');
        diagnostic.steps.push('   3. No match found (config.email is NULL)');
        diagnostic.steps.push('   4. Auto-heal SHOULD fix this but is failing');
        diagnostic.steps.push('   5. Returns "No active integration found"');
        diagnostic.steps.push('');
        diagnostic.steps.push('FIX: Update integration config with email');
        diagnostic.problem = 'EMAIL_NOT_IN_CONFIG';
        diagnostic.fix = {
          sql: `UPDATE integrations SET config = config || '{"email":"${nangoEmail}"}'::jsonb WHERE id = '${integration.id}'`,
          description: 'Add email to config so webhook can find it',
        };
      } else if (configEmail && !nangoEmail) {
        diagnostic.steps.push('⚠️  Config has email but Nango doesn\'t');
        diagnostic.steps.push('   This shouldn\'t cause webhook issues');
        diagnostic.problem = 'NANGO_MISSING_EMAIL';
      } else if (!configEmail && !nangoEmail) {
        diagnostic.steps.push('❌ NO EMAIL ANYWHERE');
        diagnostic.steps.push('   Neither config nor Nango has the email');
        diagnostic.problem = 'NO_EMAIL_FOUND';
      } else if (configEmail === nangoEmail) {
        diagnostic.steps.push('✅ Emails match! Webhook should work.');
        diagnostic.steps.push('   If webhooks still not working, check:');
        diagnostic.steps.push('   - Google Pub/Sub subscription is active');
        diagnostic.steps.push('   - Webhook endpoint is receiving notifications');
        diagnostic.steps.push('   - Check Vercel logs for webhook errors');
        diagnostic.problem = 'UNKNOWN';
      } else {
        diagnostic.steps.push('⚠️  Email mismatch:');
        diagnostic.steps.push(`   Config:  ${configEmail}`);
        diagnostic.steps.push(`   Nango:   ${nangoEmail}`);
        diagnostic.problem = 'EMAIL_MISMATCH';
      }

    } catch (error) {
      diagnostic.steps.push('❌ Failed to fetch Nango connection');
      diagnostic.steps.push('   Error: ' + (error instanceof Error ? error.message : String(error)));
      diagnostic.problem = 'NANGO_FETCH_FAILED';
      diagnostic.error = error instanceof Error ? error.message : String(error);
    }

    return NextResponse.json(diagnostic, { status: 200 });
  } catch (error) {
    console.error('Diagnostic error:', error);
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      },
      { status: 500 }
    );
  }
}
