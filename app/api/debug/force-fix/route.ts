/**
 * Force Fix Integration (No Auth Required)
 * Manually adds email to ALL Gmail integrations
 */

import { NextRequest, NextResponse } from 'next/server';
import { sql } from '@/lib/db';
import { nango, getNangoIntegrationKey } from '@/lib/nango/client';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json().catch(() => ({}));
    const { email } = body;

    const result: any = {
      timestamp: new Date().toISOString(),
      steps: [],
    };

    // Get all Gmail integrations
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
    result.integrations_updated = [];

    for (const integration of integrations) {
      const intResult: any = {
        id: integration.id,
        tenant_id: integration.tenant_id,
      };

      // Check if email already exists
      const currentEmail = integration.config?.email;
      if (currentEmail && !email) {
        intResult.status = 'skipped';
        intResult.reason = `Email already exists: ${currentEmail}`;
        result.integrations_updated.push(intResult);
        continue;
      }

      // Get email from Nango if not provided
      let emailToUse = email;
      if (!emailToUse && integration.nango_connection_id) {
        try {
          const providerKey = getNangoIntegrationKey('gmail');
          const connection = await nango.getConnection(providerKey, integration.nango_connection_id);
          emailToUse = connection.connection_config?.email || connection.end_user?.email;

          if (emailToUse) {
            intResult.email_source = 'nango';
          }
        } catch (e) {
          intResult.nango_error = e instanceof Error ? e.message : String(e);
        }
      } else if (emailToUse) {
        intResult.email_source = 'provided';
      }

      if (!emailToUse) {
        intResult.status = 'failed';
        intResult.reason = 'No email found in Nango and none provided';
        result.integrations_updated.push(intResult);
        continue;
      }

      // Update integration
      await sql`
        UPDATE integrations
        SET config = config || ${JSON.stringify({ email: emailToUse })}::jsonb,
            updated_at = NOW()
        WHERE id = ${integration.id}
      `;

      intResult.status = 'updated';
      intResult.email = emailToUse;
      intResult.previous_email = currentEmail;
      result.integrations_updated.push(intResult);
    }

    const updated = result.integrations_updated.filter((i: any) => i.status === 'updated').length;
    const skipped = result.integrations_updated.filter((i: any) => i.status === 'skipped').length;
    const failed = result.integrations_updated.filter((i: any) => i.status === 'failed').length;

    result.summary = {
      total: integrations.length,
      updated,
      skipped,
      failed,
    };

    result.steps.push('');
    result.steps.push('=== SUMMARY ===');
    result.steps.push(`Updated: ${updated}`);
    result.steps.push(`Skipped: ${skipped}`);
    result.steps.push(`Failed: ${failed}`);

    if (updated > 0) {
      result.steps.push('');
      result.steps.push('✅ Integrations updated! Webhooks should now work instantly.');
      result.steps.push('   Send a test email to verify.');
    }

    return NextResponse.json(result);
  } catch (error) {
    console.error('Force fix error:', error);
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      },
      { status: 500 }
    );
  }
}
