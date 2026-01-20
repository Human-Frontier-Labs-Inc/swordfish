/**
 * Auto-Fix Webhook Issues
 * Automatically fixes the email config problem
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { nango, getNangoIntegrationKey } from '@/lib/nango/client';

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const result: any = {
      tenantId,
      timestamp: new Date().toISOString(),
      steps: [],
    };

    // Get Gmail integration
    result.steps.push('Finding Gmail integration...');
    const integrations = await sql`
      SELECT id, tenant_id, type, config, nango_connection_id, status
      FROM integrations
      WHERE tenant_id = ${tenantId} AND type = 'gmail'
      LIMIT 1
    `;

    if (integrations.length === 0) {
      result.steps.push('❌ No Gmail integration found');
      return NextResponse.json(result, { status: 404 });
    }

    const integration = integrations[0];
    result.integrationId = integration.id;
    result.steps.push(`✅ Found integration ${integration.id}`);

    // Check if email already exists
    const currentEmail = integration.config?.email;
    if (currentEmail) {
      result.steps.push(`ℹ️  Email already exists: ${currentEmail}`);
      result.steps.push('No fix needed - webhook should work');
      result.alreadyFixed = true;
      result.email = currentEmail;
      return NextResponse.json(result);
    }

    // Get email from Nango
    if (!integration.nango_connection_id) {
      result.steps.push('❌ No Nango connection ID');
      return NextResponse.json(result, { status: 400 });
    }

    result.steps.push('Fetching email from Nango...');
    try {
      const providerKey = getNangoIntegrationKey('gmail');
      const connection = await nango.getConnection(providerKey, integration.nango_connection_id);

      const email = connection.connection_config?.email || connection.end_user?.email;

      if (!email) {
        result.steps.push('❌ No email found in Nango connection');
        result.steps.push('   Checked: connection_config.email and end_user.email');
        return NextResponse.json(result, { status: 400 });
      }

      result.steps.push(`✅ Found email: ${email}`);

      // Update integration
      result.steps.push('Updating integration config...');
      await sql`
        UPDATE integrations
        SET config = config || ${JSON.stringify({ email })}::jsonb,
            updated_at = NOW()
        WHERE id = ${integration.id}
      `;

      result.steps.push('✅ Integration updated successfully!');
      result.steps.push('');
      result.steps.push('Webhook should now work instantly.');
      result.steps.push('Send a test email to verify.');

      result.fixed = true;
      result.email = email;

      return NextResponse.json(result);
    } catch (error) {
      result.steps.push('❌ Failed to fetch from Nango');
      result.steps.push('   Error: ' + (error instanceof Error ? error.message : String(error)));
      result.error = error instanceof Error ? error.message : String(error);
      return NextResponse.json(result, { status: 500 });
    }
  } catch (error) {
    console.error('Fix error:', error);
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}
