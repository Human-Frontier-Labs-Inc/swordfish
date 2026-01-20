/**
 * Debug: Fix Integration Email
 * Temporary endpoint to manually add email to integration config
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { nango } from '@/lib/nango/client';

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    // Get Gmail integration
    const integration = await sql`
      SELECT id, tenant_id, type, config, nango_connection_id
      FROM integrations
      WHERE tenant_id = ${tenantId} AND type = 'gmail'
      LIMIT 1
    `;

    if (integration.length === 0) {
      return NextResponse.json({ error: 'No Gmail integration found' });
    }

    const int = integration[0];

    // Check if email already exists
    const currentConfig = int.config as Record<string, unknown>;
    if (currentConfig?.email) {
      return NextResponse.json({
        message: 'Email already exists in config',
        email: currentConfig.email,
      });
    }

    // Try to get email from Nango connection
    if (!int.nango_connection_id) {
      return NextResponse.json({ error: 'No Nango connection ID found' });
    }

    try {
      const connection = await nango.getConnection('google-mail', int.nango_connection_id);

      // Try multiple ways to get the email
      const email = connection.connection_config?.email ||
                   connection.end_user?.email;

      if (!email) {
        return NextResponse.json({
          error: 'Could not find email in Nango connection',
          nangoData: {
            connection_config: connection.connection_config,
            end_user: connection.end_user,
          },
        });
      }

      // Update the integration with the email
      await sql`
        UPDATE integrations
        SET config = config || ${JSON.stringify({ email })}::jsonb,
            updated_at = NOW()
        WHERE id = ${int.id}
      `;

      return NextResponse.json({
        success: true,
        message: 'Integration updated with email',
        email,
        integration_id: int.id,
      });
    } catch (e) {
      return NextResponse.json({
        error: 'Failed to fetch Nango connection',
        details: e instanceof Error ? e.message : 'Unknown error',
      }, { status: 500 });
    }
  } catch (error) {
    console.error('Fix endpoint error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    );
  }
}
