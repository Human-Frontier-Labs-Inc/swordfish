/**
 * Sync Nango Connections to Database
 * This endpoint checks Nango for connections and updates the local database
 */

import { NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { NANGO_INTEGRATIONS } from '@/lib/nango/client';

interface NangoConnection {
  id: number;
  connection_id: string;
  provider_config_key: string;
  provider: string;
  end_user?: {
    id: string;
    email?: string;
  };
}

export async function POST() {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const results: Array<{ type: string; status: string; connectionId?: string; error?: string }> = [];

    // Fetch all connections from Nango API directly
    const nangoResponse = await fetch('https://api.nango.dev/connections', {
      headers: {
        'Authorization': `Bearer ${process.env.NANGO_SECRET_KEY}`,
      },
    });

    if (!nangoResponse.ok) {
      throw new Error(`Nango API error: ${nangoResponse.status}`);
    }

    const { connections } = await nangoResponse.json() as { connections: NangoConnection[] };

    // Filter connections for this tenant (end_user.id matches tenantId)
    const tenantConnections = connections.filter(
      (c) => c.end_user?.id === tenantId
    );

    // Check each integration type
    for (const [integrationType, providerConfigKey] of Object.entries(NANGO_INTEGRATIONS)) {
      try {
        // Find connection matching this provider
        const connection = tenantConnections.find(
          (c) => c.provider_config_key === providerConfigKey
        );

        if (connection) {
          // Update the integrations table with the nango_connection_id
          await sql`
            INSERT INTO integrations (tenant_id, type, nango_connection_id, status, config, created_at, updated_at)
            VALUES (
              ${tenantId},
              ${integrationType},
              ${connection.connection_id},
              'connected',
              '{"syncEnabled": true}'::jsonb,
              NOW(),
              NOW()
            )
            ON CONFLICT (tenant_id, type)
            DO UPDATE SET
              nango_connection_id = ${connection.connection_id},
              status = 'connected',
              config = integrations.config || '{"syncEnabled": true}'::jsonb,
              error_message = NULL,
              updated_at = NOW()
          `;

          results.push({
            type: integrationType,
            status: 'synced',
            connectionId: connection.connection_id,
          });
        } else {
          results.push({
            type: integrationType,
            status: 'no_connection',
          });
        }
      } catch (err) {
        console.error(`Error syncing ${integrationType}:`, err);
        results.push({
          type: integrationType,
          status: 'error',
          error: err instanceof Error ? err.message : 'Unknown error',
        });
      }
    }

    return NextResponse.json({
      success: true,
      tenantId,
      totalNangoConnections: connections.length,
      tenantConnections: tenantConnections.length,
      results,
    });
  } catch (error) {
    console.error('Sync Nango connections error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to sync Nango connections' },
      { status: 500 }
    );
  }
}
