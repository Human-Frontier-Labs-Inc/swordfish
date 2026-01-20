/**
 * Debug: Check Integration Status
 * Temporary endpoint to diagnose webhook issues
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { nango } from '@/lib/nango/client';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    // Get Gmail integration
    const integration = await sql`
      SELECT id, tenant_id, type, status, config, nango_connection_id, created_at
      FROM integrations
      WHERE tenant_id = ${tenantId} AND type = 'gmail'
      LIMIT 1
    `;

    if (integration.length === 0) {
      return NextResponse.json({ error: 'No Gmail integration found' });
    }

    const int = integration[0];

    // Try to get Nango connection details
    let nangoDetails = null;
    if (int.nango_connection_id) {
      try {
        const connection = await nango.getConnection('google-mail', int.nango_connection_id);
        nangoDetails = {
          connection_id: connection.id,
          provider_config_key: connection.provider_config_key,
          end_user: connection.end_user,
          connection_config: connection.connection_config,
        };
      } catch (e) {
        nangoDetails = { error: e instanceof Error ? e.message : 'Failed to fetch' };
      }
    }

    return NextResponse.json({
      integration: {
        id: int.id,
        tenant_id: int.tenant_id,
        type: int.type,
        status: int.status,
        config: int.config,
        nango_connection_id: int.nango_connection_id,
        created_at: int.created_at,
      },
      nangoConnection: nangoDetails,
    });
  } catch (error) {
    console.error('Debug endpoint error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    );
  }
}
