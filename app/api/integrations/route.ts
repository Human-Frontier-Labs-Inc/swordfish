/**
 * Integrations List API
 * GET - List all integrations for tenant
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    const integrations = await sql`
      SELECT
        id,
        type,
        status,
        config->>'email' as email,
        config->>'displayName' as display_name,
        config->>'syncEnabled' as sync_enabled,
        last_sync_at,
        error_message,
        created_at,
        updated_at
      FROM integrations
      WHERE tenant_id = ${tenantId}
      ORDER BY created_at DESC
    `;

    // Map to frontend format
    const formatted = integrations.map((i: Record<string, unknown>) => ({
      id: i.id,
      type: i.type,
      status: i.status,
      email: i.email,
      displayName: i.display_name,
      syncEnabled: i.sync_enabled === 'true',
      lastSyncAt: i.last_sync_at,
      errorMessage: i.error_message,
      createdAt: i.created_at,
    }));

    return NextResponse.json({ integrations: formatted });
  } catch (error) {
    console.error('List integrations error:', error);
    return NextResponse.json({ integrations: [] });
  }
}
