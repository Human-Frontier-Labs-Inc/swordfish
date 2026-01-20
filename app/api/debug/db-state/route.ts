/**
 * Database State Check (No Auth Required)
 * Shows current state of integrations for debugging
 */

import { NextResponse } from 'next/server';
import { sql } from '@/lib/db';

export async function GET() {
  try {
    // Get ALL Gmail integrations (no tenant filter)
    const integrations = await sql`
      SELECT
        id,
        tenant_id,
        type,
        status,
        config,
        nango_connection_id,
        created_at,
        last_sync_at,
        updated_at
      FROM integrations
      WHERE type = 'gmail'
      ORDER BY created_at DESC
    `;

    const problems: string[] = [];

    const result = {
      timestamp: new Date().toISOString(),
      total_gmail_integrations: integrations.length,
      integrations: integrations.map((int) => ({
        id: int.id,
        tenant_id: int.tenant_id,
        status: int.status,
        has_nango_connection: !!int.nango_connection_id,
        nango_connection_id: int.nango_connection_id,
        config_email: int.config?.email || null,
        config_sync_enabled: int.config?.syncEnabled || false,
        full_config: int.config,
        created_at: int.created_at,
        last_sync_at: int.last_sync_at,
        updated_at: int.updated_at,
      })),
      problems: problems as string[],
      diagnosis: '' as string,
    };

    // Add diagnosis

    integrations.forEach((int, i) => {
      if (!int.nango_connection_id) {
        problems.push(`Integration ${i + 1}: No Nango connection ID`);
      }
      if (!int.config?.email) {
        problems.push(`Integration ${i + 1}: No email in config (webhook will fail to match)`);
      }
      if (int.status !== 'connected') {
        problems.push(`Integration ${i + 1}: Status is '${int.status}' (should be 'connected')`);
      }
    });

    result.problems = problems;

    if (problems.length === 0) {
      result.diagnosis = 'All integrations look OK. If webhooks still failing, check Vercel logs for errors.';
    } else {
      result.diagnosis = `Found ${problems.length} issue(s). Primary issue: email not in config.`;
    }

    return NextResponse.json(result, { status: 200 });
  } catch (error) {
    console.error('DB state check error:', error);
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      },
      { status: 500 }
    );
  }
}
