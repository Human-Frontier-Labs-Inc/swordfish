/**
 * Cron Job: Email Sync
 * Runs periodically to sync emails from all connected integrations
 * Schedule: Every 5 minutes (configured in vercel.json)
 */

import { NextRequest, NextResponse } from 'next/server';
import { runFullSync } from '@/lib/workers/email-sync';

// Vercel cron secret for authentication
const CRON_SECRET = process.env.CRON_SECRET;

export const maxDuration = 60; // Allow full 60s for sync
export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  try {
    // Verify cron secret (Vercel sends this header)
    const authHeader = request.headers.get('authorization');

    // In production, verify the secret
    if (process.env.NODE_ENV === 'production' && CRON_SECRET) {
      if (authHeader !== `Bearer ${CRON_SECRET}`) {
        console.warn('[Cron Sync] Unauthorized request');
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      }
    }

    console.log('[Cron Sync] Starting scheduled email sync...');
    const startTime = Date.now();

    const results = await runFullSync();

    const summary = {
      success: true,
      timestamp: new Date().toISOString(),
      duration: Date.now() - startTime,
      integrations: results.length,
      totalProcessed: results.reduce((sum, r) => sum + r.emailsProcessed, 0),
      totalSkipped: results.reduce((sum, r) => sum + r.emailsSkipped, 0),
      totalThreats: results.reduce((sum, r) => sum + r.threatsFound, 0),
      totalErrors: results.reduce((sum, r) => sum + r.errors.length, 0),
      anyTimedOut: results.some(r => r.timedOut),
    };

    console.log('[Cron Sync] Complete:', summary);

    return NextResponse.json(summary);
  } catch (error) {
    console.error('[Cron Sync] Failed:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Sync failed',
        timestamp: new Date().toISOString(),
      },
      { status: 500 }
    );
  }
}
