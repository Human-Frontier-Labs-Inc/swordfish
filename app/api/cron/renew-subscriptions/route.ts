/**
 * Cron: Renew Webhook Subscriptions
 * Runs hourly to renew expiring Gmail/O365 push notification subscriptions
 */

import { NextRequest, NextResponse } from 'next/server';
import { renewExpiringSubscriptions } from '@/lib/webhooks/subscriptions';

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

export async function GET(request: NextRequest) {
  try {
    // Verify cron secret
    const authHeader = request.headers.get('authorization');
    if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    console.log('[Cron] Starting subscription renewal...');
    const startTime = Date.now();

    const result = await renewExpiringSubscriptions();

    const summary = {
      success: true,
      timestamp: new Date().toISOString(),
      duration: Date.now() - startTime,
      renewed: result.renewed,
      failed: result.failed,
      errors: result.errors.length > 0 ? result.errors : undefined,
    };

    console.log('[Cron] Subscription renewal complete:', summary);

    return NextResponse.json(summary);
  } catch (error) {
    console.error('[Cron] Subscription renewal failed:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Renewal failed',
        timestamp: new Date().toISOString(),
      },
      { status: 500 }
    );
  }
}
