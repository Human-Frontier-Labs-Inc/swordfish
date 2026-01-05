/**
 * Webhook Health and Metrics Endpoint
 * Provides status and metrics for webhook processing
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getQueueStats, getDeadLetterJobs } from '@/lib/webhooks/queue';
import { getSubscriptions, renewExpiringSubscriptions } from '@/lib/webhooks/subscriptions';
import { sql } from '@/lib/db';

export const dynamic = 'force-dynamic';

interface WebhookMetrics {
  queue: {
    pending: number;
    processing: number;
    completed: number;
    failed: number;
    dead: number;
    avgProcessingTimeMs: number;
  };
  subscriptions: {
    total: number;
    active: number;
    expired: number;
    byType: {
      gmail: number;
      o365: number;
    };
  };
  recentActivity: {
    last24h: number;
    last1h: number;
    threatsFound: number;
  };
  health: {
    status: 'healthy' | 'degraded' | 'unhealthy';
    issues: string[];
    lastCheck: string;
  };
}

/**
 * GET - Get webhook health and metrics
 */
export async function GET(request: NextRequest) {
  const { userId, orgId } = await auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    // Get tenant ID from org or user
    const tenantId = orgId || userId;

    // Get queue stats
    const queueStats = await getQueueStats();

    // Get subscriptions
    const subscriptions = await getSubscriptions(tenantId);

    // Get recent activity from database
    const recentActivity = await sql`
      SELECT
        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as last_24h,
        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 hour') as last_1h,
        COUNT(*) FILTER (WHERE verdict != 'pass' AND created_at > NOW() - INTERVAL '24 hours') as threats_found
      FROM email_verdicts
      WHERE tenant_id = ${tenantId}
    `.catch(() => [{ last_24h: 0, last_1h: 0, threats_found: 0 }]);

    const activity = recentActivity[0] || { last_24h: 0, last_1h: 0, threats_found: 0 };

    // Calculate subscription stats
    const activeSubscriptions = subscriptions.filter(s => s.status === 'active');
    const expiredSubscriptions = subscriptions.filter(s => s.status === 'expired');
    const gmailSubscriptions = subscriptions.filter(s => s.type === 'gmail');
    const o365Subscriptions = subscriptions.filter(s => s.type === 'o365');

    // Determine health status
    const issues: string[] = [];

    if (queueStats.dead > 0) {
      issues.push(`${queueStats.dead} jobs in dead letter queue`);
    }

    if (expiredSubscriptions.length > 0) {
      issues.push(`${expiredSubscriptions.length} expired subscriptions`);
    }

    if (queueStats.avgProcessingTimeMs > 5000) {
      issues.push(`Average processing time ${queueStats.avgProcessingTimeMs}ms exceeds 5s SLA`);
    }

    const healthStatus = issues.length === 0
      ? 'healthy'
      : issues.length <= 2
        ? 'degraded'
        : 'unhealthy';

    const metrics: WebhookMetrics = {
      queue: queueStats,
      subscriptions: {
        total: subscriptions.length,
        active: activeSubscriptions.length,
        expired: expiredSubscriptions.length,
        byType: {
          gmail: gmailSubscriptions.length,
          o365: o365Subscriptions.length,
        },
      },
      recentActivity: {
        last24h: parseInt(activity.last_24h as string) || 0,
        last1h: parseInt(activity.last_1h as string) || 0,
        threatsFound: parseInt(activity.threats_found as string) || 0,
      },
      health: {
        status: healthStatus,
        issues,
        lastCheck: new Date().toISOString(),
      },
    };

    return NextResponse.json(metrics);
  } catch (error) {
    console.error('Webhook health check error:', error);
    return NextResponse.json(
      { error: 'Failed to get webhook metrics' },
      { status: 500 }
    );
  }
}

/**
 * POST - Trigger subscription renewal or retry dead letters
 */
export async function POST(request: NextRequest) {
  const { userId, orgId } = await auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const body = await request.json();
    const { action } = body;

    switch (action) {
      case 'renew-subscriptions': {
        const result = await renewExpiringSubscriptions();
        return NextResponse.json({
          success: true,
          renewed: result.renewed,
          failed: result.failed,
          errors: result.errors,
        });
      }

      case 'retry-dead-letters': {
        const deadJobs = await getDeadLetterJobs(10);
        const { retryJob } = await import('@/lib/webhooks/queue');

        let retried = 0;
        for (const job of deadJobs) {
          const success = await retryJob(job.id);
          if (success) retried++;
        }

        return NextResponse.json({
          success: true,
          retried,
          total: deadJobs.length,
        });
      }

      default:
        return NextResponse.json(
          { error: `Unknown action: ${action}` },
          { status: 400 }
        );
    }
  } catch (error) {
    console.error('Webhook action error:', error);
    return NextResponse.json(
      { error: 'Action failed' },
      { status: 500 }
    );
  }
}
