/**
 * Real-time Threat Feed API
 * GET - Stream threat events via SSE or poll for recent threats
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { getRecentManagedThreats, getThreatFeedStats } from '@/lib/detection/storage';

/**
 * GET - Get recent threats for live feed or stream
 */
export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const searchParams = request.nextUrl.searchParams;
    const mode = searchParams.get('mode') || 'poll';
    const since = searchParams.get('since'); // ISO timestamp
    const limit = Math.min(parseInt(searchParams.get('limit') || '20'), 50);

    if (mode === 'stream') {
      // SSE streaming mode
      return createSSEStream(tenantId, since);
    }

    // Polling mode - get recent threats
    const threats = await getRecentThreats(tenantId, since, limit);
    const stats = await getLiveStats(tenantId);

    return NextResponse.json({
      threats,
      stats,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Threat feed error:', error);
    return NextResponse.json(
      { error: 'Feed failed' },
      { status: 500 }
    );
  }
}

async function getRecentThreats(tenantId: string, since: string | null, limit: number) {
  // Sourced from email_verdicts via lib/detection/storage so the feed agrees
  // with the threat-management pages (the legacy threats table is not populated
  // by the live detection pipeline).
  return getRecentManagedThreats(tenantId, since, limit);
}

async function getLiveStats(tenantId: string) {
  // Threat counts come from email_verdicts via getThreatFeedStats (status is
  // derived there, not native), so the heartbeat agrees with the management
  // pages. Processing stats already read email_verdicts.
  const [threatStats, processing] = await Promise.all([
    getThreatFeedStats(tenantId),
    sql`
      SELECT
        COUNT(*)::int as total_processed,
        COUNT(*) FILTER (WHERE verdict = 'pass')::int as passed,
        COUNT(*) FILTER (WHERE verdict IN ('quarantine', 'block'))::int as blocked,
        ROUND(AVG(processing_time_ms)::numeric, 0) as avg_latency
      FROM email_verdicts
      WHERE tenant_id = ${tenantId}
      AND created_at >= NOW() - INTERVAL '1 hour'
    `,
  ]);

  const p = processing[0] || {};

  return {
    threats: threatStats,
    processing: {
      totalLastHour: p.total_processed || 0,
      passed: p.passed || 0,
      blocked: p.blocked || 0,
      avgLatencyMs: p.avg_latency || 0,
    },
  };
}

function createSSEStream(tenantId: string, since: string | null) {
  const encoder = new TextEncoder();
  let lastTimestamp = since || new Date().toISOString();
  let intervalId: NodeJS.Timeout;

  const stream = new ReadableStream({
    async start(controller) {
      // Send initial connection event
      controller.enqueue(encoder.encode(`event: connected\ndata: ${JSON.stringify({ tenantId, timestamp: lastTimestamp })}\n\n`));

      // Poll for new threats every 5 seconds
      const pollForThreats = async () => {
        try {
          const threats = await getRecentThreats(tenantId, lastTimestamp, 10);

          if (threats.length > 0) {
            // Update last timestamp
            lastTimestamp = (threats[0].quarantined_at as Date).toISOString();

            // Send each threat as an event
            for (const threat of threats) {
              const event = {
                type: 'threat',
                data: threat,
                timestamp: new Date().toISOString(),
              };
              controller.enqueue(encoder.encode(`event: threat\ndata: ${JSON.stringify(event)}\n\n`));
            }
          }

          // Send heartbeat with stats
          const stats = await getLiveStats(tenantId);
          controller.enqueue(encoder.encode(`event: heartbeat\ndata: ${JSON.stringify({ stats, timestamp: new Date().toISOString() })}\n\n`));
        } catch (error) {
          console.error('SSE poll error:', error);
          controller.enqueue(encoder.encode(`event: error\ndata: ${JSON.stringify({ error: 'Poll failed' })}\n\n`));
        }
      };

      // Initial poll
      await pollForThreats();

      // Set up interval
      intervalId = setInterval(pollForThreats, 5000);
    },
    cancel() {
      if (intervalId) {
        clearInterval(intervalId);
      }
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    },
  });
}
