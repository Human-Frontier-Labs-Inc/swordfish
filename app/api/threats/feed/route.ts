/**
 * Real-time Threat Feed API
 * GET - Stream threat events via SSE or poll for recent threats
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

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
  let threats;

  if (since) {
    threats = await sql`
      SELECT
        t.id,
        t.message_id,
        t.subject,
        t.sender_email,
        t.sender_name,
        t.recipient_email,
        t.threat_type,
        t.verdict,
        t.score,
        t.status,
        t.integration_type,
        t.quarantined_at,
        t.explanation,
        COALESCE(jsonb_array_length(t.signals), 0) as signal_count
      FROM threats t
      WHERE t.tenant_id = ${tenantId}
      AND t.quarantined_at > ${since}
      ORDER BY t.quarantined_at DESC
      LIMIT ${limit}
    `;
  } else {
    threats = await sql`
      SELECT
        t.id,
        t.message_id,
        t.subject,
        t.sender_email,
        t.sender_name,
        t.recipient_email,
        t.threat_type,
        t.verdict,
        t.score,
        t.status,
        t.integration_type,
        t.quarantined_at,
        t.explanation,
        COALESCE(jsonb_array_length(t.signals), 0) as signal_count
      FROM threats t
      WHERE t.tenant_id = ${tenantId}
      ORDER BY t.quarantined_at DESC
      LIMIT ${limit}
    `;
  }

  return threats;
}

async function getLiveStats(tenantId: string) {
  const stats = await sql`
    SELECT
      COUNT(*) FILTER (WHERE status = 'quarantined')::int as quarantined,
      COUNT(*) FILTER (WHERE status = 'released')::int as released,
      COUNT(*) FILTER (WHERE status = 'deleted')::int as deleted,
      COUNT(*) FILTER (WHERE quarantined_at >= NOW() - INTERVAL '24 hours')::int as last_24h,
      COUNT(*) FILTER (WHERE quarantined_at >= NOW() - INTERVAL '1 hour')::int as last_hour,
      MAX(quarantined_at) as latest_threat,
      ROUND(AVG(score)::numeric, 0) as avg_score
    FROM threats
    WHERE tenant_id = ${tenantId}
  `;

  // Get verdict processing stats from last hour
  const processing = await sql`
    SELECT
      COUNT(*)::int as total_processed,
      COUNT(*) FILTER (WHERE verdict = 'pass')::int as passed,
      COUNT(*) FILTER (WHERE verdict IN ('quarantine', 'block'))::int as blocked,
      ROUND(AVG(processing_time_ms)::numeric, 0) as avg_latency
    FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND created_at >= NOW() - INTERVAL '1 hour'
  `;

  const s = stats[0] || {};
  const p = processing[0] || {};

  return {
    threats: {
      quarantined: s.quarantined || 0,
      released: s.released || 0,
      deleted: s.deleted || 0,
      last24h: s.last_24h || 0,
      lastHour: s.last_hour || 0,
      latestThreat: s.latest_threat,
      avgScore: s.avg_score || 0,
    },
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
