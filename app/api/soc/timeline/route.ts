/**
 * SOC Timeline API
 *
 * Fetch real-time threat events for SOC dashboard
 */

import { NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function GET() {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || userId;

    // Fetch recent events from threats and audit logs
    const threats = await sql`
      SELECT
        t.id,
        t.message_id,
        t.subject,
        t.from_address,
        t.verdict,
        t.confidence,
        t.ml_classification,
        t.signals,
        t.action_taken,
        t.action_taken_at,
        t.created_at
      FROM threats t
      WHERE t.tenant_id = ${tenantId}
        AND t.created_at > NOW() - INTERVAL '24 hours'
      ORDER BY t.created_at DESC
      LIMIT 100
    `;

    // Transform to timeline events
    const events = threats.map((t: Record<string, unknown>) => {
      const severity = getSeverity(t.confidence as number);
      return {
        id: `threat_${t.id}`,
        timestamp: t.created_at,
        type: 'threat_detected',
        severity,
        title: getThreatTitle(t.ml_classification as string, t.verdict as string),
        description: (t.subject as string) || 'No subject',
        threatId: t.id,
        metadata: {
          from: t.from_address,
          verdict: t.verdict,
          confidence: t.confidence,
          signals: Array.isArray(t.signals) ? (t.signals as string[]).length : 0,
        },
      };
    });

    // Add action events
    const actionEvents = threats
      .filter((t: Record<string, unknown>) => t.action_taken && t.action_taken_at)
      .map((t: Record<string, unknown>) => ({
        id: `action_${t.id}`,
        timestamp: t.action_taken_at,
        type: t.action_taken === 'quarantine' ? 'quarantine' : 'action',
        severity: 'info' as const,
        title: `Email ${t.action_taken}`,
        description: (t.subject as string) || 'No subject',
        threatId: t.id,
        metadata: {
          action: t.action_taken,
        },
      }));

    // Combine and sort all events
    const allEvents = [...events, ...actionEvents].sort(
      (a, b) => new Date(b.timestamp as string).getTime() - new Date(a.timestamp as string).getTime()
    );

    // Calculate stats
    const stats = {
      totalThreats: threats.length,
      criticalThreats: threats.filter((t: Record<string, unknown>) => (t.confidence as number) >= 90).length,
      pendingReview: threats.filter((t: Record<string, unknown>) => t.verdict === 'review').length,
      avgResponseTime: calculateAvgResponseTime(threats as Array<Record<string, unknown>>),
    };

    return NextResponse.json({
      events: allEvents,
      stats,
    });
  } catch (error) {
    console.error('SOC timeline error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch timeline' },
      { status: 500 }
    );
  }
}

function getSeverity(confidence: number): 'critical' | 'high' | 'medium' | 'low' {
  if (confidence >= 90) return 'critical';
  if (confidence >= 70) return 'high';
  if (confidence >= 50) return 'medium';
  return 'low';
}

function getThreatTitle(classification: string, verdict: string): string {
  const classMap: Record<string, string> = {
    phishing: 'Phishing Attempt Detected',
    malware: 'Malware Detected',
    bec: 'BEC Attack Detected',
    spam: 'Spam Detected',
    suspicious: 'Suspicious Email',
  };
  return classMap[classification] || `Threat Detected (${verdict})`;
}

function calculateAvgResponseTime(threats: Array<Record<string, unknown>>): string {
  const responseTimes = threats
    .filter((t) => t.action_taken_at && t.created_at)
    .map((t) => {
      const created = new Date(t.created_at as string).getTime();
      const actioned = new Date(t.action_taken_at as string).getTime();
      return actioned - created;
    });

  if (responseTimes.length === 0) return '0s';

  const avgMs = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;

  if (avgMs < 1000) return `${Math.round(avgMs)}ms`;
  if (avgMs < 60000) return `${(avgMs / 1000).toFixed(1)}s`;
  return `${(avgMs / 60000).toFixed(1)}m`;
}
