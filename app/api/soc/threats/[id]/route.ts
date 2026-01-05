/**
 * SOC Threat Details API
 *
 * Fetch detailed threat information for investigation
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { userId, orgId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id: threatId } = await params;
    const tenantId = orgId || userId;

    // Fetch threat details
    const threats = await sql`
      SELECT
        t.*,
        e.body_text,
        e.body_html,
        e.headers as email_headers
      FROM threats t
      LEFT JOIN emails e ON t.message_id = e.message_id AND t.tenant_id = e.tenant_id
      WHERE t.id = ${threatId}
        AND t.tenant_id = ${tenantId}
      LIMIT 1
    `;

    if (threats.length === 0) {
      return NextResponse.json({ error: 'Threat not found' }, { status: 404 });
    }

    const threat = threats[0];

    // Fetch investigation notes
    const notes = await sql`
      SELECT id, author, content, created_at
      FROM investigation_notes
      WHERE threat_id = ${threatId}
      ORDER BY created_at DESC
    `;

    // Transform to response format
    const threatDetails = {
      id: threat.id,
      subject: threat.subject,
      fromAddress: threat.from_address,
      fromDisplayName: threat.from_display_name,
      toAddresses: threat.to_addresses || [],
      receivedAt: threat.received_at,
      verdict: threat.verdict,
      confidence: threat.confidence,
      classification: threat.ml_classification,
      signals: parseSignals(threat.signals),
      headers: parseHeaders(threat.email_headers),
      urls: extractUrls(threat.body_html || threat.body_text),
      attachments: threat.attachments || [],
      bodyPreview: truncate(threat.body_text, 500),
      rawHeaders: threat.email_headers,
      investigation: notes.map((n: Record<string, unknown>) => ({
        id: n.id,
        author: n.author,
        content: n.content,
        createdAt: n.created_at,
      })),
    };

    return NextResponse.json({ threat: threatDetails });
  } catch (error) {
    console.error('SOC threat details error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch threat details' },
      { status: 500 }
    );
  }
}

function parseSignals(signals: unknown): Array<{
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  score: number;
}> {
  if (!signals) return [];
  if (!Array.isArray(signals)) return [];

  return signals.map((signal) => {
    if (typeof signal === 'string') {
      return {
        type: signal,
        severity: 'medium' as const,
        description: formatSignalDescription(signal),
        score: 10,
      };
    }
    return {
      type: signal.type || 'unknown',
      severity: signal.severity || 'medium',
      description: signal.description || formatSignalDescription(signal.type),
      score: signal.score || 10,
      evidence: signal.evidence,
    };
  });
}

function formatSignalDescription(signal: string): string {
  const descriptions: Record<string, string> = {
    suspicious_url: 'Email contains suspicious or potentially malicious URLs',
    new_sender: 'First-time sender to this recipient',
    domain_mismatch: 'Reply-to domain does not match sender domain',
    urgency_language: 'Email contains urgent language patterns',
    financial_request: 'Email requests financial action or wire transfer',
    display_name_spoof: 'Display name may be impersonating a known contact',
    attachment_risk: 'Potentially risky attachment detected',
    failed_spf: 'SPF authentication failed',
    failed_dkim: 'DKIM signature verification failed',
    failed_dmarc: 'DMARC policy check failed',
  };
  return descriptions[signal] || `Signal detected: ${signal}`;
}

function parseHeaders(headers: unknown): Record<string, string> {
  if (!headers) return {};
  if (typeof headers === 'object') return headers as Record<string, string>;

  try {
    if (typeof headers === 'string') {
      return JSON.parse(headers);
    }
  } catch {
    return {};
  }
  return {};
}

function extractUrls(content: string | null): Array<{
  url: string;
  displayText?: string;
  reputation: 'unknown';
}> {
  if (!content) return [];

  const urlRegex = /https?:\/\/[^\s<>"]+/gi;
  const matches = content.match(urlRegex) || [];

  return [...new Set(matches)].slice(0, 20).map((url) => ({
    url,
    reputation: 'unknown' as const,
  }));
}

function truncate(text: string | null, maxLength: number): string {
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength) + '...';
}
