/**
 * SMTP Webhook Receiver
 * Receives emails forwarded from SMTP gateways for analysis
 */

import { NextRequest, NextResponse } from 'next/server';
import { parseEmail } from '@/lib/detection/parser';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import { logAuditEvent } from '@/lib/db/audit';
import { sendThreatNotification } from '@/lib/notifications/service';
import type { ParsedEmail, EmailAddress, Attachment } from '@/lib/detection/types';
import { sql } from '@/lib/db';
import crypto from 'crypto';

// Webhook secret for verification
const SMTP_WEBHOOK_SECRET = process.env.SMTP_WEBHOOK_SECRET;

interface SMTPWebhookPayload {
  // Standard format from SMTP gateways
  messageId: string;
  from: string;
  to: string | string[];
  subject: string;
  rawMime?: string; // Full MIME content
  headers?: Record<string, string>;
  body?: {
    text?: string;
    html?: string;
  };
  attachments?: Array<{
    filename: string;
    contentType: string;
    size: number;
    content?: string; // Base64 encoded
    checksum?: string;
  }>;
  receivedAt: string;
  // Tenant identification
  tenantId?: string;
  apiKey?: string;
}

/**
 * Verify webhook signature
 */
function verifySignature(payload: string, signature: string | null): boolean {
  if (!SMTP_WEBHOOK_SECRET) {
    // No secret configured, skip verification in development
    return process.env.NODE_ENV === 'development';
  }

  if (!signature) {
    return false;
  }

  const expectedSignature = crypto
    .createHmac('sha256', SMTP_WEBHOOK_SECRET)
    .update(payload)
    .digest('hex');

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

/**
 * Look up tenant by API key
 */
async function getTenantByApiKey(apiKey: string): Promise<string | null> {
  const result = await sql`
    SELECT tenant_id FROM api_keys
    WHERE key_hash = ${crypto.createHash('sha256').update(apiKey).digest('hex')}
    AND status = 'active'
    AND (expires_at IS NULL OR expires_at > NOW())
  `;

  return result.length > 0 ? result[0].tenant_id as string : null;
}

export async function POST(request: NextRequest) {
  const startTime = Date.now();

  try {
    const rawBody = await request.text();
    const signature = request.headers.get('x-swordfish-signature');

    // Verify webhook signature
    if (!verifySignature(rawBody, signature)) {
      console.error('Invalid webhook signature');
      return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
    }

    const payload: SMTPWebhookPayload = JSON.parse(rawBody);

    // Determine tenant
    let tenantId: string | null = payload.tenantId || null;

    if (!tenantId && payload.apiKey) {
      tenantId = await getTenantByApiKey(payload.apiKey);
    }

    if (!tenantId) {
      return NextResponse.json({ error: 'Tenant identification required' }, { status: 400 });
    }

    // Helper to parse email address
    const parseAddr = (addr: string): EmailAddress => {
      const match = addr.match(/^(?:"?([^"<]*)"?\s*)?<?([^<>\s]+@[^<>\s]+)>?$/);
      if (match) {
        const address = match[2].toLowerCase();
        return { address, displayName: match[1]?.trim(), domain: address.split('@')[1] || '' };
      }
      const address = addr.toLowerCase();
      return { address, domain: address.split('@')[1] || '' };
    };

    // Parse email
    let parsedEmail: ParsedEmail;
    if (payload.rawMime) {
      parsedEmail = parseEmail(payload.rawMime);
    } else {
      // Construct from payload
      const toAddresses = Array.isArray(payload.to) ? payload.to : [payload.to];
      const attachments: Attachment[] = (payload.attachments || []).map(a => ({
        filename: a.filename,
        contentType: a.contentType,
        size: a.size,
        hash: a.checksum,
      }));

      parsedEmail = {
        messageId: payload.messageId,
        from: parseAddr(payload.from),
        to: toAddresses.map(parseAddr),
        subject: payload.subject,
        body: {
          text: payload.body?.text,
          html: payload.body?.html,
        },
        headers: payload.headers || {},
        attachments,
        date: new Date(payload.receivedAt),
        rawHeaders: '',
      };
    }

    // Analyze email
    const verdict = await analyzeEmail(parsedEmail, tenantId);

    // Store verdict
    const verdictId = await storeVerdict(tenantId, parsedEmail.messageId, verdict);

    // Send notification for threats
    if (verdict.verdict === 'quarantine' || verdict.verdict === 'block') {
      await sendThreatNotification(tenantId, {
        type: verdict.verdict === 'block' ? 'threat_blocked' : 'threat_quarantined',
        severity: verdict.overallScore >= 80 ? 'critical' : 'warning',
        title: `Email ${verdict.verdict === 'block' ? 'Blocked' : 'Quarantined'}: ${parsedEmail.subject}`,
        message: verdict.explanation || `Threat detected from ${parsedEmail.from.address}`,
        metadata: {
          messageId: parsedEmail.messageId,
          from: parsedEmail.from.address,
          score: verdict.overallScore,
        },
      });
    }

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId: null,
      actorEmail: 'system',
      action: 'email.analyzed',
      resourceType: 'email',
      resourceId: parsedEmail.messageId,
      afterState: {
        verdict: verdict.verdict,
        score: verdict.overallScore,
        source: 'smtp_webhook',
        processingTime: Date.now() - startTime,
      },
    });

    // Return verdict for real-time response
    const response = {
      success: true,
      messageId: parsedEmail.messageId,
      verdict: {
        result: verdict.verdict,
        score: verdict.overallScore,
        confidence: verdict.confidence,
        action: getRecommendedAction({ verdict: verdict.verdict, score: verdict.overallScore }),
        signalTypes: verdict.signals
          .filter(s => s.severity === 'critical' || s.severity === 'warning')
          .map(s => s.type),
      },
      processingTime: Date.now() - startTime,
      verdictId,
    };

    return NextResponse.json(response);
  } catch (error) {
    console.error('SMTP webhook error:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Processing failed',
      },
      { status: 500 }
    );
  }
}

/**
 * Get recommended action based on verdict
 */
function getRecommendedAction(verdict: {
  verdict: string;
  score: number;
}): 'deliver' | 'quarantine' | 'reject' | 'tag' {
  if (verdict.verdict === 'malicious' || verdict.score >= 80) {
    return 'reject';
  }
  if (verdict.verdict === 'phishing' || verdict.score >= 60) {
    return 'quarantine';
  }
  if (verdict.verdict === 'suspicious' || verdict.score >= 30) {
    return 'tag';
  }
  return 'deliver';
}

/**
 * Health check endpoint
 */
export async function GET() {
  return NextResponse.json({
    status: 'healthy',
    service: 'smtp-webhook',
    timestamp: new Date().toISOString(),
  });
}
