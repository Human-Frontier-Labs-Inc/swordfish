/**
 * Email Processing Webhook
 * Receives emails from providers and runs detection pipeline
 */

import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import { sendThreatNotification } from '@/lib/notifications/service';
import { logAuditEvent } from '@/lib/db/audit';
import type { ParsedEmail, Attachment } from '@/lib/detection/types';
import crypto from 'crypto';

// Webhook secret for verification
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';

interface WebhookPayload {
  // Provider identification
  provider: 'microsoft' | 'google' | 'sendgrid' | 'postmark' | 'custom';
  tenantId: string;

  // Email data
  messageId: string;
  from: string;
  to: string[];
  cc?: string[];
  subject: string;
  body: {
    text?: string;
    html?: string;
  };
  headers?: Record<string, string>;
  rawHeaders?: string;
  attachments?: Array<{
    filename: string;
    contentType: string;
    size: number;
    content?: string; // Base64 encoded
  }>;
  receivedAt?: string;
}

/**
 * Parse email address string to EmailAddress type
 */
function parseEmailAddress(raw: string): { address: string; displayName?: string; domain: string } {
  const match = raw.match(/^(?:"?([^"<]*)"?\s*)?<?([^<>\s]+@[^<>\s]+)>?$/);
  if (match) {
    const address = match[2].toLowerCase();
    return {
      address,
      displayName: match[1]?.trim() || undefined,
      domain: address.split('@')[1] || '',
    };
  }
  const address = raw.trim().toLowerCase();
  return {
    address,
    domain: address.split('@')[1] || '',
  };
}

/**
 * Verify webhook signature
 */
function verifySignature(payload: string, signature: string): boolean {
  if (!WEBHOOK_SECRET) {
    console.warn('WEBHOOK_SECRET not set - skipping signature verification');
    return true;
  }

  const expectedSignature = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(payload)
    .digest('hex');

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

export async function POST(request: NextRequest) {
  const startTime = performance.now();

  try {
    // Get headers
    const headersList = await headers();
    const signature = headersList.get('x-webhook-signature') || '';
    const webhookToken = headersList.get('x-webhook-token') || '';

    // Get raw body for signature verification
    const rawBody = await request.text();

    // Verify signature if provided
    if (signature && !verifySignature(rawBody, signature)) {
      return NextResponse.json(
        { error: 'Invalid signature' },
        { status: 401 }
      );
    }

    // Verify webhook token if no signature
    if (!signature && webhookToken !== process.env.WEBHOOK_TOKEN) {
      return NextResponse.json(
        { error: 'Invalid webhook token' },
        { status: 401 }
      );
    }

    // Parse payload
    let payload: WebhookPayload;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      return NextResponse.json(
        { error: 'Invalid JSON payload' },
        { status: 400 }
      );
    }

    // Validate required fields
    if (!payload.tenantId || !payload.from || !payload.to?.length || !payload.subject) {
      return NextResponse.json(
        { error: 'Missing required fields: tenantId, from, to, subject' },
        { status: 400 }
      );
    }

    // Convert attachments
    const attachments: Attachment[] = (payload.attachments || []).map(att => ({
      filename: att.filename,
      contentType: att.contentType,
      size: att.size,
      content: att.content ? Buffer.from(att.content, 'base64') : undefined,
    }));

    // Build ParsedEmail that matches the expected type
    const parsedEmail: ParsedEmail = {
      messageId: payload.messageId || `webhook-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      subject: payload.subject,
      from: parseEmailAddress(payload.from),
      to: payload.to.map(parseEmailAddress),
      cc: payload.cc?.map(parseEmailAddress),
      date: payload.receivedAt ? new Date(payload.receivedAt) : new Date(),
      headers: payload.headers || {},
      body: {
        text: payload.body.text,
        html: payload.body.html,
      },
      attachments,
      rawHeaders: payload.rawHeaders || '',
    };

    // Run detection pipeline
    const verdict = await analyzeEmail(parsedEmail, payload.tenantId);

    // Store the verdict
    await storeVerdict(payload.tenantId, parsedEmail.messageId, verdict, parsedEmail);

    // Send notifications for threats
    if (verdict.verdict === 'quarantine' || verdict.verdict === 'block') {
      await sendThreatNotification(payload.tenantId, {
        type: verdict.verdict === 'block' ? 'threat_blocked' : 'threat_quarantined',
        severity: verdict.overallScore >= 80 ? 'critical' : 'warning',
        title: `Email ${verdict.verdict === 'block' ? 'Blocked' : 'Quarantined'}: ${payload.subject}`,
        message: verdict.explanation || `Threat detected from ${payload.from}`,
        metadata: {
          messageId: parsedEmail.messageId,
          from: payload.from,
          score: verdict.overallScore,
        },
      });
    }

    // Log audit event
    await logAuditEvent({
      tenantId: payload.tenantId,
      actorId: null,
      actorEmail: 'system',
      action: 'email.processed',
      resourceType: 'email',
      resourceId: parsedEmail.messageId,
      afterState: {
        verdict: verdict.verdict,
        score: verdict.overallScore,
        provider: payload.provider,
        processingTimeMs: performance.now() - startTime,
      },
    });

    // Return verdict
    return NextResponse.json({
      success: true,
      messageId: parsedEmail.messageId,
      verdict: verdict.verdict,
      score: verdict.overallScore,
      confidence: verdict.confidence,
      explanation: verdict.explanation,
      recommendation: verdict.recommendation,
      signals: verdict.signals.map(s => ({
        type: s.type,
        severity: s.severity,
        detail: s.detail,
      })),
      processingTimeMs: Math.round(performance.now() - startTime),
    });
  } catch (error) {
    console.error('Webhook processing error:', error);

    return NextResponse.json(
      {
        error: 'Processing failed',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

/**
 * Health check for webhook endpoint
 */
export async function GET() {
  return NextResponse.json({
    status: 'healthy',
    endpoint: '/api/webhooks/email',
    methods: ['POST'],
    requiredHeaders: ['x-webhook-token OR x-webhook-signature'],
  });
}
