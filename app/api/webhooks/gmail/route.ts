/**
 * Gmail Push Notification Webhook
 * Receives notifications from Google Pub/Sub when new emails arrive
 */

import { NextRequest, NextResponse } from 'next/server';
import { sql } from '@/lib/db';
import { getGmailMessage, getGmailHistory, refreshGmailToken } from '@/lib/integrations/gmail';
import { parseGmailEmail } from '@/lib/detection/parser';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import { sendThreatNotification } from '@/lib/notifications/service';
import { logAuditEvent } from '@/lib/db/audit';
import { autoRemediate } from '@/lib/workers/remediation';
import { validateGooglePubSub, checkRateLimit } from '@/lib/webhooks/validation';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const WEBHOOK_AUDIENCE = process.env.GOOGLE_WEBHOOK_AUDIENCE;

// Export for Vercel configuration
export const maxDuration = 30;
export const dynamic = 'force-dynamic';

interface PubSubMessage {
  message: {
    data: string; // Base64 encoded JSON
    messageId: string;
    publishTime: string;
  };
  subscription: string;
}

interface GmailNotification {
  emailAddress: string;
  historyId: string;
}

export async function POST(request: NextRequest) {
  const startTime = Date.now();

  try {
    // Rate limiting
    const clientIp = request.headers.get('x-forwarded-for') || 'unknown';
    const rateLimit = checkRateLimit({ key: `gmail:${clientIp}`, maxRequests: 100, windowMs: 60000 });
    if (rateLimit.limited) {
      return NextResponse.json(
        { error: 'Rate limit exceeded' },
        { status: 429, headers: { 'Retry-After': '60' } }
      );
    }

    // Validate Google Pub/Sub signature
    const authHeader = request.headers.get('authorization');
    const validation = await validateGooglePubSub({
      authorizationHeader: authHeader,
      expectedAudience: WEBHOOK_AUDIENCE,
    });

    if (!validation.valid) {
      console.warn('[Gmail Webhook] Validation failed:', validation.error);
      // In production, you might want to reject invalid requests
      // For now, log and continue to avoid breaking during development
      if (process.env.NODE_ENV === 'production' && process.env.STRICT_WEBHOOK_VALIDATION === 'true') {
        return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
      }
    }

    const payload: PubSubMessage = await request.json();

    // Decode the Pub/Sub message
    const notificationData = JSON.parse(
      Buffer.from(payload.message.data, 'base64').toString('utf-8')
    ) as GmailNotification;

    const { emailAddress, historyId } = notificationData;

    console.log(`Gmail notification for ${emailAddress}, history: ${historyId}`);

    // Find the integration for this email
    const integrations = await sql`
      SELECT id, tenant_id, config
      FROM integrations
      WHERE type = 'gmail'
      AND status = 'connected'
      AND config->>'email' = ${emailAddress}
    `;

    if (integrations.length === 0) {
      console.log(`No active integration found for ${emailAddress}`);
      return NextResponse.json({ status: 'ignored' });
    }

    const integration = integrations[0];
    const tenantId = integration.tenant_id as string;
    const config = integration.config as {
      accessToken: string;
      refreshToken: string;
      historyId: string;
      tokenExpiresAt: string;
    };

    // Check if token needs refresh
    let accessToken = config.accessToken;
    if (new Date(config.tokenExpiresAt) <= new Date()) {
      console.log('Token expired, refreshing...');
      const newTokens = await refreshGmailToken({
        refreshToken: config.refreshToken,
        clientId: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
      });

      accessToken = newTokens.accessToken;

      // Update stored tokens
      await sql`
        UPDATE integrations
        SET config = config || ${JSON.stringify({
          accessToken: newTokens.accessToken,
          tokenExpiresAt: newTokens.expiresAt.toISOString(),
        })}::jsonb,
        updated_at = NOW()
        WHERE id = ${integration.id}
      `;
    }

    // Get history since last sync
    const startHistoryId = config.historyId || historyId;
    const historyResult = await getGmailHistory({
      accessToken,
      startHistoryId,
      historyTypes: ['messageAdded'],
    });

    // Process new messages
    const newMessageIds = new Set<string>();
    for (const entry of historyResult.history) {
      if (entry.messagesAdded) {
        for (const added of entry.messagesAdded) {
          newMessageIds.add(added.message.id);
        }
      }
    }

    console.log(`Found ${newMessageIds.size} new messages`);

    // Analyze each new message
    let processedCount = 0;
    for (const messageId of newMessageIds) {
      try {
        // Get full message
        const message = await getGmailMessage({
          accessToken,
          messageId,
          format: 'full',
        });

        // Parse email
        const parsedEmail = parseGmailEmail(message);

        // Analyze
        const verdict = await analyzeEmail(parsedEmail, tenantId);

        // Store verdict
        await storeVerdict(tenantId, parsedEmail.messageId, verdict);

        // Send notification and auto-remediate for threats
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

          // Auto-remediate: quarantine or block the email in mailbox
          await autoRemediate({
            tenantId,
            messageId: parsedEmail.messageId,
            externalMessageId: messageId,
            integrationId: integration.id as string,
            integrationType: 'gmail',
            verdict: verdict.verdict,
            score: verdict.overallScore,
          });
        }

        processedCount++;
      } catch (error) {
        console.error(`Failed to process message ${messageId}:`, error);
      }
    }

    // Update history ID
    await sql`
      UPDATE integrations
      SET config = config || ${JSON.stringify({ historyId: historyResult.historyId })}::jsonb,
          last_sync_at = NOW(),
          updated_at = NOW()
      WHERE id = ${integration.id}
    `;

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId: null,
      actorEmail: 'system',
      action: 'email.sync',
      resourceType: 'integration',
      resourceId: 'gmail',
      afterState: {
        messagesProcessed: processedCount,
        historyId: historyResult.historyId,
      },
    });

    return NextResponse.json({
      status: 'processed',
      messagesProcessed: processedCount,
    });
  } catch (error) {
    console.error('Gmail webhook error:', error);
    return NextResponse.json(
      { error: 'Processing failed' },
      { status: 500 }
    );
  }
}

/**
 * Verification endpoint for Pub/Sub subscription setup
 */
export async function GET() {
  return NextResponse.json({
    status: 'healthy',
    service: 'gmail-webhook',
    timestamp: new Date().toISOString(),
  });
}
