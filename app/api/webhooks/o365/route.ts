/**
 * Microsoft 365 Webhook (Change Notifications)
 * Receives notifications from Microsoft Graph subscriptions
 */

import { NextRequest, NextResponse } from 'next/server';
import { sql } from '@/lib/db';
import { getO365Email, getO365AccessToken } from '@/lib/integrations/o365';
import { parseGraphEmail } from '@/lib/detection/parser';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import { sendThreatNotification } from '@/lib/notifications/service';
import { logAuditEvent } from '@/lib/db/audit';
import { autoRemediate } from '@/lib/workers/remediation';
import { validateMicrosoftGraph, checkRateLimit } from '@/lib/webhooks/validation';

const MICROSOFT_WEBHOOK_SECRET = process.env.MICROSOFT_WEBHOOK_SECRET || '';

// Export for Vercel configuration
export const maxDuration = 30;
export const dynamic = 'force-dynamic';

interface GraphNotification {
  value: Array<{
    subscriptionId: string;
    clientState: string;
    changeType: 'created' | 'updated' | 'deleted';
    resource: string;
    resourceData: {
      id: string;
      '@odata.type': string;
      '@odata.id': string;
      '@odata.etag': string;
    };
    tenantId: string;
  }>;
  validationToken?: string;
}

export async function POST(request: NextRequest) {
  const startTime = Date.now();

  try {
    // Handle subscription validation (Microsoft sends this on subscription creation)
    const validationToken = request.nextUrl.searchParams.get('validationToken');
    if (validationToken) {
      console.log('[O365 Webhook] Subscription validation request');
      return new NextResponse(validationToken, {
        status: 200,
        headers: { 'Content-Type': 'text/plain' },
      });
    }

    // Rate limiting
    const clientIp = request.headers.get('x-forwarded-for') || 'unknown';
    const rateLimit = checkRateLimit({ key: `o365:${clientIp}`, maxRequests: 100, windowMs: 60000 });
    if (rateLimit.limited) {
      return NextResponse.json(
        { error: 'Rate limit exceeded' },
        { status: 429, headers: { 'Retry-After': '60' } }
      );
    }

    const payload: GraphNotification = await request.json();

    // Process each notification
    let processedCount = 0;
    let threatCount = 0;

    for (const notification of payload.value) {
      try {
        // Validate client state for each notification
        const validation = validateMicrosoftGraph({
          clientState: notification.clientState,
          expectedClientState: MICROSOFT_WEBHOOK_SECRET,
        });

        if (!validation.valid) {
          console.warn('[O365 Webhook] Validation failed:', validation.error);
          if (process.env.NODE_ENV === 'production' && process.env.STRICT_WEBHOOK_VALIDATION === 'true') {
            continue; // Skip invalid notifications
          }
        }

        await processNotification(notification);
        processedCount++;
      } catch (error) {
        console.error(`[O365 Webhook] Failed to process notification ${notification.subscriptionId}:`, error);
      }
    }

    console.log(`[O365 Webhook] Processed ${processedCount} notifications in ${Date.now() - startTime}ms`);

    return NextResponse.json({ status: 'processed' });
  } catch (error) {
    console.error('O365 webhook error:', error);
    return NextResponse.json(
      { error: 'Processing failed' },
      { status: 500 }
    );
  }
}

async function processNotification(notification: GraphNotification['value'][0]) {
  const { subscriptionId, changeType, resource, clientState } = notification;

  // Only process new messages
  if (changeType !== 'created') {
    return;
  }

  // Find integration by subscription ID
  const integrations = await sql`
    SELECT id, tenant_id, config, nango_connection_id
    FROM integrations
    WHERE type = 'o365'
    AND status = 'connected'
    AND config->>'subscriptionId' = ${subscriptionId}
  `;

  if (integrations.length === 0) {
    // Try finding by client state (tenant ID)
    const byState = await sql`
      SELECT id, tenant_id, config, nango_connection_id
      FROM integrations
      WHERE type = 'o365'
      AND status = 'connected'
      AND tenant_id = ${clientState}
    `;

    if (byState.length === 0) {
      console.log(`No integration found for subscription ${subscriptionId}`);
      return;
    }

    integrations.push(byState[0]);
  }

  const integration = integrations[0];
  const tenantId = integration.tenant_id as string;
  const nangoConnectionId = integration.nango_connection_id as string | null;

  // Extract message ID from resource path
  // Resource format: "Users/{userId}/Messages/{messageId}"
  const messageIdMatch = resource.match(/Messages\/(.+)$/);
  if (!messageIdMatch) {
    console.log(`Could not extract message ID from resource: ${resource}`);
    return;
  }
  const messageId = messageIdMatch[1];

  // Get fresh token from Nango
  if (!nangoConnectionId) {
    console.warn(`No Nango connection for integration ${integration.id}`);
    return;
  }

  const accessToken = await getO365AccessToken(nangoConnectionId);

  // Get the email
  const message = await getO365Email({
    accessToken,
    messageId,
  });

  // Parse email
  const parsedEmail = parseGraphEmail(message);

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
      integrationType: 'o365',
      verdict: verdict.verdict,
      score: verdict.overallScore,
    });
  }

  // Update last sync
  await sql`
    UPDATE integrations
    SET last_sync_at = NOW(), updated_at = NOW()
    WHERE id = ${integration.id}
  `;

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
      source: 'o365_webhook',
    },
  });

  console.log(`Processed O365 message ${messageId}: ${verdict.verdict} (${verdict.overallScore})`);
}

/**
 * Health check / subscription validation
 */
export async function GET() {
  return NextResponse.json({
    status: 'healthy',
    service: 'o365-webhook',
    timestamp: new Date().toISOString(),
  });
}
