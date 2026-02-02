/**
 * Microsoft 365 Webhook (Change Notifications)
 * Receives notifications from Microsoft Graph subscriptions
 *
 * SECURITY: Uses direct OAuth token management, not Nango.
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
import { loggers } from '@/lib/logging/logger';

const MICROSOFT_WEBHOOK_SECRET = process.env.MICROSOFT_WEBHOOK_SECRET || '';
const log = loggers.webhook;

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
      log.info('O365 subscription validation request');
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
    const threatCount = 0;

    for (const notification of payload.value) {
      try {
        // Validate client state for each notification
        const validation = validateMicrosoftGraph({
          clientState: notification.clientState,
          expectedClientState: MICROSOFT_WEBHOOK_SECRET,
        });

        if (!validation.valid) {
          log.warn('O365 webhook validation failed', { error: validation.error });
          if (process.env.NODE_ENV === 'production' && process.env.STRICT_WEBHOOK_VALIDATION === 'true') {
            continue; // Skip invalid notifications
          }
        }

        await processNotification(notification);
        processedCount++;
      } catch (error) {
        log.error('Failed to process O365 notification', error instanceof Error ? error : new Error(String(error)), { subscriptionId: notification.subscriptionId });
      }
    }

    log.info('O365 webhook processed', { processedCount, durationMs: Date.now() - startTime });

    return NextResponse.json({ status: 'processed' });
  } catch (error) {
    log.error('O365 webhook error', error instanceof Error ? error : new Error(String(error)));
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
    SELECT id, tenant_id, config, connected_email
    FROM integrations
    WHERE type = 'o365'
    AND status = 'connected'
    AND config->>'subscriptionId' = ${subscriptionId}
  `;

  if (integrations.length === 0) {
    // SECURITY: Do NOT fall back to clientState lookup
    // The clientState is attacker-controlled and could be spoofed to point to a different tenant
    // Only process notifications for subscriptions we have registered in our database
    log.warn('SECURITY: No subscription found, ignoring to prevent cross-tenant data leakage', {
      subscriptionId,
      clientState,
      alertType: 'cross_tenant_prevention',
    });
    return;
  }

  // SECURITY: Verify clientState matches the integration's tenant
  // This prevents tampering even when subscription ID is valid
  const integration = integrations[0];
  if (clientState !== integration.tenant_id) {
    log.error('SECURITY ALERT: clientState mismatch, rejecting notification', {
      expectedTenantId: integration.tenant_id,
      receivedClientState: clientState,
      subscriptionId,
      alertType: 'tampering_attempt',
    });
    // Log security event for monitoring
    try {
      await logAuditEvent({
        tenantId: integration.tenant_id as string,
        actorId: null,
        actorEmail: 'system',
        action: 'security.webhook_tampering_detected',
        resourceType: 'integration',
        resourceId: integration.id as string,
        afterState: {
          subscriptionId,
          expectedClientState: integration.tenant_id,
          receivedClientState: clientState,
          alertType: 'cross_tenant_attempt',
        },
      });
    } catch (auditError) {
      log.error('Failed to log security audit', auditError instanceof Error ? auditError : new Error(String(auditError)));
    }
    return;
  }

  // integration was already validated above
  const tenantId = integration.tenant_id as string;

  // Extract message ID from resource path
  // Resource format: "Users/{userId}/Messages/{messageId}"
  const messageIdMatch = resource.match(/Messages\/(.+)$/);
  if (!messageIdMatch) {
    log.warn('Could not extract message ID from resource', { resource });
    return;
  }
  const messageId = messageIdMatch[1];

  // Get fresh token using direct OAuth token manager (handles refresh automatically)
  const accessToken = await getO365AccessToken(tenantId);

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
  await storeVerdict(tenantId, parsedEmail.messageId, verdict, parsedEmail);

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

  log.info('Processed O365 message', { messageId, verdict: verdict.verdict, score: verdict.overallScore, tenantId });
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
