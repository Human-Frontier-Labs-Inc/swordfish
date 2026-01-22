/**
 * Microsoft Graph Webhook Handler
 * Processes Microsoft Graph change notifications
 */

import { sql } from '@/lib/db';
import { getO365Email, getO365AccessToken } from '@/lib/integrations/o365';
import { parseGraphEmail } from '@/lib/detection/parser';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import { sendThreatNotification } from '@/lib/notifications/service';
import { logAuditEvent } from '@/lib/db/audit';
import { autoRemediate } from '@/lib/workers/remediation';

interface GraphNotification {
  subscriptionId: string;
  clientState: string;
  changeType: 'created' | 'updated' | 'deleted';
  resource: string;
  resourceData?: {
    id: string;
    '@odata.type': string;
    '@odata.id': string;
  };
  tenantId: string;
}

export interface MicrosoftWebhookResult {
  success: boolean;
  messagesProcessed: number;
  threatsFound: number;
  errors: string[];
  processingTimeMs: number;
}

/**
 * Process Microsoft Graph change notifications
 */
export async function processMicrosoftWebhook(
  payload: Record<string, unknown>
): Promise<MicrosoftWebhookResult> {
  const startTime = Date.now();
  const errors: string[] = [];
  let messagesProcessed = 0;
  let threatsFound = 0;

  try {
    const notifications = (payload.value || [payload]) as GraphNotification[];

    for (const notification of notifications) {
      try {
        const result = await processNotification(notification);
        messagesProcessed += result.processed ? 1 : 0;
        threatsFound += result.threatFound ? 1 : 0;
        if (result.error) {
          errors.push(result.error);
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        errors.push(`Notification ${notification.subscriptionId}: ${errorMsg}`);
      }
    }

    return {
      success: errors.length === 0,
      messagesProcessed,
      threatsFound,
      errors,
      processingTimeMs: Date.now() - startTime,
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';

    return {
      success: false,
      messagesProcessed,
      threatsFound,
      errors: [errorMsg],
      processingTimeMs: Date.now() - startTime,
    };
  }
}

async function processNotification(notification: GraphNotification): Promise<{
  processed: boolean;
  threatFound: boolean;
  error?: string;
}> {
  const { subscriptionId, changeType, resource, clientState } = notification;

  // Only process new messages
  if (changeType !== 'created') {
    return { processed: false, threatFound: false };
  }

  console.log(`[Microsoft Webhook] Processing notification for subscription ${subscriptionId}`);

  // Find integration by subscription ID or client state (tenant ID)
  let integrations = await sql`
    SELECT id, tenant_id, config, nango_connection_id
    FROM integrations
    WHERE type = 'o365'
    AND status = 'connected'
    AND config->>'subscriptionId' = ${subscriptionId}
  `;

  if (integrations.length === 0 && clientState) {
    // Try finding by client state (often contains tenant ID)
    integrations = await sql`
      SELECT id, tenant_id, config, nango_connection_id
      FROM integrations
      WHERE type = 'o365'
      AND status = 'connected'
      AND tenant_id = ${clientState}
    `;
  }

  if (integrations.length === 0) {
    return {
      processed: false,
      threatFound: false,
      error: `No integration found for subscription ${subscriptionId}`,
    };
  }

  const integration = integrations[0];
  const tenantId = integration.tenant_id as string;
  const nangoConnectionId = integration.nango_connection_id as string | null;

  // Extract message ID from resource path
  const messageIdMatch = resource.match(/Messages\/(.+)$/);
  if (!messageIdMatch) {
    return {
      processed: false,
      threatFound: false,
      error: `Could not extract message ID from resource: ${resource}`,
    };
  }
  const messageId = messageIdMatch[1];

  // Check if already processed
  const existing = await sql`
    SELECT id FROM email_verdicts
    WHERE tenant_id = ${tenantId}
    AND message_id LIKE ${`%${messageId}%`}
  `;

  if (existing.length > 0) {
    return { processed: false, threatFound: false };
  }

  // Get fresh token from Nango
  if (!nangoConnectionId) {
    return {
      processed: false,
      threatFound: false,
      error: 'No Nango connection configured',
    };
  }

  const accessToken = await getO365AccessToken(nangoConnectionId);

  // Get full email
  const fullEmail = await getO365Email({
    accessToken,
    messageId,
  });

  // Parse and analyze
  const parsedEmail = parseGraphEmail(fullEmail);
  const verdict = await analyzeEmail(parsedEmail, tenantId);

  // Store verdict
  await storeVerdict(tenantId, parsedEmail.messageId, verdict, parsedEmail);

  let threatFound = false;

  // Handle threats
  if (verdict.verdict === 'quarantine' || verdict.verdict === 'block') {
    threatFound = true;

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

    // Auto-remediate
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
    actorId: null, // System action - no user actor
    actorEmail: null,
    action: 'webhook.microsoft',
    resourceType: 'email',
    resourceId: parsedEmail.messageId,
    afterState: {
      verdict: verdict.verdict,
      score: verdict.overallScore,
    },
  });

  console.log(`[Microsoft Webhook] Processed message ${messageId}: ${verdict.verdict} (${verdict.overallScore})`);

  return { processed: true, threatFound };
}
