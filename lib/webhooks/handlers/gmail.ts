/**
 * Gmail Webhook Handler
 * Processes Gmail Pub/Sub notifications
 */

import { sql } from '@/lib/db';
import { getGmailMessage, getGmailHistory, getGmailAccessToken } from '@/lib/integrations/gmail';
import { parseGmailEmail } from '@/lib/detection/parser';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import { sendThreatNotification } from '@/lib/notifications/service';
import { logAuditEvent } from '@/lib/db/audit';
import { autoRemediate } from '@/lib/workers/remediation';

interface GmailNotification {
  emailAddress: string;
  historyId: string;
}

export interface GmailWebhookResult {
  success: boolean;
  messagesProcessed: number;
  threatsFound: number;
  errors: string[];
  processingTimeMs: number;
}

/**
 * Process a Gmail Pub/Sub webhook payload
 */
export async function processGmailWebhook(
  payload: Record<string, unknown>
): Promise<GmailWebhookResult> {
  const startTime = Date.now();
  const errors: string[] = [];
  let messagesProcessed = 0;
  let threatsFound = 0;

  try {
    // Extract notification data
    const message = payload.message as { data: string; messageId: string };
    const notificationData = JSON.parse(
      Buffer.from(message.data, 'base64').toString('utf-8')
    ) as GmailNotification;

    const { emailAddress, historyId } = notificationData;

    console.log(`[Gmail Webhook] Processing notification for ${emailAddress}, history: ${historyId}`);

    // Find the integration for this email
    const integrations = await sql`
      SELECT id, tenant_id, config, nango_connection_id
      FROM integrations
      WHERE type = 'gmail'
      AND status = 'connected'
      AND config->>'email' = ${emailAddress}
    `;

    if (integrations.length === 0) {
      return {
        success: true,
        messagesProcessed: 0,
        threatsFound: 0,
        errors: [`No active integration found for ${emailAddress}`],
        processingTimeMs: Date.now() - startTime,
      };
    }

    const integration = integrations[0];
    const tenantId = integration.tenant_id as string;
    const nangoConnectionId = integration.nango_connection_id as string | null;
    const config = integration.config as {
      historyId: string;
    };

    // Get fresh token from Nango
    if (!nangoConnectionId) {
      return {
        success: false,
        messagesProcessed: 0,
        threatsFound: 0,
        errors: ['No Nango connection configured'],
        processingTimeMs: Date.now() - startTime,
      };
    }

    const accessToken = await getGmailAccessToken(nangoConnectionId);

    // Get history since last sync
    const startHistoryId = config.historyId || historyId;
    const historyResult = await getGmailHistory({
      accessToken,
      startHistoryId,
      historyTypes: ['messageAdded'],
    });

    // Collect new message IDs
    const newMessageIds = new Set<string>();
    for (const entry of historyResult.history) {
      if (entry.messagesAdded) {
        for (const added of entry.messagesAdded) {
          newMessageIds.add(added.message.id);
        }
      }
    }

    console.log(`[Gmail Webhook] Found ${newMessageIds.size} new messages`);

    // Process each new message
    for (const messageId of newMessageIds) {
      try {
        // Check if already processed
        const existing = await sql`
          SELECT id FROM email_verdicts
          WHERE tenant_id = ${tenantId}
          AND message_id LIKE ${`%${messageId}%`}
        `;

        if (existing.length > 0) {
          continue;
        }

        // Get full message
        const message = await getGmailMessage({
          accessToken,
          messageId,
          format: 'full',
        });

        // Parse and analyze
        const parsedEmail = parseGmailEmail(message);
        const verdict = await analyzeEmail(parsedEmail, tenantId);

        // Store verdict
        await storeVerdict(tenantId, parsedEmail.messageId, verdict, parsedEmail);

        messagesProcessed++;

        // Handle threats
        if (verdict.verdict === 'quarantine' || verdict.verdict === 'block') {
          threatsFound++;

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
            integrationType: 'gmail',
            verdict: verdict.verdict,
            score: verdict.overallScore,
          });
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        errors.push(`Message ${messageId}: ${errorMsg}`);
        console.error(`[Gmail Webhook] Failed to process message ${messageId}:`, error);
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
      actorId: null, // System action - no user actor
      actorEmail: null,
      action: 'webhook.gmail',
      resourceType: 'integration',
      resourceId: integration.id as string,
      afterState: {
        messagesProcessed,
        threatsFound,
        historyId: historyResult.historyId,
      },
    });

    return {
      success: true,
      messagesProcessed,
      threatsFound,
      errors,
      processingTimeMs: Date.now() - startTime,
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    errors.push(errorMsg);

    return {
      success: false,
      messagesProcessed,
      threatsFound,
      errors,
      processingTimeMs: Date.now() - startTime,
    };
  }
}
