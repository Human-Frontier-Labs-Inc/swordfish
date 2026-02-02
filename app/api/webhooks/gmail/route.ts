/**
 * Gmail Push Notification Webhook
 * Receives notifications from Google Pub/Sub when new emails arrive
 *
 * SECURITY: Uses connected_email column for tenant isolation.
 * No longer depends on Nango - uses direct OAuth token management.
 */

import { NextRequest, NextResponse } from 'next/server';
import { sql } from '@/lib/db';
import { getGmailMessage, getGmailHistory, getGmailAccessToken } from '@/lib/integrations/gmail';
import { parseGmailEmail } from '@/lib/detection/parser';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import { sendThreatNotification } from '@/lib/notifications/service';
import { logAuditEvent } from '@/lib/db/audit';
import { autoRemediate } from '@/lib/workers/remediation';
import { validateGooglePubSub, checkRateLimit } from '@/lib/webhooks/validation';
import { processGmailHistoryForUser, getGmailTokenForUser } from '@/lib/integrations/domain-wide/google-workspace';
import { getDomainUserByEmail, incrementDomainUserStats, getActiveDomainConfigs } from '@/lib/integrations/domain-wide/storage';
import { findIntegrationByEmail } from '@/lib/oauth';
import { enqueueGmailJob, isGmailQueueConfigured } from '@/lib/queue/gmail';
import { loggers } from '@/lib/logging/logger';

const WEBHOOK_AUDIENCE = process.env.GOOGLE_WEBHOOK_AUDIENCE;
const log = loggers.webhook;

// Export for Vercel configuration
// Use a slightly higher timeout, but keep processing lightweight by skipping LLM.
export const maxDuration = 60;
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

// To avoid Vercel timeouts and Neon overload, cap work per invocation
const MAX_MESSAGES_PER_WEBHOOK = 10;
const WEBHOOK_TIME_BUDGET_MS = 45_000;

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
      log.warn('Gmail webhook validation failed', { error: validation.error });
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

    log.info('Gmail notification received', { emailAddress, historyId });

    // First, check if this email is from a domain-wide monitoring config
    const domainConfigs = await getActiveDomainConfigs();
    for (const domainConfig of domainConfigs) {
      if (domainConfig.provider !== 'google_workspace') continue;

      const domainUser = await getDomainUserByEmail(domainConfig.id, emailAddress);
      if (domainUser && domainUser.isMonitored) {
        // Process via domain-wide path
        log.info('Processing domain-wide Gmail notification', { emailAddress });
        return await processDomainWideGmail(domainConfig.id, domainConfig.tenantId, emailAddress, historyId);
      }
    }

    // SECURITY: Look up integration by connected_email column (verified during OAuth)
    // This is the secure approach - only uses emails that were validated during OAuth callback
    const integrationMatch = await findIntegrationByEmail(emailAddress.toLowerCase(), 'gmail');

    let integrations: Array<{
      id: unknown;
      tenant_id: unknown;
      config: unknown;
    }> = [];

    if (integrationMatch) {
      // Found integration by verified connected_email
      const result = await sql`
        SELECT id, tenant_id, config
        FROM integrations
        WHERE id = ${integrationMatch.integrationId}
        AND type = 'gmail'
        AND status = 'connected'
      ` as Array<{ id: unknown; tenant_id: unknown; config: unknown }>;
      integrations = result;
    }

    if (integrations.length === 0) {
      // SECURITY: No fallback - only process emails for verified integrations
      log.warn('SECURITY: No verified integration found, ignoring to prevent cross-tenant data leakage', {
        emailAddress,
        alertType: 'cross_tenant_prevention',
      });
    }

    if (integrations.length === 0) {
      log.info('No active integration found', { emailAddress });
      return NextResponse.json({ status: 'ignored' });
    }

    const integration = integrations[0];
    const tenantId = integration.tenant_id as string;
    const config = integration.config as {
      historyId: string;
    };

    // If queue is configured, enqueue and return quickly
    if (isGmailQueueConfigured()) {
      try {
        const job = await enqueueGmailJob({
          tenantId,
          integrationId: integration.id as string,
          emailAddress,
          historyId,
        });

        return NextResponse.json({
          status: 'queued',
          jobId: job.id,
        });
      } catch (queueError) {
        log.error('Queue enqueue failed', queueError instanceof Error ? queueError : new Error(String(queueError)));
        return NextResponse.json(
          { status: 'queue_error', error: 'Failed to enqueue job' },
          { status: 200 }
        );
      }
    }

    // Get fresh token using direct OAuth token manager (handles refresh automatically)
    const accessToken = await getGmailAccessToken(tenantId);

    // Get history since last sync
    const startHistoryId = config.historyId || historyId;
    const historyResult = await getGmailHistory({
      accessToken,
      startHistoryId,
      historyTypes: ['messageAdded'],
    });

    // Process new messages (bounded by time and count)
    const newMessageIds = new Set<string>();
    for (const entry of historyResult.history) {
      if (entry.messagesAdded) {
        for (const added of entry.messagesAdded) {
          newMessageIds.add(added.message.id);
        }
      }
    }

    log.info('Found new messages', { count: newMessageIds.size, tenantId });

    // Analyze each new message
    let processedCount = 0;
    for (const messageId of newMessageIds) {
      // Stop early if we're close to Vercel's timeout
      if (Date.now() - startTime > WEBHOOK_TIME_BUDGET_MS) {
        log.info('Time budget reached, stopping early', { processedCount, elapsedMs: Date.now() - startTime });
        break;
      }

      // Hard cap per invocation to avoid massive batches
      if (processedCount >= MAX_MESSAGES_PER_WEBHOOK) {
        log.info('Message limit reached, stopping early', { limit: MAX_MESSAGES_PER_WEBHOOK });
        break;
      }

      try {
        // Get full message
        const message = await getGmailMessage({
          accessToken,
          messageId,
          format: 'full',
        });

        // Parse email
        const parsedEmail = parseGmailEmail(message);

        // Analyze - skip LLM here to keep webhook fast and avoid timeouts
        const verdict = await analyzeEmail(parsedEmail, tenantId, {
          skipLLM: true,
        });

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
            integrationType: 'gmail',
            verdict: verdict.verdict,
            score: verdict.overallScore,
          });
        }

        processedCount++;
      } catch (error) {
        log.error('Failed to process message', error instanceof Error ? error : new Error(String(error)), { messageId });
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
      resourceId: integration.id as string,
      afterState: {
        messagesProcessed: processedCount,
        historyId: historyResult.historyId,
        integrationType: 'gmail',
      },
    });

    return NextResponse.json({
      status: 'processed',
      messagesProcessed: processedCount,
    });
  } catch (error) {
    log.error('Gmail webhook error', error instanceof Error ? error : new Error(String(error)));

    // If Neon is saturated with connection attempts, don't keep failing
    // the webhook and triggering aggressive retries from Gmail. Instead,
    // log and return a soft success so that cron/manual sync can catch up.
    if (
      error instanceof Error &&
      (error.message.includes('Too many connections attempts') ||
        error.message.includes('Failed to acquire permit to connect to the database'))
    ) {
      return NextResponse.json(
        {
          status: 'db_backpressure',
          message: 'Neon connection limit reached; skipping webhook processing',
        },
        { status: 200 }
      );
    }

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

/**
 * Process Gmail notification for domain-wide monitored user
 */
async function processDomainWideGmail(
  configId: string,
  tenantId: string,
  userEmail: string,
  historyId: string
) {
  try {
    // Get new messages from history
    const { messageIds, newHistoryId } = await processGmailHistoryForUser(configId, userEmail, historyId);

    log.info('Domain-wide: Found new messages', { count: messageIds.length, userEmail });

    const accessToken = await getGmailTokenForUser(configId, userEmail);
    let processedCount = 0;

    for (const messageId of messageIds) {
      try {
        const message = await getGmailMessage({ accessToken, messageId, format: 'full' });
        const parsedEmail = parseGmailEmail(message);

        const verdict = await analyzeEmail(parsedEmail, tenantId, {
          skipLLM: true,
        });
        await storeVerdict(tenantId, parsedEmail.messageId, verdict, parsedEmail);

        if (verdict.verdict === 'quarantine' || verdict.verdict === 'block') {
          await sendThreatNotification(tenantId, {
            type: verdict.verdict === 'block' ? 'threat_blocked' : 'threat_quarantined',
            severity: verdict.overallScore >= 80 ? 'critical' : 'warning',
            title: `Email ${verdict.verdict === 'block' ? 'Blocked' : 'Quarantined'}: ${parsedEmail.subject}`,
            message: verdict.explanation || `Threat detected from ${parsedEmail.from.address}`,
            metadata: {
              messageId: parsedEmail.messageId,
              from: parsedEmail.from.address,
              to: userEmail,
              score: verdict.overallScore,
              domainWide: true,
            },
          });
        }

        processedCount++;
      } catch (msgError) {
        log.error('Failed to process domain-wide message', msgError instanceof Error ? msgError : new Error(String(msgError)), { messageId });
      }
    }

    // Update domain user stats
    const domainUser = await getDomainUserByEmail(configId, userEmail);
    if (domainUser) {
      await incrementDomainUserStats(domainUser.id, {
        emailsScanned: processedCount,
        threatsDetected: 0, // Would need to track this properly
      });
    }

    return NextResponse.json({
      status: 'processed',
      messagesProcessed: processedCount,
      domainWide: true,
    });
  } catch (error) {
    log.error('Domain-wide Gmail processing error', error instanceof Error ? error : new Error(String(error)));
    return NextResponse.json({ error: 'Processing failed' }, { status: 500 });
  }
}
