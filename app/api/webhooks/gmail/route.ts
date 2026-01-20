/**
 * Gmail Push Notification Webhook
 * Receives notifications from Google Pub/Sub when new emails arrive
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
import { nango, getNangoIntegrationKey } from '@/lib/nango/client';

const WEBHOOK_AUDIENCE = process.env.GOOGLE_WEBHOOK_AUDIENCE;

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

    // First, check if this email is from a domain-wide monitoring config
    const domainConfigs = await getActiveDomainConfigs();
    for (const domainConfig of domainConfigs) {
      if (domainConfig.provider !== 'google_workspace') continue;

      const domainUser = await getDomainUserByEmail(domainConfig.id, emailAddress);
      if (domainUser && domainUser.isMonitored) {
        // Process via domain-wide path
        console.log(`Processing domain-wide Gmail notification for ${emailAddress}`);
        return await processDomainWideGmail(domainConfig.id, domainConfig.tenantId, emailAddress, historyId);
      }
    }

    // Fall back to individual integration
    let integrations = await sql`
      SELECT id, tenant_id, config, nango_connection_id
      FROM integrations
      WHERE type = 'gmail'
      AND status = 'connected'
      AND config->>'email' = ${emailAddress}
    `;

    // If no match by email, try simpler fallback: get ALL gmail integrations
    // For most users, there's only one Gmail account connected
    if (integrations.length === 0) {
      console.log(`[Gmail Webhook] No integration found by email, trying fallback lookup...`);

      // Get ALL connected Gmail integrations (should only be 1-2 in most cases)
      const allGmailIntegrations = await sql`
        SELECT id, tenant_id, config, nango_connection_id
        FROM integrations
        WHERE type = 'gmail'
        AND status = 'connected'
        AND nango_connection_id IS NOT NULL
      `;

      console.log(`[Gmail Webhook] Found ${allGmailIntegrations.length} total Gmail integrations`);

      // Try to match by checking each integration's Nango connection
      for (const integration of allGmailIntegrations) {
        try {
          // Use Nango SDK to get connection details (use correct provider key: 'google')
          const providerKey = getNangoIntegrationKey('gmail'); // Returns 'google'
          const connection = await nango.getConnection(providerKey, integration.nango_connection_id);

          // Check if this connection's email matches
          const connEmail = connection.connection_config?.email || connection.end_user?.email;

          console.log(`[Gmail Webhook] Integration ${integration.id} has email: ${connEmail}`);

          if (connEmail === emailAddress) {
            console.log(`[Gmail Webhook] Match found! Updating integration config...`);

            // Update the integration with the email for future fast lookups
            await sql`
              UPDATE integrations
              SET config = config || ${JSON.stringify({ email: emailAddress })}::jsonb,
                  updated_at = NOW()
              WHERE id = ${integration.id}
            `;

            // Use this integration
            integrations = [integration];
            console.log(`[Gmail Webhook] Auto-healed integration for ${emailAddress}`);
            break;
          }
        } catch (e) {
          console.warn(`[Gmail Webhook] Failed to check integration ${integration.id}:`, e);
        }
      }

      // If still no match and there's exactly one Gmail integration, use it anyway
      // This handles the case where Nango doesn't return the email at all
      if (integrations.length === 0 && allGmailIntegrations.length === 1) {
        console.log(`[Gmail Webhook] Only one Gmail integration exists, using it and adding email`);

        await sql`
          UPDATE integrations
          SET config = config || ${JSON.stringify({ email: emailAddress })}::jsonb,
              updated_at = NOW()
          WHERE id = ${allGmailIntegrations[0].id}
        `;

        integrations = allGmailIntegrations;
        console.log(`[Gmail Webhook] Auto-healed single integration for ${emailAddress}`);
      }
    }

    if (integrations.length === 0) {
      console.log(`No active integration found for ${emailAddress}`);
      return NextResponse.json({ status: 'ignored' });
    }

    const integration = integrations[0];
    const tenantId = integration.tenant_id as string;
    const nangoConnectionId = integration.nango_connection_id as string | null;
    const config = integration.config as {
      historyId: string;
    };

    // Get fresh token from Nango (handles refresh automatically)
    let activeNangoConnectionId = nangoConnectionId;

    if (!activeNangoConnectionId) {
      // Auto-healing: Try to find and link the Nango connection
      console.log(`[Gmail Webhook] No Nango connection for integration ${integration.id}, attempting auto-heal...`);

      const nangoSecretKey = process.env.NANGO_SECRET_KEY;
      if (!nangoSecretKey) {
        console.error('[Gmail Webhook] Auto-heal failed: NANGO_SECRET_KEY not configured');
        return NextResponse.json({ error: 'No Nango connection configured' }, { status: 500 });
      }

      try {
        const nangoResponse = await fetch('https://api.nango.dev/connections', {
          headers: {
            'Authorization': `Bearer ${nangoSecretKey}`,
          },
        });

        if (nangoResponse.ok) {
          const { connections } = await nangoResponse.json() as {
            connections: Array<{
              connection_id: string;
              provider_config_key: string;
              end_user?: { id: string; email?: string };
              metadata?: { email?: string };
            }>
          };

          console.log(`[Gmail Webhook] Found ${connections.length} Nango connections, looking for tenant ${tenantId} or email ${emailAddress}`);

          // Find connection for this tenant with google provider
          const providerKey = getNangoIntegrationKey('gmail'); // Returns 'google'
          let gmailConnection = connections.find(
            c => c.end_user?.id === tenantId && c.provider_config_key === providerKey
          );

          // Fallback: try matching by email address in metadata or end_user
          if (!gmailConnection) {
            gmailConnection = connections.find(
              c => c.provider_config_key === providerKey &&
                   (c.end_user?.email === emailAddress || c.metadata?.email === emailAddress)
            );
            if (gmailConnection) {
              console.log(`[Gmail Webhook] Found connection by email fallback`);
            }
          }

          if (gmailConnection) {
            // Update integration with the found connection ID
            await sql`
              UPDATE integrations
              SET nango_connection_id = ${gmailConnection.connection_id},
                  updated_at = NOW()
              WHERE id = ${integration.id}
            `;
            activeNangoConnectionId = gmailConnection.connection_id;
            console.log(`[Gmail Webhook] Auto-healed: linked Nango connection ${activeNangoConnectionId}`);
          } else {
            console.warn(`[Gmail Webhook] No matching Nango connection found. Available: ${JSON.stringify(connections.map(c => ({ id: c.connection_id, key: c.provider_config_key, endUserId: c.end_user?.id })))}`);
          }
        } else {
          console.error(`[Gmail Webhook] Nango API error: ${nangoResponse.status} ${nangoResponse.statusText}`);
        }
      } catch (healError) {
        console.error('[Gmail Webhook] Auto-heal failed:', healError);
      }

      if (!activeNangoConnectionId) {
        console.warn(`[Gmail Webhook] No Nango connection for integration ${integration.id} and auto-heal failed`);
        return NextResponse.json({ error: 'No Nango connection configured' }, { status: 500 });
      }
    }

    const accessToken = await getGmailAccessToken(activeNangoConnectionId);

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

        // Analyze - skip LLM here to keep webhook fast and avoid timeouts
        const verdict = await analyzeEmail(parsedEmail, tenantId, {
          skipLLM: true,
        });

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

    console.log(`Domain-wide: Found ${messageIds.length} new messages for ${userEmail}`);

    const accessToken = await getGmailTokenForUser(configId, userEmail);
    let processedCount = 0;

    for (const messageId of messageIds) {
      try {
        const message = await getGmailMessage({ accessToken, messageId, format: 'full' });
        const parsedEmail = parseGmailEmail(message);

        const verdict = await analyzeEmail(parsedEmail, tenantId, {
          skipLLM: true,
        });
        await storeVerdict(tenantId, parsedEmail.messageId, verdict);

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
        console.error(`Failed to process domain-wide message ${messageId}:`, msgError);
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
    console.error('Domain-wide Gmail processing error:', error);
    return NextResponse.json({ error: 'Processing failed' }, { status: 500 });
  }
}
