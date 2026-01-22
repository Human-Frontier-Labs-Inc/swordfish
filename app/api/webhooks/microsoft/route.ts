/**
 * Microsoft Graph Webhook
 * Receives change notifications from Microsoft Graph API
 */

import { NextRequest, NextResponse } from 'next/server';
import { sql } from '@/lib/db';
import { getO365Email, getO365AccessToken } from '@/lib/integrations/o365';
import { parseGraphEmail } from '@/lib/detection/parser';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import { sendThreatNotification } from '@/lib/notifications/service';
import { logAuditEvent } from '@/lib/db/audit';

interface ChangeNotification {
  value: Array<{
    subscriptionId: string;
    clientState: string;
    changeType: 'created' | 'updated' | 'deleted';
    resource: string;
    resourceData?: {
      '@odata.type': string;
      '@odata.id': string;
      id: string;
    };
    subscriptionExpirationDateTime: string;
    tenantId: string;
  }>;
  validationToken?: string;
}

/**
 * POST - Handle Graph change notification
 */
export async function POST(request: NextRequest) {
  try {
    // Handle validation request from Microsoft
    const url = new URL(request.url);
    const validationToken = url.searchParams.get('validationToken');

    if (validationToken) {
      // Return plain text validation token
      return new NextResponse(validationToken, {
        status: 200,
        headers: { 'Content-Type': 'text/plain' },
      });
    }

    const body: ChangeNotification = await request.json();

    // Also check for validation token in body
    if (body.validationToken) {
      return new NextResponse(body.validationToken, {
        status: 200,
        headers: { 'Content-Type': 'text/plain' },
      });
    }

    // Process each notification
    let totalProcessed = 0;
    let totalThreats = 0;

    for (const notification of body.value) {
      try {
        // Verify client state matches our expected value
        const expectedState = process.env.MICROSOFT_WEBHOOK_SECRET || '';
        if (expectedState && notification.clientState !== expectedState) {
          console.warn('Invalid client state in notification');
          continue;
        }

        // Find the integration by subscription ID
        const integrations = await sql`
          SELECT id, tenant_id, nango_connection_id, config
          FROM integrations
          WHERE type = 'o365'
          AND status = 'connected'
          AND config->>'subscriptionId' = ${notification.subscriptionId}
        `;

        if (integrations.length === 0) {
          console.warn('No integration found for subscription:', notification.subscriptionId);
          continue;
        }

        const integration = integrations[0];
        const tenantId = integration.tenant_id as string;
        const nangoConnectionId = integration.nango_connection_id as string | null;

        // Get fresh access token from Nango
        if (!nangoConnectionId) {
          console.warn(`No Nango connection for integration ${integration.id}`);
          continue;
        }

        const accessToken = await getO365AccessToken(nangoConnectionId);

        // Only process 'created' changes for new emails
        if (notification.changeType !== 'created') {
          continue;
        }

        // Extract message ID from resource path
        const messageId = notification.resourceData?.id || notification.resource.split('/').pop();
        if (!messageId) {
          continue;
        }

        // Check if already processed
        const existing = await sql`
          SELECT id FROM email_verdicts
          WHERE tenant_id = ${tenantId}
          AND message_id LIKE ${`%${messageId}%`}
        `;

        if (existing.length > 0) {
          continue;
        }

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

        totalProcessed++;

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
          totalThreats++;
        }

        // Log audit event
        await logAuditEvent({
          tenantId,
          actorId: null,
          actorEmail: 'system',
          action: 'webhook.microsoft',
          resourceType: 'email',
          resourceId: parsedEmail.messageId,
          afterState: {
            verdict: verdict.verdict,
            score: verdict.overallScore,
          },
        });
      } catch (error) {
        console.error('Error processing Microsoft notification:', error);
      }
    }

    return NextResponse.json({
      processed: totalProcessed,
      threats: totalThreats,
    });
  } catch (error) {
    console.error('Microsoft webhook error:', error);
    // Return 202 Accepted even on errors to prevent excessive retries
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Unknown error' },
      { status: 202 }
    );
  }
}

/**
 * GET - Verify webhook endpoint
 */
export async function GET() {
  return NextResponse.json({
    status: 'healthy',
    endpoint: '/api/webhooks/microsoft',
    type: 'Microsoft Graph Change Notifications',
  });
}
