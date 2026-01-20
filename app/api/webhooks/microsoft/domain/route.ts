/**
 * Microsoft 365 Domain-Wide Webhook Handler
 * Receives change notifications for mail events across all monitored users
 */

import { NextRequest, NextResponse } from 'next/server';
import { getDomainConfig, getDomainUserByEmail, incrementDomainUserStats } from '@/lib/integrations/domain-wide/storage';
import { getMailMessage } from '@/lib/integrations/domain-wide/microsoft-365';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import { parseGraphEmail } from '@/lib/detection/parser';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    // Handle validation request from Graph API
    if (body.validationToken) {
      return new NextResponse(body.validationToken, {
        status: 200,
        headers: { 'Content-Type': 'text/plain' },
      });
    }

    // Process notifications
    const notifications = body.value || [];

    for (const notification of notifications) {
      try {
        const { subscriptionId, clientState, resource, changeType } = notification;

        // clientState contains the configId
        const configId = clientState;
        if (!configId) continue;

        const config = await getDomainConfig(configId);
        if (!config || config.status !== 'active') continue;

        // Extract user email from resource path: /users/{email}/messages/{messageId}
        const resourceMatch = resource.match(/\/users\/([^\/]+)\/messages\/([^\/]+)/);
        if (!resourceMatch) continue;

        const [, userEmail, messageId] = resourceMatch;

        // Get the domain user
        const domainUser = await getDomainUserByEmail(configId, userEmail);
        if (!domainUser || !domainUser.isMonitored) continue;

        // Only process new messages
        if (changeType !== 'created') continue;

        // Fetch the full message
        const message = await getMailMessage(configId, userEmail, messageId);

        // Parse and process the email
        const parsedEmail = parseGraphEmail(message);

        // Analyze the email
        const verdict = await analyzeEmail(parsedEmail, config.tenantId);

        // Store the verdict
        await storeVerdict(config.tenantId, parsedEmail.messageId, verdict);

        // Update stats
        await incrementDomainUserStats(domainUser.id, {
          emailsScanned: 1,
          threatsDetected: verdict.verdict !== 'pass' ? 1 : 0,
        });
      } catch (notificationError) {
        console.error('Error processing M365 domain notification:', notificationError);
      }
    }

    return NextResponse.json({ status: 'ok' });
  } catch (error) {
    console.error('M365 domain webhook error:', error);
    return NextResponse.json({ error: 'Webhook processing failed' }, { status: 500 });
  }
}
