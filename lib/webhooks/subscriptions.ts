/**
 * Webhook Subscription Management
 * Handles creating, renewing, and managing webhook subscriptions
 */

import { sql } from '@/lib/db';
import { refreshO365Token } from '@/lib/integrations/o365';
import { refreshGmailToken, watchGmailInbox, stopGmailWatch } from '@/lib/integrations/gmail';
import { generateClientState } from './validation';
import { logAuditEvent } from '@/lib/db/audit';

const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID!;
const MICROSOFT_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET!;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const GOOGLE_PUBSUB_TOPIC = process.env.GOOGLE_PUBSUB_TOPIC!;

const GRAPH_API_URL = 'https://graph.microsoft.com/v1.0';

export interface SubscriptionInfo {
  id: string;
  integrationId: string;
  type: 'gmail' | 'o365';
  status: 'active' | 'expired' | 'error';
  expiresAt: Date;
  createdAt: Date;
  webhookUrl: string;
}

/**
 * Create a Microsoft Graph subscription for email notifications
 */
export async function createO365Subscription(params: {
  integrationId: string;
  tenantId: string;
  accessToken: string;
  webhookUrl: string;
}): Promise<{ subscriptionId: string; expiresAt: Date }> {
  const { integrationId, tenantId, accessToken, webhookUrl } = params;

  // Client state is used to verify notifications
  const clientState = generateClientState();

  // Microsoft subscriptions expire after max 4230 minutes (~3 days)
  const expirationDateTime = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000);

  const response = await fetch(`${GRAPH_API_URL}/subscriptions`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      changeType: 'created',
      notificationUrl: webhookUrl,
      resource: 'me/mailFolders(\'Inbox\')/messages',
      expirationDateTime: expirationDateTime.toISOString(),
      clientState: clientState,
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(`Failed to create subscription: ${error.error?.message || 'Unknown error'}`);
  }

  const data = await response.json();

  // Store subscription info in integration config
  await sql`
    UPDATE integrations
    SET config = config || ${JSON.stringify({
      subscriptionId: data.id,
      subscriptionClientState: clientState,
      subscriptionExpiresAt: data.expirationDateTime,
    })}::jsonb,
    updated_at = NOW()
    WHERE id = ${integrationId}
  `;

  // Audit log
  await logAuditEvent({
    tenantId,
    actorId: null, // System action
    actorEmail: null,
    action: 'subscription.create',
    resourceType: 'integration',
    resourceId: integrationId,
    afterState: {
      subscriptionId: data.id,
      expiresAt: data.expirationDateTime,
    },
  });

  return {
    subscriptionId: data.id,
    expiresAt: new Date(data.expirationDateTime),
  };
}

/**
 * Renew a Microsoft Graph subscription
 */
export async function renewO365Subscription(params: {
  subscriptionId: string;
  accessToken: string;
}): Promise<Date> {
  const { subscriptionId, accessToken } = params;

  const expirationDateTime = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000);

  const response = await fetch(`${GRAPH_API_URL}/subscriptions/${subscriptionId}`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      expirationDateTime: expirationDateTime.toISOString(),
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(`Failed to renew subscription: ${error.error?.message || 'Unknown error'}`);
  }

  const data = await response.json();

  return new Date(data.expirationDateTime);
}

/**
 * Delete a Microsoft Graph subscription
 */
export async function deleteO365Subscription(params: {
  subscriptionId: string;
  accessToken: string;
}): Promise<void> {
  const { subscriptionId, accessToken } = params;

  const response = await fetch(`${GRAPH_API_URL}/subscriptions/${subscriptionId}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok && response.status !== 404) {
    const error = await response.json();
    throw new Error(`Failed to delete subscription: ${error.error?.message || 'Unknown error'}`);
  }
}

/**
 * Create a Gmail push notification subscription
 */
export async function createGmailSubscription(params: {
  integrationId: string;
  tenantId: string;
  accessToken: string;
}): Promise<{ historyId: string; expiresAt: Date }> {
  const { integrationId, tenantId, accessToken } = params;

  if (!GOOGLE_PUBSUB_TOPIC) {
    throw new Error('GOOGLE_PUBSUB_TOPIC environment variable not set');
  }

  const result = await watchGmailInbox({
    accessToken,
    topicName: GOOGLE_PUBSUB_TOPIC,
    labelIds: ['INBOX'],
  });

  // Store subscription info
  await sql`
    UPDATE integrations
    SET config = config || ${JSON.stringify({
      historyId: result.historyId,
      watchExpiration: result.expiration.toISOString(),
    })}::jsonb,
    updated_at = NOW()
    WHERE id = ${integrationId}
  `;

  // Audit log
  await logAuditEvent({
    tenantId,
    actorId: null, // System action
    actorEmail: null,
    action: 'subscription.create',
    resourceType: 'integration',
    resourceId: integrationId,
    afterState: {
      historyId: result.historyId,
      expiresAt: result.expiration.toISOString(),
    },
  });

  return {
    historyId: result.historyId,
    expiresAt: result.expiration,
  };
}

/**
 * Delete a Gmail push notification subscription
 */
export async function deleteGmailSubscription(accessToken: string): Promise<void> {
  await stopGmailWatch(accessToken);
}

/**
 * Get all subscriptions for a tenant
 */
export async function getSubscriptions(tenantId: string): Promise<SubscriptionInfo[]> {
  const integrations = await sql`
    SELECT id, type, config, created_at
    FROM integrations
    WHERE tenant_id = ${tenantId}
    AND status = 'connected'
  `;

  const subscriptions: SubscriptionInfo[] = [];

  for (const integration of integrations) {
    const config = integration.config as Record<string, unknown>;
    const type = integration.type as 'gmail' | 'o365';

    if (type === 'o365' && config.subscriptionId) {
      subscriptions.push({
        id: config.subscriptionId as string,
        integrationId: integration.id as string,
        type: 'o365',
        status: new Date(config.subscriptionExpiresAt as string) > new Date() ? 'active' : 'expired',
        expiresAt: new Date(config.subscriptionExpiresAt as string),
        createdAt: new Date(integration.created_at as string),
        webhookUrl: process.env.NEXT_PUBLIC_APP_URL + '/api/webhooks/o365',
      });
    } else if (type === 'gmail' && config.watchExpiration) {
      subscriptions.push({
        id: config.historyId as string,
        integrationId: integration.id as string,
        type: 'gmail',
        status: new Date(config.watchExpiration as string) > new Date() ? 'active' : 'expired',
        expiresAt: new Date(config.watchExpiration as string),
        createdAt: new Date(integration.created_at as string),
        webhookUrl: process.env.NEXT_PUBLIC_APP_URL + '/api/webhooks/gmail',
      });
    }
  }

  return subscriptions;
}

/**
 * Renew all expiring subscriptions
 * Should be called by a cron job every hour
 */
export async function renewExpiringSubscriptions(): Promise<{
  renewed: number;
  failed: number;
  errors: string[];
}> {
  const errors: string[] = [];
  let renewed = 0;
  let failed = 0;

  // Find integrations with subscriptions expiring in the next 24 hours
  const integrations = await sql`
    SELECT id, tenant_id, type, config
    FROM integrations
    WHERE status = 'connected'
    AND (
      (type = 'o365' AND (config->>'subscriptionExpiresAt')::timestamp < NOW() + INTERVAL '24 hours')
      OR
      (type = 'gmail' AND (config->>'watchExpiration')::timestamp < NOW() + INTERVAL '24 hours')
    )
  `;

  for (const integration of integrations) {
    const config = integration.config as Record<string, unknown>;
    const type = integration.type as 'gmail' | 'o365';

    try {
      // Get fresh access token
      let accessToken = config.accessToken as string;
      const tokenExpiresAt = new Date(config.tokenExpiresAt as string);

      if (tokenExpiresAt <= new Date()) {
        if (type === 'o365') {
          const newTokens = await refreshO365Token({
            refreshToken: config.refreshToken as string,
            clientId: MICROSOFT_CLIENT_ID,
            clientSecret: MICROSOFT_CLIENT_SECRET,
          });
          accessToken = newTokens.accessToken;
        } else {
          const newTokens = await refreshGmailToken({
            refreshToken: config.refreshToken as string,
            clientId: GOOGLE_CLIENT_ID,
            clientSecret: GOOGLE_CLIENT_SECRET,
          });
          accessToken = newTokens.accessToken;
        }
      }

      // Renew subscription
      if (type === 'o365' && config.subscriptionId) {
        const newExpiry = await renewO365Subscription({
          subscriptionId: config.subscriptionId as string,
          accessToken,
        });

        await sql`
          UPDATE integrations
          SET config = config || ${JSON.stringify({
            subscriptionExpiresAt: newExpiry.toISOString(),
          })}::jsonb,
          updated_at = NOW()
          WHERE id = ${integration.id}
        `;

        renewed++;
      } else if (type === 'gmail') {
        // Gmail watch needs to be recreated
        const result = await createGmailSubscription({
          integrationId: integration.id as string,
          tenantId: integration.tenant_id as string,
          accessToken,
        });

        renewed++;
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      errors.push(`Integration ${integration.id}: ${errorMsg}`);
      failed++;
    }
  }

  return { renewed, failed, errors };
}
