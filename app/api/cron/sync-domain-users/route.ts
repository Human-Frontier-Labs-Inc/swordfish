/**
 * Cron Job: Sync Domain Users
 * Runs periodically to:
 * 1. Sync users from directory (Google Workspace / Azure AD)
 * 2. Renew expiring webhook subscriptions
 *
 * Schedule: Every 6 hours
 */

import { NextRequest, NextResponse } from 'next/server';
import { getActiveDomainConfigs, getUsersWithExpiringWebhooks, updateDomainUserSyncState } from '@/lib/integrations/domain-wide/storage';
import { syncGoogleWorkspaceUsers, setupGmailWatchForAllUsers, getGmailTokenForUser } from '@/lib/integrations/domain-wide/google-workspace';
import { syncMicrosoft365Users, renewMailSubscription } from '@/lib/integrations/domain-wide/microsoft-365';

// Vercel cron config
export const maxDuration = 300; // 5 minutes max
export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  // Verify cron secret
  const cronSecret = request.headers.get('authorization')?.replace('Bearer ', '');
  if (cronSecret !== process.env.CRON_SECRET) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const results = {
    configsSynced: 0,
    usersDiscovered: 0,
    webhooksRenewed: 0,
    errors: [] as string[],
  };

  try {
    // Get all active domain configs
    const configs = await getActiveDomainConfigs();

    for (const config of configs) {
      try {
        // Sync users from directory
        if (config.provider === 'google_workspace') {
          const syncResult = await syncGoogleWorkspaceUsers(config.id);
          results.usersDiscovered += syncResult.usersDiscovered;
          if (syncResult.errors.length > 0) {
            results.errors.push(...syncResult.errors);
          }
        } else if (config.provider === 'microsoft_365') {
          const syncResult = await syncMicrosoft365Users(config.id);
          results.usersDiscovered += syncResult.usersDiscovered;
          if (syncResult.errors.length > 0) {
            results.errors.push(...syncResult.errors);
          }
        }

        results.configsSynced++;
      } catch (error) {
        results.errors.push(`Config ${config.id}: ${error}`);
      }
    }

    // Renew expiring webhooks (expires within 24 hours)
    const expiryThreshold = new Date();
    expiryThreshold.setHours(expiryThreshold.getHours() + 24);

    const expiringUsers = await getUsersWithExpiringWebhooks(expiryThreshold);

    for (const user of expiringUsers) {
      try {
        const config = await getActiveDomainConfigs().then(
          configs => configs.find(c => c.id === user.domainConfigId)
        );

        if (!config) continue;

        if (config.provider === 'google_workspace') {
          // Renew Gmail watch
          const accessToken = await getGmailTokenForUser(config.id, user.email);
          const topicName = process.env.GOOGLE_PUBSUB_TOPIC;

          if (topicName) {
            const response = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/watch`, {
              method: 'POST',
              headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                topicName,
                labelIds: ['INBOX'],
              }),
            });

            if (response.ok) {
              const data = await response.json();
              await updateDomainUserSyncState(user.id, {
                lastHistoryId: data.historyId,
                webhookExpiresAt: new Date(parseInt(data.expiration)),
              });
              results.webhooksRenewed++;
            }
          }
        } else if (config.provider === 'microsoft_365' && user.webhookSubscriptionId) {
          // Renew Graph subscription
          const newExpiry = await renewMailSubscription(config.id, user.webhookSubscriptionId);
          await updateDomainUserSyncState(user.id, {
            webhookExpiresAt: newExpiry,
          });
          results.webhooksRenewed++;
        }
      } catch (error) {
        results.errors.push(`Webhook renewal for ${user.email}: ${error}`);
      }
    }

    return NextResponse.json({
      success: true,
      ...results,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Domain sync cron error:', error);
    return NextResponse.json(
      { error: 'Sync failed', details: String(error) },
      { status: 500 }
    );
  }
}
