/**
 * Domain-Wide User Sync API
 * POST - Trigger manual user sync from directory
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getDomainConfigByTenant } from '@/lib/integrations/domain-wide/storage';
import { syncGoogleWorkspaceUsers, setupGmailWatchForAllUsers } from '@/lib/integrations/domain-wide/google-workspace';
import { syncMicrosoft365Users, setupMailSubscriptionsForAllUsers } from '@/lib/integrations/domain-wide/microsoft-365';
import type { DomainProvider } from '@/lib/integrations/domain-wide/types';

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const body = await request.json();
    const { provider, setupWebhooks } = body as { provider: DomainProvider; setupWebhooks?: boolean };

    if (!provider || !['google_workspace', 'microsoft_365'].includes(provider)) {
      return NextResponse.json(
        { error: 'Invalid provider' },
        { status: 400 }
      );
    }

    const config = await getDomainConfigByTenant(tenantId, provider);

    if (!config) {
      return NextResponse.json(
        { error: 'Domain-wide monitoring not configured for this provider' },
        { status: 404 }
      );
    }

    // Sync users from directory
    let syncResult;
    if (provider === 'google_workspace') {
      syncResult = await syncGoogleWorkspaceUsers(config.id);
    } else {
      syncResult = await syncMicrosoft365Users(config.id);
    }

    // Optionally setup webhooks for all users
    let webhookResult;
    if (setupWebhooks) {
      const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://swordfish-eight.vercel.app';

      if (provider === 'google_workspace') {
        const topicName = process.env.GOOGLE_PUBSUB_TOPIC;
        if (topicName) {
          webhookResult = await setupGmailWatchForAllUsers(config.id, topicName);
        }
      } else {
        const webhookUrl = `${baseUrl}/api/webhooks/microsoft/domain`;
        webhookResult = await setupMailSubscriptionsForAllUsers(config.id, webhookUrl);
      }
    }

    return NextResponse.json({
      success: true,
      sync: syncResult,
      webhooks: webhookResult,
    });
  } catch (error) {
    console.error('Domain-wide sync error:', error);
    return NextResponse.json(
      { error: 'Failed to sync users' },
      { status: 500 }
    );
  }
}
