/**
 * Register Gmail Push Notifications
 * Registers push notifications for an existing Gmail integration
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { refreshGmailToken } from '@/lib/integrations/gmail';
import { createGmailSubscription } from '@/lib/webhooks/subscriptions';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    // Check if GOOGLE_PUBSUB_TOPIC is configured
    if (!process.env.GOOGLE_PUBSUB_TOPIC) {
      return NextResponse.json(
        { error: 'Push notifications not configured - GOOGLE_PUBSUB_TOPIC not set' },
        { status: 400 }
      );
    }

    // Get Gmail integration
    const integrations = await sql`
      SELECT id, config
      FROM integrations
      WHERE tenant_id = ${tenantId}
      AND type = 'gmail'
      AND status = 'connected'
    `;

    if (integrations.length === 0) {
      return NextResponse.json(
        { error: 'No connected Gmail integration found' },
        { status: 404 }
      );
    }

    const integration = integrations[0];
    const config = integration.config as {
      accessToken: string;
      refreshToken: string;
      tokenExpiresAt: string;
      watchExpiration?: string;
    };

    // Check if already has active push subscription
    if (config.watchExpiration && new Date(config.watchExpiration) > new Date()) {
      return NextResponse.json({
        status: 'already_active',
        expiresAt: config.watchExpiration,
        message: 'Push notifications already active',
      });
    }

    // Refresh token if needed
    let accessToken = config.accessToken;
    if (new Date(config.tokenExpiresAt) <= new Date()) {
      const newTokens = await refreshGmailToken({
        refreshToken: config.refreshToken,
        clientId: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
      });
      accessToken = newTokens.accessToken;

      // Update tokens in database
      await sql`
        UPDATE integrations
        SET config = config || ${JSON.stringify({
          accessToken: newTokens.accessToken,
          tokenExpiresAt: newTokens.expiresAt.toISOString(),
        })}::jsonb,
        updated_at = NOW()
        WHERE id = ${integration.id}
      `;
    }

    // Register push notifications
    const subscription = await createGmailSubscription({
      integrationId: integration.id as string,
      tenantId,
      accessToken,
    });

    return NextResponse.json({
      status: 'registered',
      expiresAt: subscription.expiresAt.toISOString(),
      message: 'Push notifications registered successfully',
    });
  } catch (error) {
    console.error('Failed to register Gmail push:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Registration failed' },
      { status: 500 }
    );
  }
}
