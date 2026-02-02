/**
 * Gmail OAuth Callback
 *
 * Handles the OAuth code exchange with SECURITY VALIDATIONS:
 * 1. Validates state token (CSRF protection)
 * 2. Verifies the connected email matches the user's Swordfish email
 * 3. Ensures the email isn't already connected by another tenant
 * 4. Stores tokens encrypted with direct OAuth (no Nango)
 */

import { NextRequest, NextResponse } from 'next/server';
import { exchangeGmailCode, getGmailUserProfile, getOrCreateQuarantineLabel } from '@/lib/integrations/gmail';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';
import { createGmailSubscription } from '@/lib/webhooks/subscriptions';
import {
  validateOAuthState,
  verifyEmailMatch,
  storeTokens,
  isEmailAlreadyConnected,
} from '@/lib/oauth';
import { loggers } from '@/lib/logging/logger';

const log = loggers.integration;

const GMAIL_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GMAIL_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const GMAIL_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/api/integrations/gmail/callback';

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const code = searchParams.get('code');
  const state = searchParams.get('state');
  const error = searchParams.get('error');
  const errorDescription = searchParams.get('error_description');

  // Handle OAuth errors from Google
  if (error) {
    log.warn('Gmail OAuth error from Google', { error, errorDescription });
    return NextResponse.redirect(
      new URL(`/dashboard/integrations?error=${encodeURIComponent(errorDescription || error)}`, request.url)
    );
  }

  if (!code || !state) {
    return NextResponse.redirect(
      new URL('/dashboard/integrations?error=Missing code or state', request.url)
    );
  }

  try {
    // SECURITY: Validate state token (CSRF protection)
    const stateValidation = await validateOAuthState(state);

    if (!stateValidation.valid || !stateValidation.state) {
      log.warn('Gmail OAuth state validation failed', {
        error: stateValidation.error,
        state: state.substring(0, 10) + '...',
      });
      return NextResponse.redirect(
        new URL(`/dashboard/integrations?error=${encodeURIComponent(stateValidation.error || 'Invalid state')}`, request.url)
      );
    }

    const { tenantId, userId, expectedEmail, codeVerifier } = stateValidation.state;

    // Exchange code for tokens (with PKCE if used)
    const tokens = await exchangeGmailCode({
      code,
      clientId: GMAIL_CLIENT_ID,
      clientSecret: GMAIL_CLIENT_SECRET,
      redirectUri: GMAIL_REDIRECT_URI,
      codeVerifier: codeVerifier || undefined,
    });

    // Get user profile from Google
    const profile = await getGmailUserProfile(tokens.accessToken);
    const connectedEmail = profile.email.toLowerCase();

    // SECURITY: Verify the connected email matches the expected email
    if (!verifyEmailMatch(expectedEmail, connectedEmail)) {
      log.error('Gmail OAuth email mismatch - SECURITY ALERT', {
        tenantId,
        expectedEmail,
        connectedEmail,
        alertType: 'email_mismatch',
      });

      // Audit this security event
      await logAuditEvent({
        tenantId,
        actorId: null,
        actorEmail: connectedEmail,
        action: 'security.oauth_email_mismatch',
        resourceType: 'integration',
        afterState: {
          expectedEmail,
          connectedEmail,
          provider: 'gmail',
        },
      });

      return NextResponse.redirect(
        new URL(
          `/dashboard/integrations?error=${encodeURIComponent(
            `Email mismatch: You signed in with ${connectedEmail} but your Swordfish account uses ${expectedEmail}. Please try again and sign in with ${expectedEmail}.`
          )}`,
          request.url
        )
      );
    }

    // SECURITY: Check if this email is already connected by another tenant
    const existingTenant = await isEmailAlreadyConnected(connectedEmail, 'gmail', tenantId);
    if (existingTenant) {
      log.error('Gmail OAuth email already connected by another tenant', {
        tenantId,
        connectedEmail,
        existingTenant,
      });

      return NextResponse.redirect(
        new URL(
          `/dashboard/integrations?error=${encodeURIComponent(
            'This Gmail account is already connected to another organization. Please contact support if you believe this is an error.'
          )}`,
          request.url
        )
      );
    }

    // Create quarantine label
    let quarantineLabelId: string | null = null;
    try {
      quarantineLabelId = await getOrCreateQuarantineLabel(tokens.accessToken);
    } catch (e) {
      log.warn('Failed to create quarantine label', { error: e instanceof Error ? e.message : String(e) });
    }

    // Store tokens using the new token manager (encrypted)
    await storeTokens({
      tenantId,
      provider: 'gmail',
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresAt: tokens.expiresAt,
      scopes: tokens.scope,
      connectedEmail,
      providerUserId: profile.email, // Google uses email as the user ID
    });

    // Store additional config (non-token data)
    await sql`
      UPDATE integrations
      SET config = config || ${JSON.stringify({
        historyId: profile.historyId,
        quarantineLabelId,
        syncEnabled: true,
      })}::jsonb,
      updated_at = NOW()
      WHERE tenant_id = ${tenantId} AND type = 'gmail'
    `;

    // Get integration ID for audit and subscription
    const [integration] = await sql`
      SELECT id FROM integrations
      WHERE tenant_id = ${tenantId} AND type = 'gmail'
    `;

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId: null,
      actorEmail: connectedEmail,
      action: 'integration.connect',
      resourceType: 'integration',
      resourceId: integration.id as string,
      afterState: {
        email: connectedEmail,
        integrationType: 'gmail',
        clerkUserId: userId,
        securityValidated: true,
      },
    });

    // Register Gmail push notifications for real-time email detection
    try {
      if (process.env.GOOGLE_PUBSUB_TOPIC) {
        const subscription = await createGmailSubscription({
          integrationId: integration.id as string,
          tenantId,
          accessToken: tokens.accessToken,
        });
        log.info('Gmail push notifications enabled', {
          tenantId,
          expiresAt: subscription.expiresAt,
        });
      }
    } catch (pushError) {
      // Don't fail the connection if push setup fails - cron will still work
      log.warn('Failed to setup push notifications', {
        error: pushError instanceof Error ? pushError.message : String(pushError),
      });
    }

    log.info('Gmail integration connected successfully', {
      tenantId,
      email: connectedEmail,
    });

    return NextResponse.redirect(
      new URL('/dashboard/integrations?success=Gmail connected successfully', request.url)
    );
  } catch (error) {
    log.error('Gmail callback error', error instanceof Error ? error : new Error(String(error)));
    return NextResponse.redirect(
      new URL(
        `/dashboard/integrations?error=${encodeURIComponent(
          error instanceof Error ? error.message : 'Connection failed'
        )}`,
        request.url
      )
    );
  }
}
