/**
 * Microsoft 365 OAuth Callback
 *
 * Handles the OAuth code exchange with SECURITY VALIDATIONS:
 * 1. Validates state token (CSRF protection)
 * 2. Verifies the connected email matches the user's Swordfish email
 * 3. Ensures the email isn't already connected by another tenant
 * 4. Stores tokens encrypted with direct OAuth (no Nango)
 */

import { NextRequest, NextResponse } from 'next/server';
import { exchangeO365Code, getO365UserProfile, getOrCreateQuarantineFolder } from '@/lib/integrations/o365';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';
import { createO365Subscription } from '@/lib/webhooks/subscriptions';
import {
  validateOAuthState,
  verifyEmailMatch,
  storeTokens,
  isEmailAlreadyConnected,
} from '@/lib/oauth';
import { loggers } from '@/lib/logging/logger';

const log = loggers.integration;

const O365_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID!;
const O365_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET!;
const O365_REDIRECT_URI = process.env.MICROSOFT_REDIRECT_URI || 'http://localhost:3000/api/integrations/o365/callback';

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const code = searchParams.get('code');
  const state = searchParams.get('state');
  const error = searchParams.get('error');
  const errorDescription = searchParams.get('error_description');

  // Handle OAuth errors from Microsoft
  if (error) {
    log.warn('O365 OAuth error from Microsoft', { error, errorDescription });
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
      log.warn('O365 OAuth state validation failed', {
        error: stateValidation.error,
        state: state.substring(0, 10) + '...',
      });
      return NextResponse.redirect(
        new URL(`/dashboard/integrations?error=${encodeURIComponent(stateValidation.error || 'Invalid state')}`, request.url)
      );
    }

    const { tenantId, userId, expectedEmail, codeVerifier } = stateValidation.state;

    // Exchange code for tokens (with PKCE if used)
    const tokens = await exchangeO365Code({
      code,
      clientId: O365_CLIENT_ID,
      clientSecret: O365_CLIENT_SECRET,
      redirectUri: O365_REDIRECT_URI,
      codeVerifier: codeVerifier || undefined,
    });

    // Get user profile from Microsoft Graph
    const profile = await getO365UserProfile(tokens.accessToken);
    const connectedEmail = profile.email.toLowerCase();

    // SECURITY: Verify the connected email matches the expected email
    if (!verifyEmailMatch(expectedEmail, connectedEmail)) {
      log.error('O365 OAuth email mismatch - SECURITY ALERT', {
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
          provider: 'o365',
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
    const existingTenant = await isEmailAlreadyConnected(connectedEmail, 'o365', tenantId);
    if (existingTenant) {
      log.error('O365 OAuth email already connected by another tenant', {
        tenantId,
        connectedEmail,
        existingTenant,
      });

      return NextResponse.redirect(
        new URL(
          `/dashboard/integrations?error=${encodeURIComponent(
            'This Microsoft account is already connected to another organization. Please contact support if you believe this is an error.'
          )}`,
          request.url
        )
      );
    }

    // Create quarantine folder
    let quarantineFolderId: string | null = null;
    try {
      quarantineFolderId = await getOrCreateQuarantineFolder(tokens.accessToken);
    } catch (e) {
      log.warn('Failed to create quarantine folder', { error: e instanceof Error ? e.message : String(e) });
    }

    // Store tokens using the new token manager (encrypted)
    await storeTokens({
      tenantId,
      provider: 'o365',
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresAt: tokens.expiresAt,
      scopes: tokens.scope,
      connectedEmail,
      providerUserId: profile.id,
    });

    // Store additional config (non-token data)
    await sql`
      UPDATE integrations
      SET config = config || ${JSON.stringify({
        microsoftTenantId: profile.tenantId,
        displayName: profile.displayName,
        quarantineFolderId,
        syncEnabled: true,
        syncFolders: ['inbox'],
      })}::jsonb,
      updated_at = NOW()
      WHERE tenant_id = ${tenantId} AND type = 'o365'
    `;

    // Get integration ID for audit and subscription
    const [integration] = await sql`
      SELECT id FROM integrations
      WHERE tenant_id = ${tenantId} AND type = 'o365'
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
        integrationType: 'o365',
        clerkUserId: userId,
        securityValidated: true,
      },
    });

    // Register Microsoft Graph webhook for real-time email detection
    try {
      const webhookUrl = `${process.env.NEXT_PUBLIC_APP_URL}/api/webhooks/o365`;
      const subscription = await createO365Subscription({
        integrationId: integration.id as string,
        tenantId,
        accessToken: tokens.accessToken,
        webhookUrl,
      });
      log.info('O365 push notifications enabled', {
        tenantId,
        expiresAt: subscription.expiresAt,
      });
    } catch (pushError) {
      // Don't fail the connection if push setup fails - cron will still work
      log.warn('Failed to setup push notifications', {
        error: pushError instanceof Error ? pushError.message : String(pushError),
      });
    }

    log.info('O365 integration connected successfully', {
      tenantId,
      email: connectedEmail,
    });

    return NextResponse.redirect(
      new URL('/dashboard/integrations?success=Microsoft 365 connected successfully', request.url)
    );
  } catch (error) {
    log.error('O365 callback error', error instanceof Error ? error : new Error(String(error)));
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
