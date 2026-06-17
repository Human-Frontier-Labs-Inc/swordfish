/**
 * Microsoft OAuth Flow
 * Handles Microsoft Graph API authentication for email integration.
 *
 * SECURITY: Tokens are stored ENCRYPTED in the `integrations` table via the
 * direct OAuth token manager (`lib/oauth/token-manager.ts`) under provider
 * type `o365` — the SAME storage the webhook + sync worker read from. The
 * legacy plaintext `provider_connections` path has been removed.
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';
import { storeTokens, revokeTokens } from '@/lib/oauth/token-manager';

const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID || '';
const MICROSOFT_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET || '';
const MICROSOFT_REDIRECT_URI = process.env.MICROSOFT_REDIRECT_URI || '';

const MICROSOFT_AUTH_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
const MICROSOFT_TOKEN_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';

// Provider type used in the `integrations` table (matches token-manager + webhook).
const PROVIDER = 'o365' as const;

// Required scopes for email access
const SCOPES = [
  'openid',
  'profile',
  'email',
  'offline_access',
  'Mail.Read',
  'Mail.ReadBasic',
].join(' ');

/**
 * GET - Initiate OAuth flow or handle callback
 */
export async function GET(request: NextRequest) {
  const { userId, orgId } = await auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const tenantId = orgId || `personal_${userId}`;
  const searchParams = request.nextUrl.searchParams;
  const code = searchParams.get('code');
  const error = searchParams.get('error');
  const state = searchParams.get('state');

  // Handle error from Microsoft
  if (error) {
    const errorDescription = searchParams.get('error_description') || 'Unknown error';
    console.error('Microsoft OAuth error:', error, errorDescription);
    return NextResponse.redirect(
      new URL(`/dashboard/settings?error=microsoft_auth_failed&message=${encodeURIComponent(errorDescription)}`, request.url)
    );
  }

  // Handle callback with authorization code
  if (code) {
    try {
      // Verify state to prevent CSRF
      const expectedState = await getStoredState(tenantId);
      if (state !== expectedState) {
        return NextResponse.redirect(
          new URL('/dashboard/settings?error=invalid_state', request.url)
        );
      }

      // Exchange code for tokens
      const tokenResponse = await fetch(MICROSOFT_TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: MICROSOFT_CLIENT_ID,
          client_secret: MICROSOFT_CLIENT_SECRET,
          code,
          redirect_uri: MICROSOFT_REDIRECT_URI,
          grant_type: 'authorization_code',
          scope: SCOPES,
        }),
      });

      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.json();
        console.error('Token exchange failed:', errorData);
        return NextResponse.redirect(
          new URL('/dashboard/settings?error=token_exchange_failed', request.url)
        );
      }

      const tokens = await tokenResponse.json();

      if (!tokens.access_token || !tokens.refresh_token) {
        // offline_access scope is required to receive a refresh token.
        console.error('Microsoft token response missing access or refresh token');
        return NextResponse.redirect(
          new URL('/dashboard/settings?error=missing_tokens', request.url)
        );
      }

      // Get user email from Microsoft Graph
      const userResponse = await fetch('https://graph.microsoft.com/v1.0/me', {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      });

      const userData = userResponse.ok ? await userResponse.json() : {};
      const email = (userData.mail || userData.userPrincipalName || 'unknown').toLowerCase();
      const providerUserId: string | undefined = userData.id || undefined;

      const expiresAt = new Date(
        Date.now() + (tokens.expires_in ? tokens.expires_in * 1000 : 3600 * 1000)
      );

      // Ensure the integration row exists (storeTokens does an UPDATE).
      await sql`
        INSERT INTO integrations (tenant_id, type, status, config)
        VALUES (${tenantId}, ${PROVIDER}, 'pending', '{}'::jsonb)
        ON CONFLICT (tenant_id, type) DO UPDATE SET
          status = CASE
            WHEN integrations.status = 'connected' THEN integrations.status
            ELSE 'pending'
          END,
          updated_at = NOW()
      `;

      // Store tokens ENCRYPTED in `integrations` (single canonical token store).
      await storeTokens({
        tenantId,
        provider: PROVIDER,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        expiresAt,
        scopes: tokens.scope || SCOPES,
        connectedEmail: email,
        providerUserId,
      });

      // Store non-token config (display name).
      await sql`
        UPDATE integrations
        SET config = config || ${JSON.stringify({ displayName: userData.displayName })}::jsonb,
            updated_at = NOW()
        WHERE tenant_id = ${tenantId} AND type = ${PROVIDER}
      `;

      // Update tenant settings
      await sql`
        UPDATE tenant_settings
        SET settings = jsonb_set(
          COALESCE(settings, '{}'::jsonb),
          '{integrations,microsoftConnected}',
          'true'
        ),
        updated_at = NOW()
        WHERE tenant_id = ${tenantId}
      `;

      // Log audit event
      await logAuditEvent({
        tenantId,
        actorId: userId,
        actorEmail: email,
        action: 'provider.connected',
        resourceType: 'provider',
        resourceId: 'microsoft',
        afterState: { email },
      });

      // Clear stored state
      await clearStoredState(tenantId);

      return NextResponse.redirect(
        new URL('/dashboard/settings?success=microsoft_connected', request.url)
      );
    } catch (error) {
      console.error('Microsoft OAuth callback error:', error);
      return NextResponse.redirect(
        new URL('/dashboard/settings?error=connection_failed', request.url)
      );
    }
  }

  // Initiate OAuth flow
  if (!MICROSOFT_CLIENT_ID || !MICROSOFT_REDIRECT_URI) {
    return NextResponse.json(
      { error: 'Microsoft OAuth not configured' },
      { status: 500 }
    );
  }

  // Generate and store state for CSRF protection
  const oauthState = crypto.randomUUID();
  await storeState(tenantId, oauthState);

  const authUrl = new URL(MICROSOFT_AUTH_URL);
  authUrl.searchParams.set('client_id', MICROSOFT_CLIENT_ID);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', MICROSOFT_REDIRECT_URI);
  authUrl.searchParams.set('scope', SCOPES);
  authUrl.searchParams.set('state', oauthState);
  authUrl.searchParams.set('prompt', 'consent');

  return NextResponse.redirect(authUrl.toString());
}

/**
 * DELETE - Disconnect Microsoft integration
 */
export async function DELETE() {
  const { userId, orgId } = await auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const tenantId = orgId || `personal_${userId}`;

  try {
    // Revoke tokens and disconnect (clears encrypted tokens in `integrations`).
    await revokeTokens(tenantId, PROVIDER);

    // Update tenant settings
    await sql`
      UPDATE tenant_settings
      SET settings = jsonb_set(
        COALESCE(settings, '{}'::jsonb),
        '{integrations,microsoftConnected}',
        'false'
      ),
      updated_at = NOW()
      WHERE tenant_id = ${tenantId}
    `;

    // Log audit event
    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'provider.disconnected',
      resourceType: 'provider',
      resourceId: 'microsoft',
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Failed to disconnect Microsoft:', error);
    return NextResponse.json(
      { error: 'Failed to disconnect' },
      { status: 500 }
    );
  }
}

// Helper functions for state management
async function storeState(tenantId: string, state: string): Promise<void> {
  await sql`
    INSERT INTO oauth_states (tenant_id, state, expires_at)
    VALUES (${tenantId}, ${state}, NOW() + INTERVAL '10 minutes')
    ON CONFLICT (tenant_id)
    DO UPDATE SET state = ${state}, expires_at = NOW() + INTERVAL '10 minutes'
  `;
}

async function getStoredState(tenantId: string): Promise<string | null> {
  const result = await sql`
    SELECT state FROM oauth_states
    WHERE tenant_id = ${tenantId} AND expires_at > NOW()
    LIMIT 1
  `;
  return result.length > 0 ? result[0].state : null;
}

async function clearStoredState(tenantId: string): Promise<void> {
  await sql`
    DELETE FROM oauth_states WHERE tenant_id = ${tenantId}
  `;
}
