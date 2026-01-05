/**
 * Google OAuth Flow
 * Handles Google Workspace authentication for email integration
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || '';

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';

// Required scopes for email access
// Note: gmail.readonly is a restricted scope requiring Google verification
// For initial setup, we use basic scopes. Full Gmail access requires app verification.
const SCOPES = [
  'openid',
  'email',
  'profile',
  // 'https://www.googleapis.com/auth/gmail.readonly', // Requires Google verification
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

  // Handle error from Google
  if (error) {
    console.error('Google OAuth error:', error);
    return NextResponse.redirect(
      new URL(`/dashboard/settings?error=google_auth_failed&message=${encodeURIComponent(error)}`, request.url)
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
      const tokenResponse = await fetch(GOOGLE_TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: GOOGLE_CLIENT_ID,
          client_secret: GOOGLE_CLIENT_SECRET,
          code,
          redirect_uri: GOOGLE_REDIRECT_URI,
          grant_type: 'authorization_code',
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

      // Get user info from Google
      const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      });

      const userData = userResponse.ok ? await userResponse.json() : {};
      const email = userData.email || 'unknown';

      // Store connection in database
      await sql`
        INSERT INTO provider_connections (
          tenant_id,
          provider,
          access_token,
          refresh_token,
          token_expires_at,
          scopes,
          email,
          status,
          metadata
        ) VALUES (
          ${tenantId},
          'google',
          ${tokens.access_token},
          ${tokens.refresh_token || null},
          ${tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000).toISOString() : null},
          ${SCOPES.split(' ')},
          ${email},
          'active',
          ${JSON.stringify({ name: userData.name, picture: userData.picture })}
        )
        ON CONFLICT (tenant_id, provider)
        DO UPDATE SET
          access_token = ${tokens.access_token},
          refresh_token = COALESCE(${tokens.refresh_token}, provider_connections.refresh_token),
          token_expires_at = ${tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000).toISOString() : null},
          email = ${email},
          status = 'active',
          metadata = ${JSON.stringify({ name: userData.name, picture: userData.picture })},
          updated_at = NOW()
      `;

      // Update tenant settings
      await sql`
        UPDATE tenant_settings
        SET settings = jsonb_set(
          COALESCE(settings, '{}'::jsonb),
          '{integrations,googleConnected}',
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
        resourceId: 'google',
        afterState: { email },
      });

      // Clear stored state
      await clearStoredState(tenantId);

      return NextResponse.redirect(
        new URL('/dashboard/settings?success=google_connected', request.url)
      );
    } catch (error) {
      console.error('Google OAuth callback error:', error);
      return NextResponse.redirect(
        new URL('/dashboard/settings?error=connection_failed', request.url)
      );
    }
  }

  // Initiate OAuth flow
  if (!GOOGLE_CLIENT_ID || !GOOGLE_REDIRECT_URI) {
    return NextResponse.json(
      { error: 'Google OAuth not configured' },
      { status: 500 }
    );
  }

  // Generate and store state for CSRF protection
  const oauthState = crypto.randomUUID();
  await storeState(tenantId, oauthState);

  const authUrl = new URL(GOOGLE_AUTH_URL);
  authUrl.searchParams.set('client_id', GOOGLE_CLIENT_ID);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', GOOGLE_REDIRECT_URI);
  authUrl.searchParams.set('scope', SCOPES);
  authUrl.searchParams.set('state', oauthState);
  authUrl.searchParams.set('access_type', 'offline');
  authUrl.searchParams.set('prompt', 'consent');

  return NextResponse.redirect(authUrl.toString());
}

/**
 * DELETE - Disconnect Google integration
 */
export async function DELETE() {
  const { userId, orgId } = await auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const tenantId = orgId || `personal_${userId}`;

  try {
    // Get current token to revoke
    const connection = await sql`
      SELECT access_token FROM provider_connections
      WHERE tenant_id = ${tenantId} AND provider = 'google' AND status = 'active'
      LIMIT 1
    `;

    if (connection.length > 0 && connection[0].access_token) {
      // Revoke token with Google
      try {
        await fetch(`https://oauth2.googleapis.com/revoke?token=${connection[0].access_token}`, {
          method: 'POST',
        });
      } catch {
        // Token revocation failed, but continue with disconnect
        console.warn('Failed to revoke Google token');
      }
    }

    // Update connection status
    await sql`
      UPDATE provider_connections
      SET status = 'revoked', updated_at = NOW()
      WHERE tenant_id = ${tenantId} AND provider = 'google'
    `;

    // Update tenant settings
    await sql`
      UPDATE tenant_settings
      SET settings = jsonb_set(
        COALESCE(settings, '{}'::jsonb),
        '{integrations,googleConnected}',
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
      resourceId: 'google',
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Failed to disconnect Google:', error);
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
