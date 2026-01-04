/**
 * Microsoft OAuth Flow
 * Handles Microsoft Graph API authentication for email integration
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID || '';
const MICROSOFT_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET || '';
const MICROSOFT_REDIRECT_URI = process.env.MICROSOFT_REDIRECT_URI || '';

const MICROSOFT_AUTH_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
const MICROSOFT_TOKEN_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';

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

      // Get user email from Microsoft Graph
      const userResponse = await fetch('https://graph.microsoft.com/v1.0/me', {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      });

      const userData = userResponse.ok ? await userResponse.json() : {};
      const email = userData.mail || userData.userPrincipalName || 'unknown';

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
          'microsoft',
          ${tokens.access_token},
          ${tokens.refresh_token || null},
          ${tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000).toISOString() : null},
          ${SCOPES.split(' ')},
          ${email},
          'active',
          ${JSON.stringify({ displayName: userData.displayName })}
        )
        ON CONFLICT (tenant_id, provider)
        DO UPDATE SET
          access_token = ${tokens.access_token},
          refresh_token = COALESCE(${tokens.refresh_token}, provider_connections.refresh_token),
          token_expires_at = ${tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000).toISOString() : null},
          email = ${email},
          status = 'active',
          metadata = ${JSON.stringify({ displayName: userData.displayName })},
          updated_at = NOW()
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
    // Remove connection
    await sql`
      UPDATE provider_connections
      SET status = 'revoked', updated_at = NOW()
      WHERE tenant_id = ${tenantId} AND provider = 'microsoft'
    `;

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
