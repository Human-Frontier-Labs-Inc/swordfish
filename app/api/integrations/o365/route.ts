/**
 * Microsoft 365 Integration API
 *
 * GET/POST - Generate OAuth authorization URL
 * DELETE - Disconnect integration
 *
 * SECURITY: Uses direct OAuth with email verification.
 * The connected email MUST match the user's Swordfish email.
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth, currentUser } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { getO365AuthUrl } from '@/lib/integrations/o365';
import { createOAuthState, isEmailAlreadyConnected, revokeTokens } from '@/lib/oauth';
import { loggers } from '@/lib/logging/logger';

const log = loggers.integration;

const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID || '';
const REDIRECT_URI = process.env.MICROSOFT_REDIRECT_URI || '';

/**
 * GET/POST - Generate O365 OAuth authorization URL
 *
 * Returns an auth URL that the frontend opens for the user.
 * The state token prevents CSRF and validates email on callback.
 */
export async function GET(request: NextRequest) {
  return handleAuthRequest(request);
}

export async function POST(request: NextRequest) {
  return handleAuthRequest(request);
}

async function handleAuthRequest(_request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    // Get user's Swordfish email - this is the email that MUST be used for O365
    const user = await currentUser();
    const userEmail = user?.emailAddresses?.[0]?.emailAddress;

    if (!userEmail) {
      return NextResponse.json(
        { error: 'No email address found on your account' },
        { status: 400 }
      );
    }

    // Check if this email is already connected by another tenant
    const existingTenant = await isEmailAlreadyConnected(userEmail, 'o365', tenantId);
    if (existingTenant) {
      log.warn('Email already connected by another tenant', {
        email: userEmail,
        existingTenant,
        requestingTenant: tenantId,
      });
      return NextResponse.json(
        { error: 'This Microsoft account is already connected to another organization' },
        { status: 409 }
      );
    }

    // Ensure integration record exists
    await sql`
      INSERT INTO integrations (tenant_id, type, status, config)
      VALUES (${tenantId}, 'o365', 'pending', '{}'::jsonb)
      ON CONFLICT (tenant_id, type) DO UPDATE SET
        status = CASE
          WHEN integrations.status = 'connected' THEN integrations.status
          ELSE 'pending'
        END,
        updated_at = NOW()
    `;

    // Create OAuth state with email validation
    const { stateToken, codeChallenge } = await createOAuthState({
      tenantId,
      userId,
      provider: 'o365',
      redirectUri: REDIRECT_URI,
      expectedEmail: userEmail,
    });

    // Generate authorization URL with PKCE
    const authUrl = getO365AuthUrl({
      clientId: MICROSOFT_CLIENT_ID,
      redirectUri: REDIRECT_URI,
      state: stateToken,
      codeChallenge,
      loginHint: userEmail, // Pre-fill the email to guide user
    });

    log.info('O365 OAuth flow initiated', {
      tenantId,
      expectedEmail: userEmail,
    });

    return NextResponse.json({
      authUrl,
      expectedEmail: userEmail,
      message: `Please sign in with ${userEmail} to connect your Microsoft account.`,
    });
  } catch (error) {
    log.error('O365 auth URL generation failed', error instanceof Error ? error : new Error(String(error)));
    return NextResponse.json({ error: 'Failed to start OAuth flow' }, { status: 500 });
  }
}

/**
 * DELETE - Disconnect O365 integration
 *
 * Revokes tokens and clears connection data.
 */
export async function DELETE() {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    // Revoke tokens and disconnect
    await revokeTokens(tenantId, 'o365');

    log.info('O365 integration disconnected', { tenantId });

    return NextResponse.json({ success: true });
  } catch (error) {
    log.error('O365 disconnect failed', error instanceof Error ? error : new Error(String(error)));
    return NextResponse.json({ error: 'Failed to disconnect' }, { status: 500 });
  }
}
