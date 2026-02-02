/**
 * Gmail Integration API
 *
 * GET/POST - Generate OAuth authorization URL
 * DELETE - Disconnect integration
 *
 * SECURITY: Uses direct OAuth with email verification.
 * The connected Gmail account MUST match the user's Swordfish email.
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth, currentUser } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { getGmailAuthUrl } from '@/lib/integrations/gmail';
import { createOAuthState, isEmailAlreadyConnected, revokeTokens } from '@/lib/oauth';
import { loggers } from '@/lib/logging/logger';

const log = loggers.integration;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || '';

/**
 * GET/POST - Generate Gmail OAuth authorization URL
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

    // Get user's Swordfish email - this is the email that MUST be used for Gmail
    const user = await currentUser();
    const userEmail = user?.emailAddresses?.[0]?.emailAddress;

    if (!userEmail) {
      return NextResponse.json(
        { error: 'No email address found on your account' },
        { status: 400 }
      );
    }

    // Check if this email is already connected by another tenant
    const existingTenant = await isEmailAlreadyConnected(userEmail, 'gmail', tenantId);
    if (existingTenant) {
      log.warn('Email already connected by another tenant', {
        email: userEmail,
        existingTenant,
        requestingTenant: tenantId,
      });
      return NextResponse.json(
        { error: 'This Gmail account is already connected to another organization' },
        { status: 409 }
      );
    }

    // Ensure integration record exists
    await sql`
      INSERT INTO integrations (tenant_id, type, status, config)
      VALUES (${tenantId}, 'gmail', 'pending', '{}'::jsonb)
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
      provider: 'gmail',
      redirectUri: REDIRECT_URI,
      expectedEmail: userEmail,
    });

    // Generate authorization URL with PKCE
    const authUrl = getGmailAuthUrl({
      clientId: GOOGLE_CLIENT_ID,
      redirectUri: REDIRECT_URI,
      state: stateToken,
      codeChallenge,
      loginHint: userEmail, // Pre-fill the email to guide user
    });

    log.info('Gmail OAuth flow initiated', {
      tenantId,
      expectedEmail: userEmail,
    });

    return NextResponse.json({
      authUrl,
      expectedEmail: userEmail,
      message: `Please sign in with ${userEmail} to connect your Gmail account.`,
    });
  } catch (error) {
    log.error('Gmail auth URL generation failed', error instanceof Error ? error : new Error(String(error)));
    return NextResponse.json({ error: 'Failed to start OAuth flow' }, { status: 500 });
  }
}

/**
 * DELETE - Disconnect Gmail integration
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
    await revokeTokens(tenantId, 'gmail');

    log.info('Gmail integration disconnected', { tenantId });

    return NextResponse.json({ success: true });
  } catch (error) {
    log.error('Gmail disconnect failed', error instanceof Error ? error : new Error(String(error)));
    return NextResponse.json({ error: 'Failed to disconnect' }, { status: 500 });
  }
}
