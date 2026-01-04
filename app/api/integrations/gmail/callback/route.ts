/**
 * Gmail OAuth Callback
 * Handles the OAuth code exchange
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { exchangeGmailCode, getGmailUserProfile, getOrCreateQuarantineLabel } from '@/lib/integrations/gmail';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

const GMAIL_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GMAIL_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const GMAIL_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/api/integrations/gmail/callback';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.redirect(new URL('/sign-in', request.url));
    }

    const tenantId = orgId || `personal_${userId}`;
    const searchParams = request.nextUrl.searchParams;

    const code = searchParams.get('code');
    const state = searchParams.get('state');
    const error = searchParams.get('error');
    const errorDescription = searchParams.get('error_description');

    // Handle OAuth errors
    if (error) {
      console.error('Gmail OAuth error:', error, errorDescription);
      return NextResponse.redirect(
        new URL(`/dashboard/integrations?error=${encodeURIComponent(errorDescription || error)}`, request.url)
      );
    }

    if (!code || !state) {
      return NextResponse.redirect(
        new URL('/dashboard/integrations?error=Missing code or state', request.url)
      );
    }

    // Verify state token
    const stateResult = await sql`
      SELECT * FROM integration_states
      WHERE tenant_id = ${tenantId} AND state = ${state} AND provider = 'gmail' AND expires_at > NOW()
    `;

    if (stateResult.length === 0) {
      return NextResponse.redirect(
        new URL('/dashboard/integrations?error=Invalid or expired state', request.url)
      );
    }

    // Delete used state
    await sql`DELETE FROM integration_states WHERE tenant_id = ${tenantId} AND provider = 'gmail'`;

    // Exchange code for tokens
    const tokens = await exchangeGmailCode({
      code,
      clientId: GMAIL_CLIENT_ID,
      clientSecret: GMAIL_CLIENT_SECRET,
      redirectUri: GMAIL_REDIRECT_URI,
    });

    // Get user profile
    const profile = await getGmailUserProfile(tokens.accessToken);

    // Create quarantine label
    let quarantineLabelId: string | null = null;
    try {
      quarantineLabelId = await getOrCreateQuarantineLabel(tokens.accessToken);
    } catch (e) {
      console.warn('Failed to create quarantine label:', e);
    }

    // Build config
    const config = {
      type: 'gmail',
      clientId: GMAIL_CLIENT_ID,
      accessToken: tokens.accessToken, // TODO: Encrypt
      refreshToken: tokens.refreshToken, // TODO: Encrypt
      tokenExpiresAt: tokens.expiresAt.toISOString(),
      email: profile.email,
      historyId: profile.historyId,
      syncEnabled: true,
      quarantineLabelId,
    };

    // Upsert integration
    await sql`
      INSERT INTO integrations (tenant_id, type, status, config, created_at, updated_at)
      VALUES (${tenantId}, 'gmail', 'connected', ${JSON.stringify(config)}::jsonb, NOW(), NOW())
      ON CONFLICT (tenant_id, type)
      DO UPDATE SET
        status = 'connected',
        config = ${JSON.stringify(config)}::jsonb,
        error_message = NULL,
        updated_at = NOW()
    `;

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'integration.connect',
      resourceType: 'integration',
      resourceId: 'gmail',
      afterState: { email: profile.email },
    });

    return NextResponse.redirect(
      new URL('/dashboard/integrations?success=Gmail connected successfully', request.url)
    );
  } catch (error) {
    console.error('Gmail callback error:', error);
    return NextResponse.redirect(
      new URL(`/dashboard/integrations?error=${encodeURIComponent(error instanceof Error ? error.message : 'Connection failed')}`, request.url)
    );
  }
}
