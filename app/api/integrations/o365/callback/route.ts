/**
 * Microsoft 365 OAuth Callback
 * Handles the OAuth code exchange
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { exchangeO365Code, getO365UserProfile, getOrCreateQuarantineFolder } from '@/lib/integrations/o365';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

const O365_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID!;
const O365_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET!;
const O365_REDIRECT_URI = process.env.MICROSOFT_REDIRECT_URI || 'http://localhost:3000/api/integrations/o365/callback';

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
      console.error('O365 OAuth error:', error, errorDescription);
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
      WHERE tenant_id = ${tenantId} AND state = ${state} AND provider = 'o365' AND expires_at > NOW()
    `;

    if (stateResult.length === 0) {
      return NextResponse.redirect(
        new URL('/dashboard/integrations?error=Invalid or expired state', request.url)
      );
    }

    // Delete used state
    await sql`DELETE FROM integration_states WHERE tenant_id = ${tenantId} AND provider = 'o365'`;

    // Exchange code for tokens
    const tokens = await exchangeO365Code({
      code,
      clientId: O365_CLIENT_ID,
      clientSecret: O365_CLIENT_SECRET,
      redirectUri: O365_REDIRECT_URI,
    });

    // Get user profile
    const profile = await getO365UserProfile(tokens.accessToken);

    // Create quarantine folder
    let quarantineFolderId: string | null = null;
    try {
      quarantineFolderId = await getOrCreateQuarantineFolder(tokens.accessToken);
    } catch (e) {
      console.warn('Failed to create quarantine folder:', e);
    }

    // Build config
    const config = {
      type: 'o365',
      tenantId: profile.tenantId,
      clientId: O365_CLIENT_ID,
      accessToken: tokens.accessToken, // TODO: Encrypt
      refreshToken: tokens.refreshToken, // TODO: Encrypt
      tokenExpiresAt: tokens.expiresAt.toISOString(),
      email: profile.email,
      displayName: profile.displayName,
      syncEnabled: true,
      syncFolders: ['inbox'],
      quarantineFolderId,
    };

    // Upsert integration and get ID
    const [integration] = await sql`
      INSERT INTO integrations (tenant_id, type, status, config, created_at, updated_at)
      VALUES (${tenantId}, 'o365', 'connected', ${JSON.stringify(config)}::jsonb, NOW(), NOW())
      ON CONFLICT (tenant_id, type)
      DO UPDATE SET
        status = 'connected',
        config = ${JSON.stringify(config)}::jsonb,
        error_message = NULL,
        updated_at = NOW()
      RETURNING id
    `;

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'integration.connect',
      resourceType: 'integration',
      resourceId: integration.id as string,
      afterState: { email: profile.email, integrationType: 'o365' },
    });

    return NextResponse.redirect(
      new URL('/dashboard/integrations?success=Microsoft 365 connected successfully', request.url)
    );
  } catch (error) {
    console.error('O365 callback error:', error);
    return NextResponse.redirect(
      new URL(`/dashboard/integrations?error=${encodeURIComponent(error instanceof Error ? error.message : 'Connection failed')}`, request.url)
    );
  }
}
