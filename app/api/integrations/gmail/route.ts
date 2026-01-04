/**
 * Gmail Integration API
 * GET - Get auth URL
 * DELETE - Disconnect integration
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getGmailAuthUrl } from '@/lib/integrations/gmail';
import { sql } from '@/lib/db';
import crypto from 'crypto';

const GMAIL_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GMAIL_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/api/integrations/gmail/callback';

/**
 * GET - Generate OAuth URL
 */
export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    // Generate state token for CSRF protection
    const state = crypto.randomBytes(32).toString('hex');

    // Store state in database for verification
    await sql`
      INSERT INTO integration_states (tenant_id, state, provider, expires_at)
      VALUES (${tenantId}, ${state}, 'gmail', NOW() + INTERVAL '15 minutes')
      ON CONFLICT (tenant_id, provider)
      DO UPDATE SET state = ${state}, expires_at = NOW() + INTERVAL '15 minutes'
    `;

    const authUrl = getGmailAuthUrl({
      clientId: GMAIL_CLIENT_ID,
      redirectUri: GMAIL_REDIRECT_URI,
      state,
    });

    return NextResponse.json({ authUrl });
  } catch (error) {
    console.error('Gmail auth URL error:', error);
    return NextResponse.json({ error: 'Failed to generate auth URL' }, { status: 500 });
  }
}

/**
 * DELETE - Disconnect integration
 */
export async function DELETE(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    // Update integration status
    await sql`
      UPDATE integrations
      SET status = 'disconnected', config = config || '{"accessToken": null, "refreshToken": null}'::jsonb, updated_at = NOW()
      WHERE tenant_id = ${tenantId} AND type = 'gmail'
    `;

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Gmail disconnect error:', error);
    return NextResponse.json({ error: 'Failed to disconnect' }, { status: 500 });
  }
}
