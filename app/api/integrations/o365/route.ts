/**
 * Microsoft 365 Integration API
 * POST - Create Nango session for OAuth flow
 * DELETE - Disconnect integration
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth, currentUser } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { createNangoSession, nango } from '@/lib/nango/client';

/**
 * POST - Create Nango session for O365 OAuth
 * Returns a session token that the frontend uses to open Nango's Connect UI
 */
export async function POST(_request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    // Get user email for display in Nango UI (optional but nice)
    const user = await currentUser();
    const userEmail = user?.emailAddresses?.[0]?.emailAddress;

    // Create Nango session - this handles CSRF, state, etc.
    const session = await createNangoSession(tenantId, 'o365', userEmail);

    return NextResponse.json({
      authUrl: session.connectLink,
      sessionToken: session.sessionToken,
      expiresAt: session.expiresAt,
    });
  } catch (error) {
    console.error('O365 Nango session error:', error);
    return NextResponse.json({ error: 'Failed to create session' }, { status: 500 });
  }
}

/**
 * GET - Legacy auth URL endpoint (deprecated, use POST for Nango)
 * Kept for backwards compatibility during migration
 */
export async function GET(request: NextRequest) {
  // Redirect to POST behavior by returning Nango session
  return POST(request);
}

/**
 * DELETE - Disconnect integration
 */
export async function DELETE() {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    // Get the Nango connection ID to delete
    const [integration] = await sql`
      SELECT nango_connection_id FROM integrations
      WHERE tenant_id = ${tenantId} AND type = 'o365'
    `;

    // Delete from Nango if we have a connection
    if (integration?.nango_connection_id) {
      try {
        await nango.deleteConnection('outlook', integration.nango_connection_id);
      } catch (nangoError) {
        // Log but don't fail - connection might already be deleted
        console.warn('Nango delete warning:', nangoError);
      }
    }

    // Update local integration status
    await sql`
      UPDATE integrations
      SET status = 'disconnected', nango_connection_id = NULL, updated_at = NOW()
      WHERE tenant_id = ${tenantId} AND type = 'o365'
    `;

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('O365 disconnect error:', error);
    return NextResponse.json({ error: 'Failed to disconnect' }, { status: 500 });
  }
}
