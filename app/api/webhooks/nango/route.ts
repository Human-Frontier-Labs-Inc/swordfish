/**
 * Nango Webhook Handler
 *
 * Receives webhooks from Nango when OAuth connections are created, updated, or deleted.
 * Updates our integrations table to store the nango_connection_id for token retrieval.
 */

import { NextRequest, NextResponse } from 'next/server';
import { sql } from '@/lib/db';
import { nango, NANGO_INTEGRATIONS } from '@/lib/nango/client';
import { logAuditEvent } from '@/lib/db/audit';
import type { IntegrationType } from '@/lib/integrations/types';

export const maxDuration = 10;
export const dynamic = 'force-dynamic';

/**
 * Map Nango provider config key back to our integration type
 */
function mapNangoProviderToIntegrationType(
  providerConfigKey: string
): IntegrationType | null {
  const entries = Object.entries(NANGO_INTEGRATIONS) as [IntegrationType, string][];
  for (const [type, nangoKey] of entries) {
    if (nangoKey === providerConfigKey) {
      return type;
    }
  }
  return null;
}

interface NangoAuthWebhook {
  type: 'auth';
  operation: 'creation' | 'update' | 'deletion';
  success: boolean;
  connectionId: string;
  providerConfigKey: string;
  provider: string;
  environment: string;
  endUser?: {
    endUserId: string;
    email?: string;
    displayName?: string;
  };
  error?: {
    type: string;
    message: string;
  };
}

interface NangoSyncWebhook {
  type: 'sync';
  // Sync webhooks have different structure - we don't use these yet
}

type NangoWebhookPayload = NangoAuthWebhook | NangoSyncWebhook;

export async function POST(request: NextRequest) {
  try {
    const rawBody = await request.text();
    const body: NangoWebhookPayload = JSON.parse(rawBody);

    // Verify webhook signature
    // Nango sends signature in headers that we can verify
    const headers = Object.fromEntries(request.headers.entries());
    const isValid = nango.verifyIncomingWebhookRequest(rawBody, headers);

    if (!isValid) {
      console.warn('[Nango Webhook] Invalid signature');
      return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
    }

    // Handle auth webhooks (connection events)
    if (body.type === 'auth') {
      return handleAuthWebhook(body as NangoAuthWebhook);
    }

    // Acknowledge other webhook types
    return NextResponse.json({ received: true });
  } catch (error) {
    console.error('[Nango Webhook] Error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

async function handleAuthWebhook(webhook: NangoAuthWebhook) {
  const { operation, success, connectionId, providerConfigKey, endUser, error } = webhook;

  // Map Nango provider to our integration type
  const integrationType = mapNangoProviderToIntegrationType(providerConfigKey);
  if (!integrationType) {
    console.warn(`[Nango Webhook] Unknown provider: ${providerConfigKey}`);
    return NextResponse.json({ received: true });
  }

  // The endUser.endUserId is our tenant ID (we set it when creating the session)
  const tenantId = endUser?.endUserId;
  if (!tenantId) {
    console.warn('[Nango Webhook] Missing endUser.endUserId (tenant ID)');
    return NextResponse.json({ received: true });
  }

  console.log(
    `[Nango Webhook] ${operation} for ${integrationType}, tenant: ${tenantId}, success: ${success}`
  );

  if (operation === 'creation' && success) {
    // New connection created - store the nango_connection_id
    // Note: tenant_id can be a UUID (org) or string (personal_xxx), so we handle both
    await sql`
      INSERT INTO integrations (tenant_id, type, nango_connection_id, status, config)
      VALUES (
        ${tenantId},
        ${integrationType},
        ${connectionId},
        'connected',
        '{"syncEnabled": true}'::jsonb
      )
      ON CONFLICT (tenant_id, type)
      DO UPDATE SET
        nango_connection_id = ${connectionId},
        status = 'connected',
        error_message = NULL,
        config = integrations.config || '{"syncEnabled": true}'::jsonb,
        updated_at = NOW()
    `;

    await logAuditEvent({
      tenantId,
      actorId: null,
      actorEmail: null,
      action: 'INTEGRATION_CONNECTED',
      resourceType: 'integration',
      resourceId: connectionId,
      afterState: { type: integrationType, provider: providerConfigKey },
    });
  } else if (operation === 'creation' && !success) {
    // Connection failed
    await sql`
      UPDATE integrations
      SET
        status = 'error',
        error_message = ${error?.message || 'OAuth connection failed'},
        updated_at = NOW()
      WHERE tenant_id = ${tenantId} AND type = ${integrationType}
    `;

    await logAuditEvent({
      tenantId,
      actorId: null,
      actorEmail: null,
      action: 'INTEGRATION_ERROR',
      resourceType: 'integration',
      afterState: { type: integrationType, error: error?.message },
    });
  } else if (operation === 'deletion') {
    // Connection was deleted (user revoked access or disconnected)
    await sql`
      UPDATE integrations
      SET
        nango_connection_id = NULL,
        status = 'disconnected',
        updated_at = NOW()
      WHERE tenant_id = ${tenantId} AND type = ${integrationType}
    `;

    await logAuditEvent({
      tenantId,
      actorId: null,
      actorEmail: null,
      action: 'INTEGRATION_DISCONNECTED',
      resourceType: 'integration',
      resourceId: connectionId,
      afterState: { type: integrationType },
    });
  } else if (operation === 'update') {
    // Connection was updated (e.g., re-authenticated)
    if (success) {
      await sql`
        UPDATE integrations
        SET
          nango_connection_id = ${connectionId},
          status = 'connected',
          error_message = NULL,
          updated_at = NOW()
        WHERE tenant_id = ${tenantId} AND type = ${integrationType}
      `;
    }
  }

  return NextResponse.json({ received: true });
}
