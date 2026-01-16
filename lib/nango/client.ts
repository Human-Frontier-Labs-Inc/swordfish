/**
 * Nango Client
 *
 * Centralized Nango SDK instance for OAuth token management.
 * Nango handles OAuth flows, secure token storage, and automatic refresh.
 */

import { Nango } from '@nangohq/node';
import type { IntegrationType } from '@/lib/integrations/types';

// Lazy-initialized Nango client to prevent build-time initialization errors
let _nango: Nango | null = null;

function getNangoClient(): Nango {
  if (!_nango) {
    if (!process.env.NANGO_SECRET_KEY) {
      throw new Error('NANGO_SECRET_KEY is not configured');
    }
    _nango = new Nango({
      secretKey: process.env.NANGO_SECRET_KEY,
    });
  }
  return _nango;
}

// Proxy for backward compatibility - lazily initializes on first use
export const nango = new Proxy({} as Nango, {
  get(_, prop) {
    return (getNangoClient() as unknown as Record<string | symbol, unknown>)[prop];
  },
});

/**
 * Maps our internal integration types to Nango provider config keys.
 * These must match the integration IDs configured in the Nango dashboard.
 */
export const NANGO_INTEGRATIONS = {
  gmail: 'google',
  o365: 'outlook',
  // SMTP doesn't use OAuth, so no Nango integration needed
} as const satisfies Partial<Record<IntegrationType, string>>;

export type NangoIntegrationType = keyof typeof NANGO_INTEGRATIONS;

/**
 * Check if an integration type uses Nango for OAuth
 */
export function usesNango(type: IntegrationType): type is NangoIntegrationType {
  return type in NANGO_INTEGRATIONS;
}

/**
 * Get Nango provider config key for an integration type
 */
export function getNangoIntegrationKey(type: NangoIntegrationType): string {
  return NANGO_INTEGRATIONS[type];
}

/**
 * Get a fresh access token from Nango for an integration.
 * Nango automatically handles token refresh if needed.
 *
 * @param type - Integration type (gmail or o365)
 * @param connectionId - Nango connection ID (stored in integrations.nango_connection_id)
 * @returns Fresh access token
 */
export async function getAccessToken(
  type: NangoIntegrationType,
  connectionId: string
): Promise<string> {
  const providerConfigKey = getNangoIntegrationKey(type);
  const connection = await nango.getConnection(providerConfigKey, connectionId);

  // Nango returns credentials based on auth type
  // For OAuth2, this includes access_token
  const credentials = connection.credentials as { access_token: string };
  return credentials.access_token;
}

/**
 * Create a connect session for the frontend to initiate OAuth flow.
 * Returns a session token that the frontend uses with Nango's Connect UI.
 *
 * @param tenantId - Your tenant/org ID (becomes Nango's end_user.id)
 * @param integrationType - Which integration to allow
 * @param userEmail - Optional email for display in Nango UI
 */
export async function createNangoSession(
  tenantId: string,
  integrationType: NangoIntegrationType,
  userEmail?: string
) {
  const providerConfigKey = getNangoIntegrationKey(integrationType);

  const session = await nango.createConnectSession({
    end_user: {
      id: tenantId,
      ...(userEmail && { email: userEmail }),
    },
    allowed_integrations: [providerConfigKey],
  });

  // Build connect link from session token
  const connectLink = `https://connect.nango.dev/?session_token=${session.data.token}`;

  return {
    sessionToken: session.data.token,
    connectLink,
    expiresAt: session.data.expires_at,
  };
}
