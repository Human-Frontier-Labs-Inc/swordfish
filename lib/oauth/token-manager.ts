/**
 * OAuth Token Manager
 *
 * Centralized management of OAuth tokens for Gmail and O365 integrations.
 * Handles:
 * - Token storage (encrypted at rest)
 * - Token retrieval with automatic refresh
 * - Token revocation
 *
 * This replaces Nango's token management with direct control.
 */

import { sql } from '@/lib/db';
import { encrypt, decrypt } from '@/lib/security/encryption';
import { refreshGmailToken } from '@/lib/integrations/gmail';
import { refreshO365Token } from '@/lib/integrations/o365';
import { loggers } from '@/lib/logging/logger';
import type { IntegrationType } from '@/lib/integrations/types';

const log = loggers.integration;

// Refresh tokens 5 minutes before expiry to avoid edge cases
const TOKEN_REFRESH_BUFFER_MS = 5 * 60 * 1000;

export interface StoredTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
  scopes: string;
}

export interface StoreTokensParams {
  tenantId: string;
  provider: IntegrationType;
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
  scopes: string;
  connectedEmail: string;
  providerUserId?: string;
}

/**
 * Store OAuth tokens for an integration (encrypted)
 */
export async function storeTokens(params: StoreTokensParams): Promise<void> {
  const {
    tenantId,
    provider,
    accessToken,
    refreshToken,
    expiresAt,
    scopes,
    connectedEmail,
    providerUserId,
  } = params;

  // Encrypt tokens before storage
  const encryptedAccessToken = encrypt(accessToken);
  const encryptedRefreshToken = encrypt(refreshToken);

  await sql`
    UPDATE integrations
    SET
      oauth_access_token = ${encryptedAccessToken},
      oauth_refresh_token = ${encryptedRefreshToken},
      oauth_token_expires_at = ${expiresAt},
      oauth_scopes = ${scopes},
      connected_email = ${connectedEmail.toLowerCase()},
      connected_email_verified_at = NOW(),
      oauth_provider_user_id = ${providerUserId || null},
      status = 'connected',
      error_message = NULL,
      updated_at = NOW()
    WHERE tenant_id = ${tenantId}
    AND type = ${provider}
  `;

  log.info('Stored OAuth tokens', {
    tenantId,
    provider,
    email: connectedEmail,
    expiresAt: expiresAt.toISOString(),
  });
}

/**
 * Get a fresh access token for an integration
 * Automatically refreshes if expired or about to expire
 */
export async function getAccessToken(
  tenantId: string,
  provider: IntegrationType
): Promise<string> {
  // Get current tokens
  const results = await sql`
    SELECT
      oauth_access_token,
      oauth_refresh_token,
      oauth_token_expires_at,
      oauth_scopes,
      connected_email
    FROM integrations
    WHERE tenant_id = ${tenantId}
    AND type = ${provider}
    AND status = 'connected'
    LIMIT 1
  `;

  if (results.length === 0) {
    throw new Error(`No connected ${provider} integration for tenant ${tenantId}`);
  }

  const integration = results[0];

  if (!integration.oauth_access_token || !integration.oauth_refresh_token) {
    throw new Error(`Integration ${provider} missing OAuth tokens - needs reconnection`);
  }

  // Decrypt tokens
  const accessToken = decrypt(integration.oauth_access_token as string);
  const refreshToken = decrypt(integration.oauth_refresh_token as string);
  const expiresAt = new Date(integration.oauth_token_expires_at as string);

  // Check if token needs refresh
  const now = new Date();
  const needsRefresh = expiresAt.getTime() - now.getTime() < TOKEN_REFRESH_BUFFER_MS;

  if (needsRefresh) {
    log.info('Token expired or expiring soon, refreshing', {
      tenantId,
      provider,
      expiresAt: expiresAt.toISOString(),
    });

    try {
      const newTokens = await refreshTokens(tenantId, provider, refreshToken);
      return newTokens.accessToken;
    } catch (error) {
      log.error('Token refresh failed', error instanceof Error ? error : new Error(String(error)), {
        tenantId,
        provider,
      });

      // Mark integration as needing re-auth
      await sql`
        UPDATE integrations
        SET status = 'error', error_message = 'Token refresh failed - please reconnect', updated_at = NOW()
        WHERE tenant_id = ${tenantId} AND type = ${provider}
      `;

      throw new Error(`Token refresh failed for ${provider} - user needs to reconnect`);
    }
  }

  return accessToken;
}

/**
 * Refresh tokens and store new ones
 */
async function refreshTokens(
  tenantId: string,
  provider: IntegrationType,
  refreshToken: string
): Promise<StoredTokens> {
  let newTokens: { accessToken: string; refreshToken: string; expiresAt: Date; scope: string };

  if (provider === 'gmail') {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
      throw new Error('Google OAuth credentials not configured');
    }

    newTokens = await refreshGmailToken({
      refreshToken,
      clientId,
      clientSecret,
    });
  } else if (provider === 'o365') {
    const clientId = process.env.MICROSOFT_CLIENT_ID;
    const clientSecret = process.env.MICROSOFT_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
      throw new Error('Microsoft OAuth credentials not configured');
    }

    newTokens = await refreshO365Token({
      refreshToken,
      clientId,
      clientSecret,
    });
  } else {
    throw new Error(`Unsupported provider for token refresh: ${provider}`);
  }

  // Store the new tokens
  const encryptedAccessToken = encrypt(newTokens.accessToken);
  const encryptedRefreshToken = encrypt(newTokens.refreshToken);

  await sql`
    UPDATE integrations
    SET
      oauth_access_token = ${encryptedAccessToken},
      oauth_refresh_token = ${encryptedRefreshToken},
      oauth_token_expires_at = ${newTokens.expiresAt},
      oauth_scopes = ${newTokens.scope},
      updated_at = NOW()
    WHERE tenant_id = ${tenantId}
    AND type = ${provider}
  `;

  log.info('Refreshed OAuth tokens', {
    tenantId,
    provider,
    newExpiresAt: newTokens.expiresAt.toISOString(),
  });

  return {
    accessToken: newTokens.accessToken,
    refreshToken: newTokens.refreshToken,
    expiresAt: newTokens.expiresAt,
    scopes: newTokens.scope,
  };
}

/**
 * Get the connected email for an integration
 */
export async function getConnectedEmail(
  tenantId: string,
  provider: IntegrationType
): Promise<string | null> {
  const results = await sql`
    SELECT connected_email
    FROM integrations
    WHERE tenant_id = ${tenantId}
    AND type = ${provider}
    AND status = 'connected'
    LIMIT 1
  `;

  if (results.length === 0) {
    return null;
  }

  return results[0].connected_email as string | null;
}

/**
 * Revoke tokens and disconnect integration
 */
export async function revokeTokens(
  tenantId: string,
  provider: IntegrationType
): Promise<void> {
  // Get current tokens to revoke with provider
  const results = await sql`
    SELECT oauth_access_token, oauth_refresh_token
    FROM integrations
    WHERE tenant_id = ${tenantId}
    AND type = ${provider}
  `;

  if (results.length > 0 && results[0].oauth_access_token) {
    const accessToken = decrypt(results[0].oauth_access_token as string);

    // Attempt to revoke with the provider (best effort)
    try {
      if (provider === 'gmail') {
        await fetch(`https://oauth2.googleapis.com/revoke?token=${accessToken}`, {
          method: 'POST',
        });
      } else if (provider === 'o365') {
        // Microsoft doesn't have a revoke endpoint for user tokens
        // The token will expire naturally
      }
    } catch (error) {
      log.warn('Token revocation with provider failed (non-critical)', {
        tenantId,
        provider,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  // Clear tokens and disconnect
  await sql`
    UPDATE integrations
    SET
      oauth_access_token = NULL,
      oauth_refresh_token = NULL,
      oauth_token_expires_at = NULL,
      connected_email = NULL,
      connected_email_verified_at = NULL,
      oauth_provider_user_id = NULL,
      status = 'disconnected',
      updated_at = NOW()
    WHERE tenant_id = ${tenantId}
    AND type = ${provider}
  `;

  log.info('Revoked OAuth tokens', { tenantId, provider });
}

/**
 * Check if an email is already connected by another tenant
 * Returns the tenant ID if connected, null otherwise
 */
export async function isEmailAlreadyConnected(
  email: string,
  provider: IntegrationType,
  excludeTenantId?: string
): Promise<string | null> {
  let query;

  if (excludeTenantId) {
    query = sql`
      SELECT tenant_id
      FROM integrations
      WHERE type = ${provider}
      AND status = 'connected'
      AND connected_email = ${email.toLowerCase()}
      AND tenant_id != ${excludeTenantId}
      LIMIT 1
    `;
  } else {
    query = sql`
      SELECT tenant_id
      FROM integrations
      WHERE type = ${provider}
      AND status = 'connected'
      AND connected_email = ${email.toLowerCase()}
      LIMIT 1
    `;
  }

  const results = await query;

  if (results.length > 0) {
    return results[0].tenant_id as string;
  }

  return null;
}

/**
 * Find integration by connected email (for webhook routing)
 */
export async function findIntegrationByEmail(
  email: string,
  provider: IntegrationType
): Promise<{ tenantId: string; integrationId: string } | null> {
  const results = await sql`
    SELECT id, tenant_id
    FROM integrations
    WHERE type = ${provider}
    AND status = 'connected'
    AND connected_email = ${email.toLowerCase()}
    LIMIT 1
  `;

  if (results.length === 0) {
    return null;
  }

  return {
    tenantId: results[0].tenant_id as string,
    integrationId: results[0].id as string,
  };
}
