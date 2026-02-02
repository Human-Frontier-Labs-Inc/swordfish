/**
 * OAuth State Manager
 *
 * Provides secure state token management for OAuth flows.
 * Prevents CSRF attacks by validating state tokens on callback.
 * Supports PKCE for enhanced security.
 */

import { randomBytes, createHash } from 'crypto';
import { sql } from '@/lib/db';
import type { IntegrationType } from '@/lib/integrations/types';

export interface OAuthStateParams {
  tenantId: string;
  userId: string;
  provider: IntegrationType;
  redirectUri: string;
  expectedEmail: string; // The email we expect to be connected (user's Swordfish email)
}

export interface OAuthState {
  id: string;
  tenantId: string;
  userId: string;
  provider: IntegrationType;
  stateToken: string;
  codeVerifier: string | null;
  redirectUri: string;
  expectedEmail: string;
  createdAt: Date;
  expiresAt: Date;
}

export interface StateValidationResult {
  valid: boolean;
  state?: OAuthState;
  error?: string;
}

/**
 * Generate a cryptographically secure random string
 */
function generateSecureToken(length: number = 32): string {
  return randomBytes(length).toString('base64url');
}

/**
 * Generate PKCE code verifier and challenge
 * Used for enhanced security in OAuth 2.0 flows
 */
export function generatePKCE(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = generateSecureToken(32);
  const codeChallenge = createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  return { codeVerifier, codeChallenge };
}

/**
 * Create a new OAuth state token for CSRF protection
 *
 * @param params State creation parameters
 * @returns State token and optional PKCE values
 */
export async function createOAuthState(params: OAuthStateParams): Promise<{
  stateToken: string;
  codeVerifier: string;
  codeChallenge: string;
}> {
  const { tenantId, userId, provider, redirectUri, expectedEmail } = params;

  // Generate secure tokens
  const stateToken = generateSecureToken(32);
  const { codeVerifier, codeChallenge } = generatePKCE();

  // Delete any existing state for this tenant/provider combo
  await sql`
    DELETE FROM oauth_states
    WHERE tenant_id = ${tenantId} AND provider = ${provider}
  `;

  // Insert new state
  await sql`
    INSERT INTO oauth_states (
      tenant_id,
      user_id,
      provider,
      state_token,
      code_verifier,
      redirect_uri,
      expected_email,
      expires_at
    ) VALUES (
      ${tenantId},
      ${userId},
      ${provider},
      ${stateToken},
      ${codeVerifier},
      ${redirectUri},
      ${expectedEmail.toLowerCase()},
      NOW() + INTERVAL '10 minutes'
    )
  `;

  return { stateToken, codeVerifier, codeChallenge };
}

/**
 * Validate an OAuth state token on callback
 *
 * @param stateToken The state token from the OAuth callback
 * @returns Validation result with state details if valid
 */
export async function validateOAuthState(stateToken: string): Promise<StateValidationResult> {
  if (!stateToken || typeof stateToken !== 'string') {
    return { valid: false, error: 'Missing or invalid state token' };
  }

  // Look up the state
  const results = await sql`
    SELECT
      id,
      tenant_id,
      user_id,
      provider,
      state_token,
      code_verifier,
      redirect_uri,
      expected_email,
      created_at,
      expires_at,
      used_at
    FROM oauth_states
    WHERE state_token = ${stateToken}
    LIMIT 1
  `;

  if (results.length === 0) {
    return { valid: false, error: 'State token not found - possible CSRF attack' };
  }

  const stateRow = results[0];

  // Check if already used
  if (stateRow.used_at) {
    return { valid: false, error: 'State token already used - possible replay attack' };
  }

  // Check if expired
  const expiresAt = new Date(stateRow.expires_at as string);
  if (expiresAt < new Date()) {
    return { valid: false, error: 'State token expired' };
  }

  // Mark as used (atomic to prevent race conditions)
  const updateResult = await sql`
    UPDATE oauth_states
    SET used_at = NOW()
    WHERE id = ${stateRow.id}
    AND used_at IS NULL
    RETURNING id
  `;

  if (updateResult.length === 0) {
    return { valid: false, error: 'State token was used by another request' };
  }

  return {
    valid: true,
    state: {
      id: stateRow.id as string,
      tenantId: stateRow.tenant_id as string,
      userId: stateRow.user_id as string,
      provider: stateRow.provider as IntegrationType,
      stateToken: stateRow.state_token as string,
      codeVerifier: stateRow.code_verifier as string | null,
      redirectUri: stateRow.redirect_uri as string,
      expectedEmail: stateRow.expected_email as string,
      createdAt: new Date(stateRow.created_at as string),
      expiresAt: new Date(stateRow.expires_at as string),
    },
  };
}

/**
 * Verify that the email from OAuth matches the expected email
 *
 * @param expectedEmail Email we expected (user's Swordfish email)
 * @param actualEmail Email returned by OAuth provider
 * @returns Whether the emails match (case-insensitive)
 */
export function verifyEmailMatch(expectedEmail: string, actualEmail: string): boolean {
  if (!expectedEmail || !actualEmail) {
    return false;
  }

  return expectedEmail.toLowerCase().trim() === actualEmail.toLowerCase().trim();
}

/**
 * Clean up expired OAuth states
 * Should be called periodically (e.g., by a cron job)
 */
export async function cleanupExpiredStates(): Promise<number> {
  const result = await sql`
    DELETE FROM oauth_states
    WHERE expires_at < NOW() - INTERVAL '1 hour'
    OR used_at < NOW() - INTERVAL '1 hour'
  `;

  return result.length;
}
