/**
 * Webhook Signature Validation
 * Ensures webhooks are from legitimate sources
 */

import crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';

// HIGH-4 FIX: Prevent ALLOW_UNSIGNED_WEBHOOKS from being set in production
// This env var is ONLY for development/testing - never production
if (process.env.NODE_ENV === 'production' && process.env.ALLOW_UNSIGNED_WEBHOOKS === 'true') {
  console.error(
    '\n\n' +
    '='.repeat(80) + '\n' +
    'SECURITY CRITICAL ERROR\n' +
    '='.repeat(80) + '\n' +
    'ALLOW_UNSIGNED_WEBHOOKS=true is set in production!\n' +
    'This allows attackers to send forged webhook requests.\n' +
    'Remove this environment variable immediately.\n' +
    '='.repeat(80) + '\n\n'
  );
  // Don't exit the process, but log the critical error
  // In production, this will be visible in logs for immediate attention
}

// Singleton OAuth2Client for Google token verification
let googleOAuth2Client: OAuth2Client | null = null;

function getGoogleOAuth2Client(): OAuth2Client {
  if (!googleOAuth2Client) {
    googleOAuth2Client = new OAuth2Client();
  }
  return googleOAuth2Client;
}

/**
 * Validate Google Pub/Sub push notification
 * SECURITY: Now properly verifies JWT signature against Google's public keys
 * @see https://cloud.google.com/pubsub/docs/push#authentication
 */
export async function validateGooglePubSub(params: {
  authorizationHeader: string | null;
  expectedAudience?: string;
}): Promise<{ valid: boolean; email?: string; error?: string }> {
  const { authorizationHeader, expectedAudience } = params;

  // Check for Bearer token
  if (!authorizationHeader?.startsWith('Bearer ')) {
    // In development, allow unsigned requests
    if (process.env.NODE_ENV === 'development' && process.env.ALLOW_UNSIGNED_WEBHOOKS === 'true') {
      return { valid: true, email: 'development@test.local' };
    }
    return { valid: false, error: 'Missing or invalid Authorization header' };
  }

  const token = authorizationHeader.substring(7);

  try {
    const client = getGoogleOAuth2Client();

    // SECURITY FIX: Verify the JWT signature using Google's public keys
    // This ensures the token was actually issued by Google and not forged
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: expectedAudience, // Will throw if audience doesn't match
    });

    const payload = ticket.getPayload();

    if (!payload) {
      return { valid: false, error: 'Invalid token payload' };
    }

    // Verify issuer is Google
    if (!payload.iss?.includes('accounts.google.com')) {
      return { valid: false, error: `Invalid issuer: ${payload.iss}` };
    }

    // Additional claim validation
    const now = Math.floor(Date.now() / 1000);

    if (payload.exp && payload.exp < now) {
      return { valid: false, error: 'Token expired' };
    }

    if (payload.iat && payload.iat > now + 60) {
      return { valid: false, error: 'Token issued in the future' };
    }

    return {
      valid: true,
      email: payload.email || payload.sub,
    };
  } catch (error) {
    // Log verification failures for security monitoring
    console.warn('[Webhook Validation] Google JWT verification failed:', error instanceof Error ? error.message : 'Unknown error');

    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Token validation failed',
    };
  }
}

/**
 * Validate Microsoft Graph webhook notification
 * Microsoft uses clientState for validation
 * @see https://learn.microsoft.com/en-us/graph/webhooks#notification-validation
 */
export function validateMicrosoftGraph(params: {
  clientState: string;
  expectedClientState: string;
}): { valid: boolean; error?: string } {
  const { clientState, expectedClientState } = params;

  if (!expectedClientState) {
    // No client state configured, skip validation
    return { valid: true };
  }

  if (!clientState) {
    return { valid: false, error: 'Missing clientState in notification' };
  }

  // Use timing-safe comparison to prevent timing attacks
  const clientStateBuffer = Buffer.from(clientState);
  const expectedBuffer = Buffer.from(expectedClientState);

  if (clientStateBuffer.length !== expectedBuffer.length) {
    return { valid: false, error: 'Invalid clientState' };
  }

  if (!crypto.timingSafeEqual(clientStateBuffer, expectedBuffer)) {
    return { valid: false, error: 'Invalid clientState' };
  }

  return { valid: true };
}

/**
 * Generate a secure client state for Microsoft Graph subscriptions
 */
export function generateClientState(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Validate HMAC signature for generic webhooks
 * Used for custom webhook integrations
 */
export function validateHmacSignature(params: {
  payload: string;
  signature: string;
  secret: string;
  algorithm?: 'sha256' | 'sha1';
}): { valid: boolean; error?: string } {
  const { payload, signature, secret, algorithm = 'sha256' } = params;

  if (!signature) {
    return { valid: false, error: 'Missing signature' };
  }

  if (!secret) {
    return { valid: false, error: 'Webhook secret not configured' };
  }

  try {
    const expectedSignature = crypto
      .createHmac(algorithm, secret)
      .update(payload)
      .digest('hex');

    // Handle signatures that may have prefix like "sha256="
    const cleanSignature = signature.replace(/^(sha256=|sha1=)/, '');

    const signatureBuffer = Buffer.from(cleanSignature, 'hex');
    const expectedBuffer = Buffer.from(expectedSignature, 'hex');

    if (signatureBuffer.length !== expectedBuffer.length) {
      return { valid: false, error: 'Invalid signature length' };
    }

    if (!crypto.timingSafeEqual(signatureBuffer, expectedBuffer)) {
      return { valid: false, error: 'Invalid signature' };
    }

    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Signature validation failed',
    };
  }
}

/**
 * Rate limiting for webhook endpoints
 * Returns true if the request should be rate limited
 */
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();

export function checkRateLimit(params: {
  key: string;
  maxRequests?: number;
  windowMs?: number;
}): { limited: boolean; remaining: number; resetAt: Date } {
  const { key, maxRequests = 100, windowMs = 60000 } = params;
  const now = Date.now();

  let entry = rateLimitMap.get(key);

  if (!entry || entry.resetAt < now) {
    entry = { count: 0, resetAt: now + windowMs };
    rateLimitMap.set(key, entry);
  }

  entry.count++;

  // Clean up old entries periodically
  if (rateLimitMap.size > 10000) {
    for (const [k, v] of rateLimitMap.entries()) {
      if (v.resetAt < now) {
        rateLimitMap.delete(k);
      }
    }
  }

  return {
    limited: entry.count > maxRequests,
    remaining: Math.max(0, maxRequests - entry.count),
    resetAt: new Date(entry.resetAt),
  };
}
