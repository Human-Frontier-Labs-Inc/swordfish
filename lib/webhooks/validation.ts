/**
 * Webhook Signature Validation
 * Ensures webhooks are from legitimate sources
 */

import crypto from 'crypto';

/**
 * Validate Google Pub/Sub push notification
 * Google Cloud Pub/Sub uses OIDC tokens for authentication
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
    // Decode JWT without verification to get header
    const [headerB64, payloadB64] = token.split('.');
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());

    // Verify claims
    const now = Math.floor(Date.now() / 1000);

    if (payload.exp && payload.exp < now) {
      return { valid: false, error: 'Token expired' };
    }

    if (payload.iat && payload.iat > now + 60) {
      return { valid: false, error: 'Token issued in the future' };
    }

    // Check audience if provided
    if (expectedAudience && payload.aud !== expectedAudience) {
      return { valid: false, error: `Invalid audience: ${payload.aud}` };
    }

    // Verify issuer is Google
    if (!payload.iss?.includes('accounts.google.com')) {
      return { valid: false, error: `Invalid issuer: ${payload.iss}` };
    }

    // In production, you should verify the signature using Google's public keys
    // For now, we validate the structure and claims
    // TODO: Add full JWT signature verification with google-auth-library

    return {
      valid: true,
      email: payload.email || payload.sub,
    };
  } catch (error) {
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
