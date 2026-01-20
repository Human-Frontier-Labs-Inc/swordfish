/**
 * Webhook Signature Module
 *
 * Provides HMAC-SHA256 signature generation and verification for webhooks.
 * Prevents replay attacks through timestamp validation.
 * Uses timing-safe comparison to prevent timing attacks.
 */

import { createHmac, timingSafeEqual } from 'crypto';

/**
 * Algorithm used for HMAC signatures
 */
export const SIGNATURE_ALGORITHM = 'sha256';

/**
 * Default timestamp tolerance (5 minutes)
 */
const DEFAULT_TOLERANCE_SECONDS = 300;

/**
 * Maximum clock skew allowed (30 seconds into future)
 */
const MAX_CLOCK_SKEW_SECONDS = 30;

/**
 * Custom error for webhook signature failures
 */
export class WebhookSignatureError extends Error {
  code: string;

  constructor(message: string, code = 'SIGNATURE_ERROR') {
    super(message);
    this.name = 'WebhookSignatureError';
    this.code = code;
  }
}

/**
 * Generate an HMAC-SHA256 signature for a webhook payload
 *
 * The signed payload format is: timestamp.payload
 * This ensures the timestamp is cryptographically bound to the payload.
 *
 * @param payload The JSON payload string
 * @param secret The webhook secret key
 * @param timestamp Unix timestamp as string
 * @returns Hex-encoded HMAC-SHA256 signature
 */
export function generateSignature(payload: string, secret: string, timestamp: string): string {
  // Combine timestamp and payload to prevent replay attacks
  const signedPayload = `${timestamp}.${payload}`;

  const hmac = createHmac(SIGNATURE_ALGORITHM, secret);
  hmac.update(signedPayload);

  return hmac.digest('hex');
}

/**
 * Verify an HMAC-SHA256 signature
 *
 * Uses constant-time comparison to prevent timing attacks.
 *
 * @param payload The received payload string
 * @param signature The signature to verify (hex string)
 * @param secret The webhook secret key
 * @param timestamp The timestamp used in signature
 * @returns true if signature is valid, false otherwise
 */
export function verifySignature(
  payload: string,
  signature: string,
  secret: string,
  timestamp: string
): boolean {
  // Validate signature format (should be 64 hex characters for SHA256)
  if (!signature || typeof signature !== 'string') {
    return false;
  }

  // Check if signature looks like valid hex
  if (!/^[a-f0-9]{64}$/i.test(signature)) {
    return false;
  }

  try {
    // Generate expected signature
    const expectedSignature = generateSignature(payload, secret, timestamp);

    // Use timing-safe comparison
    const sigBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expectedSignature, 'hex');

    // Buffers must be same length for timingSafeEqual
    if (sigBuffer.length !== expectedBuffer.length) {
      return false;
    }

    return timingSafeEqual(sigBuffer, expectedBuffer);
  } catch {
    // Any error during verification means invalid signature
    return false;
  }
}

/**
 * Verify that a webhook timestamp is recent (not a replay attack)
 *
 * @param timestamp Unix timestamp as string
 * @param toleranceSeconds Maximum age in seconds (default: 5 minutes)
 * @returns true if timestamp is within acceptable range
 */
export function verifyWebhookTimestamp(
  timestamp: string,
  toleranceSeconds = DEFAULT_TOLERANCE_SECONDS
): boolean {
  // Parse timestamp
  const timestampNum = parseInt(timestamp, 10);

  // Check for valid number
  if (isNaN(timestampNum) || timestampNum <= 0) {
    return false;
  }

  const now = Math.floor(Date.now() / 1000);

  // Check if timestamp is too old (replay attack prevention)
  if (now - timestampNum > toleranceSeconds) {
    return false;
  }

  // Check if timestamp is too far in the future (clock skew protection)
  if (timestampNum - now > MAX_CLOCK_SKEW_SECONDS) {
    return false;
  }

  return true;
}

/**
 * Webhook payload headers
 */
export interface WebhookHeaders {
  'x-webhook-signature': string;
  'x-webhook-timestamp': string;
  'content-type': string;
}

/**
 * Create a signed webhook payload ready to send
 *
 * @param event The event type (e.g., 'threat.detected')
 * @param data The event data
 * @param secret The webhook secret for signing
 * @returns Object with headers and body
 */
export function createWebhookPayload<T>(
  event: string,
  data: T,
  secret: string
): {
  headers: WebhookHeaders;
  body: string;
} {
  const timestamp = String(Math.floor(Date.now() / 1000));

  // Create the body
  const bodyObject = {
    event,
    data,
    timestamp,
  };
  const body = JSON.stringify(bodyObject);

  // Generate signature
  const signature = generateSignature(body, secret, timestamp);

  return {
    headers: {
      'x-webhook-signature': signature,
      'x-webhook-timestamp': timestamp,
      'content-type': 'application/json',
    },
    body,
  };
}

/**
 * Verify an incoming webhook request
 *
 * @param body The request body as string
 * @param signature The x-webhook-signature header value
 * @param timestamp The x-webhook-timestamp header value
 * @param secret The webhook secret
 * @param toleranceSeconds Timestamp tolerance (default: 5 minutes)
 * @throws WebhookSignatureError if verification fails
 */
export function verifyWebhookRequest(
  body: string,
  signature: string,
  timestamp: string,
  secret: string,
  toleranceSeconds = DEFAULT_TOLERANCE_SECONDS
): void {
  // Step 1: Verify timestamp is recent
  if (!verifyWebhookTimestamp(timestamp, toleranceSeconds)) {
    throw new WebhookSignatureError('Webhook timestamp too old or invalid', 'TIMESTAMP_INVALID');
  }

  // Step 2: Verify signature
  if (!verifySignature(body, signature, secret, timestamp)) {
    throw new WebhookSignatureError('Webhook signature verification failed', 'INVALID_SIGNATURE');
  }
}

/**
 * Parse and verify a webhook, returning the typed payload
 *
 * @param body The request body as string
 * @param signature The x-webhook-signature header value
 * @param timestamp The x-webhook-timestamp header value
 * @param secret The webhook secret
 * @returns Parsed webhook payload
 * @throws WebhookSignatureError if verification fails
 */
export function parseAndVerifyWebhook<T = unknown>(
  body: string,
  signature: string,
  timestamp: string,
  secret: string
): { event: string; data: T; timestamp: string } {
  // Verify the webhook
  verifyWebhookRequest(body, signature, timestamp, secret);

  // Parse the body
  try {
    return JSON.parse(body) as { event: string; data: T; timestamp: string };
  } catch {
    throw new WebhookSignatureError('Invalid webhook payload format', 'INVALID_PAYLOAD');
  }
}
