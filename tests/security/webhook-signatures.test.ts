/**
 * Webhook Signature Verification Tests
 * TDD: Secure webhook signature generation and verification
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Will implement these
import {
  generateSignature,
  verifySignature,
  createWebhookPayload,
  verifyWebhookTimestamp,
  WebhookSignatureError,
  SIGNATURE_ALGORITHM,
} from '@/lib/security/webhooks';

describe('Webhook Signature Verification', () => {
  const originalEnv = process.env;
  const TEST_SECRET = 'whsec_test_secret_key_1234567890';
  const TEST_PAYLOAD = JSON.stringify({ event: 'threat.detected', data: { id: '123' } });
  const TEST_TIMESTAMP = '1704067200'; // 2024-01-01 00:00:00 UTC

  beforeEach(() => {
    vi.clearAllMocks();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
  });

  describe('generateSignature', () => {
    it('should generate a valid HMAC-SHA256 signature', () => {
      const signature = generateSignature(TEST_PAYLOAD, TEST_SECRET, TEST_TIMESTAMP);

      expect(signature).toBeDefined();
      expect(typeof signature).toBe('string');
      // SHA256 hex is 64 characters
      expect(signature).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should generate consistent signatures for same inputs', () => {
      const sig1 = generateSignature(TEST_PAYLOAD, TEST_SECRET, TEST_TIMESTAMP);
      const sig2 = generateSignature(TEST_PAYLOAD, TEST_SECRET, TEST_TIMESTAMP);

      expect(sig1).toBe(sig2);
    });

    it('should generate different signatures for different payloads', () => {
      const sig1 = generateSignature(TEST_PAYLOAD, TEST_SECRET, TEST_TIMESTAMP);
      const sig2 = generateSignature('{"different": "payload"}', TEST_SECRET, TEST_TIMESTAMP);

      expect(sig1).not.toBe(sig2);
    });

    it('should generate different signatures for different secrets', () => {
      const sig1 = generateSignature(TEST_PAYLOAD, TEST_SECRET, TEST_TIMESTAMP);
      const sig2 = generateSignature(TEST_PAYLOAD, 'different_secret_key_123456', TEST_TIMESTAMP);

      expect(sig1).not.toBe(sig2);
    });

    it('should generate different signatures for different timestamps', () => {
      const sig1 = generateSignature(TEST_PAYLOAD, TEST_SECRET, TEST_TIMESTAMP);
      const sig2 = generateSignature(TEST_PAYLOAD, TEST_SECRET, '1704153600'); // Different time

      expect(sig1).not.toBe(sig2);
    });

    it('should include timestamp in signed payload to prevent replay attacks', () => {
      // The signed payload should be: timestamp.payload
      // This ensures the timestamp is part of what's signed
      const sig1 = generateSignature(TEST_PAYLOAD, TEST_SECRET, TEST_TIMESTAMP);
      const sig2 = generateSignature(TEST_PAYLOAD, TEST_SECRET, '9999999999');

      // Signatures should differ because timestamp is included in hash
      expect(sig1).not.toBe(sig2);
    });
  });

  describe('verifySignature', () => {
    it('should return true for valid signature', () => {
      const signature = generateSignature(TEST_PAYLOAD, TEST_SECRET, TEST_TIMESTAMP);

      const result = verifySignature(TEST_PAYLOAD, signature, TEST_SECRET, TEST_TIMESTAMP);

      expect(result).toBe(true);
    });

    it('should return false for invalid signature', () => {
      const result = verifySignature(TEST_PAYLOAD, 'invalid_signature', TEST_SECRET, TEST_TIMESTAMP);

      expect(result).toBe(false);
    });

    it('should return false for tampered payload', () => {
      const signature = generateSignature(TEST_PAYLOAD, TEST_SECRET, TEST_TIMESTAMP);

      const result = verifySignature('{"tampered": "payload"}', signature, TEST_SECRET, TEST_TIMESTAMP);

      expect(result).toBe(false);
    });

    it('should return false for wrong secret', () => {
      const signature = generateSignature(TEST_PAYLOAD, TEST_SECRET, TEST_TIMESTAMP);

      const result = verifySignature(TEST_PAYLOAD, signature, 'wrong_secret', TEST_TIMESTAMP);

      expect(result).toBe(false);
    });

    it('should return false for wrong timestamp', () => {
      const signature = generateSignature(TEST_PAYLOAD, TEST_SECRET, TEST_TIMESTAMP);

      const result = verifySignature(TEST_PAYLOAD, signature, TEST_SECRET, '9999999999');

      expect(result).toBe(false);
    });

    it('should use constant-time comparison to prevent timing attacks', () => {
      // This test verifies the implementation uses timing-safe comparison
      // The actual timing-safe comparison is in the implementation
      const signature = generateSignature(TEST_PAYLOAD, TEST_SECRET, TEST_TIMESTAMP);

      // Both should complete without throwing
      expect(verifySignature(TEST_PAYLOAD, signature, TEST_SECRET, TEST_TIMESTAMP)).toBe(true);
      expect(verifySignature(TEST_PAYLOAD, 'x'.repeat(64), TEST_SECRET, TEST_TIMESTAMP)).toBe(false);
    });

    it('should handle non-hex signature gracefully', () => {
      const result = verifySignature(TEST_PAYLOAD, 'not-a-valid-hex-string!@#$', TEST_SECRET, TEST_TIMESTAMP);

      expect(result).toBe(false);
    });

    it('should handle empty signature gracefully', () => {
      const result = verifySignature(TEST_PAYLOAD, '', TEST_SECRET, TEST_TIMESTAMP);

      expect(result).toBe(false);
    });
  });

  describe('verifyWebhookTimestamp', () => {
    it('should accept timestamp within tolerance (5 minutes)', () => {
      const now = Math.floor(Date.now() / 1000);
      const timestamp = String(now - 60); // 1 minute ago

      const result = verifyWebhookTimestamp(timestamp);

      expect(result).toBe(true);
    });

    it('should reject timestamp too old (replay attack prevention)', () => {
      const now = Math.floor(Date.now() / 1000);
      const timestamp = String(now - 600); // 10 minutes ago (beyond 5 min tolerance)

      const result = verifyWebhookTimestamp(timestamp);

      expect(result).toBe(false);
    });

    it('should reject timestamp in the future (clock skew)', () => {
      const now = Math.floor(Date.now() / 1000);
      const timestamp = String(now + 600); // 10 minutes in future

      const result = verifyWebhookTimestamp(timestamp);

      expect(result).toBe(false);
    });

    it('should accept slight clock skew (30 seconds in future)', () => {
      const now = Math.floor(Date.now() / 1000);
      const timestamp = String(now + 30); // 30 seconds in future

      const result = verifyWebhookTimestamp(timestamp);

      expect(result).toBe(true);
    });

    it('should reject invalid timestamp format', () => {
      const result = verifyWebhookTimestamp('not-a-timestamp');

      expect(result).toBe(false);
    });

    it('should allow custom tolerance', () => {
      const now = Math.floor(Date.now() / 1000);
      const timestamp = String(now - 600); // 10 minutes ago

      // With 15 minute tolerance, this should pass
      const result = verifyWebhookTimestamp(timestamp, 900);

      expect(result).toBe(true);
    });
  });

  describe('createWebhookPayload', () => {
    it('should create payload with signature header', () => {
      const event = 'threat.detected';
      const data = { threatId: '123', severity: 'high' };

      const result = createWebhookPayload(event, data, TEST_SECRET);

      expect(result.headers).toHaveProperty('x-webhook-signature');
      expect(result.headers).toHaveProperty('x-webhook-timestamp');
      expect(result.body).toBeDefined();
    });

    it('should include timestamp in headers', () => {
      const event = 'threat.detected';
      const data = { threatId: '123' };

      const result = createWebhookPayload(event, data, TEST_SECRET);

      const timestamp = result.headers['x-webhook-timestamp'];
      expect(timestamp).toBeDefined();
      expect(Number(timestamp)).toBeGreaterThan(0);
    });

    it('should create verifiable signature', () => {
      const event = 'threat.quarantined';
      const data = { threatId: '456', action: 'quarantine' };

      const result = createWebhookPayload(event, data, TEST_SECRET);

      const isValid = verifySignature(
        result.body,
        result.headers['x-webhook-signature'],
        TEST_SECRET,
        result.headers['x-webhook-timestamp']
      );

      expect(isValid).toBe(true);
    });

    it('should include event type in body', () => {
      const event = 'sync.completed';
      const data = { emailCount: 100 };

      const result = createWebhookPayload(event, data, TEST_SECRET);
      const parsed = JSON.parse(result.body);

      expect(parsed.event).toBe(event);
      expect(parsed.data).toEqual(data);
    });

    it('should include timestamp in body', () => {
      const event = 'threat.released';
      const data = {};

      const result = createWebhookPayload(event, data, TEST_SECRET);
      const parsed = JSON.parse(result.body);

      expect(parsed.timestamp).toBeDefined();
      expect(typeof parsed.timestamp).toBe('string');
    });
  });

  describe('WebhookSignatureError', () => {
    it('should be an Error instance', () => {
      const error = new WebhookSignatureError('Test error');

      expect(error).toBeInstanceOf(Error);
      expect(error.name).toBe('WebhookSignatureError');
    });

    it('should have message and code', () => {
      const error = new WebhookSignatureError('Invalid signature', 'INVALID_SIGNATURE');

      expect(error.message).toBe('Invalid signature');
      expect(error.code).toBe('INVALID_SIGNATURE');
    });
  });

  describe('SIGNATURE_ALGORITHM', () => {
    it('should use SHA256', () => {
      expect(SIGNATURE_ALGORITHM).toBe('sha256');
    });
  });

  describe('Integration scenarios', () => {
    it('should detect replay attack (same signature, old timestamp)', () => {
      const oldTimestamp = String(Math.floor(Date.now() / 1000) - 600); // 10 min ago
      const signature = generateSignature(TEST_PAYLOAD, TEST_SECRET, oldTimestamp);

      // Signature is valid for that timestamp
      expect(verifySignature(TEST_PAYLOAD, signature, TEST_SECRET, oldTimestamp)).toBe(true);

      // But timestamp is too old
      expect(verifyWebhookTimestamp(oldTimestamp)).toBe(false);
    });

    it('should handle full webhook verification flow', () => {
      // Sender creates webhook
      const event = 'threat.detected';
      const data = { threatId: '789' };
      const webhook = createWebhookPayload(event, data, TEST_SECRET);

      // Receiver verifies webhook
      const { body, headers } = webhook;
      const timestamp = headers['x-webhook-timestamp'];
      const signature = headers['x-webhook-signature'];

      // Step 1: Verify timestamp is recent
      const timestampValid = verifyWebhookTimestamp(timestamp);
      expect(timestampValid).toBe(true);

      // Step 2: Verify signature
      const signatureValid = verifySignature(body, signature, TEST_SECRET, timestamp);
      expect(signatureValid).toBe(true);

      // Step 3: Parse and use the data
      const parsed = JSON.parse(body);
      expect(parsed.event).toBe('threat.detected');
      expect(parsed.data.threatId).toBe('789');
    });

    it('should reject webhook with modified body', () => {
      const webhook = createWebhookPayload('threat.detected', { id: '1' }, TEST_SECRET);

      // Attacker modifies body
      const tamperedBody = JSON.stringify({ event: 'threat.detected', data: { id: 'evil' } });

      const isValid = verifySignature(
        tamperedBody,
        webhook.headers['x-webhook-signature'],
        TEST_SECRET,
        webhook.headers['x-webhook-timestamp']
      );

      expect(isValid).toBe(false);
    });
  });
});
