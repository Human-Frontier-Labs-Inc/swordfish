/**
 * Webhook Validation Tests
 * Tests for webhook signature validation and rate limiting
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  validateGooglePubSub,
  validateMicrosoftGraph,
  validateHmacSignature,
  checkRateLimit,
  generateClientState,
} from '@/lib/webhooks/validation';

describe('Webhook Validation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('validateGooglePubSub', () => {
    it('should reject missing authorization header', async () => {
      const result = await validateGooglePubSub({
        authorizationHeader: null,
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Missing');
    });

    it('should reject invalid authorization format', async () => {
      const result = await validateGooglePubSub({
        authorizationHeader: 'Basic invalid',
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Missing');
    });

    it('should allow development mode with flag', async () => {
      const originalEnv = process.env.NODE_ENV;
      const originalFlag = process.env.ALLOW_UNSIGNED_WEBHOOKS;

      process.env.NODE_ENV = 'development';
      process.env.ALLOW_UNSIGNED_WEBHOOKS = 'true';

      const result = await validateGooglePubSub({
        authorizationHeader: null,
      });

      expect(result.valid).toBe(true);
      expect(result.email).toBe('development@test.local');

      process.env.NODE_ENV = originalEnv;
      process.env.ALLOW_UNSIGNED_WEBHOOKS = originalFlag;
    });

    it('should validate JWT structure', async () => {
      // Create a mock JWT (not cryptographically valid, but structurally correct)
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({
        iss: 'https://accounts.google.com',
        sub: 'test@example.com',
        email: 'test@example.com',
        aud: 'https://swordfish.app/api/webhooks/gmail',
        iat: Math.floor(Date.now() / 1000) - 60,
        exp: Math.floor(Date.now() / 1000) + 3600,
      })).toString('base64url');
      const signature = 'mock_signature';

      const token = `${header}.${payload}.${signature}`;

      const result = await validateGooglePubSub({
        authorizationHeader: `Bearer ${token}`,
      });

      // Should pass structure validation
      expect(result.valid).toBe(true);
      expect(result.email).toBe('test@example.com');
    });

    it('should reject expired tokens', async () => {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({
        iss: 'https://accounts.google.com',
        sub: 'test@example.com',
        exp: Math.floor(Date.now() / 1000) - 3600, // Expired 1 hour ago
        iat: Math.floor(Date.now() / 1000) - 7200,
      })).toString('base64url');
      const signature = 'mock_signature';

      const token = `${header}.${payload}.${signature}`;

      const result = await validateGooglePubSub({
        authorizationHeader: `Bearer ${token}`,
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('expired');
    });

    it('should reject invalid issuer', async () => {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({
        iss: 'https://malicious.com',
        sub: 'test@example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000) - 60,
      })).toString('base64url');
      const signature = 'mock_signature';

      const token = `${header}.${payload}.${signature}`;

      const result = await validateGooglePubSub({
        authorizationHeader: `Bearer ${token}`,
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid issuer');
    });

    it('should validate audience when expected', async () => {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({
        iss: 'https://accounts.google.com',
        sub: 'test@example.com',
        aud: 'https://different-app.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000) - 60,
      })).toString('base64url');
      const signature = 'mock_signature';

      const token = `${header}.${payload}.${signature}`;

      const result = await validateGooglePubSub({
        authorizationHeader: `Bearer ${token}`,
        expectedAudience: 'https://swordfish.app/api/webhooks/gmail',
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid audience');
    });
  });

  describe('validateMicrosoftGraph', () => {
    it('should validate matching client state', () => {
      const result = validateMicrosoftGraph({
        clientState: 'my-secret-state-123',
        expectedClientState: 'my-secret-state-123',
      });

      expect(result.valid).toBe(true);
    });

    it('should reject mismatched client state', () => {
      const result = validateMicrosoftGraph({
        clientState: 'wrong-state',
        expectedClientState: 'my-secret-state-123',
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid clientState');
    });

    it('should reject missing client state', () => {
      const result = validateMicrosoftGraph({
        clientState: '',
        expectedClientState: 'my-secret-state-123',
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Missing clientState');
    });

    it('should skip validation when no expected state configured', () => {
      const result = validateMicrosoftGraph({
        clientState: 'any-state',
        expectedClientState: '',
      });

      expect(result.valid).toBe(true);
    });
  });

  describe('validateHmacSignature', () => {
    it('should validate correct HMAC signature', () => {
      const secret = 'my-webhook-secret';
      const payload = '{"test":"data"}';

      // Generate the expected signature
      const crypto = require('crypto');
      const expectedSig = crypto.createHmac('sha256', secret).update(payload).digest('hex');

      const result = validateHmacSignature({
        payload,
        signature: expectedSig,
        secret,
      });

      expect(result.valid).toBe(true);
    });

    it('should validate signature with sha256= prefix', () => {
      const secret = 'my-webhook-secret';
      const payload = '{"test":"data"}';

      const crypto = require('crypto');
      const expectedSig = crypto.createHmac('sha256', secret).update(payload).digest('hex');

      const result = validateHmacSignature({
        payload,
        signature: `sha256=${expectedSig}`,
        secret,
      });

      expect(result.valid).toBe(true);
    });

    it('should reject invalid signature', () => {
      const result = validateHmacSignature({
        payload: '{"test":"data"}',
        signature: 'invalid-signature-hex',
        secret: 'my-webhook-secret',
      });

      expect(result.valid).toBe(false);
    });

    it('should reject missing signature', () => {
      const result = validateHmacSignature({
        payload: '{"test":"data"}',
        signature: '',
        secret: 'my-webhook-secret',
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Missing signature');
    });

    it('should reject missing secret', () => {
      const result = validateHmacSignature({
        payload: '{"test":"data"}',
        signature: 'some-signature',
        secret: '',
      });

      expect(result.valid).toBe(false);
      expect(result.error).toContain('not configured');
    });
  });

  describe('checkRateLimit', () => {
    it('should allow requests within limit', () => {
      const result = checkRateLimit({
        key: 'test-unique-key-1',
        maxRequests: 10,
        windowMs: 60000,
      });

      expect(result.limited).toBe(false);
      expect(result.remaining).toBe(9);
    });

    it('should block requests exceeding limit', () => {
      const key = 'test-unique-key-2';

      // Make maxRequests + 1 calls
      for (let i = 0; i < 5; i++) {
        checkRateLimit({ key, maxRequests: 5, windowMs: 60000 });
      }

      const result = checkRateLimit({ key, maxRequests: 5, windowMs: 60000 });

      expect(result.limited).toBe(true);
      expect(result.remaining).toBe(0);
    });

    it('should use different limits for different keys', () => {
      const result1 = checkRateLimit({ key: 'key-a-unique', maxRequests: 1, windowMs: 60000 });
      const result2 = checkRateLimit({ key: 'key-b-unique', maxRequests: 1, windowMs: 60000 });

      expect(result1.limited).toBe(false);
      expect(result2.limited).toBe(false);
    });

    it('should provide reset time', () => {
      const result = checkRateLimit({
        key: 'test-unique-key-3',
        maxRequests: 10,
        windowMs: 60000,
      });

      expect(result.resetAt).toBeInstanceOf(Date);
      expect(result.resetAt.getTime()).toBeGreaterThan(Date.now());
    });
  });

  describe('generateClientState', () => {
    it('should generate unique values', () => {
      const state1 = generateClientState();
      const state2 = generateClientState();

      expect(state1).not.toBe(state2);
    });

    it('should generate hex string', () => {
      const state = generateClientState();

      expect(state).toMatch(/^[0-9a-f]+$/);
    });

    it('should generate 64 character string (32 bytes)', () => {
      const state = generateClientState();

      expect(state.length).toBe(64);
    });
  });
});
