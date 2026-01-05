/**
 * Outbound Webhook System Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock fetch
global.fetch = vi.fn();

// Mock database
vi.mock('@/lib/db', () => ({
  sql: vi.fn(),
}));

import {
  generateSignature,
  verifySignature,
  createPayload,
  buildCEFEvent,
  threatToCEF,
} from '@/lib/webhooks/outbound';
import { buildCEFEvent as buildCEF, threatToCEF as toCEF } from '@/lib/integrations/splunk';

describe('Webhook Signature', () => {
  it('should generate consistent HMAC signatures', () => {
    const payload = JSON.stringify({ event: 'test', data: { id: '123' } });
    const secret = 'webhook_secret_key';

    const signature1 = generateSignature(payload, secret);
    const signature2 = generateSignature(payload, secret);

    expect(signature1).toBe(signature2);
    expect(signature1).toHaveLength(64); // SHA256 hex is 64 chars
  });

  it('should generate different signatures for different payloads', () => {
    const secret = 'webhook_secret_key';
    const signature1 = generateSignature('payload1', secret);
    const signature2 = generateSignature('payload2', secret);

    expect(signature1).not.toBe(signature2);
  });

  it('should verify valid signatures', () => {
    const payload = 'test_payload';
    const secret = 'test_secret';
    const signature = generateSignature(payload, secret);

    expect(verifySignature(payload, signature, secret)).toBe(true);
  });

  it('should reject invalid signatures', () => {
    const payload = 'test_payload';
    const secret = 'test_secret';
    const wrongSignature = 'a'.repeat(64);

    expect(verifySignature(payload, wrongSignature, secret)).toBe(false);
  });
});

describe('Webhook Payload', () => {
  it('should create valid webhook payload', () => {
    const payload = createPayload('threat.detected', 'tenant_123', {
      threatId: 'threat_456',
      severity: 'high',
    });

    expect(payload.id).toBeDefined();
    expect(payload.event).toBe('threat.detected');
    expect(payload.tenantId).toBe('tenant_123');
    expect(payload.data.threatId).toBe('threat_456');
    expect(payload.metadata?.version).toBe('1.0');
    expect(payload.timestamp).toBeDefined();
  });

  it('should generate unique IDs for each payload', () => {
    const payload1 = createPayload('threat.detected', 'tenant_123', {});
    const payload2 = createPayload('threat.detected', 'tenant_123', {});

    expect(payload1.id).not.toBe(payload2.id);
  });
});

describe('CEF Event Formatting', () => {
  it('should build valid CEF event string', () => {
    const event = {
      version: '0',
      deviceVendor: 'Swordfish',
      deviceProduct: 'Email Security',
      deviceVersion: '1.0',
      signatureId: 'phishing',
      name: 'Email Threat: phishing',
      severity: 7,
      extensions: {
        src: 'attacker@malicious.com',
        dst: 'victim@company.com',
        msg: 'Urgent: Password Reset Required',
        cs1: 'threat_123',
        cs1Label: 'ThreatID',
      },
    };

    const cefString = buildCEF(event);

    expect(cefString).toContain('CEF:0');
    expect(cefString).toContain('Swordfish');
    expect(cefString).toContain('Email Security');
    expect(cefString).toContain('phishing');
    expect(cefString).toContain('src=attacker@malicious.com');
    expect(cefString).toContain('cs1Label=ThreatID');
  });

  it('should escape special characters in CEF fields', () => {
    const event = {
      version: '0',
      deviceVendor: 'Test|Vendor',
      deviceProduct: 'Product\\Name',
      deviceVersion: '1.0',
      signatureId: 'test',
      name: 'Test Event',
      severity: 3,
      extensions: {
        msg: 'Message with = and \n newline',
      },
    };

    const cefString = buildCEF(event);

    expect(cefString).toContain('Test\\|Vendor');
    expect(cefString).toContain('\\=');
    expect(cefString).toContain('\\n');
  });

  it('should convert threat to CEF format', () => {
    const threat = {
      id: 'threat_123',
      fromAddress: 'attacker@bad.com',
      toAddresses: ['victim@company.com'],
      subject: 'Click here now!',
      verdict: 'phishing',
      severity: 'high',
      confidence: 92,
      verdictReason: 'Contains malicious URL',
      actionTaken: 'quarantine',
      messageId: 'msg_456',
      receivedAt: '2024-01-15T10:30:00Z',
    };

    const cefEvent = toCEF(threat);

    expect(cefEvent.signatureId).toBe('phishing');
    expect(cefEvent.severity).toBe(7); // high = 7
    expect(cefEvent.extensions.src).toBe('attacker@bad.com');
    expect(cefEvent.extensions.cn1).toBe(92);
  });
});

describe('Webhook Delivery', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should retry on failure', async () => {
    // First call fails, second succeeds
    (global.fetch as ReturnType<typeof vi.fn>)
      .mockRejectedValueOnce(new Error('Network error'))
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => 'OK',
      });

    // Import after mocking
    const { deliverWebhook } = await import('@/lib/webhooks/outbound');

    const webhook = {
      id: 'webhook_1',
      tenantId: 'tenant_123',
      name: 'Test Webhook',
      url: 'https://example.com/webhook',
      secret: 'test_secret',
      events: ['threat.detected' as const],
      isActive: true,
      retryCount: 2,
      retryDelayMs: 10, // Short delay for tests
      timeoutMs: 5000,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const payload = createPayload('threat.detected', 'tenant_123', { test: true });

    const result = await deliverWebhook(webhook, payload);

    expect(result.success).toBe(true);
    expect(result.attempts).toBe(2);
    expect(global.fetch).toHaveBeenCalledTimes(2);
  });

  it('should not retry on 4xx errors (except 429)', async () => {
    (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: false,
      status: 400,
      text: async () => 'Bad Request',
    });

    const { deliverWebhook } = await import('@/lib/webhooks/outbound');

    const webhook = {
      id: 'webhook_1',
      tenantId: 'tenant_123',
      name: 'Test Webhook',
      url: 'https://example.com/webhook',
      secret: 'test_secret',
      events: ['threat.detected' as const],
      isActive: true,
      retryCount: 3,
      retryDelayMs: 10,
      timeoutMs: 5000,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const payload = createPayload('threat.detected', 'tenant_123', { test: true });

    const result = await deliverWebhook(webhook, payload);

    expect(result.success).toBe(false);
    expect(result.attempts).toBe(1); // No retries on 4xx
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it('should include correct headers', async () => {
    (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => 'OK',
    });

    const { deliverWebhook } = await import('@/lib/webhooks/outbound');

    const webhook = {
      id: 'webhook_1',
      tenantId: 'tenant_123',
      name: 'Test Webhook',
      url: 'https://example.com/webhook',
      secret: 'test_secret',
      events: ['threat.detected' as const],
      isActive: true,
      headers: { 'X-Custom': 'value' },
      retryCount: 0,
      retryDelayMs: 10,
      timeoutMs: 5000,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const payload = createPayload('threat.detected', 'tenant_123', { test: true });

    await deliverWebhook(webhook, payload);

    const fetchCall = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const headers = fetchCall[1].headers;

    expect(headers['Content-Type']).toBe('application/json');
    expect(headers['X-Webhook-Id']).toBe('webhook_1');
    expect(headers['X-Webhook-Event']).toBe('threat.detected');
    expect(headers['X-Webhook-Signature']).toContain('sha256=');
    expect(headers['X-Custom']).toBe('value');
  });
});

describe('Rate Limiting', () => {
  it('should track rate limit state', async () => {
    const { checkRateLimit, RATE_LIMITS } = await import('@/lib/api/rate-limit');

    const config = RATE_LIMITS.starter;

    // First request should pass
    const result1 = checkRateLimit('test_key', config);
    expect(result1.allowed).toBe(true);
    expect(result1.remaining).toBe(99);

    // Subsequent requests should decrement
    const result2 = checkRateLimit('test_key', config);
    expect(result2.allowed).toBe(true);
    expect(result2.remaining).toBe(98);
  });

  it('should block when limit exceeded', async () => {
    const { checkRateLimit } = await import('@/lib/api/rate-limit');

    // Use a unique key to avoid cross-test contamination
    const uniqueKey = `test_key_${Date.now()}`;
    const config = { maxRequests: 2, windowMs: 60000 };

    checkRateLimit(uniqueKey, config);
    checkRateLimit(uniqueKey, config);

    // Third request should be blocked
    const result = checkRateLimit(uniqueKey, config);
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
  });
});
