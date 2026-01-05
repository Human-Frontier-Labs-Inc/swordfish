/**
 * O365 Webhook Handler Tests
 * Tests for Microsoft Graph notification processing
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { NextRequest } from 'next/server';

// Mock modules
vi.mock('@/lib/db', () => ({
  sql: vi.fn().mockImplementation(() => Promise.resolve([])),
}));

vi.mock('@/lib/integrations/o365', () => ({
  getO365Email: vi.fn().mockResolvedValue({
    id: 'msg-1',
    internetMessageId: '<msg-1@test.com>',
    subject: 'Test Email',
    from: { emailAddress: { address: 'sender@test.com', name: 'Sender' } },
    toRecipients: [{ emailAddress: { address: 'recipient@test.com', name: 'Recipient' } }],
    receivedDateTime: new Date().toISOString(),
    body: { contentType: 'text', content: 'Test body' },
    hasAttachments: false,
  }),
  refreshO365Token: vi.fn().mockResolvedValue({
    accessToken: 'new-access-token',
    refreshToken: 'new-refresh-token',
    expiresAt: new Date(Date.now() + 3600000),
  }),
}));

vi.mock('@/lib/detection/parser', () => ({
  parseGraphEmail: vi.fn().mockReturnValue({
    messageId: 'msg-1',
    subject: 'Test Email',
    from: { address: 'sender@test.com', domain: 'test.com' },
    to: [{ address: 'recipient@test.com', domain: 'test.com' }],
    date: new Date(),
    headers: {},
    body: { text: 'Test body' },
    attachments: [],
    rawHeaders: '',
  }),
}));

vi.mock('@/lib/detection/pipeline', () => ({
  analyzeEmail: vi.fn().mockResolvedValue({
    messageId: 'msg-1',
    tenantId: 'tenant-1',
    verdict: 'pass',
    overallScore: 10,
    confidence: 0.9,
    signals: [],
    layerResults: [],
    processingTimeMs: 100,
    analyzedAt: new Date(),
  }),
}));

vi.mock('@/lib/detection/storage', () => ({
  storeVerdict: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('@/lib/notifications/service', () => ({
  sendThreatNotification: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('@/lib/db/audit', () => ({
  logAuditEvent: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('@/lib/workers/remediation', () => ({
  autoRemediate: vi.fn().mockResolvedValue({ success: true }),
}));

vi.mock('@/lib/webhooks/validation', () => ({
  validateMicrosoftGraph: vi.fn().mockReturnValue({ valid: true }),
  checkRateLimit: vi.fn().mockReturnValue({ limited: false, remaining: 99, resetAt: new Date() }),
}));

describe('O365 Webhook Handler', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    // Reset mocks to default implementations
    const { checkRateLimit, validateMicrosoftGraph } = await import('@/lib/webhooks/validation');
    vi.mocked(checkRateLimit).mockReturnValue({
      limited: false,
      remaining: 99,
      resetAt: new Date(),
    });
    vi.mocked(validateMicrosoftGraph).mockReturnValue({ valid: true });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('POST /api/webhooks/o365', () => {
    it('should respond to validation request', async () => {
      const { POST } = await import('@/app/api/webhooks/o365/route');

      const request = new NextRequest(
        'http://localhost/api/webhooks/o365?validationToken=test-validation-token',
        {
          method: 'POST',
        }
      );

      const response = await POST(request);

      expect(response.status).toBe(200);
      const text = await response.text();
      expect(text).toBe('test-validation-token');
      expect(response.headers.get('Content-Type')).toBe('text/plain');
    });

    it('should process change notification', async () => {
      const { POST } = await import('@/app/api/webhooks/o365/route');
      const { sql } = await import('@/lib/db');

      // Mock finding integration
      vi.mocked(sql)
        .mockResolvedValueOnce([
          {
            id: 'int-1',
            tenant_id: 'tenant-1',
            config: {
              accessToken: 'valid-token',
              refreshToken: 'refresh-token',
              tokenExpiresAt: new Date(Date.now() + 3600000).toISOString(),
              subscriptionId: 'sub-1',
            },
          },
        ] as any)
        .mockResolvedValue([] as any);

      const notification = {
        value: [
          {
            subscriptionId: 'sub-1',
            clientState: 'test-client-state',
            changeType: 'created',
            resource: "Users/user-1/Messages/msg-1",
            resourceData: { id: 'msg-1', '@odata.type': '#Microsoft.Graph.Message' },
            tenantId: 'azure-tenant-1',
          },
        ],
      };

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(notification),
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.status).toBe('processed');
    });

    it('should handle rate limiting', async () => {
      const { POST } = await import('@/app/api/webhooks/o365/route');
      const { checkRateLimit } = await import('@/lib/webhooks/validation');

      vi.mocked(checkRateLimit).mockReturnValue({
        limited: true,
        remaining: 0,
        resetAt: new Date(Date.now() + 60000),
      });

      const notification = {
        value: [
          {
            subscriptionId: 'sub-1',
            clientState: 'test-client-state',
            changeType: 'created',
            resource: "Users/user-1/Messages/msg-1",
            tenantId: 'azure-tenant-1',
          },
        ],
      };

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(notification),
      });

      const response = await POST(request);

      expect(response.status).toBe(429);
    });

    it('should skip non-created change types', async () => {
      const { POST } = await import('@/app/api/webhooks/o365/route');
      const { sql } = await import('@/lib/db');

      const notification = {
        value: [
          {
            subscriptionId: 'sub-1',
            clientState: 'test-client-state',
            changeType: 'updated', // Not 'created'
            resource: "Users/user-1/Messages/msg-1",
            tenantId: 'azure-tenant-1',
          },
        ],
      };

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(notification),
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      // SQL should not be called for subscription lookup since changeType != 'created'
    });

    it('should skip invalid client state in strict mode', async () => {
      const originalEnv = process.env.STRICT_WEBHOOK_VALIDATION;
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.STRICT_WEBHOOK_VALIDATION = 'true';
      process.env.NODE_ENV = 'production';

      const { POST } = await import('@/app/api/webhooks/o365/route');
      const { validateMicrosoftGraph } = await import('@/lib/webhooks/validation');

      vi.mocked(validateMicrosoftGraph).mockReturnValue({
        valid: false,
        error: 'Invalid clientState',
      });

      const notification = {
        value: [
          {
            subscriptionId: 'sub-1',
            clientState: 'invalid-state',
            changeType: 'created',
            resource: "Users/user-1/Messages/msg-1",
            tenantId: 'azure-tenant-1',
          },
        ],
      };

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(notification),
      });

      const response = await POST(request);

      expect(response.status).toBe(200); // Still returns 200 but skips processing

      process.env.STRICT_WEBHOOK_VALIDATION = originalEnv;
      process.env.NODE_ENV = originalNodeEnv;
    });
  });

  describe('GET /api/webhooks/o365', () => {
    it('should return health status', async () => {
      const { GET } = await import('@/app/api/webhooks/o365/route');

      const response = await GET();

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.status).toBe('healthy');
      expect(data.service).toBe('o365-webhook');
    });
  });
});
