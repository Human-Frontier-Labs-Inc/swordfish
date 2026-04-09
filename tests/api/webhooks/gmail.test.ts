/**
 * Gmail Webhook API Tests
 * Tests for POST /api/webhooks/gmail endpoint
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { NextRequest } from 'next/server';

// Mock database
vi.mock('@/lib/db', () => ({
  sql: vi.fn(),
  withTransaction: vi.fn().mockImplementation(async (fn: (tx: unknown) => Promise<unknown>) => {
    const mockTx = vi.fn().mockResolvedValue([]);
    return fn(mockTx);
  }),
}));

// Mock OAuth module
vi.mock('@/lib/oauth', () => ({
  findIntegrationByEmail: vi.fn(),
}));

// Mock validation
vi.mock('@/lib/webhooks/validation', () => ({
  validateGooglePubSub: vi.fn(),
  checkRateLimit: vi.fn(),
}));

// Mock Gmail functions
vi.mock('@/lib/integrations/gmail', () => ({
  getGmailMessage: vi.fn(),
  getGmailHistory: vi.fn(),
  getGmailAccessToken: vi.fn(),
}));

// Mock domain-wide functions
vi.mock('@/lib/integrations/domain-wide/google-workspace', () => ({
  processGmailHistoryForUser: vi.fn(),
  getGmailTokenForUser: vi.fn(),
}));

vi.mock('@/lib/integrations/domain-wide/storage', () => ({
  getDomainUserByEmail: vi.fn(),
  incrementDomainUserStats: vi.fn(),
  getActiveDomainConfigs: vi.fn(),
}));

// Mock parser
vi.mock('@/lib/detection/parser', () => ({
  parseGmailEmail: vi.fn(),
}));

// Mock pipeline
vi.mock('@/lib/detection/pipeline', () => ({
  analyzeEmail: vi.fn(),
}));

// Mock storage
vi.mock('@/lib/detection/storage', () => ({
  storeVerdict: vi.fn(),
}));

// Mock notifications
vi.mock('@/lib/notifications/service', () => ({
  sendThreatNotification: vi.fn(),
}));

// Mock audit
vi.mock('@/lib/db/audit', () => ({
  logAuditEvent: vi.fn(),
}));

// Mock remediation
vi.mock('@/lib/workers/remediation', () => ({
  autoRemediate: vi.fn(),
}));

// Mock queue
vi.mock('@/lib/queue/gmail', () => ({
  enqueueGmailJob: vi.fn(),
  isGmailQueueConfigured: vi.fn(),
}));

import { sql } from '@/lib/db';
import { validateGooglePubSub, checkRateLimit } from '@/lib/webhooks/validation';
import { getGmailHistory, getGmailAccessToken, getGmailMessage } from '@/lib/integrations/gmail';
import { getActiveDomainConfigs, getDomainUserByEmail } from '@/lib/integrations/domain-wide/storage';
import { parseGmailEmail } from '@/lib/detection/parser';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import { isGmailQueueConfigured, enqueueGmailJob } from '@/lib/queue/gmail';
import { findIntegrationByEmail } from '@/lib/oauth';
import { POST, GET } from '@/app/api/webhooks/gmail/route';

describe('Gmail Webhook API', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Default mocks
    (checkRateLimit as ReturnType<typeof vi.fn>).mockReturnValue({
      limited: false,
      remaining: 99,
      resetAt: new Date(),
    });

    (validateGooglePubSub as ReturnType<typeof vi.fn>).mockResolvedValue({
      valid: true,
      email: 'service-account@google.com',
    });

    (getActiveDomainConfigs as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (isGmailQueueConfigured as ReturnType<typeof vi.fn>).mockReturnValue(false);

    // Default: findIntegrationByEmail returns null (no integration found)
    (findIntegrationByEmail as ReturnType<typeof vi.fn>).mockResolvedValue(null);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const createPubSubPayload = (emailAddress: string, historyId: string) => ({
    message: {
      data: Buffer.from(JSON.stringify({ emailAddress, historyId })).toString('base64'),
      messageId: 'pubsub-msg-123',
      publishTime: new Date().toISOString(),
    },
    subscription: 'projects/test/subscriptions/gmail-push',
  });

  describe('Rate Limiting', () => {
    it('should return 429 when rate limit exceeded', async () => {
      (checkRateLimit as ReturnType<typeof vi.fn>).mockReturnValue({
        limited: true,
        remaining: 0,
        resetAt: new Date(Date.now() + 60000),
      });

      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        body: JSON.stringify(createPubSubPayload('user@test.com', '12345')),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(429);
      expect(response.headers.get('Retry-After')).toBe('60');
      const data = await response.json();
      expect(data.error).toBe('Rate limit exceeded');
    });

    it('should extract client IP for rate limiting', async () => {
      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        body: JSON.stringify(createPubSubPayload('user@test.com', '12345')),
        headers: {
          'Content-Type': 'application/json',
          'x-forwarded-for': '192.168.1.100',
        },
      });

      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      await POST(request);

      expect(checkRateLimit).toHaveBeenCalledWith(
        expect.objectContaining({
          key: 'gmail:192.168.1.100',
        })
      );
    });
  });

  describe('Google Pub/Sub Validation', () => {
    it('should validate Authorization header', async () => {
      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        body: JSON.stringify(createPubSubPayload('user@test.com', '12345')),
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer valid-token',
        },
      });

      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      await POST(request);

      expect(validateGooglePubSub).toHaveBeenCalledWith({
        authorizationHeader: 'Bearer valid-token',
        expectedAudience: undefined, // GOOGLE_WEBHOOK_AUDIENCE not set in test
      });
    });

    it('should reject invalid tokens in production with strict validation', async () => {
      const originalEnv = process.env.NODE_ENV;
      const originalStrict = process.env.STRICT_WEBHOOK_VALIDATION;

      process.env.NODE_ENV = 'production';
      process.env.STRICT_WEBHOOK_VALIDATION = 'true';

      (validateGooglePubSub as ReturnType<typeof vi.fn>).mockResolvedValue({
        valid: false,
        error: 'Invalid token',
      });

      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        body: JSON.stringify(createPubSubPayload('user@test.com', '12345')),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(401);
      const data = await response.json();
      expect(data.error).toBe('Invalid signature');

      process.env.NODE_ENV = originalEnv;
      process.env.STRICT_WEBHOOK_VALIDATION = originalStrict;
    });
  });

  describe('Integration Lookup', () => {
    it('should find integration by email address', async () => {
      // Mock findIntegrationByEmail to return the integration
      (findIntegrationByEmail as ReturnType<typeof vi.fn>).mockResolvedValue({
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        if (query.includes('SELECT id, tenant_id')) {
          return [{
            id: 'int-123',
            tenant_id: 'tenant-123',
            config: { historyId: '10000' },
            connected_email: 'user@example.com',
          }];
        }
        return [];
      });

      (getGmailAccessToken as ReturnType<typeof vi.fn>).mockResolvedValue('access-token');
      (getGmailHistory as ReturnType<typeof vi.fn>).mockResolvedValue({
        history: [],
        historyId: '12346',
      });

      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        body: JSON.stringify(createPubSubPayload('user@test.com', '12345')),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.status).toBe('processed');
    });

    it('should return 404 when no integration found', async () => {
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        body: JSON.stringify(createPubSubPayload('unknown@test.com', '12345')),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(404);
      const data = await response.json();
      expect(data.error).toBe('No matching integration');
    });

    it('should NOT process emails for unverified addresses (security)', async () => {
      // findIntegrationByEmail returns null - no verified integration for this email
      const { findIntegrationByEmail } = await import('@/lib/oauth');
      (findIntegrationByEmail as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      // SQL returns empty as well
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        body: JSON.stringify(createPubSubPayload('attacker@evil.com', '12345')),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(404);
      const data = await response.json();
      expect(data.error).toBe('No matching integration'); // Should reject unverified emails
    });
  });

  describe('Message Processing', () => {
    const mockIntegration = {
      id: 'int-123',
      tenant_id: 'tenant-123',
      config: { historyId: '10000' },
      connected_email: 'user@example.com',
    };

    const mockParsedEmail = {
      messageId: 'msg-123',
      subject: 'Test Email',
      from: { address: 'sender@test.com', domain: 'test.com' },
      to: [{ address: 'user@test.com', domain: 'test.com' }],
      date: new Date(),
      headers: {},
      body: { text: 'Test body' },
      attachments: [],
      rawHeaders: '',
    };

    const mockVerdict = {
      messageId: 'msg-123',
      tenantId: 'tenant-123',
      verdict: 'pass' as const,
      overallScore: 15,
      confidence: 0.9,
      signals: [],
      layerResults: [],
      processingTimeMs: 100,
      analyzedAt: new Date(),
    };

    beforeEach(() => {
      // Mock findIntegrationByEmail to return the integration
      (findIntegrationByEmail as ReturnType<typeof vi.fn>).mockResolvedValue({
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        if (query.includes('SELECT id, tenant_id')) {
          return [mockIntegration];
        }
        return [];
      });

      (getGmailAccessToken as ReturnType<typeof vi.fn>).mockResolvedValue('access-token');
      (getGmailHistory as ReturnType<typeof vi.fn>).mockResolvedValue({
        history: [{
          messagesAdded: [{ message: { id: 'gmail-msg-123' } }],
        }],
        historyId: '12346',
      });
      (getGmailMessage as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'gmail-msg-123' });
      (parseGmailEmail as ReturnType<typeof vi.fn>).mockReturnValue(mockParsedEmail);
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(mockVerdict);
      (storeVerdict as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    });

    it('should process new messages from history', async () => {
      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        body: JSON.stringify(createPubSubPayload('user@test.com', '12345')),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.status).toBe('processed');
      expect(data.messagesProcessed).toBe(1);

      expect(getGmailMessage).toHaveBeenCalledWith({
        accessToken: 'access-token',
        messageId: 'gmail-msg-123',
        format: 'full',
      });
      expect(analyzeEmail).toHaveBeenCalled();
      expect(storeVerdict).toHaveBeenCalled();
    });

    it('should skip LLM analysis for webhook processing', async () => {
      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        body: JSON.stringify(createPubSubPayload('user@test.com', '12345')),
        headers: { 'Content-Type': 'application/json' },
      });

      await POST(request);

      const analyzeCall = (analyzeEmail as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(analyzeCall[2]).toEqual({ skipLLM: true });
    });

    it('should trigger auto-remediation for threats', async () => {
      const threatVerdict = { ...mockVerdict, verdict: 'quarantine' as const, overallScore: 75 };
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(threatVerdict);

      const { autoRemediate } = await import('@/lib/workers/remediation');
      const { sendThreatNotification } = await import('@/lib/notifications/service');

      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        body: JSON.stringify(createPubSubPayload('user@test.com', '12345')),
        headers: { 'Content-Type': 'application/json' },
      });

      await POST(request);

      expect(sendThreatNotification).toHaveBeenCalled();
      expect(autoRemediate).toHaveBeenCalledWith(expect.objectContaining({
        tenantId: 'tenant-123',
        integrationType: 'gmail',
        verdict: 'quarantine',
      }));
    });
  });

  describe('Queue Integration', () => {
    it('should enqueue job when queue is configured', async () => {
      (isGmailQueueConfigured as ReturnType<typeof vi.fn>).mockReturnValue(true);
      (enqueueGmailJob as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'job-123' });

      // Mock findIntegrationByEmail to return the integration
      (findIntegrationByEmail as ReturnType<typeof vi.fn>).mockResolvedValue({
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        if (query.includes('SELECT id, tenant_id')) {
          return [{
            id: 'int-123',
            tenant_id: 'tenant-123',
            config: { historyId: '10000' },
            connected_email: 'user@example.com',
          }];
        }
        return [];
      });

      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        body: JSON.stringify(createPubSubPayload('user@test.com', '12345')),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.status).toBe('queued');
      expect(data.jobId).toBe('job-123');

      expect(enqueueGmailJob).toHaveBeenCalledWith(expect.objectContaining({
        tenantId: 'tenant-123',
        emailAddress: 'user@test.com',
        historyId: '12345',
      }));
    });
  });

  describe('Error Handling', () => {
    it('should handle Neon connection overload gracefully', async () => {
      // Mock findIntegrationByEmail to return an integration so we proceed to SQL query
      (findIntegrationByEmail as ReturnType<typeof vi.fn>).mockResolvedValue({
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      // SQL fails with Neon connection error
      (sql as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error('Too many connections attempts for this endpoint')
      );

      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        body: JSON.stringify(createPubSubPayload('user@test.com', '12345')),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      // Should return 200 to prevent Gmail from retrying aggressively
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.status).toBe('db_backpressure');
    });

    it('should handle message processing errors gracefully', async () => {
      // Mock findIntegrationByEmail to return the integration
      (findIntegrationByEmail as ReturnType<typeof vi.fn>).mockResolvedValue({
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        if (query.includes('SELECT id, tenant_id')) {
          return [{
            id: 'int-123',
            tenant_id: 'tenant-123',
            config: { historyId: '10000' },
            connected_email: 'user@example.com',
          }];
        }
        return [];
      });

      (getGmailAccessToken as ReturnType<typeof vi.fn>).mockResolvedValue('access-token');
      (getGmailHistory as ReturnType<typeof vi.fn>).mockResolvedValue({
        history: [{
          messagesAdded: [{ message: { id: 'gmail-msg-123' } }],
        }],
        historyId: '12346',
      });
      (getGmailMessage as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('API error'));

      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        body: JSON.stringify(createPubSubPayload('user@test.com', '12345')),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      // Should still return success - individual message errors shouldn't fail the webhook
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.status).toBe('processed');
      expect(data.messagesProcessed).toBe(0);
    });

    it('should return 500 on general processing failure', async () => {
      // Mock findIntegrationByEmail to return an integration so we proceed to SQL query
      (findIntegrationByEmail as ReturnType<typeof vi.fn>).mockResolvedValue({
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      // SQL fails with general error
      (sql as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Unknown database error'));

      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        body: JSON.stringify(createPubSubPayload('user@test.com', '12345')),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(500);
      const data = await response.json();
      expect(data.error).toBe('Processing failed');
    });
  });

  describe('Health Check', () => {
    it('should return healthy status on GET', async () => {
      const response = await GET();

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.status).toBe('healthy');
      expect(data.service).toBe('gmail-webhook');
      expect(data.timestamp).toBeDefined();
    });
  });
});
