/**
 * Gmail Webhook Handler Tests
 * Tests for Gmail Pub/Sub notification processing
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { NextRequest } from 'next/server';

// Mock modules
vi.mock('@/lib/db', () => ({
  sql: vi.fn().mockImplementation(() => Promise.resolve([])),
}));

vi.mock('@/lib/integrations/gmail', () => ({
  getGmailMessage: vi.fn().mockResolvedValue({
    id: 'msg-1',
    threadId: 'thread-1',
    payload: {
      headers: [
        { name: 'From', value: 'sender@test.com' },
        { name: 'To', value: 'recipient@test.com' },
        { name: 'Subject', value: 'Test Email' },
        { name: 'Date', value: new Date().toISOString() },
      ],
      body: { data: Buffer.from('Test body').toString('base64') },
    },
  }),
  getGmailHistory: vi.fn().mockResolvedValue({
    history: [
      {
        id: 'history-1',
        messagesAdded: [{ message: { id: 'msg-1' } }],
      },
    ],
    historyId: '12345',
  }),
  refreshGmailToken: vi.fn().mockResolvedValue({
    accessToken: 'new-access-token',
    expiresAt: new Date(Date.now() + 3600000),
  }),
}));

vi.mock('@/lib/detection/parser', () => ({
  parseGmailEmail: vi.fn().mockReturnValue({
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
  validateGooglePubSub: vi.fn().mockResolvedValue({ valid: true, email: 'test@google.com' }),
  checkRateLimit: vi.fn().mockReturnValue({ limited: false, remaining: 99, resetAt: new Date() }),
}));

describe('Gmail Webhook Handler', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    // Reset mocks to default implementations
    const { checkRateLimit, validateGooglePubSub } = await import('@/lib/webhooks/validation');
    vi.mocked(checkRateLimit).mockReturnValue({
      limited: false,
      remaining: 99,
      resetAt: new Date(),
    });
    vi.mocked(validateGooglePubSub).mockResolvedValue({ valid: true, email: 'test@google.com' });

    // Reset Gmail integration mocks
    const { getGmailMessage, getGmailHistory, refreshGmailToken } = await import('@/lib/integrations/gmail');
    vi.mocked(getGmailMessage).mockResolvedValue({
      id: 'msg-1',
      threadId: 'thread-1',
      payload: {
        headers: [
          { name: 'From', value: 'sender@test.com' },
          { name: 'To', value: 'recipient@test.com' },
          { name: 'Subject', value: 'Test Email' },
          { name: 'Date', value: new Date().toISOString() },
        ],
        body: { data: Buffer.from('Test body').toString('base64') },
      },
    });
    vi.mocked(getGmailHistory).mockResolvedValue({
      history: [
        {
          id: 'history-1',
          messagesAdded: [{ message: { id: 'msg-1' } }],
        },
      ],
      historyId: '12345',
    });
    vi.mocked(refreshGmailToken).mockResolvedValue({
      accessToken: 'new-access-token',
      expiresAt: new Date(Date.now() + 3600000),
    });

    // Reset parser mock
    const { parseGmailEmail } = await import('@/lib/detection/parser');
    vi.mocked(parseGmailEmail).mockReturnValue({
      messageId: 'msg-1',
      subject: 'Test Email',
      from: { address: 'sender@test.com', domain: 'test.com' },
      to: [{ address: 'recipient@test.com', domain: 'test.com' }],
      date: new Date(),
      headers: {},
      body: { text: 'Test body' },
      attachments: [],
      rawHeaders: '',
    });

    // Reset detection pipeline mock (default to 'pass')
    const { analyzeEmail } = await import('@/lib/detection/pipeline');
    vi.mocked(analyzeEmail).mockResolvedValue({
      messageId: 'msg-1',
      tenantId: 'tenant-1',
      verdict: 'pass',
      overallScore: 10,
      confidence: 0.9,
      signals: [],
      layerResults: [],
      processingTimeMs: 100,
      analyzedAt: new Date(),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('POST /api/webhooks/gmail', () => {
    it('should process valid Pub/Sub notification', async () => {
      const { POST } = await import('@/app/api/webhooks/gmail/route');
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
              historyId: '11111',
              email: 'test@gmail.com',
            },
          },
        ] as any)
        .mockResolvedValue([] as any); // For existing check

      const notification = {
        emailAddress: 'test@gmail.com',
        historyId: '12345',
      };

      const pubSubPayload = {
        message: {
          data: Buffer.from(JSON.stringify(notification)).toString('base64'),
          messageId: 'pubsub-1',
          publishTime: new Date().toISOString(),
        },
        subscription: 'projects/test/subscriptions/gmail-webhook',
      };

      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(pubSubPayload),
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.status).toBe('processed');
    });

    it('should handle rate limiting', async () => {
      const { POST } = await import('@/app/api/webhooks/gmail/route');
      const { checkRateLimit } = await import('@/lib/webhooks/validation');

      vi.mocked(checkRateLimit).mockReturnValue({
        limited: true,
        remaining: 0,
        resetAt: new Date(Date.now() + 60000),
      });

      const pubSubPayload = {
        message: {
          data: Buffer.from(JSON.stringify({ emailAddress: 'test@gmail.com', historyId: '12345' })).toString('base64'),
          messageId: 'pubsub-1',
          publishTime: new Date().toISOString(),
        },
        subscription: 'projects/test/subscriptions/gmail-webhook',
      };

      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(pubSubPayload),
      });

      const response = await POST(request);

      expect(response.status).toBe(429);
    });

    it('should return ignored for unknown email', async () => {
      const { POST } = await import('@/app/api/webhooks/gmail/route');
      const { sql } = await import('@/lib/db');
      const { checkRateLimit } = await import('@/lib/webhooks/validation');

      vi.mocked(checkRateLimit).mockReturnValue({
        limited: false,
        remaining: 99,
        resetAt: new Date(),
      });

      // No integration found
      vi.mocked(sql).mockResolvedValueOnce([] as any);

      const pubSubPayload = {
        message: {
          data: Buffer.from(JSON.stringify({ emailAddress: 'unknown@gmail.com', historyId: '12345' })).toString('base64'),
          messageId: 'pubsub-1',
          publishTime: new Date().toISOString(),
        },
        subscription: 'projects/test/subscriptions/gmail-webhook',
      };

      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(pubSubPayload),
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.status).toBe('ignored');
    });

    it('should process threats and trigger auto-remediate', async () => {
      const { POST } = await import('@/app/api/webhooks/gmail/route');
      const { sql } = await import('@/lib/db');
      const { analyzeEmail } = await import('@/lib/detection/pipeline');
      const { autoRemediate } = await import('@/lib/workers/remediation');
      const { sendThreatNotification } = await import('@/lib/notifications/service');
      const { checkRateLimit } = await import('@/lib/webhooks/validation');

      vi.mocked(checkRateLimit).mockReturnValue({
        limited: false,
        remaining: 99,
        resetAt: new Date(),
      });

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
              historyId: '11111',
              email: 'test@gmail.com',
            },
          },
        ] as any)
        .mockResolvedValue([] as any);

      // Mock threat detection
      vi.mocked(analyzeEmail).mockResolvedValueOnce({
        messageId: 'msg-1',
        tenantId: 'tenant-1',
        verdict: 'quarantine',
        overallScore: 75,
        confidence: 0.95,
        signals: [{ type: 'phishing', score: 75, description: 'Suspicious link' }],
        layerResults: [],
        processingTimeMs: 150,
        analyzedAt: new Date(),
      });

      const pubSubPayload = {
        message: {
          data: Buffer.from(JSON.stringify({ emailAddress: 'test@gmail.com', historyId: '12345' })).toString('base64'),
          messageId: 'pubsub-1',
          publishTime: new Date().toISOString(),
        },
        subscription: 'projects/test/subscriptions/gmail-webhook',
      };

      const request = new NextRequest('http://localhost/api/webhooks/gmail', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(pubSubPayload),
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      expect(sendThreatNotification).toHaveBeenCalled();
      expect(autoRemediate).toHaveBeenCalled();
    });
  });

  describe('GET /api/webhooks/gmail', () => {
    it('should return health status', async () => {
      const { GET } = await import('@/app/api/webhooks/gmail/route');

      const response = await GET();

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.status).toBe('healthy');
      expect(data.service).toBe('gmail-webhook');
    });
  });
});
