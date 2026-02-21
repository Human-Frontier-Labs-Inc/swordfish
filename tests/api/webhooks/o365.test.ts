/**
 * O365 Webhook API Tests
 * Tests for POST /api/webhooks/o365 endpoint
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { NextRequest } from 'next/server';

// Mock database
vi.mock('@/lib/db', () => ({
  sql: vi.fn(),
}));

// Mock validation
vi.mock('@/lib/webhooks/validation', () => ({
  validateMicrosoftGraph: vi.fn(),
  checkRateLimit: vi.fn(),
}));

// Mock O365 functions
vi.mock('@/lib/integrations/o365', () => ({
  getO365Email: vi.fn(),
  getO365AccessToken: vi.fn(),
}));

// Mock parser
vi.mock('@/lib/detection/parser', () => ({
  parseGraphEmail: vi.fn(),
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

import { sql } from '@/lib/db';
import { validateMicrosoftGraph, checkRateLimit } from '@/lib/webhooks/validation';
import { getO365Email, getO365AccessToken } from '@/lib/integrations/o365';
import { parseGraphEmail } from '@/lib/detection/parser';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import { logAuditEvent } from '@/lib/db/audit';
import { POST, GET } from '@/app/api/webhooks/o365/route';

describe('O365 Webhook API', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Default mocks
    (checkRateLimit as ReturnType<typeof vi.fn>).mockReturnValue({
      limited: false,
      remaining: 99,
      resetAt: new Date(),
    });

    (validateMicrosoftGraph as ReturnType<typeof vi.fn>).mockReturnValue({
      valid: true,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const createGraphNotification = (overrides = {}) => ({
    value: [{
      subscriptionId: 'sub-123',
      clientState: 'tenant-123', // Should match tenant_id
      changeType: 'created' as const,
      resource: 'Users/user-id/Messages/msg-123',
      resourceData: {
        id: 'msg-123',
        '@odata.type': '#Microsoft.Graph.Message',
        '@odata.id': 'msg-123',
        '@odata.etag': 'etag-123',
      },
      tenantId: 'ms-tenant-123',
      ...overrides,
    }],
  });

  describe('Subscription Validation', () => {
    it('should return validation token on subscription setup', async () => {
      const request = new NextRequest(
        'http://localhost/api/webhooks/o365?validationToken=test-validation-token',
        { method: 'POST' }
      );

      const response = await POST(request);

      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toBe('text/plain');
      const text = await response.text();
      expect(text).toBe('test-validation-token');
    });
  });

  describe('Rate Limiting', () => {
    it('should return 429 when rate limit exceeded', async () => {
      (checkRateLimit as ReturnType<typeof vi.fn>).mockReturnValue({
        limited: true,
        remaining: 0,
        resetAt: new Date(Date.now() + 60000),
      });

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification()),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(429);
      expect(response.headers.get('Retry-After')).toBe('60');
      const data = await response.json();
      expect(data.error).toBe('Rate limit exceeded');
    });

    it('should extract client IP for rate limiting', async () => {
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification()),
        headers: {
          'Content-Type': 'application/json',
          'x-forwarded-for': '10.0.0.1',
        },
      });

      await POST(request);

      expect(checkRateLimit).toHaveBeenCalledWith(
        expect.objectContaining({
          key: 'o365:10.0.0.1',
        })
      );
    });
  });

  describe('Client State Validation', () => {
    it('should validate clientState for each notification', async () => {
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification({ clientState: 'test-state' })),
        headers: { 'Content-Type': 'application/json' },
      });

      await POST(request);

      expect(validateMicrosoftGraph).toHaveBeenCalledWith({
        clientState: 'test-state',
        expectedClientState: '', // MICROSOFT_WEBHOOK_SECRET not set in test
      });
    });

    it('should skip invalid notifications in production with strict validation', async () => {
      const originalEnv = process.env.NODE_ENV;
      const originalStrict = process.env.STRICT_WEBHOOK_VALIDATION;

      process.env.NODE_ENV = 'production';
      process.env.STRICT_WEBHOOK_VALIDATION = 'true';

      (validateMicrosoftGraph as ReturnType<typeof vi.fn>).mockReturnValue({
        valid: false,
        error: 'Invalid clientState',
      });

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification()),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      // Should return success but skip invalid notifications
      expect(response.status).toBe(200);
      expect(sql).not.toHaveBeenCalled(); // No DB operations

      process.env.NODE_ENV = originalEnv;
      process.env.STRICT_WEBHOOK_VALIDATION = originalStrict;
    });
  });

  describe('Security - Cross-Tenant Protection', () => {
    it('should reject notifications for unknown subscriptions', async () => {
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification({ subscriptionId: 'unknown-sub' })),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.status).toBe('processed');

      // Should NOT have fetched any email (security check)
      expect(getO365Email).not.toHaveBeenCalled();
    });

    it('should reject notifications with mismatched clientState (tampering detection)', async () => {
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([{
        id: 'int-123',
        tenant_id: 'tenant-123',
        config: { subscriptionId: 'sub-123' },
        connected_email: 'user@example.com',
      }]);

      // clientState doesn't match tenant_id
      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification({ clientState: 'different-tenant' })),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);

      // Should log security audit event
      expect(logAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'security.webhook_tampering_detected',
          afterState: expect.objectContaining({
            alertType: 'cross_tenant_attempt',
            expectedClientState: 'tenant-123',
            receivedClientState: 'different-tenant',
          }),
        })
      );

      // Should NOT have processed the email
      expect(getO365Email).not.toHaveBeenCalled();
    });
  });

  describe('Notification Processing', () => {
    const mockIntegration = {
      id: 'int-123',
      tenant_id: 'tenant-123',
      config: { subscriptionId: 'sub-123' },
      connected_email: 'user@example.com',
    };

    const mockParsedEmail = {
      messageId: 'msg-123',
      subject: 'Test Email',
      from: { address: 'sender@test.com', domain: 'test.com' },
      to: [{ address: 'user@company.com', domain: 'company.com' }],
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
      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        if (query.includes('SELECT id, tenant_id')) {
          return [mockIntegration];
        }
        return [];
      });

      (getO365AccessToken as ReturnType<typeof vi.fn>).mockResolvedValue('access-token');
      (getO365Email as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'msg-123' });
      (parseGraphEmail as ReturnType<typeof vi.fn>).mockReturnValue(mockParsedEmail);
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(mockVerdict);
      (storeVerdict as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    });

    it('should process new message notifications', async () => {
      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification()),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.status).toBe('processed');

      expect(getO365Email).toHaveBeenCalledWith({
        accessToken: 'access-token',
        messageId: 'msg-123',
      });
      expect(analyzeEmail).toHaveBeenCalled();
      expect(storeVerdict).toHaveBeenCalled();
    });

    it('should only process created messages (not updated/deleted)', async () => {
      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification({ changeType: 'updated' })),
        headers: { 'Content-Type': 'application/json' },
      });

      await POST(request);

      // Should not process updated messages
      expect(getO365Email).not.toHaveBeenCalled();
    });

    it('should trigger auto-remediation for threats', async () => {
      const threatVerdict = { ...mockVerdict, verdict: 'block' as const, overallScore: 90 };
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(threatVerdict);

      const { autoRemediate } = await import('@/lib/workers/remediation');
      const { sendThreatNotification } = await import('@/lib/notifications/service');

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification()),
        headers: { 'Content-Type': 'application/json' },
      });

      await POST(request);

      expect(sendThreatNotification).toHaveBeenCalledWith(
        'tenant-123',
        expect.objectContaining({
          type: 'threat_blocked',
          severity: 'critical',
        })
      );

      expect(autoRemediate).toHaveBeenCalledWith(expect.objectContaining({
        tenantId: 'tenant-123',
        integrationType: 'o365',
        verdict: 'block',
      }));
    });

    it('should use warning severity for lower-score threats', async () => {
      const threatVerdict = { ...mockVerdict, verdict: 'quarantine' as const, overallScore: 65 };
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(threatVerdict);

      const { sendThreatNotification } = await import('@/lib/notifications/service');

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification()),
        headers: { 'Content-Type': 'application/json' },
      });

      await POST(request);

      expect(sendThreatNotification).toHaveBeenCalledWith(
        'tenant-123',
        expect.objectContaining({
          severity: 'warning', // Not critical because score < 80
        })
      );
    });

    it('should update integration last_sync_at', async () => {
      const sqlCalls: string[] = [];
      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        sqlCalls.push(query);
        if (query.includes('SELECT id, tenant_id')) {
          return [mockIntegration];
        }
        return [];
      });

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification()),
        headers: { 'Content-Type': 'application/json' },
      });

      await POST(request);

      const updateCall = sqlCalls.find(q => q.includes('UPDATE integrations') && q.includes('last_sync_at'));
      expect(updateCall).toBeDefined();
    });

    it('should log audit event for processed emails', async () => {
      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification()),
        headers: { 'Content-Type': 'application/json' },
      });

      await POST(request);

      expect(logAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-123',
          action: 'email.analyzed',
          resourceType: 'email',
          afterState: expect.objectContaining({
            source: 'o365_webhook',
            verdict: 'pass',
          }),
        })
      );
    });
  });

  describe('Error Handling', () => {
    it('should handle notification processing errors gracefully', async () => {
      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        if (query.includes('SELECT id, tenant_id')) {
          return [{
            id: 'int-123',
            tenant_id: 'tenant-123',
            config: { subscriptionId: 'sub-123' },
            connected_email: 'user@example.com',
          }];
        }
        return [];
      });

      (getO365AccessToken as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error('Token refresh failed')
      );

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification()),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      // Should return success - individual errors shouldn't fail the entire webhook
      expect(response.status).toBe(200);
    });

    it('should return 500 on critical failure', async () => {
      (checkRateLimit as ReturnType<typeof vi.fn>).mockImplementation(() => {
        throw new Error('Rate limit service unavailable');
      });

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification()),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(500);
      const data = await response.json();
      expect(data.error).toBe('Processing failed');
    });

    it('should skip notifications without valid subscription', async () => {
      // Return empty array - no matching subscription found
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(createGraphNotification()),
        headers: { 'Content-Type': 'application/json' },
      });

      await POST(request);

      // Should not try to get token if no subscription matches
      expect(getO365AccessToken).not.toHaveBeenCalled();
    });
  });

  describe('Multiple Notifications', () => {
    it('should process multiple notifications in a single request', async () => {
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([{
        id: 'int-123',
        tenant_id: 'tenant-123',
        config: { subscriptionId: 'sub-123' },
        connected_email: 'user@example.com',
      }]);

      (getO365AccessToken as ReturnType<typeof vi.fn>).mockResolvedValue('access-token');
      (getO365Email as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'msg-123' });
      (parseGraphEmail as ReturnType<typeof vi.fn>).mockReturnValue({
        messageId: 'msg-123',
        subject: 'Test',
        from: { address: 'sender@test.com', domain: 'test.com' },
        to: [],
        date: new Date(),
        headers: {},
        body: { text: '' },
        attachments: [],
        rawHeaders: '',
      });
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue({
        verdict: 'pass',
        overallScore: 10,
      });

      const multiNotification = {
        value: [
          {
            subscriptionId: 'sub-123',
            clientState: 'tenant-123',
            changeType: 'created' as const,
            resource: 'Users/user-id/Messages/msg-1',
            resourceData: { id: 'msg-1', '@odata.type': '', '@odata.id': '', '@odata.etag': '' },
            tenantId: 'ms-tenant-123',
          },
          {
            subscriptionId: 'sub-123',
            clientState: 'tenant-123',
            changeType: 'created' as const,
            resource: 'Users/user-id/Messages/msg-2',
            resourceData: { id: 'msg-2', '@odata.type': '', '@odata.id': '', '@odata.etag': '' },
            tenantId: 'ms-tenant-123',
          },
        ],
      };

      const request = new NextRequest('http://localhost/api/webhooks/o365', {
        method: 'POST',
        body: JSON.stringify(multiNotification),
        headers: { 'Content-Type': 'application/json' },
      });

      await POST(request);

      // Should process both messages
      expect(getO365Email).toHaveBeenCalledTimes(2);
    });
  });

  describe('Health Check', () => {
    it('should return healthy status on GET', async () => {
      const response = await GET();

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.status).toBe('healthy');
      expect(data.service).toBe('o365-webhook');
      expect(data.timestamp).toBeDefined();
    });
  });
});
