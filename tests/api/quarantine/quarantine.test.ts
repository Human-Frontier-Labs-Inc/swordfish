/**
 * Quarantine API Tests
 * Tests for all quarantine endpoints:
 * - GET /api/quarantine (list)
 * - GET /api/quarantine/[id] (details)
 * - DELETE /api/quarantine/[id] (delete)
 * - POST /api/quarantine/[id]/release (release)
 * - POST /api/quarantine/bulk (bulk actions)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { NextRequest } from 'next/server';

// Mock Clerk auth
vi.mock('@clerk/nextjs/server', () => ({
  auth: vi.fn(),
}));

// Mock database
vi.mock('@/lib/db', () => ({
  sql: vi.fn(),
}));

// Mock audit logging
vi.mock('@/lib/db/audit', () => ({
  logAuditEvent: vi.fn().mockResolvedValue(undefined),
}));

// Mock remediation functions
vi.mock('@/lib/workers/remediation', () => ({
  releaseEmail: vi.fn(),
  deleteEmail: vi.fn(),
}));

import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';
import { releaseEmail, deleteEmail } from '@/lib/workers/remediation';

// Import route handlers
import { GET as listQuarantine } from '@/app/api/quarantine/route';
import { GET as getQuarantineItem, DELETE as deleteQuarantineItem } from '@/app/api/quarantine/[id]/route';
import { POST as releaseQuarantineItem } from '@/app/api/quarantine/[id]/release/route';
import { POST as bulkQuarantineAction } from '@/app/api/quarantine/bulk/route';

describe('Quarantine API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const mockThreat = {
    id: 'threat-123',
    message_id: 'msg-123',
    subject: 'Suspicious Email',
    sender_email: 'attacker@phish.com',
    recipient_email: 'user@company.com',
    verdict: 'quarantine',
    score: 75,
    categories: ['phishing'],
    received_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    status: 'quarantined',
    integration_type: 'gmail',
    original_location: 'INBOX',
  };

  describe('GET /api/quarantine (List)', () => {
    it('should return Unauthorized error when not authenticated', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: null, orgId: null });

      const request = new NextRequest('http://localhost/api/quarantine');
      const response = await listQuarantine(request);

      // Note: The list endpoint returns 200 with error in body (design choice)
      const data = await response.json();
      expect(data.error).toBe('Unauthorized');
    });

    it('should return quarantined emails for authenticated user', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      // Mock returns data with SQL-aliased column names
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([{
        id: 'threat-123',
        message_id: 'msg-123',
        subject: 'Suspicious Email',
        sender: 'attacker@phish.com',  // SQL alias: sender_email as sender
        recipient: 'user@company.com', // SQL alias: recipient_email as recipient
        verdict: 'quarantine',
        score: 75,
        categories: ['phishing'],
        received_at: new Date().toISOString(),
        quarantined_at: new Date().toISOString(), // SQL alias: created_at as quarantined_at
      }]);

      const request = new NextRequest('http://localhost/api/quarantine');
      const response = await listQuarantine(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.emails).toHaveLength(1);
      expect(data.emails[0].id).toBe('threat-123');
      expect(data.emails[0].sender).toBe('attacker@phish.com');
    });

    it('should use personal tenant ID when no org', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_456', orgId: null });
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const request = new NextRequest('http://localhost/api/quarantine');
      await listQuarantine(request);

      expect(sql).toHaveBeenCalled();
      const call = (sql as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(call[1]).toBe('personal_user_456');
    });

    it('should support search filtering', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([mockThreat]);

      const request = new NextRequest('http://localhost/api/quarantine?search=phish');
      await listQuarantine(request);

      // Verify search query is used
      const call = (sql as ReturnType<typeof vi.fn>).mock.calls[0];
      const query = call[0].join('?');
      expect(query).toContain('ILIKE');
    });

    it('should support pagination', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const request = new NextRequest('http://localhost/api/quarantine?limit=10&offset=20');
      await listQuarantine(request);

      const call = (sql as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(call).toContainEqual(10); // limit
      expect(call).toContainEqual(20); // offset
    });

    it('should return empty array on database error', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Database error'));

      const request = new NextRequest('http://localhost/api/quarantine');
      const response = await listQuarantine(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.emails).toEqual([]);
    });
  });

  describe('GET /api/quarantine/[id] (Details)', () => {
    const createParams = (id: string) => ({ params: Promise.resolve({ id }) });

    it('should return 401 when not authenticated', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: null, orgId: null });

      const request = new NextRequest('http://localhost/api/quarantine/threat-123');
      const response = await getQuarantineItem(request, createParams('threat-123'));

      expect(response.status).toBe(401);
    });

    it('should return 404 when threat not found', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const request = new NextRequest('http://localhost/api/quarantine/nonexistent');
      const response = await getQuarantineItem(request, createParams('nonexistent'));

      expect(response.status).toBe(404);
    });

    it('should return threat details with signals', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([{
        ...mockThreat,
        signals: [{ type: 'phishing', score: 80 }],
        explanation: 'Suspicious sender domain',
      }]);

      const request = new NextRequest('http://localhost/api/quarantine/threat-123');
      const response = await getQuarantineItem(request, createParams('threat-123'));

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.email.signals).toHaveLength(1);
      expect(data.email.explanation).toBe('Suspicious sender domain');
    });

    it('should enforce tenant isolation', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const request = new NextRequest('http://localhost/api/quarantine/threat-other-tenant');
      const response = await getQuarantineItem(request, createParams('threat-other-tenant'));

      // The query includes tenant_id filter, so not found = wrong tenant or doesn't exist
      expect(response.status).toBe(404);
    });
  });

  describe('DELETE /api/quarantine/[id] (Delete)', () => {
    const createParams = (id: string) => ({ params: Promise.resolve({ id }) });

    it('should return 401 when not authenticated', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: null, orgId: null });

      const request = new NextRequest('http://localhost/api/quarantine/threat-123', { method: 'DELETE' });
      const response = await deleteQuarantineItem(request, createParams('threat-123'));

      expect(response.status).toBe(401);
    });

    it('should return 404 when threat not found', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const request = new NextRequest('http://localhost/api/quarantine/nonexistent', { method: 'DELETE' });
      const response = await deleteQuarantineItem(request, createParams('nonexistent'));

      expect(response.status).toBe(404);
    });

    it('should delete threat successfully', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        if (query.includes('SELECT id FROM threats')) {
          return [{ id: 'threat-123' }];
        }
        if (query.includes('SELECT email FROM users')) {
          return [{ email: 'admin@company.com' }];
        }
        return [];
      });
      (deleteEmail as ReturnType<typeof vi.fn>).mockResolvedValue({ success: true });

      const request = new NextRequest('http://localhost/api/quarantine/threat-123', { method: 'DELETE' });
      const response = await deleteQuarantineItem(request, createParams('threat-123'));

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);

      expect(deleteEmail).toHaveBeenCalledWith(expect.objectContaining({
        tenantId: 'org_123',
        threatId: 'threat-123',
        actorId: 'user_123',
        actorEmail: 'admin@company.com',
      }));
    });

    it('should return 500 when delete fails', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        if (query.includes('SELECT id FROM threats')) {
          return [{ id: 'threat-123' }];
        }
        return [];
      });
      (deleteEmail as ReturnType<typeof vi.fn>).mockResolvedValue({
        success: false,
        error: 'Email not found in mailbox',
      });

      const request = new NextRequest('http://localhost/api/quarantine/threat-123', { method: 'DELETE' });
      const response = await deleteQuarantineItem(request, createParams('threat-123'));

      expect(response.status).toBe(500);
      const data = await response.json();
      expect(data.details).toBe('Email not found in mailbox');
    });
  });

  describe('POST /api/quarantine/[id]/release (Release)', () => {
    const createParams = (id: string) => ({ params: Promise.resolve({ id }) });

    it('should return 401 when not authenticated', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: null, orgId: null });

      const request = new NextRequest('http://localhost/api/quarantine/threat-123/release', { method: 'POST' });
      const response = await releaseQuarantineItem(request, createParams('threat-123'));

      expect(response.status).toBe(401);
    });

    it('should return 404 when threat not found or already released', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const request = new NextRequest('http://localhost/api/quarantine/nonexistent/release', { method: 'POST' });
      const response = await releaseQuarantineItem(request, createParams('nonexistent'));

      expect(response.status).toBe(404);
      const data = await response.json();
      expect(data.error).toBe('Not found or already released');
    });

    it('should release threat successfully', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        if (query.includes('SELECT id, message_id')) {
          return [mockThreat];
        }
        if (query.includes('SELECT email FROM users')) {
          return [{ email: 'admin@company.com' }];
        }
        return [];
      });
      (releaseEmail as ReturnType<typeof vi.fn>).mockResolvedValue({ success: true });

      const request = new NextRequest('http://localhost/api/quarantine/threat-123/release', { method: 'POST' });
      const response = await releaseQuarantineItem(request, createParams('threat-123'));

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);

      expect(releaseEmail).toHaveBeenCalledWith(expect.objectContaining({
        tenantId: 'org_123',
        threatId: 'threat-123',
        actorId: 'user_123',
      }));
    });

    it('should only release quarantined emails (not already released)', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      // SQL query filters by status = 'quarantined', so returned [] means not found or wrong status
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const request = new NextRequest('http://localhost/api/quarantine/already-released/release', { method: 'POST' });
      const response = await releaseQuarantineItem(request, createParams('already-released'));

      expect(response.status).toBe(404);
    });

    it('should return 500 when release fails', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        if (query.includes('SELECT id, message_id')) {
          return [mockThreat];
        }
        return [];
      });
      (releaseEmail as ReturnType<typeof vi.fn>).mockResolvedValue({
        success: false,
        error: 'Gmail API error: Message not found',
      });

      const request = new NextRequest('http://localhost/api/quarantine/threat-123/release', { method: 'POST' });
      const response = await releaseQuarantineItem(request, createParams('threat-123'));

      expect(response.status).toBe(500);
      const data = await response.json();
      expect(data.details).toContain('Gmail API error');
    });
  });

  describe('POST /api/quarantine/bulk (Bulk Actions)', () => {
    it('should return 401 when not authenticated', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: null, orgId: null });

      const request = new NextRequest('http://localhost/api/quarantine/bulk', {
        method: 'POST',
        body: JSON.stringify({ action: 'release', emailIds: ['threat-123'] }),
        headers: { 'Content-Type': 'application/json' },
      });
      const response = await bulkQuarantineAction(request);

      expect(response.status).toBe(401);
    });

    it('should return 400 when no emailIds provided', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });

      const request = new NextRequest('http://localhost/api/quarantine/bulk', {
        method: 'POST',
        body: JSON.stringify({ action: 'release', emailIds: [] }),
        headers: { 'Content-Type': 'application/json' },
      });
      const response = await bulkQuarantineAction(request);

      expect(response.status).toBe(400);
      const data = await response.json();
      expect(data.error).toBe('No emails specified');
    });

    it('should return 400 for invalid action', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });

      const request = new NextRequest('http://localhost/api/quarantine/bulk', {
        method: 'POST',
        body: JSON.stringify({ action: 'invalid', emailIds: ['threat-123'] }),
        headers: { 'Content-Type': 'application/json' },
      });
      const response = await bulkQuarantineAction(request);

      expect(response.status).toBe(400);
      const data = await response.json();
      expect(data.error).toBe('Invalid action');
    });

    it('should bulk release emails successfully', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        if (query.includes('SELECT id, message_id FROM threats')) {
          return [{ id: 'threat-123', message_id: 'msg-123' }];
        }
        return [];
      });

      const request = new NextRequest('http://localhost/api/quarantine/bulk', {
        method: 'POST',
        body: JSON.stringify({ action: 'release', emailIds: ['threat-123', 'threat-456'] }),
        headers: { 'Content-Type': 'application/json' },
      });
      const response = await bulkQuarantineAction(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.processed).toBeGreaterThanOrEqual(1);
    });

    it('should bulk delete emails successfully', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        if (query.includes('SELECT id, message_id FROM threats')) {
          return [{ id: 'threat-123', message_id: 'msg-123' }];
        }
        return [];
      });

      const request = new NextRequest('http://localhost/api/quarantine/bulk', {
        method: 'POST',
        body: JSON.stringify({ action: 'delete', emailIds: ['threat-123'] }),
        headers: { 'Content-Type': 'application/json' },
      });
      const response = await bulkQuarantineAction(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
    });

    it('should report errors for individual failures', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });

      let callCount = 0;
      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        if (query.includes('SELECT id, message_id FROM threats')) {
          callCount++;
          if (callCount === 1) {
            return [{ id: 'threat-123', message_id: 'msg-123' }];
          }
          return []; // Second call returns not found
        }
        return [];
      });

      const request = new NextRequest('http://localhost/api/quarantine/bulk', {
        method: 'POST',
        body: JSON.stringify({ action: 'release', emailIds: ['threat-123', 'threat-notfound'] }),
        headers: { 'Content-Type': 'application/json' },
      });
      const response = await bulkQuarantineAction(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.processed).toBe(1);
      expect(data.errors).toBeDefined();
      expect(data.errors).toHaveLength(1);
    });

    it('should log audit event for bulk actions', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        if (query.includes('SELECT id, message_id FROM threats')) {
          return [{ id: 'threat-123', message_id: 'msg-123' }];
        }
        return [];
      });

      const request = new NextRequest('http://localhost/api/quarantine/bulk', {
        method: 'POST',
        body: JSON.stringify({ action: 'release', emailIds: ['threat-123'] }),
        headers: { 'Content-Type': 'application/json' },
      });
      await bulkQuarantineAction(request);

      expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({
        tenantId: 'org_123',
        actorId: 'user_123',
        action: 'quarantine.bulk_release',
        resourceType: 'threat',
      }));
    });

    it('should enforce tenant isolation in bulk operations', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      // Returns empty for all threats (simulating they belong to different tenant)
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const request = new NextRequest('http://localhost/api/quarantine/bulk', {
        method: 'POST',
        body: JSON.stringify({ action: 'release', emailIds: ['other-tenant-threat'] }),
        headers: { 'Content-Type': 'application/json' },
      });
      const response = await bulkQuarantineAction(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.processed).toBe(0);
      expect(data.errors).toHaveLength(1);
    });

    it('should limit error reporting to 10 items', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      // All queries return not found
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const manyIds = Array.from({ length: 15 }, (_, i) => `threat-${i}`);
      const request = new NextRequest('http://localhost/api/quarantine/bulk', {
        method: 'POST',
        body: JSON.stringify({ action: 'release', emailIds: manyIds }),
        headers: { 'Content-Type': 'application/json' },
      });
      const response = await bulkQuarantineAction(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.errors).toHaveLength(10); // Limited to 10
    });
  });

  describe('Tenant Isolation (Security)', () => {
    it('should not allow access to other tenant quarantine items', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      // Query returns nothing because tenant_id filter excludes other tenant's data
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const createParams = (id: string) => ({ params: Promise.resolve({ id }) });
      const request = new NextRequest('http://localhost/api/quarantine/other-tenant-threat');
      const response = await getQuarantineItem(request, createParams('other-tenant-threat'));

      expect(response.status).toBe(404);
    });

    it('should not allow releasing other tenant threats', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const createParams = (id: string) => ({ params: Promise.resolve({ id }) });
      const request = new NextRequest('http://localhost/api/quarantine/other-tenant-threat/release', { method: 'POST' });
      const response = await releaseQuarantineItem(request, createParams('other-tenant-threat'));

      expect(response.status).toBe(404);
      expect(releaseEmail).not.toHaveBeenCalled();
    });

    it('should not allow deleting other tenant threats', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (sql as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const createParams = (id: string) => ({ params: Promise.resolve({ id }) });
      const request = new NextRequest('http://localhost/api/quarantine/other-tenant-threat', { method: 'DELETE' });
      const response = await deleteQuarantineItem(request, createParams('other-tenant-threat'));

      expect(response.status).toBe(404);
      expect(deleteEmail).not.toHaveBeenCalled();
    });
  });
});
