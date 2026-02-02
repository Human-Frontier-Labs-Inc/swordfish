/**
 * Remediation Transaction Safety Tests (HIGH-2)
 *
 * Tests that remediation failures properly update DB status
 * instead of leaving inconsistent state.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock the database module
vi.mock('@/lib/db', () => ({
  sql: vi.fn(),
}));

// Mock Gmail functions
vi.mock('@/lib/integrations/gmail', () => ({
  modifyGmailMessage: vi.fn(),
  trashGmailMessage: vi.fn(),
  untrashGmailMessage: vi.fn(),
  findGmailMessageByMessageId: vi.fn(),
  getOrCreateQuarantineLabel: vi.fn().mockResolvedValue('Label_123'),
  getGmailAccessToken: vi.fn().mockResolvedValue('mock-token'),
}));

// Mock O365 functions
vi.mock('@/lib/integrations/o365', () => ({
  moveO365Email: vi.fn(),
  getOrCreateQuarantineFolder: vi.fn().mockResolvedValue('folder-id'),
  getO365AccessToken: vi.fn().mockResolvedValue('mock-token'),
}));

// Mock audit logging
vi.mock('@/lib/db/audit', () => ({
  logAuditEvent: vi.fn().mockResolvedValue(undefined),
}));

// Mock notifications
vi.mock('@/lib/notifications/service', () => ({
  sendNotification: vi.fn().mockResolvedValue(undefined),
}));

import { sql } from '@/lib/db';
import { autoRemediate } from '@/lib/workers/remediation';

describe('Remediation Transaction Safety (HIGH-2)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('autoRemediate', () => {
    const baseParams = {
      tenantId: 'tenant-123',
      messageId: 'msg-123',
      externalMessageId: 'ext-msg-123',
      integrationId: 'int-123',
      integrationType: 'gmail' as const,
      verdict: 'quarantine' as const,
      score: 75,
    };

    it('should set status to remediation_pending before mailbox operation', async () => {
      const sqlCalls: string[] = [];

      (sql as unknown as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        sqlCalls.push(query);

        // Return mock data based on query
        // Check for integration status (new query pattern)
        if (query.includes('SELECT id FROM integrations') && query.includes('status')) {
          return [{ id: 'int-123' }]; // Integration is connected
        }
        if (query.includes('SELECT subject, from_address')) {
          return [{ subject: 'Test', from_address: 'test@test.com', to_addresses: ['user@test.com'], signals: [] }];
        }
        if (query.includes('SELECT id FROM threats')) {
          return []; // No existing threat
        }
        return [];
      });

      // The Gmail quarantine will succeed
      const { modifyGmailMessage } = await import('@/lib/integrations/gmail');
      (modifyGmailMessage as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

      await autoRemediate(baseParams);

      // Verify remediation_pending was set before the final quarantined status
      const insertCall = sqlCalls.find(q => q.includes('INSERT INTO threats'));
      expect(insertCall).toBeDefined();
      expect(insertCall).toContain('remediation_pending');
    });

    it('should set status to quarantined on successful mailbox operation', async () => {
      const sqlCalls: string[] = [];

      (sql as unknown as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        sqlCalls.push(query);

        // Check for integration status (new query pattern)
        if (query.includes('SELECT id FROM integrations') && query.includes('status')) {
          return [{ id: 'int-123' }]; // Integration is connected
        }
        if (query.includes('SELECT subject, from_address')) {
          return [{ subject: 'Test', from_address: 'test@test.com', to_addresses: ['user@test.com'], signals: [] }];
        }
        if (query.includes('SELECT id FROM threats')) {
          return [{ id: 'threat-123' }]; // Existing threat
        }
        return [];
      });

      const { modifyGmailMessage } = await import('@/lib/integrations/gmail');
      (modifyGmailMessage as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

      const result = await autoRemediate(baseParams);

      expect(result.success).toBe(true);

      // Verify final update set status to quarantined
      const finalUpdate = sqlCalls.filter(q => q.includes('UPDATE threats') && q.includes('quarantined'));
      expect(finalUpdate.length).toBeGreaterThan(0);
    });

    it('should set status to remediation_failed when mailbox operation fails', async () => {
      const sqlCalls: string[] = [];

      (sql as unknown as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        sqlCalls.push(query);

        // Check for integration status (new query pattern)
        if (query.includes('SELECT id FROM integrations') && query.includes('status')) {
          return [{ id: 'int-123' }]; // Integration is connected
        }
        if (query.includes('SELECT subject, from_address')) {
          return [{ subject: 'Test', from_address: 'test@test.com', to_addresses: ['user@test.com'], signals: [] }];
        }
        if (query.includes('SELECT id FROM threats')) {
          return [{ id: 'threat-123' }];
        }
        return [];
      });

      // Make Gmail quarantine fail
      const { modifyGmailMessage } = await import('@/lib/integrations/gmail');
      (modifyGmailMessage as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Gmail API error'));

      const result = await autoRemediate(baseParams);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Mailbox operation failed');

      // Verify status was set to remediation_failed
      const failedUpdate = sqlCalls.filter(q => q.includes('UPDATE threats') && q.includes('remediation_failed'));
      expect(failedUpdate.length).toBeGreaterThan(0);
    });

    it('should return error when integration not found', async () => {
      (sql as unknown as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const result = await autoRemediate(baseParams);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Integration not found');
    });

    it('should return error when integration not connected', async () => {
      // When integration exists but status is NOT 'connected',
      // the query `SELECT id FROM integrations WHERE id = ? AND status = 'connected'`
      // will return 0 rows (empty array)
      (sql as unknown as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const result = await autoRemediate(baseParams);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Integration not found or not connected');
    });

    it('should handle O365 remediation the same way', async () => {
      const sqlCalls: string[] = [];

      (sql as unknown as ReturnType<typeof vi.fn>).mockImplementation(async (strings: TemplateStringsArray) => {
        const query = strings.join('?');
        sqlCalls.push(query);

        if (query.includes('SELECT') && query.includes('integrations')) {
          return [{
            id: 'int-123',
            status: 'connected',
            tenant_id: 'tenant-123',
            type: 'o365',
            config: { quarantineFolderId: 'folder-123' }
          }];
        }
        if (query.includes('SELECT subject, from_address')) {
          return [{ subject: 'Test', from_address: 'test@test.com', to_addresses: ['user@test.com'], signals: [] }];
        }
        if (query.includes('SELECT id FROM threats')) {
          return [];
        }
        return [];
      });

      const { moveO365Email } = await import('@/lib/integrations/o365');
      (moveO365Email as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('O365 API error'));

      const result = await autoRemediate({
        ...baseParams,
        integrationType: 'o365',
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Mailbox operation failed');
    });
  });
});
