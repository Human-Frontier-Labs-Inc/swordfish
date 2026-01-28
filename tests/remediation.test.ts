/**
 * Remediation Service Tests
 * TDD approach to ensure release, delete, and quarantine operations work correctly
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock the database and external services
vi.mock('@/lib/db', () => ({
  sql: vi.fn(),
}));

vi.mock('@/lib/integrations/gmail', () => ({
  modifyGmailMessage: vi.fn(),
  trashGmailMessage: vi.fn(),
  getOrCreateQuarantineLabel: vi.fn().mockResolvedValue('Label_123'),
  getGmailAccessToken: vi.fn().mockResolvedValue('mock-token'),
}));

vi.mock('@/lib/integrations/o365', () => ({
  moveO365Email: vi.fn(),
  getOrCreateQuarantineFolder: vi.fn().mockResolvedValue('folder-123'),
  getO365AccessToken: vi.fn().mockResolvedValue('mock-token'),
}));

vi.mock('@/lib/db/audit', () => ({
  logAuditEvent: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('@/lib/notifications/service', () => ({
  sendNotification: vi.fn().mockResolvedValue(undefined),
}));

import { sql } from '@/lib/db';
import { modifyGmailMessage, trashGmailMessage } from '@/lib/integrations/gmail';
import { moveO365Email } from '@/lib/integrations/o365';
import { releaseEmail, deleteEmail, quarantineEmail } from '@/lib/workers/remediation';

const mockSql = sql as unknown as ReturnType<typeof vi.fn>;

describe('Remediation Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('releaseEmail', () => {
    it('should successfully release email when integration_id is NULL but integration exists', async () => {
      // Mock: Threat with NULL integration_id
      mockSql
        .mockResolvedValueOnce([{
          id: 'threat-123',
          tenant_id: 'tenant-abc',
          message_id: 'msg-id-123',
          external_message_id: 'external-gmail-id',
          integration_id: null, // NULL integration_id
          integration_type: 'gmail',
          status: 'quarantined',
          nango_connection_id: null, // NULL because LEFT JOIN with NULL integration_id
        }])
        // Mock: Fallback integration lookup
        .mockResolvedValueOnce([{
          nango_connection_id: 'nango-conn-123',
        }])
        // Mock: Update threat status
        .mockResolvedValueOnce([]);

      const result = await releaseEmail({
        tenantId: 'tenant-abc',
        threatId: 'threat-123',
        actorId: 'user-123',
        actorEmail: 'user@example.com',
      });

      expect(result.success).toBe(true);
      expect(result.action).toBe('release');
      expect(modifyGmailMessage).toHaveBeenCalled();
    });

    it('should fail gracefully when no integration exists', async () => {
      mockSql
        .mockResolvedValueOnce([{
          id: 'threat-123',
          tenant_id: 'tenant-abc',
          message_id: 'msg-id-123',
          external_message_id: null,
          integration_id: null,
          integration_type: 'gmail',
          status: 'quarantined',
          nango_connection_id: null,
        }])
        // Mock: No integration found
        .mockResolvedValueOnce([]);

      const result = await releaseEmail({
        tenantId: 'tenant-abc',
        threatId: 'threat-123',
        actorId: 'user-123',
        actorEmail: 'user@example.com',
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('No Nango connection configured');
    });

    it('should use external_message_id when available', async () => {
      mockSql
        .mockResolvedValueOnce([{
          id: 'threat-123',
          tenant_id: 'tenant-abc',
          message_id: 'internal-msg-id',
          external_message_id: 'gmail-external-id-abc',
          integration_id: 'int-123',
          integration_type: 'gmail',
          status: 'quarantined',
          nango_connection_id: 'nango-conn-123',
        }])
        .mockResolvedValueOnce([]);

      await releaseEmail({
        tenantId: 'tenant-abc',
        threatId: 'threat-123',
        actorId: 'user-123',
        actorEmail: 'user@example.com',
      });

      // Should use external_message_id for Gmail API call
      expect(modifyGmailMessage).toHaveBeenCalledWith(
        expect.objectContaining({
          messageId: 'gmail-external-id-abc',
        })
      );
    });

    it('should return error when threat not found', async () => {
      mockSql.mockResolvedValueOnce([]);

      const result = await releaseEmail({
        tenantId: 'tenant-abc',
        threatId: 'nonexistent',
        actorId: 'user-123',
        actorEmail: 'user@example.com',
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Threat not found');
    });
  });

  describe('deleteEmail', () => {
    it('should successfully delete email with proper integration', async () => {
      mockSql
        .mockResolvedValueOnce([{
          id: 'threat-123',
          tenant_id: 'tenant-abc',
          message_id: 'msg-id-123',
          external_message_id: 'gmail-id-456',
          integration_id: null,
          integration_type: 'gmail',
          status: 'quarantined',
          nango_connection_id: null,
        }])
        .mockResolvedValueOnce([{
          nango_connection_id: 'nango-conn-123',
        }])
        .mockResolvedValueOnce([]);

      const result = await deleteEmail({
        tenantId: 'tenant-abc',
        threatId: 'threat-123',
        actorId: 'user-123',
        actorEmail: 'user@example.com',
      });

      expect(result.success).toBe(true);
      expect(result.action).toBe('delete');
      expect(trashGmailMessage).toHaveBeenCalled();
    });

    it('should handle O365 integration type', async () => {
      mockSql
        .mockResolvedValueOnce([{
          id: 'threat-123',
          tenant_id: 'tenant-abc',
          message_id: 'o365-msg-id',
          external_message_id: 'AAMkAG...',
          integration_id: 'int-456',
          integration_type: 'o365',
          status: 'quarantined',
          nango_connection_id: 'nango-o365',
        }])
        .mockResolvedValueOnce([]);

      const result = await deleteEmail({
        tenantId: 'tenant-abc',
        threatId: 'threat-123',
        actorId: 'user-123',
        actorEmail: 'user@example.com',
      });

      expect(result.success).toBe(true);
      expect(moveO365Email).toHaveBeenCalledWith(
        expect.objectContaining({
          destinationFolderId: 'deleteditems',
        })
      );
    });
  });

  describe('quarantineEmail', () => {
    it('should successfully quarantine email', async () => {
      mockSql
        .mockResolvedValueOnce([{
          id: 'threat-123',
          tenant_id: 'tenant-abc',
          message_id: 'msg-id-123',
          external_message_id: 'gmail-id',
          integration_id: null,
          integration_type: 'gmail',
          status: 'active',
          nango_connection_id: null,
        }])
        .mockResolvedValueOnce([{
          nango_connection_id: 'nango-conn-123',
        }])
        .mockResolvedValueOnce([]);

      const result = await quarantineEmail({
        tenantId: 'tenant-abc',
        threatId: 'threat-123',
        actorId: 'user-123',
        actorEmail: 'user@example.com',
      });

      expect(result.success).toBe(true);
      expect(result.action).toBe('quarantine');
      expect(modifyGmailMessage).toHaveBeenCalled();
    });
  });

  describe('Data Integrity Scenarios', () => {
    it('should handle missing external_message_id by using message_id', async () => {
      mockSql
        .mockResolvedValueOnce([{
          id: 'threat-123',
          tenant_id: 'tenant-abc',
          message_id: 'only-internal-id',
          external_message_id: null, // Missing external_message_id
          integration_id: null,
          integration_type: 'gmail',
          status: 'quarantined',
          nango_connection_id: null,
        }])
        .mockResolvedValueOnce([{
          nango_connection_id: 'nango-conn-123',
        }])
        .mockResolvedValueOnce([]);

      const result = await releaseEmail({
        tenantId: 'tenant-abc',
        threatId: 'threat-123',
        actorId: 'user-123',
        actorEmail: 'user@example.com',
      });

      // Should attempt with message_id as fallback
      expect(modifyGmailMessage).toHaveBeenCalledWith(
        expect.objectContaining({
          messageId: 'only-internal-id',
        })
      );
    });

    it('should handle Outlook-format message_id with Gmail integration gracefully', async () => {
      // This tests the scenario where message_id format doesn't match integration type
      mockSql
        .mockResolvedValueOnce([{
          id: 'threat-123',
          tenant_id: 'tenant-abc',
          message_id: '<IA4PR10MB8730...@namprd10.prod.outlook.com>', // Outlook format
          external_message_id: null,
          integration_id: null,
          integration_type: 'gmail', // But integration is Gmail!
          status: 'quarantined',
          nango_connection_id: null,
        }])
        .mockResolvedValueOnce([{
          nango_connection_id: 'nango-conn-123',
        }])
        .mockResolvedValueOnce([]);

      // Mock Gmail API to reject invalid message ID
      (modifyGmailMessage as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
        new Error('Invalid message ID format')
      );

      const result = await releaseEmail({
        tenantId: 'tenant-abc',
        threatId: 'threat-123',
        actorId: 'user-123',
        actorEmail: 'user@example.com',
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Message ID format');
    });
  });
});
