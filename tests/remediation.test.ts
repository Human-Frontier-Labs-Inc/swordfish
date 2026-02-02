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
  untrashGmailMessage: vi.fn(),
  findGmailMessageByMessageId: vi.fn().mockResolvedValue('gmail-msg-id-123'),
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
  beforeEach(async () => {
    vi.resetAllMocks();
    // Re-establish default mock implementations after reset
    const gmail = await import('@/lib/integrations/gmail');
    vi.mocked(gmail.findGmailMessageByMessageId).mockResolvedValue('gmail-msg-id-123');
    vi.mocked(gmail.getOrCreateQuarantineLabel).mockResolvedValue('Label_123');
    vi.mocked(gmail.getGmailAccessToken).mockResolvedValue('mock-token');

    const o365 = await import('@/lib/integrations/o365');
    vi.mocked(o365.getOrCreateQuarantineFolder).mockResolvedValue('folder-123');
    vi.mocked(o365.getO365AccessToken).mockResolvedValue('mock-token');
  });

  describe('releaseEmail', () => {
    it('should successfully release email when integration_id is NULL but integration exists', async () => {
      // Mock 1: Threat query
      // Mock 2: Update threat status (no integration lookup - uses tenant-based tokens)
      mockSql
        .mockResolvedValueOnce([{
          id: 'threat-123',
          tenant_id: 'tenant-abc',
          message_id: 'msg-id-123',
          external_message_id: 'external-gmail-id',
          integration_id: null, // NULL integration_id
          integration_type: 'gmail',
          status: 'quarantined',
          connected_email: null,
        }])
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

    it('should fail gracefully when token retrieval fails', async () => {
      // Mock 1: Threat query - returns valid threat
      mockSql.mockResolvedValueOnce([{
        id: 'threat-123',
        tenant_id: 'tenant-abc',
        message_id: 'msg-id-123',
        external_message_id: null,
        integration_id: null,
        integration_type: 'gmail',
        status: 'quarantined',
        connected_email: null,
      }]);

      // Mock getGmailAccessToken to throw an error
      const gmail = await import('@/lib/integrations/gmail');
      vi.mocked(gmail.getGmailAccessToken).mockRejectedValueOnce(new Error('No connected integration'));

      const result = await releaseEmail({
        tenantId: 'tenant-abc',
        threatId: 'threat-123',
        actorId: 'user-123',
        actorEmail: 'user@example.com',
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('No connected integration');
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
          connected_email: 'user@example.com',
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
      // Mock 1: Threat query
      // Mock 2: Update threat status (no integration lookup - uses tenant-based tokens)
      mockSql
        .mockResolvedValueOnce([{
          id: 'threat-123',
          tenant_id: 'tenant-abc',
          message_id: 'msg-id-123',
          external_message_id: 'gmail-id-456',
          integration_id: null,
          integration_type: 'gmail',
          status: 'quarantined',
          connected_email: null,
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
          connected_email: 'user@company.onmicrosoft.com',
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
      // Mock 1: Threat query
      // Mock 2: Update query (no integration lookup needed - uses tenant-based tokens)
      mockSql
        .mockResolvedValueOnce([{
          id: 'threat-123',
          tenant_id: 'tenant-abc',
          message_id: 'msg-id-123',
          external_message_id: 'gmail-id',
          integration_id: null,
          integration_type: 'gmail',
          status: 'active',
          connected_email: null,
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
      // Mock 1: Threat query
      // Mock 2: Update query (no integration lookup needed - uses tenant-based tokens)
      mockSql
        .mockResolvedValueOnce([{
          id: 'threat-123',
          tenant_id: 'tenant-abc',
          message_id: 'only-internal-id',
          external_message_id: null, // Missing external_message_id
          integration_id: null,
          integration_type: 'gmail',
          status: 'quarantined',
          connected_email: null,
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
      // This tests the scenario where message_id (RFC 5322 header) is from Outlook
      // but email was received via Gmail. This is NORMAL for cross-platform emails.
      // e.g., email sent FROM Outlook TO Gmail has Outlook-format Message-ID header.
      // Mock 1: Threat query
      // Mock 2: Update query (no integration lookup needed - uses tenant-based tokens)
      mockSql
        .mockResolvedValueOnce([{
          id: 'threat-123',
          tenant_id: 'tenant-abc',
          message_id: '<IA4PR10MB8730...@namprd10.prod.outlook.com>', // Outlook format (from sender)
          external_message_id: null, // No Gmail API message ID available
          integration_id: null,
          integration_type: 'gmail', // Received via Gmail - this is correct!
          status: 'quarantined',
          connected_email: null,
        }])
        .mockResolvedValueOnce([]);

      // The remediation should proceed - the message_id format doesn't need to match
      // integration type since message_id is the RFC 5322 header from the SENDING server
      const result = await releaseEmail({
        tenantId: 'tenant-abc',
        threatId: 'threat-123',
        actorId: 'user-123',
        actorEmail: 'user@example.com',
      });

      // Should succeed - cross-platform emails are valid
      expect(result.success).toBe(true);
      // The code correctly looks up the Gmail API message ID by the RFC 5322 Message-ID header
      // when the message_id format doesn't match the integration type
      expect(modifyGmailMessage).toHaveBeenCalledWith(
        expect.objectContaining({
          messageId: 'gmail-msg-id-123', // The looked-up Gmail API message ID
        })
      );
    });

    it('should reject when external_message_id format mismatches integration type', async () => {
      // This tests a REAL data integrity issue - when external_message_id
      // (the platform API message ID) doesn't match the integration type
      // Mock 1: Threat query - returns error case before update is called
      mockSql
        .mockResolvedValueOnce([{
          id: 'threat-123',
          tenant_id: 'tenant-abc',
          message_id: '<IA4PR10MB8730abc@namprd10.prod.outlook.com>',
          external_message_id: 'AAMkAGIwMDAwMDM0LTg2NjctNDI3NS1hY2E4LTZmYjcwNWQwMDBkZQ==', // O365 Graph API ID (should be Gmail ID!)
          integration_id: null,
          integration_type: 'gmail', // But external_message_id is O365 format!
          status: 'quarantined',
          connected_email: null,
        }]);

      const result = await releaseEmail({
        tenantId: 'tenant-abc',
        threatId: 'threat-123',
        actorId: 'user-123',
        actorEmail: 'user@example.com',
      });

      // Should fail - external_message_id format mismatch is a real data integrity issue
      expect(result.success).toBe(false);
      expect(result.error).toContain('External message ID format');
      expect(result.error).toContain('Data integrity issue');
    });
  });
});
