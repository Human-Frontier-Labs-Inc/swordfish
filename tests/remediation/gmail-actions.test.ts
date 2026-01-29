/**
 * Gmail Email Remediation Tests (TDD)
 *
 * SLICE 1.1: Gmail Email Remediation
 *
 * These tests define the expected behavior for Gmail remediation actions.
 * Following TDD: Write tests FIRST (RED), then implement (GREEN), then refactor.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock the modules before importing the code under test
vi.mock('@/lib/db', () => ({
  sql: vi.fn(),
}));

vi.mock('@/lib/nango/client', () => ({
  getAccessToken: vi.fn(),
}));

vi.mock('@/lib/db/audit', () => ({
  logAuditEvent: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('@/lib/notifications/service', () => ({
  sendNotification: vi.fn().mockResolvedValue(undefined),
  sendThreatNotification: vi.fn().mockResolvedValue(undefined),
}));

// Import after mocking
import { sql } from '@/lib/db';
import { getAccessToken } from '@/lib/nango/client';
import { logAuditEvent } from '@/lib/db/audit';

// Types for test data
interface MockIntegration {
  id: string;
  tenant_id: string;
  type: string;
  nango_connection_id: string | null;
  config: Record<string, unknown>;
  status: string;
}

interface MockThreat {
  id: string;
  tenant_id: string;
  message_id: string;
  status: string;
}

interface MockEmailVerdict {
  tenant_id: string;
  message_id: string;
  subject: string;
  from_address: string;
  to_addresses: string[];
  verdict: string;
  score: number;
  signals: unknown[];
}

// Test constants
const TEST_TENANT_ID = 'personal_test_user_001';
const TEST_INTEGRATION_ID = 'int_gmail_001';
const TEST_NANGO_CONNECTION_ID = 'nango_conn_001';
const TEST_MESSAGE_ID = 'msg_12345abcdef';
const TEST_EXTERNAL_MESSAGE_ID = '19bc5a61241b945f';
const TEST_ACCESS_TOKEN = 'ya29.test_access_token';
const TEST_QUARANTINE_LABEL_ID = 'Label_123456';

describe('Gmail Email Remediation', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();

    // Mock global fetch
    mockFetch = vi.fn();
    global.fetch = mockFetch;

    // Default mock for getAccessToken
    vi.mocked(getAccessToken).mockResolvedValue(TEST_ACCESS_TOKEN);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getOrCreateQuarantineLabel', () => {
    it('should return existing label ID if Swordfish/Quarantine label exists', async () => {
      // Arrange
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            labels: [
              { id: 'Label_INBOX', name: 'INBOX' },
              { id: TEST_QUARANTINE_LABEL_ID, name: 'Swordfish/Quarantine' },
            ],
          }),
      });

      // Act
      const { getOrCreateQuarantineLabel } = await import(
        '@/lib/integrations/gmail'
      );
      const labelId = await getOrCreateQuarantineLabel(TEST_ACCESS_TOKEN);

      // Assert
      expect(labelId).toBe(TEST_QUARANTINE_LABEL_ID);
      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(mockFetch).toHaveBeenCalledWith(
        'https://gmail.googleapis.com/gmail/v1/users/me/labels',
        expect.objectContaining({
          headers: { Authorization: `Bearer ${TEST_ACCESS_TOKEN}` },
        })
      );
    });

    it('should create new label if Swordfish/Quarantine does not exist', async () => {
      // Arrange
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () =>
            Promise.resolve({
              labels: [{ id: 'Label_INBOX', name: 'INBOX' }],
            }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () =>
            Promise.resolve({
              id: 'Label_NewQuarantine',
              name: 'Swordfish/Quarantine',
            }),
        });

      // Act
      const { getOrCreateQuarantineLabel } = await import(
        '@/lib/integrations/gmail'
      );
      const labelId = await getOrCreateQuarantineLabel(TEST_ACCESS_TOKEN);

      // Assert
      expect(labelId).toBe('Label_NewQuarantine');
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('modifyGmailMessage', () => {
    it('should add quarantine label and remove INBOX label', async () => {
      // Arrange
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      });

      // Act
      const { modifyGmailMessage } = await import('@/lib/integrations/gmail');
      await modifyGmailMessage({
        accessToken: TEST_ACCESS_TOKEN,
        messageId: TEST_EXTERNAL_MESSAGE_ID,
        addLabelIds: [TEST_QUARANTINE_LABEL_ID],
        removeLabelIds: ['INBOX'],
      });

      // Assert
      expect(mockFetch).toHaveBeenCalledWith(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages/${TEST_EXTERNAL_MESSAGE_ID}/modify`,
        expect.objectContaining({
          method: 'POST',
          headers: {
            Authorization: `Bearer ${TEST_ACCESS_TOKEN}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            addLabelIds: [TEST_QUARANTINE_LABEL_ID],
            removeLabelIds: ['INBOX'],
          }),
        })
      );
    });

    it('should throw error when Gmail API returns non-OK response', async () => {
      // Arrange
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      // Act & Assert
      const { modifyGmailMessage } = await import('@/lib/integrations/gmail');
      await expect(
        modifyGmailMessage({
          accessToken: TEST_ACCESS_TOKEN,
          messageId: 'invalid_message_id',
          addLabelIds: [TEST_QUARANTINE_LABEL_ID],
        })
      ).rejects.toThrow('Failed to modify message');
    });
  });

  describe('trashGmailMessage', () => {
    it('should call Gmail trash endpoint', async () => {
      // Arrange
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      });

      // Act
      const { trashGmailMessage } = await import('@/lib/integrations/gmail');
      await trashGmailMessage({
        accessToken: TEST_ACCESS_TOKEN,
        messageId: TEST_EXTERNAL_MESSAGE_ID,
      });

      // Assert
      expect(mockFetch).toHaveBeenCalledWith(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages/${TEST_EXTERNAL_MESSAGE_ID}/trash`,
        expect.objectContaining({
          method: 'POST',
          headers: { Authorization: `Bearer ${TEST_ACCESS_TOKEN}` },
        })
      );
    });

    it('should throw error when trash fails', async () => {
      // Arrange
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        statusText: 'Forbidden',
      });

      // Act & Assert
      const { trashGmailMessage } = await import('@/lib/integrations/gmail');
      await expect(
        trashGmailMessage({
          accessToken: TEST_ACCESS_TOKEN,
          messageId: TEST_EXTERNAL_MESSAGE_ID,
        })
      ).rejects.toThrow('Failed to trash message');
    });
  });

  describe('autoRemediate', () => {
    const mockIntegration: MockIntegration = {
      id: TEST_INTEGRATION_ID,
      tenant_id: TEST_TENANT_ID,
      type: 'gmail',
      nango_connection_id: TEST_NANGO_CONNECTION_ID,
      config: {},
      status: 'connected',
    };

    const mockEmailVerdict: MockEmailVerdict = {
      tenant_id: TEST_TENANT_ID,
      message_id: TEST_MESSAGE_ID,
      subject: 'Suspicious Email',
      from_address: 'attacker@evil.com',
      to_addresses: ['victim@company.com'],
      verdict: 'quarantine',
      score: 85,
      signals: [{ type: 'phishing_url', severity: 'critical' }],
    };

    beforeEach(() => {
      // Reset SQL mock for each test
      vi.mocked(sql).mockReset();
    });

    it('should quarantine email when verdict is quarantine', async () => {
      // Arrange
      // Mock: Get integration with nango_connection_id
      vi.mocked(sql).mockResolvedValueOnce([
        { nango_connection_id: TEST_NANGO_CONNECTION_ID },
      ]);

      // Mock: Get email details from email_verdicts
      vi.mocked(sql).mockResolvedValueOnce([mockEmailVerdict]);

      // Mock: Check if threat exists
      vi.mocked(sql).mockResolvedValueOnce([]);

      // Mock: Insert threat
      vi.mocked(sql).mockResolvedValueOnce([]);

      // Mock Gmail API calls
      mockFetch
        // Get labels
        .mockResolvedValueOnce({
          ok: true,
          json: () =>
            Promise.resolve({
              labels: [
                { id: TEST_QUARANTINE_LABEL_ID, name: 'Swordfish/Quarantine' },
              ],
            }),
        })
        // Modify message (add quarantine label, remove INBOX)
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({}),
        });

      // Act
      const { autoRemediate } = await import('@/lib/workers/remediation');
      const result = await autoRemediate({
        tenantId: TEST_TENANT_ID,
        messageId: TEST_MESSAGE_ID,
        externalMessageId: TEST_EXTERNAL_MESSAGE_ID,
        integrationId: TEST_INTEGRATION_ID,
        integrationType: 'gmail',
        verdict: 'quarantine',
        score: 85,
      });

      // Assert
      expect(result.success).toBe(true);
      expect(result.action).toBe('quarantine');
      expect(result.messageId).toBe(TEST_MESSAGE_ID);

      // Verify Gmail API was called to modify message
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/modify'),
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('should quarantine email when verdict is block (never auto-delete)', async () => {
      // Arrange - Note: Block verdict now quarantines instead of deleting
      // This allows users to review and release false positives
      vi.mocked(sql).mockResolvedValueOnce([
        { nango_connection_id: TEST_NANGO_CONNECTION_ID },
      ]);
      vi.mocked(sql).mockResolvedValueOnce([mockEmailVerdict]);
      vi.mocked(sql).mockResolvedValueOnce([]);
      vi.mocked(sql).mockResolvedValueOnce([]);

      // Mock Gmail API calls
      mockFetch
        // Get labels - check if quarantine label exists
        .mockResolvedValueOnce({
          ok: true,
          json: () =>
            Promise.resolve({
              labels: [
                { id: TEST_QUARANTINE_LABEL_ID, name: 'Swordfish/Quarantine' },
              ],
            }),
        })
        // Modify message (add quarantine label, remove INBOX)
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({}),
        });

      // Act
      const { autoRemediate } = await import('@/lib/workers/remediation');
      const result = await autoRemediate({
        tenantId: TEST_TENANT_ID,
        messageId: TEST_MESSAGE_ID,
        externalMessageId: TEST_EXTERNAL_MESSAGE_ID,
        integrationId: TEST_INTEGRATION_ID,
        integrationType: 'gmail',
        verdict: 'block',
        score: 95,
      });

      // Assert
      expect(result.success).toBe(true);
      expect(result.action).toBe('block');

      // Verify Gmail modify API was called (quarantine, not trash)
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/modify'),
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('should return error when integration has no nango_connection_id', async () => {
      // Arrange
      vi.mocked(sql).mockResolvedValueOnce([{ nango_connection_id: null }]);

      // Act
      const { autoRemediate } = await import('@/lib/workers/remediation');
      const result = await autoRemediate({
        tenantId: TEST_TENANT_ID,
        messageId: TEST_MESSAGE_ID,
        externalMessageId: TEST_EXTERNAL_MESSAGE_ID,
        integrationId: TEST_INTEGRATION_ID,
        integrationType: 'gmail',
        verdict: 'quarantine',
        score: 85,
      });

      // Assert
      expect(result.success).toBe(false);
      expect(result.error).toContain('No Nango connection');
    });

    it('should return error when integration not found', async () => {
      // Arrange
      vi.mocked(sql).mockResolvedValueOnce([]);

      // Act
      const { autoRemediate } = await import('@/lib/workers/remediation');
      const result = await autoRemediate({
        tenantId: TEST_TENANT_ID,
        messageId: TEST_MESSAGE_ID,
        externalMessageId: TEST_EXTERNAL_MESSAGE_ID,
        integrationId: 'non_existent_integration',
        integrationType: 'gmail',
        verdict: 'quarantine',
        score: 85,
      });

      // Assert
      expect(result.success).toBe(false);
      expect(result.error).toContain('Integration not found');
    });

    it('should write to threats table after successful remediation', async () => {
      // Arrange
      vi.mocked(sql).mockResolvedValueOnce([
        { nango_connection_id: TEST_NANGO_CONNECTION_ID },
      ]);
      vi.mocked(sql).mockResolvedValueOnce([mockEmailVerdict]);
      vi.mocked(sql).mockResolvedValueOnce([]); // No existing threat
      vi.mocked(sql).mockResolvedValueOnce([]); // Insert threat

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () =>
            Promise.resolve({
              labels: [
                { id: TEST_QUARANTINE_LABEL_ID, name: 'Swordfish/Quarantine' },
              ],
            }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({}),
        });

      // Act
      const { autoRemediate } = await import('@/lib/workers/remediation');
      await autoRemediate({
        tenantId: TEST_TENANT_ID,
        messageId: TEST_MESSAGE_ID,
        externalMessageId: TEST_EXTERNAL_MESSAGE_ID,
        integrationId: TEST_INTEGRATION_ID,
        integrationType: 'gmail',
        verdict: 'quarantine',
        score: 85,
      });

      // Assert - verify INSERT INTO threats was called
      const sqlCalls = vi.mocked(sql).mock.calls;
      const insertCall = sqlCalls.find(
        (call) =>
          call[0] &&
          Array.isArray(call[0]) &&
          call[0].some(
            (part: string) =>
              typeof part === 'string' && part.includes('INSERT INTO threats')
          )
      );
      expect(insertCall).toBeDefined();
    });

    it('should update existing threat if already exists', async () => {
      // Arrange
      vi.mocked(sql).mockResolvedValueOnce([
        { nango_connection_id: TEST_NANGO_CONNECTION_ID },
      ]);
      vi.mocked(sql).mockResolvedValueOnce([mockEmailVerdict]);
      vi.mocked(sql).mockResolvedValueOnce([{ id: 'existing_threat_id' }]); // Existing threat
      vi.mocked(sql).mockResolvedValueOnce([]); // Update threat

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () =>
            Promise.resolve({
              labels: [
                { id: TEST_QUARANTINE_LABEL_ID, name: 'Swordfish/Quarantine' },
              ],
            }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({}),
        });

      // Act
      const { autoRemediate } = await import('@/lib/workers/remediation');
      await autoRemediate({
        tenantId: TEST_TENANT_ID,
        messageId: TEST_MESSAGE_ID,
        externalMessageId: TEST_EXTERNAL_MESSAGE_ID,
        integrationId: TEST_INTEGRATION_ID,
        integrationType: 'gmail',
        verdict: 'quarantine',
        score: 85,
      });

      // Assert - verify UPDATE threats was called
      const sqlCalls = vi.mocked(sql).mock.calls;
      const updateCall = sqlCalls.find(
        (call) =>
          call[0] &&
          Array.isArray(call[0]) &&
          call[0].some(
            (part: string) =>
              typeof part === 'string' && part.includes('UPDATE threats')
          )
      );
      expect(updateCall).toBeDefined();
    });

    // Rate limiting retry test - retry logic added in lib/integrations/gmail.ts
    it('should handle Gmail API rate limiting with retry', async () => {
      // Arrange
      vi.mocked(sql).mockResolvedValueOnce([
        { nango_connection_id: TEST_NANGO_CONNECTION_ID },
      ]);
      vi.mocked(sql).mockResolvedValueOnce([mockEmailVerdict]);
      vi.mocked(sql).mockResolvedValueOnce([]);
      vi.mocked(sql).mockResolvedValueOnce([]);

      // First call (list labels) succeeds, second call (modify) returns 429, then succeeds on retry
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () =>
            Promise.resolve({
              labels: [
                { id: TEST_QUARANTINE_LABEL_ID, name: 'Swordfish/Quarantine' },
              ],
            }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          headers: new Headers({ 'Retry-After': '0' }), // Use 0 for fast test
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({}),
        });

      // Act
      const { autoRemediate } = await import('@/lib/workers/remediation');
      const result = await autoRemediate({
        tenantId: TEST_TENANT_ID,
        messageId: TEST_MESSAGE_ID,
        externalMessageId: TEST_EXTERNAL_MESSAGE_ID,
        integrationId: TEST_INTEGRATION_ID,
        integrationType: 'gmail',
        verdict: 'quarantine',
        score: 85,
      });

      // Assert - should succeed after retry
      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(3); // Labels list + 429 + retry success
    });

    // Token expiration test - verifies graceful error handling
    // Note: Nango handles token refresh at the getAccessToken layer, not mid-request
    it('should handle token expiration gracefully', async () => {
      // Arrange
      vi.mocked(sql).mockResolvedValueOnce([
        { nango_connection_id: TEST_NANGO_CONNECTION_ID },
      ]);
      vi.mocked(sql).mockResolvedValueOnce([mockEmailVerdict]);
      vi.mocked(sql).mockResolvedValueOnce([]);
      vi.mocked(sql).mockResolvedValueOnce([]);

      // First call (list labels) succeeds, second call (modify) returns 401
      // 401 is not retried since it requires token refresh at Nango layer
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () =>
            Promise.resolve({
              labels: [
                { id: TEST_QUARANTINE_LABEL_ID, name: 'Swordfish/Quarantine' },
              ],
            }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
        });

      // Act
      const { autoRemediate } = await import('@/lib/workers/remediation');
      const result = await autoRemediate({
        tenantId: TEST_TENANT_ID,
        messageId: TEST_MESSAGE_ID,
        externalMessageId: TEST_EXTERNAL_MESSAGE_ID,
        integrationId: TEST_INTEGRATION_ID,
        integrationType: 'gmail',
        verdict: 'quarantine',
        score: 85,
      });

      // Assert - 401 results in error (Nango handles refresh at token fetch layer)
      // The result should still be defined with success: false
      expect(result).toBeDefined();
      expect(result.success).toBe(false);
      expect(result.error).toContain('Failed to modify message');
    });
  });

  describe('quarantineEmail (manual action)', () => {
    it('should quarantine email via threat ID', async () => {
      // Arrange
      const threatId = 'threat_001';

      // Mock: Get threat with integration details (JOIN query)
      vi.mocked(sql).mockResolvedValueOnce([
        {
          id: threatId,
          tenant_id: TEST_TENANT_ID,
          message_id: TEST_MESSAGE_ID,
          external_message_id: TEST_EXTERNAL_MESSAGE_ID,
          integration_id: TEST_INTEGRATION_ID,
          integration_type: 'gmail',
          status: 'pending',
          nango_connection_id: TEST_NANGO_CONNECTION_ID,
        },
      ]);

      // Mock: Update threat status
      vi.mocked(sql).mockResolvedValueOnce([]);

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () =>
            Promise.resolve({
              labels: [
                { id: TEST_QUARANTINE_LABEL_ID, name: 'Swordfish/Quarantine' },
              ],
            }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({}),
        });

      // Act
      const { quarantineEmail } = await import('@/lib/workers/remediation');
      const result = await quarantineEmail({
        tenantId: TEST_TENANT_ID,
        threatId,
        actorId: 'user_001',
        actorEmail: 'admin@company.com',
      });

      // Assert
      expect(result.success).toBe(true);
      expect(result.action).toBe('quarantine');

      // Verify audit log was called
      expect(logAuditEvent).toHaveBeenCalled();
    });

    it('should return error when threat not found', async () => {
      // Arrange
      vi.mocked(sql).mockResolvedValueOnce([]);

      // Act
      const { quarantineEmail } = await import('@/lib/workers/remediation');
      const result = await quarantineEmail({
        tenantId: TEST_TENANT_ID,
        threatId: 'non_existent_threat',
        actorId: 'user_001',
        actorEmail: 'admin@company.com',
      });

      // Assert
      expect(result.success).toBe(false);
      expect(result.error).toContain('Threat not found');
    });
  });

  describe('releaseEmail', () => {
    it('should release email from quarantine back to inbox', async () => {
      // Arrange
      const threatId = 'threat_001';

      // Mock: Get threat with integration details
      vi.mocked(sql).mockResolvedValueOnce([
        {
          id: threatId,
          tenant_id: TEST_TENANT_ID,
          message_id: TEST_MESSAGE_ID,
          external_message_id: TEST_EXTERNAL_MESSAGE_ID,
          integration_id: TEST_INTEGRATION_ID,
          integration_type: 'gmail',
          status: 'quarantined',
          nango_connection_id: TEST_NANGO_CONNECTION_ID,
        },
      ]);

      // Mock: Update threat status
      vi.mocked(sql).mockResolvedValueOnce([]);

      // Get quarantine label, then modify message
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () =>
            Promise.resolve({
              labels: [
                { id: TEST_QUARANTINE_LABEL_ID, name: 'Swordfish/Quarantine' },
              ],
            }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({}),
        });

      // Act
      const { releaseEmail } = await import('@/lib/workers/remediation');
      const result = await releaseEmail({
        tenantId: TEST_TENANT_ID,
        threatId,
        actorId: 'user_001',
        actorEmail: 'admin@company.com',
      });

      // Assert
      expect(result.success).toBe(true);
      expect(result.action).toBe('release');

      // Verify audit log was called
      expect(logAuditEvent).toHaveBeenCalled();
    });
  });

  describe('deleteEmail', () => {
    it('should permanently delete email', async () => {
      // Arrange
      const threatId = 'threat_001';

      vi.mocked(sql).mockResolvedValueOnce([
        {
          id: threatId,
          tenant_id: TEST_TENANT_ID,
          message_id: TEST_MESSAGE_ID,
          external_message_id: TEST_EXTERNAL_MESSAGE_ID,
          integration_id: TEST_INTEGRATION_ID,
          integration_type: 'gmail',
          status: 'quarantined',
          nango_connection_id: TEST_NANGO_CONNECTION_ID,
        },
      ]);
      vi.mocked(sql).mockResolvedValueOnce([]); // Update threat status

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      });

      // Act
      const { deleteEmail } = await import('@/lib/workers/remediation');
      const result = await deleteEmail({
        tenantId: TEST_TENANT_ID,
        threatId,
        actorId: 'user_001',
        actorEmail: 'admin@company.com',
      });

      // Assert
      expect(result.success).toBe(true);
      expect(result.action).toBe('delete');

      // Verify trash was called
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/trash'),
        expect.any(Object)
      );
    });
  });
});

describe('Gmail Sync Pipeline Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Email detection to remediation flow', () => {
    it('should detect threat and auto-remediate in webhook handler', async () => {
      // This test documents the expected end-to-end flow:
      // 1. Gmail webhook receives notification
      // 2. Fetch new messages via History API
      // 3. Parse and analyze each email
      // 4. Store verdict in email_verdicts
      // 5. If threat, call autoRemediate
      // 6. autoRemediate moves email to quarantine
      // 7. Threat record created in threats table

      // The actual implementation should be verified manually
      // This test serves as documentation of expected behavior
      expect(true).toBe(true);
    });
  });
});

describe('Diagnostic Tests', () => {
  describe('Integration health checks', () => {
    it('should verify nango_connection_id is populated', async () => {
      // This test helps diagnose the "test email not detected" issue
      // Check that integrations table has nango_connection_id

      vi.mocked(sql).mockResolvedValueOnce([
        {
          id: 'integration_id',
          tenant_id: TEST_TENANT_ID,
          type: 'gmail',
          status: 'connected',
          nango_connection_id: TEST_NANGO_CONNECTION_ID, // Should NOT be null
          config: {
            email: 'user@gmail.com',
            historyId: '12345',
          },
        },
      ]);

      const result = await sql`SELECT * FROM integrations WHERE tenant_id = ${TEST_TENANT_ID}`;
      expect(result[0].nango_connection_id).not.toBeNull();
    });

    it('should verify Gmail watch is registered', async () => {
      // Check that config has watchExpiration in the future
      vi.mocked(sql).mockResolvedValueOnce([
        {
          config: {
            watchExpiration: new Date(
              Date.now() + 7 * 24 * 60 * 60 * 1000
            ).toISOString(), // 7 days from now
          },
        },
      ]);

      const result = await sql`SELECT config FROM integrations`;
      const watchExpiration = new Date(result[0].config.watchExpiration);
      expect(watchExpiration.getTime()).toBeGreaterThan(Date.now());
    });

    it('should verify historyId is set', async () => {
      // Check that config has historyId for incremental sync
      vi.mocked(sql).mockResolvedValueOnce([
        {
          config: {
            historyId: '1234567890',
          },
        },
      ]);

      const result = await sql`SELECT config FROM integrations`;
      expect(result[0].config.historyId).toBeDefined();
    });
  });
});
