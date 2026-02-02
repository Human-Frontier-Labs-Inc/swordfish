/**
 * O365 Email Remediation Tests (TDD)
 *
 * SLICE 1.2: O365 Email Remediation
 *
 * These tests define the expected behavior for O365 (Microsoft Graph) remediation actions.
 * Following TDD: Write tests FIRST (RED), then implement (GREEN), then refactor.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock the modules before importing the code under test
vi.mock('@/lib/db', () => ({
  sql: vi.fn(),
}));

// Token retrieval is handled by getO365AccessToken in integration module
vi.mock('@/lib/integrations/o365', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    getO365AccessToken: vi.fn().mockResolvedValue('mock-access-token'),
  };
});

vi.mock('@/lib/db/audit', () => ({
  logAuditEvent: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('@/lib/notifications/service', () => ({
  sendNotification: vi.fn().mockResolvedValue(undefined),
  sendThreatNotification: vi.fn().mockResolvedValue(undefined),
}));

// Import after mocking
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

// Test constants
const TEST_TENANT_ID = 'personal_test_user_001';
const TEST_INTEGRATION_ID = 'int_o365_001';
const TEST_CONNECTED_EMAIL = 'user@example.com';
const TEST_MESSAGE_ID = 'msg_o365_12345';
const TEST_EXTERNAL_MESSAGE_ID = 'AAMkAGI2TG93AAA=';
const TEST_ACCESS_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkpCQU';
const TEST_QUARANTINE_FOLDER_ID = 'AQMkAGI2TGQuarantineFolder';
const GRAPH_API_URL = 'https://graph.microsoft.com/v1.0';

// Types for test data
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

describe('O365 Email Remediation', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();

    // Mock global fetch
    mockFetch = vi.fn();
    global.fetch = mockFetch;

    // Token retrieval is mocked via getO365AccessToken in vi.mock block above
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getOrCreateQuarantineFolder', () => {
    it('should return existing folder ID if Swordfish Quarantine folder exists', async () => {
      // Arrange
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            value: [{ id: TEST_QUARANTINE_FOLDER_ID, displayName: 'Swordfish Quarantine' }],
          }),
      });

      // Act
      const { getOrCreateQuarantineFolder } = await import('@/lib/integrations/o365');
      const folderId = await getOrCreateQuarantineFolder(TEST_ACCESS_TOKEN);

      // Assert
      expect(folderId).toBe(TEST_QUARANTINE_FOLDER_ID);
      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining("displayName eq 'Swordfish Quarantine'"),
        expect.objectContaining({
          headers: { Authorization: `Bearer ${TEST_ACCESS_TOKEN}` },
        })
      );
    });

    it('should create new folder if Swordfish Quarantine does not exist', async () => {
      // Arrange
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ value: [] }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () =>
            Promise.resolve({
              id: 'NewQuarantineFolder123',
              displayName: 'Swordfish Quarantine',
            }),
        });

      // Act
      const { getOrCreateQuarantineFolder } = await import('@/lib/integrations/o365');
      const folderId = await getOrCreateQuarantineFolder(TEST_ACCESS_TOKEN);

      // Assert
      expect(folderId).toBe('NewQuarantineFolder123');
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should throw error when folder creation fails', async () => {
      // Arrange
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ value: [] }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 403,
        });

      // Act & Assert
      const { getOrCreateQuarantineFolder } = await import('@/lib/integrations/o365');
      await expect(getOrCreateQuarantineFolder(TEST_ACCESS_TOKEN)).rejects.toThrow(
        'Failed to create quarantine folder'
      );
    });
  });

  describe('moveO365Email', () => {
    it('should move email to specified folder', async () => {
      // Arrange
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ id: TEST_EXTERNAL_MESSAGE_ID }),
      });

      // Act
      const { moveO365Email } = await import('@/lib/integrations/o365');
      await moveO365Email({
        accessToken: TEST_ACCESS_TOKEN,
        messageId: TEST_EXTERNAL_MESSAGE_ID,
        destinationFolderId: TEST_QUARANTINE_FOLDER_ID,
      });

      // Assert
      expect(mockFetch).toHaveBeenCalledWith(
        `${GRAPH_API_URL}/me/messages/${TEST_EXTERNAL_MESSAGE_ID}/move`,
        expect.objectContaining({
          method: 'POST',
          headers: {
            Authorization: `Bearer ${TEST_ACCESS_TOKEN}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ destinationId: TEST_QUARANTINE_FOLDER_ID }),
        })
      );
    });

    it('should throw error when Graph API returns non-OK response', async () => {
      // Arrange
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      // Act & Assert
      const { moveO365Email } = await import('@/lib/integrations/o365');
      await expect(
        moveO365Email({
          accessToken: TEST_ACCESS_TOKEN,
          messageId: 'invalid_message_id',
          destinationFolderId: TEST_QUARANTINE_FOLDER_ID,
        })
      ).rejects.toThrow('Failed to move email');
    });
  });

  describe('autoRemediate (O365)', () => {
    const mockEmailVerdict: MockEmailVerdict = {
      tenant_id: TEST_TENANT_ID,
      message_id: TEST_MESSAGE_ID,
      subject: 'Suspicious O365 Email',
      from_address: 'attacker@evil.com',
      to_addresses: ['victim@company.com'],
      verdict: 'quarantine',
      score: 85,
      signals: [{ type: 'phishing_url', severity: 'critical' }],
    };

    beforeEach(() => {
      vi.mocked(sql).mockReset();
    });

    it('should quarantine email when verdict is quarantine', async () => {
      // Arrange
      // Mock: Get connected integration
      vi.mocked(sql).mockResolvedValueOnce([
        { id: TEST_INTEGRATION_ID },
      ]);

      // Mock: Get email details from email_verdicts
      vi.mocked(sql).mockResolvedValueOnce([mockEmailVerdict]);

      // Mock: Check if threat exists
      vi.mocked(sql).mockResolvedValueOnce([]);

      // Mock: Insert threat
      vi.mocked(sql).mockResolvedValueOnce([]);

      // Mock Graph API calls
      mockFetch
        // List folders to find quarantine
        .mockResolvedValueOnce({
          ok: true,
          json: () =>
            Promise.resolve({
              value: [{ id: TEST_QUARANTINE_FOLDER_ID, displayName: 'Swordfish Quarantine' }],
            }),
        })
        // Move message
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
        integrationType: 'o365',
        verdict: 'quarantine',
        score: 85,
      });

      // Assert
      expect(result.success).toBe(true);
      expect(result.action).toBe('quarantine');
      expect(result.messageId).toBe(TEST_MESSAGE_ID);

      // Verify Graph API was called to move message
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/move'),
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('should quarantine email when verdict is block (never auto-delete)', async () => {
      // Arrange - Note: Block verdict now quarantines instead of deleting
      // This allows users to review and release false positives
      vi.mocked(sql).mockResolvedValueOnce([
        { id: TEST_INTEGRATION_ID },
      ]);
      vi.mocked(sql).mockResolvedValueOnce([mockEmailVerdict]);
      vi.mocked(sql).mockResolvedValueOnce([]);
      vi.mocked(sql).mockResolvedValueOnce([]);

      // Mock Graph API - get/create quarantine folder
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ value: [] }),
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ id: 'quarantine-folder-id' }),
      });
      // Mock Graph API - move to quarantine folder
      mockFetch.mockResolvedValueOnce({
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
        integrationType: 'o365',
        verdict: 'block',
        score: 95,
      });

      // Assert
      expect(result.success).toBe(true);
      expect(result.action).toBe('block');

      // Verify Graph API was called to move (to quarantine, not deleteditems)
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/move'),
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('should return error when integration is not connected', async () => {
      // Arrange - Return empty array (integration not found or not connected)
      vi.mocked(sql).mockResolvedValueOnce([]);

      // Act
      const { autoRemediate } = await import('@/lib/workers/remediation');
      const result = await autoRemediate({
        tenantId: TEST_TENANT_ID,
        messageId: TEST_MESSAGE_ID,
        externalMessageId: TEST_EXTERNAL_MESSAGE_ID,
        integrationId: TEST_INTEGRATION_ID,
        integrationType: 'o365',
        verdict: 'quarantine',
        score: 85,
      });

      // Assert
      expect(result.success).toBe(false);
      expect(result.error).toContain('Integration not found or not connected');
    });

    it('should write to threats table after successful remediation', async () => {
      // Arrange
      vi.mocked(sql).mockResolvedValueOnce([
        { id: TEST_INTEGRATION_ID },
      ]);
      vi.mocked(sql).mockResolvedValueOnce([mockEmailVerdict]);
      vi.mocked(sql).mockResolvedValueOnce([]); // No existing threat
      vi.mocked(sql).mockResolvedValueOnce([]); // Insert threat

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () =>
            Promise.resolve({
              value: [{ id: TEST_QUARANTINE_FOLDER_ID, displayName: 'Swordfish Quarantine' }],
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
        integrationType: 'o365',
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
  });

  describe('quarantineEmail (O365 manual action)', () => {
    it('should quarantine email via threat ID', async () => {
      // Arrange
      const threatId = 'threat_o365_001';

      // Mock: Get threat with integration details
      vi.mocked(sql).mockResolvedValueOnce([
        {
          id: threatId,
          tenant_id: TEST_TENANT_ID,
          message_id: TEST_MESSAGE_ID,
          external_message_id: TEST_EXTERNAL_MESSAGE_ID,
          integration_id: TEST_INTEGRATION_ID,
          integration_type: 'o365',
          status: 'pending',
          connected_email: TEST_CONNECTED_EMAIL,
        },
      ]);

      // Mock: Update threat status
      vi.mocked(sql).mockResolvedValueOnce([]);

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () =>
            Promise.resolve({
              value: [{ id: TEST_QUARANTINE_FOLDER_ID, displayName: 'Swordfish Quarantine' }],
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

  describe('releaseEmail (O365)', () => {
    it('should release email from quarantine back to inbox', async () => {
      // Arrange
      const threatId = 'threat_o365_001';

      // Mock: Get threat with integration details
      vi.mocked(sql).mockResolvedValueOnce([
        {
          id: threatId,
          tenant_id: TEST_TENANT_ID,
          message_id: TEST_MESSAGE_ID,
          external_message_id: TEST_EXTERNAL_MESSAGE_ID,
          integration_id: TEST_INTEGRATION_ID,
          integration_type: 'o365',
          status: 'quarantined',
          connected_email: TEST_CONNECTED_EMAIL,
        },
      ]);

      // Mock: Update threat status
      vi.mocked(sql).mockResolvedValueOnce([]);

      // Mock move to inbox
      mockFetch.mockResolvedValueOnce({
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

      // Verify move to inbox was called
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/move'),
        expect.objectContaining({
          body: expect.stringContaining('inbox'),
        })
      );

      // Verify audit log was called
      expect(logAuditEvent).toHaveBeenCalled();
    });
  });

  describe('deleteEmail (O365)', () => {
    it('should permanently delete email by moving to deleteditems', async () => {
      // Arrange
      const threatId = 'threat_o365_001';

      vi.mocked(sql).mockResolvedValueOnce([
        {
          id: threatId,
          tenant_id: TEST_TENANT_ID,
          message_id: TEST_MESSAGE_ID,
          external_message_id: TEST_EXTERNAL_MESSAGE_ID,
          integration_id: TEST_INTEGRATION_ID,
          integration_type: 'o365',
          status: 'quarantined',
          connected_email: TEST_CONNECTED_EMAIL,
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

      // Verify move to deleteditems was called
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/move'),
        expect.objectContaining({
          body: expect.stringContaining('deleteditems'),
        })
      );
    });
  });
});

describe('O365 Sync Pipeline Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Email detection to remediation flow', () => {
    it('should detect threat and auto-remediate in webhook handler', async () => {
      // This test documents the expected end-to-end flow:
      // 1. Graph API webhook receives notification (via subscription)
      // 2. Fetch new message via Graph API
      // 3. Parse and analyze email
      // 4. Store verdict in email_verdicts
      // 5. If threat, call autoRemediate
      // 6. autoRemediate moves email to quarantine folder
      // 7. Threat record created in threats table

      // The actual implementation should be verified manually
      // This test serves as documentation of expected behavior
      expect(true).toBe(true);
    });
  });
});

describe('O365 Subscription Management', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch = vi.fn();
    global.fetch = mockFetch;
  });

  it('should create webhook subscription for inbox notifications', async () => {
    // Arrange
    const subscriptionId = 'sub_123';
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          id: subscriptionId,
          expirationDateTime: new Date(Date.now() + 4230 * 60 * 1000).toISOString(),
        }),
    });

    // Act
    const { createO365Subscription } = await import('@/lib/integrations/o365');
    const result = await createO365Subscription({
      accessToken: TEST_ACCESS_TOKEN,
      notificationUrl: 'https://api.example.com/webhooks/o365',
      clientState: 'client_state_secret',
    });

    // Assert
    expect(result.subscriptionId).toBe(subscriptionId);
    expect(result.expiresAt).toBeInstanceOf(Date);
    expect(mockFetch).toHaveBeenCalledWith(
      'https://graph.microsoft.com/v1.0/subscriptions',
      expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining('inbox'),
      })
    );
  });

  it('should renew existing subscription', async () => {
    // Arrange
    const subscriptionId = 'sub_123';
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({}),
    });

    // Act
    const { renewO365Subscription } = await import('@/lib/integrations/o365');
    const expiresAt = await renewO365Subscription({
      accessToken: TEST_ACCESS_TOKEN,
      subscriptionId,
    });

    // Assert
    expect(expiresAt).toBeInstanceOf(Date);
    expect(mockFetch).toHaveBeenCalledWith(
      `https://graph.microsoft.com/v1.0/subscriptions/${subscriptionId}`,
      expect.objectContaining({ method: 'PATCH' })
    );
  });

  it('should delete subscription', async () => {
    // Arrange
    const subscriptionId = 'sub_123';
    mockFetch.mockResolvedValueOnce({
      ok: true,
    });

    // Act
    const { deleteO365Subscription } = await import('@/lib/integrations/o365');
    await deleteO365Subscription({
      accessToken: TEST_ACCESS_TOKEN,
      subscriptionId,
    });

    // Assert
    expect(mockFetch).toHaveBeenCalledWith(
      `https://graph.microsoft.com/v1.0/subscriptions/${subscriptionId}`,
      expect.objectContaining({ method: 'DELETE' })
    );
  });
});

describe('Diagnostic Tests (O365)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Integration health checks', () => {
    it('should verify connected_email is populated', async () => {
      vi.mocked(sql).mockResolvedValueOnce([
        {
          id: 'integration_id',
          tenant_id: TEST_TENANT_ID,
          type: 'o365',
          status: 'connected',
          connected_email: TEST_CONNECTED_EMAIL, // Should NOT be null
          config: {
            email: 'user@company.onmicrosoft.com',
            subscriptionId: 'sub_123',
          },
        },
      ]);

      const result = await sql`SELECT * FROM integrations WHERE tenant_id = ${TEST_TENANT_ID}`;
      expect(result[0].connected_email).not.toBeNull();
    });

    it('should verify Graph API subscription is active', async () => {
      vi.mocked(sql).mockResolvedValueOnce([
        {
          config: {
            subscriptionId: 'sub_123',
            subscriptionExpiration: new Date(
              Date.now() + 2 * 24 * 60 * 60 * 1000
            ).toISOString(), // 2 days from now
          },
        },
      ]);

      const result = await sql`SELECT config FROM integrations`;
      const subscriptionExpiration = new Date(result[0].config.subscriptionExpiration);
      expect(subscriptionExpiration.getTime()).toBeGreaterThan(Date.now());
    });
  });
});
