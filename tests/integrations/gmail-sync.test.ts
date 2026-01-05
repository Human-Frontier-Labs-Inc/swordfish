/**
 * Gmail / Google Workspace Sync Tests
 *
 * TDD tests for full email content sync via Gmail API
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Import after mocking
import {
  GmailSyncWorker,
  GmailSyncState,
  GmailEmailContent,
  HistorySyncResult,
} from '@/lib/integrations/gmail/sync-worker';

describe('Gmail Sync Worker', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('History Sync', () => {
    it('should fetch new messages since last historyId', async () => {
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        historyId: '12345',
      });

      // Mock history response
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          history: [
            {
              id: '12346',
              messagesAdded: [
                { message: { id: 'msg-1', threadId: 'thread-1' } },
              ],
            },
          ],
          historyId: '12350',
        }),
      });

      // Mock message fetch
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'msg-1',
          threadId: 'thread-1',
          payload: {
            headers: [
              { name: 'From', value: 'sender@example.com' },
              { name: 'To', value: 'recipient@example.com' },
              { name: 'Subject', value: 'Test Email' },
              { name: 'Date', value: 'Mon, 15 Jan 2024 10:00:00 +0000' },
            ],
            body: { data: 'VGVzdCBib2R5' }, // base64 "Test body"
          },
        }),
      });

      const result = await worker.performHistorySync();

      expect(result.newEmails).toHaveLength(1);
      expect(result.newEmails[0].messageId).toBe('msg-1');
      expect(result.historyId).toBe('12350');
    });

    it('should handle pagination in history sync', async () => {
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        historyId: '10000',
      });

      // First page
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          history: [
            { id: '10001', messagesAdded: [{ message: { id: 'msg-1' } }] },
          ],
          historyId: '10050',
          nextPageToken: 'page2-token',
        }),
      });

      // Second page
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          history: [
            { id: '10051', messagesAdded: [{ message: { id: 'msg-2' } }] },
          ],
          historyId: '10100',
        }),
      });

      // Fetch messages
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => createMockMessage('msg-1'),
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => createMockMessage('msg-2'),
      });

      const result = await worker.performHistorySync();

      expect(result.newEmails).toHaveLength(2);
      expect(result.historyId).toBe('10100');
    });

    it('should fall back to full sync when history is too old', async () => {
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        historyId: '1', // Very old history ID
      });

      // History API returns 404 for expired history
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: async () => ({ error: { code: 404, message: 'historyId is too old' } }),
      });

      // Full sync - list messages
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          messages: [{ id: 'msg-1' }, { id: 'msg-2' }],
          resultSizeEstimate: 2,
        }),
      });

      // Fetch each message
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => createMockMessage('msg-1'),
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => createMockMessage('msg-2'),
      });

      // Get profile for new historyId
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          emailAddress: 'user@example.com',
          historyId: '99999',
        }),
      });

      const result = await worker.performHistorySync();

      expect(result.newEmails).toHaveLength(2);
      expect(result.fullSyncRequired).toBe(true);
    });

    it('should respect maxResults limit', async () => {
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        historyId: '10000',
        maxResults: 10,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          history: [],
          historyId: '10000',
        }),
      });

      await worker.performHistorySync();

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringMatching(/maxResults=10/),
        expect.any(Object)
      );
    });
  });

  describe('Full Email Content Fetch', () => {
    it('should fetch and decode complete email', async () => {
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'msg-1',
          threadId: 'thread-1',
          internalDate: '1705312800000',
          payload: {
            headers: [
              { name: 'From', value: 'John Doe <sender@example.com>' },
              { name: 'To', value: 'recipient@example.com' },
              { name: 'Subject', value: 'Important Email' },
              { name: 'Message-ID', value: '<unique-id@example.com>' },
              { name: 'Authentication-Results', value: 'spf=pass; dkim=pass' },
              { name: 'Reply-To', value: 'different@example.com' },
            ],
            mimeType: 'multipart/alternative',
            parts: [
              {
                mimeType: 'text/plain',
                body: { data: 'SGVsbG8gV29ybGQ=' }, // "Hello World"
              },
              {
                mimeType: 'text/html',
                body: { data: 'PHA-SGVsbG8gV29ybGQ8L3A-' }, // "<p>Hello World</p>"
              },
            ],
          },
        }),
      });

      const email = await worker.fetchEmailContent('msg-1');

      expect(email.messageId).toBe('msg-1');
      expect(email.from.address).toBe('sender@example.com');
      expect(email.from.name).toBe('John Doe');
      expect(email.subject).toBe('Important Email');
      expect(email.headers).toHaveLength(6);
      expect(email.body.text).toBe('Hello World');
    });

    it('should fetch attachments when present', async () => {
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'msg-1',
          threadId: 'thread-1',
          payload: {
            headers: [
              { name: 'From', value: 'sender@example.com' },
              { name: 'Subject', value: 'With Attachment' },
            ],
            mimeType: 'multipart/mixed',
            parts: [
              {
                mimeType: 'text/plain',
                body: { data: 'VGVzdA==' },
              },
              {
                partId: '1',
                mimeType: 'application/pdf',
                filename: 'invoice.pdf',
                body: { attachmentId: 'attach-1', size: 1024 },
              },
              {
                partId: '2',
                mimeType: 'application/octet-stream',
                filename: 'malware.exe',
                body: { attachmentId: 'attach-2', size: 2048 },
              },
            ],
          },
        }),
      });

      const email = await worker.fetchEmailContent('msg-1', { includeAttachments: true });

      expect(email.attachments).toHaveLength(2);
      expect(email.attachments[0].name).toBe('invoice.pdf');
      expect(email.attachments[1].name).toBe('malware.exe');
    });

    it('should fetch attachment content when requested', async () => {
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'msg-1',
          payload: {
            headers: [{ name: 'From', value: 'sender@example.com' }],
            mimeType: 'multipart/mixed',
            parts: [
              {
                partId: '1',
                mimeType: 'application/pdf',
                filename: 'doc.pdf',
                body: { attachmentId: 'attach-1', size: 5000 },
              },
            ],
          },
        }),
      });

      // Fetch attachment content
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          size: 5000,
          data: 'YmFzZTY0ZW5jb2RlZGNvbnRlbnQ=',
        }),
      });

      const email = await worker.fetchEmailContent('msg-1', {
        includeAttachments: true,
        fetchAttachmentContent: true,
      });

      expect(email.attachments[0].content).toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('Email Parsing', () => {
    it('should extract URLs from email body', () => {
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      const html = `
        <p>Check out these links:</p>
        <a href="https://legitimate.com/page">Safe Link</a>
        <a href="http://phishing-site.com/steal">Click Here</a>
        <a href="https://bit.ly/abc123">Shortened</a>
      `;

      const urls = worker.extractUrls(html);

      expect(urls).toHaveLength(3);
      expect(urls).toContain('https://legitimate.com/page');
      expect(urls).toContain('http://phishing-site.com/steal');
      expect(urls).toContain('https://bit.ly/abc123');
    });

    it('should detect reply-to mismatch', () => {
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      const email: GmailEmailContent = {
        messageId: 'msg-1',
        threadId: 'thread-1',
        internetMessageId: '<test@example.com>',
        from: { address: 'ceo@company.com', name: 'CEO' },
        to: [{ address: 'employee@company.com' }],
        subject: 'Urgent Wire Transfer',
        receivedAt: new Date(),
        headers: [
          { name: 'Reply-To', value: 'attacker@evil.com' },
        ],
        body: { html: '', text: '' },
        attachments: [],
      };

      const signals = worker.analyzeEmailSignals(email);

      expect(signals).toContainEqual(
        expect.objectContaining({
          type: 'reply_to_mismatch',
          severity: 'warning',
        })
      );
    });

    it('should detect SPF/DKIM failures from headers', () => {
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      const email: GmailEmailContent = {
        messageId: 'msg-1',
        threadId: 'thread-1',
        internetMessageId: '<test@example.com>',
        from: { address: 'sender@example.com', name: 'Sender' },
        to: [{ address: 'recipient@company.com' }],
        subject: 'Test',
        receivedAt: new Date(),
        headers: [
          { name: 'Authentication-Results', value: 'spf=fail; dkim=fail; dmarc=fail' },
        ],
        body: { html: '', text: '' },
        attachments: [],
      };

      const signals = worker.analyzeEmailSignals(email);

      expect(signals).toContainEqual(
        expect.objectContaining({
          type: 'spf_fail',
          severity: 'critical',
        })
      );
      expect(signals).toContainEqual(
        expect.objectContaining({
          type: 'dkim_fail',
          severity: 'critical',
        })
      );
    });

    it('should detect suspicious attachment types', () => {
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      const email: GmailEmailContent = {
        messageId: 'msg-1',
        threadId: 'thread-1',
        internetMessageId: '<test@example.com>',
        from: { address: 'sender@example.com', name: 'Sender' },
        to: [{ address: 'recipient@company.com' }],
        subject: 'Invoice',
        receivedAt: new Date(),
        headers: [],
        body: { html: '', text: '' },
        attachments: [
          { id: '1', name: 'invoice.exe', contentType: 'application/octet-stream', size: 1024 },
          { id: '2', name: 'document.js', contentType: 'application/javascript', size: 512 },
          { id: '3', name: 'macro.xlsm', contentType: 'application/vnd.ms-excel.sheet.macroEnabled.12', size: 2048 },
        ],
      };

      const signals = worker.analyzeEmailSignals(email);

      expect(signals.filter(s => s.type === 'dangerous_attachment')).toHaveLength(3);
    });
  });

  describe('Sync State Management', () => {
    it('should save sync state after successful sync', async () => {
      const saveSyncState = vi.fn();
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        historyId: '10000',
        onSaveSyncState: saveSyncState,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          history: [],
          historyId: '10100',
        }),
      });

      await worker.performHistorySync();

      expect(saveSyncState).toHaveBeenCalledWith(
        expect.objectContaining({
          historyId: '10100',
          lastSyncAt: expect.any(Date),
        })
      );
    });

    it('should track sync progress', async () => {
      const onProgress = vi.fn();
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        historyId: '10000',
        onProgress,
      });

      // Multiple pages
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          history: Array(50).fill({ id: '1', messagesAdded: [{ message: { id: 'msg' } }] }),
          historyId: '10050',
          nextPageToken: 'page2',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          history: Array(30).fill({ id: '2', messagesAdded: [{ message: { id: 'msg' } }] }),
          historyId: '10100',
        }),
      });

      // Mock message fetches (simplified - all return same mock)
      for (let i = 0; i < 80; i++) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => createMockMessage(`msg-${i}`),
        });
      }

      await worker.performHistorySync();

      expect(onProgress).toHaveBeenCalled();
    });
  });

  describe('Error Handling', () => {
    it('should handle rate limiting with retry', async () => {
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        historyId: '10000',
      });

      // First call rate limited
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: new Headers({ 'Retry-After': '1' }),
        json: async () => ({ error: { code: 429, message: 'Rate Limit Exceeded' } }),
      });

      // Retry succeeds
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          history: [{ id: '10001', messagesAdded: [{ message: { id: 'msg-1' } }] }],
          historyId: '10100',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => createMockMessage('msg-1'),
      });

      const result = await worker.performHistorySync();

      expect(result.newEmails).toHaveLength(1);
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should handle token expiration', async () => {
      const onTokenExpired = vi.fn().mockResolvedValue('new-access-token');
      const worker = new GmailSyncWorker({
        accessToken: 'expired-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        historyId: '10000',
        onTokenExpired,
      });

      // First call fails with 401
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: { code: 401, message: 'Invalid Credentials' } }),
      });

      // Retry with new token succeeds
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          history: [{ id: '10001', messagesAdded: [{ message: { id: 'msg-1' } }] }],
          historyId: '10100',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => createMockMessage('msg-1'),
      });

      const result = await worker.performHistorySync();

      expect(onTokenExpired).toHaveBeenCalled();
      expect(result.newEmails).toHaveLength(1);
    });

    it('should handle network errors gracefully', async () => {
      const worker = new GmailSyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        historyId: '10000',
      });

      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      await expect(worker.performHistorySync()).rejects.toThrow('Network error');
    });
  });
});

describe('Gmail Batch Operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should batch multiple message fetches', async () => {
    const worker = new GmailSyncWorker({
      accessToken: 'test-token',
      tenantId: 'tenant-123',
      integrationId: 'int-123',
    });

    // Gmail batch API uses multipart response
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ([
        { id: 'msg-1', payload: { headers: [{ name: 'From', value: 'a@test.com' }] } },
        { id: 'msg-2', payload: { headers: [{ name: 'From', value: 'b@test.com' }] } },
        { id: 'msg-3', payload: { headers: [{ name: 'From', value: 'c@test.com' }] } },
      ]),
    });

    const emails = await worker.batchFetchEmails(['msg-1', 'msg-2', 'msg-3']);

    expect(emails).toHaveLength(3);
  });

  it('should handle partial batch failures', async () => {
    const worker = new GmailSyncWorker({
      accessToken: 'test-token',
      tenantId: 'tenant-123',
      integrationId: 'int-123',
    });

    // Some messages found, some not
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ([
        { id: 'msg-1', payload: { headers: [{ name: 'From', value: 'a@test.com' }] } },
        null, // Message not found
        { id: 'msg-3', payload: { headers: [{ name: 'From', value: 'c@test.com' }] } },
      ]),
    });

    const emails = await worker.batchFetchEmails(['msg-1', 'msg-2', 'msg-3']);

    expect(emails).toHaveLength(2);
    expect(emails.map(e => e.messageId)).toEqual(['msg-1', 'msg-3']);
  });
});

// Helper function to create mock Gmail message
function createMockMessage(id: string): Record<string, unknown> {
  return {
    id,
    threadId: `thread-${id}`,
    internalDate: '1705312800000',
    payload: {
      headers: [
        { name: 'From', value: `sender-${id}@example.com` },
        { name: 'To', value: 'recipient@example.com' },
        { name: 'Subject', value: `Test Email ${id}` },
        { name: 'Message-ID', value: `<${id}@example.com>` },
      ],
      mimeType: 'text/plain',
      body: { data: 'VGVzdCBib2R5' },
    },
  };
}
