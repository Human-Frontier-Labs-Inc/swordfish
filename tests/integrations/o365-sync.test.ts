/**
 * Microsoft 365 Email Sync Tests
 *
 * TDD tests for full email content sync via Graph API
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Import after mocking
import {
  O365SyncWorker,
  O365SyncState,
  O365EmailContent,
  DeltaSyncResult,
} from '@/lib/integrations/o365/sync-worker';

describe('O365 Sync Worker', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Delta Sync', () => {
    it('should fetch new emails since last delta link', async () => {
      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      // Mock delta response
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: [
            {
              id: 'msg-1',
              internetMessageId: '<abc@example.com>',
              subject: 'Test Email',
              from: { emailAddress: { address: 'sender@example.com', name: 'Sender' } },
              toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
              receivedDateTime: '2024-01-15T10:00:00Z',
              body: { contentType: 'html', content: '<p>Test body</p>' },
              hasAttachments: false,
            },
          ],
          '@odata.deltaLink': 'https://graph.microsoft.com/v1.0/me/messages/delta?$deltaToken=xyz',
        }),
      });

      const result = await worker.performDeltaSync();

      expect(result.newEmails).toHaveLength(1);
      expect(result.newEmails[0].messageId).toBe('msg-1');
      expect(result.deltaLink).toContain('deltaToken=xyz');
    });

    it('should handle pagination in delta sync', async () => {
      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      // First page
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: [{ id: 'msg-1', subject: 'Email 1' }],
          '@odata.nextLink': 'https://graph.microsoft.com/v1.0/me/messages/delta?$skipToken=abc',
        }),
      });

      // Second page
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: [{ id: 'msg-2', subject: 'Email 2' }],
          '@odata.deltaLink': 'https://graph.microsoft.com/v1.0/me/messages/delta?$deltaToken=final',
        }),
      });

      const result = await worker.performDeltaSync();

      expect(result.newEmails).toHaveLength(2);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should fall back to full sync when delta token expired', async () => {
      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        deltaLink: 'https://graph.microsoft.com/v1.0/me/messages/delta?$deltaToken=expired',
      });

      // Delta sync fails with 410 Gone
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 410,
        json: async () => ({ error: { code: 'syncStateNotFound' } }),
      });

      // Fall back to full sync
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: [{ id: 'msg-1', subject: 'Email 1' }],
          '@odata.deltaLink': 'https://graph.microsoft.com/v1.0/me/messages/delta?$deltaToken=new',
        }),
      });

      const result = await worker.performDeltaSync();

      expect(result.newEmails).toHaveLength(1);
      expect(result.fullSyncRequired).toBe(true);
    });

    it('should respect maxResults limit', async () => {
      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        maxResults: 10,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: [],
          '@odata.deltaLink': 'https://graph.microsoft.com/v1.0/me/messages/delta?$deltaToken=xyz',
        }),
      });

      await worker.performDeltaSync();

      // URL params are encoded, so $top becomes %24top
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringMatching(/top=10/),
        expect.any(Object)
      );
    });
  });

  describe('Full Email Content Fetch', () => {
    it('should fetch complete email with headers and body', async () => {
      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'msg-1',
          internetMessageId: '<unique-id@example.com>',
          subject: 'Important Email',
          from: { emailAddress: { address: 'sender@malicious.com', name: 'Legit Sender' } },
          toRecipients: [{ emailAddress: { address: 'victim@company.com', name: 'Victim' } }],
          ccRecipients: [],
          receivedDateTime: '2024-01-15T10:00:00Z',
          sentDateTime: '2024-01-15T09:59:00Z',
          body: { contentType: 'html', content: '<p>Click here: <a href="http://phish.com">Link</a></p>' },
          internetMessageHeaders: [
            { name: 'Authentication-Results', value: 'spf=fail; dkim=fail' },
            { name: 'Received', value: 'from suspicious.server' },
            { name: 'Return-Path', value: '<bounce@different.com>' },
            { name: 'Reply-To', value: 'attacker@evil.com' },
          ],
          hasAttachments: true,
        }),
      });

      const email = await worker.fetchEmailContent('msg-1');

      expect(email.messageId).toBe('msg-1');
      expect(email.internetMessageId).toBe('<unique-id@example.com>');
      expect(email.from.address).toBe('sender@malicious.com');
      expect(email.headers).toHaveLength(4);
      expect(email.body.html).toContain('phish.com');
    });

    it('should fetch attachments when present', async () => {
      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      // Email with attachments flag
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'msg-1',
          hasAttachments: true,
          body: { content: 'Test' },
        }),
      });

      // Attachments list
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: [
            {
              id: 'attach-1',
              name: 'invoice.pdf',
              contentType: 'application/pdf',
              size: 1024,
              isInline: false,
            },
            {
              id: 'attach-2',
              name: 'malware.exe',
              contentType: 'application/octet-stream',
              size: 2048,
              isInline: false,
            },
          ],
        }),
      });

      const email = await worker.fetchEmailContent('msg-1', { includeAttachments: true });

      expect(email.attachments).toHaveLength(2);
      expect(email.attachments[0].name).toBe('invoice.pdf');
      expect(email.attachments[1].name).toBe('malware.exe');
    });

    it('should handle large attachments with content fetch', async () => {
      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'msg-1',
          hasAttachments: true,
          body: { content: 'Test' },
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: [{
            id: 'attach-1',
            name: 'document.docx',
            contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            size: 5000000, // 5MB
            contentBytes: null, // Large attachments don't include content inline
          }],
        }),
      });

      // Fetch attachment content separately
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          contentBytes: 'base64encodedcontent...',
        }),
      });

      const email = await worker.fetchEmailContent('msg-1', {
        includeAttachments: true,
        fetchAttachmentContent: true,
      });

      expect(email.attachments[0].content).toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });
  });

  describe('Email Parsing', () => {
    it('should extract URLs from email body', () => {
      const worker = new O365SyncWorker({
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
      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      const email: O365EmailContent = {
        messageId: 'msg-1',
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
      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      const email: O365EmailContent = {
        messageId: 'msg-1',
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
      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      const email: O365EmailContent = {
        messageId: 'msg-1',
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
      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        onSaveSyncState: saveSyncState,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: [],
          '@odata.deltaLink': 'https://graph.microsoft.com/v1.0/me/messages/delta?$deltaToken=new-token',
        }),
      });

      await worker.performDeltaSync();

      expect(saveSyncState).toHaveBeenCalledWith(
        expect.objectContaining({
          deltaLink: expect.stringContaining('deltaToken=new-token'),
          lastSyncAt: expect.any(Date),
        })
      );
    });

    it('should load existing sync state', async () => {
      const existingState: O365SyncState = {
        deltaLink: 'https://graph.microsoft.com/v1.0/me/messages/delta?$deltaToken=existing',
        lastSyncAt: new Date('2024-01-14T10:00:00Z'),
        emailsProcessed: 100,
      };

      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        deltaLink: existingState.deltaLink,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: [],
          '@odata.deltaLink': 'https://graph.microsoft.com/v1.0/me/messages/delta?$deltaToken=updated',
        }),
      });

      await worker.performDeltaSync();

      // Should use existing delta link
      expect(mockFetch).toHaveBeenCalledWith(
        existingState.deltaLink,
        expect.any(Object)
      );
    });

    it('should track sync progress', async () => {
      const onProgress = vi.fn();
      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        onProgress,
      });

      // Multiple pages
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: Array(50).fill({ id: 'msg', subject: 'Test' }),
          '@odata.nextLink': 'https://graph.microsoft.com/next',
        }),
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: Array(30).fill({ id: 'msg', subject: 'Test' }),
          '@odata.deltaLink': 'https://graph.microsoft.com/delta',
        }),
      });

      await worker.performDeltaSync();

      expect(onProgress).toHaveBeenCalledWith({ emailsFetched: 50, page: 1 });
      expect(onProgress).toHaveBeenCalledWith({ emailsFetched: 80, page: 2 });
    });
  });

  describe('Error Handling', () => {
    it('should handle rate limiting with retry', async () => {
      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      // First call rate limited
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: new Headers({ 'Retry-After': '1' }),
        json: async () => ({ error: { code: 'TooManyRequests' } }),
      });

      // Retry succeeds
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: [{ id: 'msg-1' }],
          '@odata.deltaLink': 'https://graph.microsoft.com/delta',
        }),
      });

      const result = await worker.performDeltaSync();

      expect(result.newEmails).toHaveLength(1);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should handle token expiration', async () => {
      const onTokenExpired = vi.fn().mockResolvedValue('new-access-token');
      const worker = new O365SyncWorker({
        accessToken: 'expired-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
        onTokenExpired,
      });

      // First call fails with 401
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: { code: 'InvalidAuthenticationToken' } }),
      });

      // Retry with new token succeeds
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: [{ id: 'msg-1' }],
          '@odata.deltaLink': 'https://graph.microsoft.com/delta',
        }),
      });

      const result = await worker.performDeltaSync();

      expect(onTokenExpired).toHaveBeenCalled();
      expect(result.newEmails).toHaveLength(1);
    });

    it('should handle network errors gracefully', async () => {
      const worker = new O365SyncWorker({
        accessToken: 'test-token',
        tenantId: 'tenant-123',
        integrationId: 'int-123',
      });

      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      await expect(worker.performDeltaSync()).rejects.toThrow('Network error');
    });
  });
});

describe('O365 Batch Operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should batch multiple email fetches', async () => {
    const worker = new O365SyncWorker({
      accessToken: 'test-token',
      tenantId: 'tenant-123',
      integrationId: 'int-123',
    });

    // Batch request
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        responses: [
          { id: '1', status: 200, body: { id: 'msg-1', subject: 'Email 1' } },
          { id: '2', status: 200, body: { id: 'msg-2', subject: 'Email 2' } },
          { id: '3', status: 200, body: { id: 'msg-3', subject: 'Email 3' } },
        ],
      }),
    });

    const emails = await worker.batchFetchEmails(['msg-1', 'msg-2', 'msg-3']);

    expect(emails).toHaveLength(3);
    expect(mockFetch).toHaveBeenCalledWith(
      'https://graph.microsoft.com/v1.0/$batch',
      expect.objectContaining({
        method: 'POST',
      })
    );
  });

  it('should handle partial batch failures', async () => {
    const worker = new O365SyncWorker({
      accessToken: 'test-token',
      tenantId: 'tenant-123',
      integrationId: 'int-123',
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        responses: [
          { id: '1', status: 200, body: { id: 'msg-1', subject: 'Email 1' } },
          { id: '2', status: 404, body: { error: { code: 'ItemNotFound' } } },
          { id: '3', status: 200, body: { id: 'msg-3', subject: 'Email 3' } },
        ],
      }),
    });

    const emails = await worker.batchFetchEmails(['msg-1', 'msg-2', 'msg-3']);

    expect(emails).toHaveLength(2);
    expect(emails.map(e => e.messageId)).toEqual(['msg-1', 'msg-3']);
  });
});
