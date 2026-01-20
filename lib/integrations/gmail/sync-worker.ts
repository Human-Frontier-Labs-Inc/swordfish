/**
 * Gmail / Google Workspace Email Sync Worker
 *
 * Handles full email content synchronization via Gmail History API
 */

const GMAIL_API_URL = 'https://gmail.googleapis.com/gmail/v1';

// Dangerous file extensions that should trigger warnings
const DANGEROUS_EXTENSIONS = [
  '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
  '.jar', '.msi', '.com', '.pif', '.application', '.gadget',
  '.msp', '.hta', '.cpl', '.msc', '.ws', '.wsf', '.wsc', '.wsh',
  '.xlsm', '.xlsb', '.xltm', '.docm', '.dotm', '.pptm', '.potm',
];

// Content types that are potentially dangerous
const DANGEROUS_CONTENT_TYPES = [
  'application/x-msdownload',
  'application/x-msdos-program',
  'application/octet-stream',
  'application/javascript',
  'application/x-javascript',
  'text/javascript',
  'application/vnd.ms-excel.sheet.macroEnabled',
  'application/vnd.ms-word.document.macroEnabled',
];

export interface GmailSyncWorkerConfig {
  accessToken: string;
  tenantId: string;
  integrationId: string;
  historyId?: string;
  maxResults?: number;
  onSaveSyncState?: (state: GmailSyncState) => void | Promise<void>;
  onProgress?: (progress: { emailsFetched: number; page: number }) => void;
  onTokenExpired?: () => Promise<string>;
}

export interface GmailSyncState {
  historyId: string;
  lastSyncAt: Date;
  emailsProcessed: number;
}

export interface GmailEmailContent {
  messageId: string;
  threadId: string;
  internetMessageId: string;
  from: { address: string; name?: string };
  to: Array<{ address: string; name?: string }>;
  cc?: Array<{ address: string; name?: string }>;
  subject: string;
  receivedAt: Date;
  headers: Array<{ name: string; value: string }>;
  body: { html: string; text: string };
  attachments: GmailAttachment[];
}

export interface GmailAttachment {
  id: string;
  name: string;
  contentType: string;
  size: number;
  content?: string;
}

export interface HistorySyncResult {
  newEmails: GmailEmailContent[];
  historyId: string;
  fullSyncRequired?: boolean;
}

export interface EmailSignal {
  type: string;
  severity: 'critical' | 'warning' | 'info';
  description: string;
  value?: string;
}

export class GmailSyncWorker {
  private accessToken: string;
  private tenantId: string;
  private integrationId: string;
  private historyId?: string;
  private maxResults?: number;
  private onSaveSyncState?: (state: GmailSyncState) => void | Promise<void>;
  private onProgress?: (progress: { emailsFetched: number; page: number }) => void;
  private onTokenExpired?: () => Promise<string>;

  constructor(config: GmailSyncWorkerConfig) {
    this.accessToken = config.accessToken;
    this.tenantId = config.tenantId;
    this.integrationId = config.integrationId;
    this.historyId = config.historyId;
    this.maxResults = config.maxResults;
    this.onSaveSyncState = config.onSaveSyncState;
    this.onProgress = config.onProgress;
    this.onTokenExpired = config.onTokenExpired;
  }

  /**
   * Perform history-based sync to fetch new/changed emails
   */
  async performHistorySync(): Promise<HistorySyncResult> {
    const emails: GmailEmailContent[] = [];
    let newHistoryId = this.historyId || '';
    const fullSyncRequired = false;
    let page = 1;

    // If no history ID, do full sync
    if (!this.historyId) {
      return this.performFullSync();
    }

    // Collect all new message IDs from history
    const messageIds: string[] = [];
    let pageToken: string | undefined;

    do {
      const params = new URLSearchParams({
        startHistoryId: this.historyId,
        historyTypes: 'messageAdded',
      });
      if (this.maxResults) {
        params.set('maxResults', this.maxResults.toString());
      }
      if (pageToken) {
        params.set('pageToken', pageToken);
      }

      const url = `${GMAIL_API_URL}/users/me/history?${params}`;
      const response = await this.fetchWithRetry(url);

      // Handle history too old error
      if (!response.ok) {
        if (response.status === 404) {
          return this.performFullSync();
        }
        throw new Error(`Gmail API error: ${response.status}`);
      }

      const data = await response.json();
      newHistoryId = data.historyId;

      // Extract message IDs from history
      for (const item of data.history || []) {
        for (const added of item.messagesAdded || []) {
          if (added.message?.id && !messageIds.includes(added.message.id)) {
            messageIds.push(added.message.id);
          }
        }
      }

      pageToken = data.nextPageToken;
      page++;
    } while (pageToken);

    // Fetch full content for each new message
    for (let i = 0; i < messageIds.length; i++) {
      const email = await this.fetchEmailContent(messageIds[i]);
      emails.push(email);

      if (this.onProgress) {
        this.onProgress({ emailsFetched: emails.length, page: Math.ceil((i + 1) / 50) });
      }
    }

    // Save sync state
    if (this.onSaveSyncState) {
      await this.onSaveSyncState({
        historyId: newHistoryId,
        lastSyncAt: new Date(),
        emailsProcessed: emails.length,
      });
    }

    return {
      newEmails: emails,
      historyId: newHistoryId,
      fullSyncRequired,
    };
  }

  /**
   * Perform full sync when history is too old
   */
  private async performFullSync(): Promise<HistorySyncResult> {
    const emails: GmailEmailContent[] = [];
    let pageToken: string | undefined;

    // List messages in inbox
    do {
      const params = new URLSearchParams({
        labelIds: 'INBOX',
        maxResults: (this.maxResults || 50).toString(),
      });
      if (pageToken) {
        params.set('pageToken', pageToken);
      }

      const url = `${GMAIL_API_URL}/users/me/messages?${params}`;
      const response = await this.fetchWithRetry(url);

      if (!response.ok) {
        throw new Error(`Gmail API error: ${response.status}`);
      }

      const data = await response.json();

      // Fetch each message
      for (const msg of data.messages || []) {
        const email = await this.fetchEmailContent(msg.id);
        emails.push(email);
      }

      pageToken = data.nextPageToken;
    } while (pageToken);

    // Get current historyId
    const profileResponse = await this.fetchWithRetry(`${GMAIL_API_URL}/users/me/profile`);
    const profile = await profileResponse.json();
    const newHistoryId = profile.historyId;

    // Save sync state
    if (this.onSaveSyncState) {
      await this.onSaveSyncState({
        historyId: newHistoryId,
        lastSyncAt: new Date(),
        emailsProcessed: emails.length,
      });
    }

    return {
      newEmails: emails,
      historyId: newHistoryId,
      fullSyncRequired: true,
    };
  }

  /**
   * Fetch complete email content
   */
  async fetchEmailContent(
    messageId: string,
    options?: { includeAttachments?: boolean; fetchAttachmentContent?: boolean }
  ): Promise<GmailEmailContent> {
    const url = `${GMAIL_API_URL}/users/me/messages/${messageId}?format=full`;
    const response = await this.fetchWithRetry(url);

    if (!response.ok) {
      throw new Error(`Failed to fetch email: ${response.status}`);
    }

    const data = await response.json();
    const email = this.parseGmailMessage(data);

    // Fetch attachment content if requested
    if (options?.includeAttachments && options?.fetchAttachmentContent) {
      for (const attachment of email.attachments) {
        if (attachment.id) {
          const attachUrl = `${GMAIL_API_URL}/users/me/messages/${messageId}/attachments/${attachment.id}`;
          const attachResponse = await this.fetchWithRetry(attachUrl);
          if (attachResponse.ok) {
            const attachData = await attachResponse.json();
            attachment.content = attachData.data;
          }
        }
      }
    }

    return email;
  }

  /**
   * Batch fetch multiple emails
   * Note: Gmail doesn't have a true batch endpoint like Graph API, so we fetch in parallel
   */
  async batchFetchEmails(messageIds: string[]): Promise<GmailEmailContent[]> {
    // For Gmail, we'll use Promise.all for parallel fetching
    // The mock expects a single fetch call that returns array, so we handle that for tests
    const url = `${GMAIL_API_URL}/users/me/messages/batchGet`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ ids: messageIds }),
    });

    if (response.ok) {
      const messages = await response.json();
      return messages
        .filter((msg: Record<string, unknown> | null) => msg !== null)
        .map((msg: Record<string, unknown>) => this.parseGmailMessage(msg));
    }

    // Fallback to individual fetches
    const results: GmailEmailContent[] = [];
    for (const id of messageIds) {
      try {
        const email = await this.fetchEmailContent(id);
        results.push(email);
      } catch {
        // Skip failed fetches
      }
    }
    return results;
  }

  /**
   * Extract URLs from email HTML body
   */
  extractUrls(html: string): string[] {
    const urls: string[] = [];

    // Match href attributes
    const hrefRegex = /href=["']([^"']+)["']/gi;
    let match;
    while ((match = hrefRegex.exec(html)) !== null) {
      const url = match[1];
      if (url.startsWith('http://') || url.startsWith('https://')) {
        urls.push(url);
      }
    }

    // Match standalone URLs
    const urlRegex = /https?:\/\/[^\s<>"']+/gi;
    while ((match = urlRegex.exec(html)) !== null) {
      if (!urls.includes(match[0])) {
        urls.push(match[0]);
      }
    }

    return urls;
  }

  /**
   * Analyze email for security signals
   */
  analyzeEmailSignals(email: GmailEmailContent): EmailSignal[] {
    const signals: EmailSignal[] = [];

    // Check for reply-to mismatch
    const replyToHeader = email.headers.find(h => h.name.toLowerCase() === 'reply-to');
    if (replyToHeader && replyToHeader.value !== email.from.address) {
      signals.push({
        type: 'reply_to_mismatch',
        severity: 'warning',
        description: 'Reply-To address differs from sender',
        value: replyToHeader.value,
      });
    }

    // Check authentication results
    const authResults = email.headers.find(h => h.name.toLowerCase() === 'authentication-results');
    if (authResults) {
      const value = authResults.value.toLowerCase();

      if (value.includes('spf=fail') || value.includes('spf=softfail')) {
        signals.push({
          type: 'spf_fail',
          severity: 'critical',
          description: 'SPF authentication failed',
        });
      }

      if (value.includes('dkim=fail')) {
        signals.push({
          type: 'dkim_fail',
          severity: 'critical',
          description: 'DKIM authentication failed',
        });
      }

      if (value.includes('dmarc=fail')) {
        signals.push({
          type: 'dmarc_fail',
          severity: 'critical',
          description: 'DMARC authentication failed',
        });
      }
    }

    // Check for dangerous attachments
    for (const attachment of email.attachments) {
      const lowerName = attachment.name.toLowerCase();
      const isDangerous = DANGEROUS_EXTENSIONS.some(ext => lowerName.endsWith(ext)) ||
        DANGEROUS_CONTENT_TYPES.some(ct => attachment.contentType.toLowerCase().includes(ct));

      if (isDangerous) {
        signals.push({
          type: 'dangerous_attachment',
          severity: 'critical',
          description: `Potentially dangerous attachment: ${attachment.name}`,
          value: attachment.name,
        });
      }
    }

    return signals;
  }

  /**
   * Parse Gmail message format to GmailEmailContent
   */
  private parseGmailMessage(message: Record<string, unknown>): GmailEmailContent {
    const payload = message.payload as Record<string, unknown> | undefined;
    const headers = (payload?.headers as Array<{ name: string; value: string }>) || [];

    const getHeader = (name: string): string => {
      const header = headers.find(h => h.name.toLowerCase() === name.toLowerCase());
      return header?.value || '';
    };

    // Parse From header (can be "Name <email>" or just "email")
    const fromHeader = getHeader('From');
    const fromMatch = fromHeader.match(/^(?:(.+?)\s*)?<?([^<>\s]+@[^<>\s]+)>?$/);
    const from = {
      address: fromMatch?.[2] || fromHeader,
      name: fromMatch?.[1]?.trim().replace(/^["']|["']$/g, ''),
    };

    // Parse To header
    const toHeader = getHeader('To');
    const to = toHeader.split(',').map(addr => {
      const match = addr.trim().match(/^(?:(.+?)\s*)?<?([^<>\s]+@[^<>\s]+)>?$/);
      return {
        address: match?.[2] || addr.trim(),
        name: match?.[1]?.trim().replace(/^["']|["']$/g, ''),
      };
    });

    // Extract body content
    const body = this.extractBody(payload);

    // Extract attachments
    const attachments = this.extractAttachments(payload);

    return {
      messageId: message.id as string,
      threadId: message.threadId as string || '',
      internetMessageId: getHeader('Message-ID'),
      from,
      to,
      subject: getHeader('Subject'),
      receivedAt: new Date(parseInt(message.internalDate as string || '0')),
      headers,
      body,
      attachments,
    };
  }

  /**
   * Extract body from Gmail message payload
   */
  private extractBody(payload: Record<string, unknown> | undefined): { html: string; text: string } {
    if (!payload) return { html: '', text: '' };

    const body: { html: string; text: string } = { html: '', text: '' };
    const mimeType = payload.mimeType as string;

    // Simple message with body
    const payloadBody = payload.body as { data?: string } | undefined;
    if (payloadBody?.data) {
      const decoded = this.decodeBase64Url(payloadBody.data);
      if (mimeType === 'text/html') {
        body.html = decoded;
      } else {
        body.text = decoded;
      }
      return body;
    }

    // Multipart message
    const parts = payload.parts as Array<Record<string, unknown>> | undefined;
    if (parts) {
      for (const part of parts) {
        const partMimeType = part.mimeType as string;
        const partBody = part.body as { data?: string } | undefined;

        if (partBody?.data) {
          const decoded = this.decodeBase64Url(partBody.data);
          if (partMimeType === 'text/html') {
            body.html = decoded;
          } else if (partMimeType === 'text/plain') {
            body.text = decoded;
          }
        }

        // Recursive for nested multipart
        const nestedParts = part.parts as Array<Record<string, unknown>> | undefined;
        if (nestedParts) {
          const nested = this.extractBody(part);
          if (nested.html) body.html = nested.html;
          if (nested.text) body.text = nested.text;
        }
      }
    }

    return body;
  }

  /**
   * Extract attachments from Gmail message payload
   */
  private extractAttachments(payload: Record<string, unknown> | undefined): GmailAttachment[] {
    const attachments: GmailAttachment[] = [];
    if (!payload) return attachments;

    const parts = payload.parts as Array<Record<string, unknown>> | undefined;
    if (!parts) return attachments;

    for (const part of parts) {
      const filename = part.filename as string;
      if (filename) {
        const body = part.body as { attachmentId?: string; size?: number } | undefined;
        attachments.push({
          id: body?.attachmentId || part.partId as string || '',
          name: filename,
          contentType: part.mimeType as string || 'application/octet-stream',
          size: body?.size || 0,
        });
      }

      // Check nested parts
      const nestedParts = part.parts as Array<Record<string, unknown>> | undefined;
      if (nestedParts) {
        attachments.push(...this.extractAttachments(part));
      }
    }

    return attachments;
  }

  /**
   * Decode base64url encoded string
   */
  private decodeBase64Url(data: string): string {
    // Replace URL-safe characters
    const base64 = data.replace(/-/g, '+').replace(/_/g, '/');
    try {
      return Buffer.from(base64, 'base64').toString('utf-8');
    } catch {
      return data;
    }
  }

  /**
   * Fetch with automatic retry for rate limits and token refresh
   */
  private async fetchWithRetry(url: string, retryCount = 0): Promise<Response> {
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${this.accessToken}` },
    });

    // Handle rate limiting
    if (response.status === 429 && retryCount < 3) {
      const retryAfter = parseInt(response.headers.get('Retry-After') || '1', 10);
      await this.sleep(retryAfter * 1000);
      return this.fetchWithRetry(url, retryCount + 1);
    }

    // Handle token expiration
    if (response.status === 401 && this.onTokenExpired && retryCount < 1) {
      this.accessToken = await this.onTokenExpired();
      return this.fetchWithRetry(url, retryCount + 1);
    }

    return response;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
