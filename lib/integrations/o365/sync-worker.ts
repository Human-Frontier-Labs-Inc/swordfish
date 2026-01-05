/**
 * Microsoft 365 Email Sync Worker
 *
 * Handles full email content synchronization via Graph API delta sync
 */

const GRAPH_API_URL = 'https://graph.microsoft.com/v1.0';

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

export interface O365SyncWorkerConfig {
  accessToken: string;
  tenantId: string;
  integrationId: string;
  deltaLink?: string;
  maxResults?: number;
  onSaveSyncState?: (state: O365SyncState) => void | Promise<void>;
  onProgress?: (progress: { emailsFetched: number; page: number }) => void;
  onTokenExpired?: () => Promise<string>;
}

export interface O365SyncState {
  deltaLink: string;
  lastSyncAt: Date;
  emailsProcessed: number;
}

export interface O365EmailContent {
  messageId: string;
  internetMessageId: string;
  from: { address: string; name?: string };
  to: Array<{ address: string; name?: string }>;
  cc?: Array<{ address: string; name?: string }>;
  subject: string;
  receivedAt: Date;
  sentAt?: Date;
  headers: Array<{ name: string; value: string }>;
  body: { html: string; text: string };
  attachments: O365Attachment[];
}

export interface O365Attachment {
  id: string;
  name: string;
  contentType: string;
  size: number;
  isInline?: boolean;
  content?: string;
}

export interface DeltaSyncResult {
  newEmails: O365EmailContent[];
  deltaLink: string;
  fullSyncRequired?: boolean;
}

export interface EmailSignal {
  type: string;
  severity: 'critical' | 'warning' | 'info';
  description: string;
  value?: string;
}

export class O365SyncWorker {
  private accessToken: string;
  private tenantId: string;
  private integrationId: string;
  private deltaLink?: string;
  private maxResults?: number;
  private onSaveSyncState?: (state: O365SyncState) => void | Promise<void>;
  private onProgress?: (progress: { emailsFetched: number; page: number }) => void;
  private onTokenExpired?: () => Promise<string>;

  constructor(config: O365SyncWorkerConfig) {
    this.accessToken = config.accessToken;
    this.tenantId = config.tenantId;
    this.integrationId = config.integrationId;
    this.deltaLink = config.deltaLink;
    this.maxResults = config.maxResults;
    this.onSaveSyncState = config.onSaveSyncState;
    this.onProgress = config.onProgress;
    this.onTokenExpired = config.onTokenExpired;
  }

  /**
   * Perform delta sync to fetch new/changed emails
   */
  async performDeltaSync(): Promise<DeltaSyncResult> {
    const emails: O365EmailContent[] = [];
    let nextUrl: string;
    let finalDeltaLink = '';
    let fullSyncRequired = false;
    let page = 1;

    // Build initial URL
    if (this.deltaLink) {
      nextUrl = this.deltaLink;
    } else {
      const params = new URLSearchParams({
        $select: 'id,internetMessageId,subject,from,toRecipients,ccRecipients,receivedDateTime,sentDateTime,body,internetMessageHeaders,hasAttachments',
      });
      if (this.maxResults) {
        params.set('$top', this.maxResults.toString());
      }
      nextUrl = `${GRAPH_API_URL}/me/messages/delta?${params}`;
    }

    // Paginate through all results
    while (nextUrl) {
      const response = await this.fetchWithRetry(nextUrl);

      if (!response.ok) {
        // Handle delta token expiration (410 Gone)
        if (response.status === 410) {
          fullSyncRequired = true;
          // Reset to full sync
          const params = new URLSearchParams({
            $select: 'id,internetMessageId,subject,from,toRecipients,ccRecipients,receivedDateTime,sentDateTime,body,internetMessageHeaders,hasAttachments',
          });
          if (this.maxResults) {
            params.set('$top', this.maxResults.toString());
          }
          nextUrl = `${GRAPH_API_URL}/me/messages/delta?${params}`;
          continue;
        }
        throw new Error(`Graph API error: ${response.status}`);
      }

      const data = await response.json();

      // Process emails from this page
      for (const message of data.value || []) {
        const email = this.parseGraphMessage(message);
        emails.push(email);
      }

      // Report progress
      if (this.onProgress) {
        this.onProgress({ emailsFetched: emails.length, page });
      }

      // Check for next page or final delta link
      if (data['@odata.nextLink']) {
        nextUrl = data['@odata.nextLink'];
        page++;
      } else if (data['@odata.deltaLink']) {
        finalDeltaLink = data['@odata.deltaLink'];
        nextUrl = '';
      } else {
        nextUrl = '';
      }
    }

    // Save sync state
    if (this.onSaveSyncState && finalDeltaLink) {
      await this.onSaveSyncState({
        deltaLink: finalDeltaLink,
        lastSyncAt: new Date(),
        emailsProcessed: emails.length,
      });
    }

    return {
      newEmails: emails,
      deltaLink: finalDeltaLink,
      fullSyncRequired,
    };
  }

  /**
   * Fetch complete email content with headers and optionally attachments
   */
  async fetchEmailContent(
    messageId: string,
    options?: { includeAttachments?: boolean; fetchAttachmentContent?: boolean }
  ): Promise<O365EmailContent> {
    const url = `${GRAPH_API_URL}/me/messages/${messageId}?$select=id,internetMessageId,subject,from,toRecipients,ccRecipients,receivedDateTime,sentDateTime,body,internetMessageHeaders,hasAttachments`;

    const response = await this.fetchWithRetry(url);
    if (!response.ok) {
      throw new Error(`Failed to fetch email: ${response.status}`);
    }

    const data = await response.json();
    const email = this.parseGraphMessage(data);

    // Fetch attachments if requested
    if (options?.includeAttachments && data.hasAttachments) {
      const attachmentsUrl = `${GRAPH_API_URL}/me/messages/${messageId}/attachments`;
      const attachResponse = await this.fetchWithRetry(attachmentsUrl);

      if (attachResponse.ok) {
        const attachData = await attachResponse.json();
        email.attachments = attachData.value.map((a: Record<string, unknown>) => ({
          id: a.id as string,
          name: a.name as string,
          contentType: a.contentType as string,
          size: a.size as number,
          isInline: a.isInline as boolean,
          content: a.contentBytes as string | undefined,
        }));

        // Fetch content for large attachments if requested
        if (options.fetchAttachmentContent) {
          for (const attachment of email.attachments) {
            if (!attachment.content && attachment.size > 0) {
              const contentUrl = `${GRAPH_API_URL}/me/messages/${messageId}/attachments/${attachment.id}`;
              const contentResponse = await this.fetchWithRetry(contentUrl);
              if (contentResponse.ok) {
                const contentData = await contentResponse.json();
                attachment.content = contentData.contentBytes;
              }
            }
          }
        }
      }
    }

    return email;
  }

  /**
   * Batch fetch multiple emails using Graph API batch endpoint
   */
  async batchFetchEmails(messageIds: string[]): Promise<O365EmailContent[]> {
    const requests = messageIds.map((id, index) => ({
      id: (index + 1).toString(),
      method: 'GET',
      url: `/me/messages/${id}?$select=id,internetMessageId,subject,from,toRecipients,ccRecipients,receivedDateTime,sentDateTime,body,internetMessageHeaders,hasAttachments`,
    }));

    const response = await fetch(`${GRAPH_API_URL}/$batch`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ requests }),
    });

    if (!response.ok) {
      throw new Error(`Batch request failed: ${response.status}`);
    }

    const data = await response.json();
    const emails: O365EmailContent[] = [];

    for (const res of data.responses) {
      if (res.status === 200) {
        emails.push(this.parseGraphMessage(res.body));
      }
    }

    return emails;
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
  analyzeEmailSignals(email: O365EmailContent): EmailSignal[] {
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
   * Parse Graph API message format to O365EmailContent
   */
  private parseGraphMessage(message: Record<string, unknown>): O365EmailContent {
    const from = message.from as { emailAddress: { address: string; name?: string } } | undefined;
    const toRecipients = message.toRecipients as Array<{ emailAddress: { address: string; name?: string } }> || [];
    const ccRecipients = message.ccRecipients as Array<{ emailAddress: { address: string; name?: string } }> || [];
    const headers = message.internetMessageHeaders as Array<{ name: string; value: string }> || [];
    const body = message.body as { contentType: string; content: string } | undefined;

    return {
      messageId: message.id as string,
      internetMessageId: message.internetMessageId as string || '',
      from: {
        address: from?.emailAddress?.address || '',
        name: from?.emailAddress?.name,
      },
      to: toRecipients.map(r => ({
        address: r.emailAddress?.address || '',
        name: r.emailAddress?.name,
      })),
      cc: ccRecipients.map(r => ({
        address: r.emailAddress?.address || '',
        name: r.emailAddress?.name,
      })),
      subject: message.subject as string || '',
      receivedAt: new Date(message.receivedDateTime as string || Date.now()),
      sentAt: message.sentDateTime ? new Date(message.sentDateTime as string) : undefined,
      headers,
      body: {
        html: body?.contentType === 'html' ? body.content || '' : '',
        text: body?.contentType === 'text' ? body.content || '' : '',
      },
      attachments: [],
    };
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
