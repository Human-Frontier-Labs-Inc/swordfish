/**
 * Email parser - normalizes emails from various sources into ParsedEmail format
 */

import type { ParsedEmail, EmailAddress, Attachment, AuthenticationResults, AuthResult } from './types';

/**
 * Parse raw email content (MIME format) into structured ParsedEmail
 */
export function parseEmail(rawEmail: string): ParsedEmail {
  const lines = rawEmail.split(/\r?\n/);
  const headers: Record<string, string> = {};
  let headerEndIndex = 0;

  // Parse headers
  let currentHeader = '';
  let currentValue = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Empty line marks end of headers
    if (line === '') {
      if (currentHeader) {
        headers[currentHeader.toLowerCase()] = currentValue.trim();
      }
      headerEndIndex = i + 1;
      break;
    }

    // Continuation of previous header (starts with whitespace)
    if (/^\s/.test(line)) {
      currentValue += ' ' + line.trim();
      continue;
    }

    // New header
    if (currentHeader) {
      headers[currentHeader.toLowerCase()] = currentValue.trim();
    }

    const colonIndex = line.indexOf(':');
    if (colonIndex > 0) {
      currentHeader = line.substring(0, colonIndex);
      currentValue = line.substring(colonIndex + 1).trim();
    }
  }

  // Parse body
  const bodyContent = lines.slice(headerEndIndex).join('\n');

  // Parse MIME multipart content (including attachments)
  const { body, attachments } = parseMimeContent(bodyContent, headers['content-type']);

  return {
    messageId: headers['message-id'] || generateMessageId(),
    subject: decodeHeader(headers['subject'] || ''),
    from: parseEmailAddress(headers['from'] || ''),
    replyTo: headers['reply-to'] ? parseEmailAddress(headers['reply-to']) : undefined,
    to: parseEmailAddressList(headers['to'] || ''),
    cc: headers['cc'] ? parseEmailAddressList(headers['cc']) : undefined,
    date: parseDate(headers['date']),
    headers,
    body,
    attachments,
    rawHeaders: lines.slice(0, headerEndIndex).join('\n'),
  };
}

/**
 * Parse email from Microsoft Graph API format
 */
export function parseGraphEmail(graphMessage: Record<string, unknown>): ParsedEmail {
  const from = graphMessage.from as { emailAddress: { address: string; name?: string } } | undefined;
  const toRecipients = (graphMessage.toRecipients || []) as Array<{ emailAddress: { address: string; name?: string } }>;

  return {
    messageId: (graphMessage.internetMessageId as string) || (graphMessage.id as string) || generateMessageId(),
    subject: (graphMessage.subject as string) || '',
    from: from ? {
      address: from.emailAddress.address,
      displayName: from.emailAddress.name,
      domain: extractDomain(from.emailAddress.address),
    } : { address: '', domain: '' },
    to: toRecipients.map(r => ({
      address: r.emailAddress.address,
      displayName: r.emailAddress.name,
      domain: extractDomain(r.emailAddress.address),
    })),
    date: new Date((graphMessage.receivedDateTime as string) || Date.now()),
    headers: (graphMessage.internetMessageHeaders as Record<string, string>) || {},
    body: {
      text: (graphMessage.body as { content?: string })?.content,
      html: (graphMessage.body as { contentType?: string })?.contentType === 'html'
        ? (graphMessage.body as { content?: string })?.content
        : undefined,
    },
    attachments: parseGraphAttachments(graphMessage.attachments as unknown[]),
    rawHeaders: '',
  };
}

/**
 * Parse email from Gmail API format
 */
export function parseGmailEmail(gmailMessage: Record<string, unknown>): ParsedEmail {
  const payload = gmailMessage.payload as Record<string, unknown> | undefined;
  const headers = ((payload?.headers || []) as Array<{ name: string; value: string }>)
    .reduce((acc, h) => ({ ...acc, [h.name.toLowerCase()]: h.value }), {} as Record<string, string>);

  return {
    messageId: headers['message-id'] || (gmailMessage.id as string) || generateMessageId(),
    subject: headers['subject'] || '',
    from: parseEmailAddress(headers['from'] || ''),
    replyTo: headers['reply-to'] ? parseEmailAddress(headers['reply-to']) : undefined,
    to: parseEmailAddressList(headers['to'] || ''),
    cc: headers['cc'] ? parseEmailAddressList(headers['cc']) : undefined,
    date: new Date(parseInt(gmailMessage.internalDate as string) || Date.now()),
    headers,
    body: parseGmailBody(payload),
    attachments: parseGmailAttachments(payload),
    rawHeaders: '',
  };
}

/**
 * Parse Authentication-Results header
 */
export function parseAuthenticationResults(header: string): AuthenticationResults {
  const results: AuthenticationResults = {
    spf: { result: 'none' },
    dkim: { result: 'none' },
    dmarc: { result: 'none' },
  };

  if (!header) return results;

  // Parse SPF
  const spfMatch = header.match(/spf=(\w+)/i);
  if (spfMatch) {
    results.spf = { result: normalizeAuthResult(spfMatch[1]) };
  }

  // Parse DKIM
  const dkimMatch = header.match(/dkim=(\w+)/i);
  if (dkimMatch) {
    results.dkim = { result: normalizeAuthResult(dkimMatch[1]) };
  }

  // Parse DMARC
  const dmarcMatch = header.match(/dmarc=(\w+)/i);
  if (dmarcMatch) {
    results.dmarc = { result: normalizeAuthResult(dmarcMatch[1]) };
  }

  return results;
}

// Helper functions

function parseEmailAddress(raw: string): EmailAddress {
  const trimmed = raw.trim();

  // Format 1: "Display Name" <email@domain.com>
  const quotedMatch = trimmed.match(/^"([^"]+)"\s*<([^<>\s]+@[^<>\s]+)>$/);
  if (quotedMatch) {
    const address = quotedMatch[2].toLowerCase();
    return {
      address,
      displayName: quotedMatch[1].trim(),
      domain: extractDomain(address),
    };
  }

  // Format 2: Display Name <email@domain.com>
  const angleMatch = trimmed.match(/^([^<]+)<([^<>\s]+@[^<>\s]+)>$/);
  if (angleMatch) {
    const address = angleMatch[2].toLowerCase();
    return {
      address,
      displayName: angleMatch[1].trim(),
      domain: extractDomain(address),
    };
  }

  // Format 3: <email@domain.com>
  const bracketOnlyMatch = trimmed.match(/^<([^<>\s]+@[^<>\s]+)>$/);
  if (bracketOnlyMatch) {
    const address = bracketOnlyMatch[1].toLowerCase();
    return {
      address,
      domain: extractDomain(address),
    };
  }

  // Format 4: Simple email@domain.com
  const simpleMatch = trimmed.match(/^([^\s@]+@[^\s@]+)$/);
  if (simpleMatch) {
    const address = simpleMatch[1].toLowerCase();
    return {
      address,
      domain: extractDomain(address),
    };
  }

  // Fallback - try to extract any email-like pattern
  const emailMatch = trimmed.match(/([^\s<>@]+@[^\s<>@]+)/);
  if (emailMatch) {
    const address = emailMatch[1].toLowerCase();
    return {
      address,
      domain: extractDomain(address),
    };
  }

  // Last resort fallback
  const address = trimmed.toLowerCase();
  return {
    address,
    domain: extractDomain(address),
  };
}

function parseEmailAddressList(raw: string): EmailAddress[] {
  if (!raw) return [];
  return raw.split(',').map(addr => parseEmailAddress(addr.trim()));
}

function extractDomain(email: string): string {
  const parts = email.split('@');
  return parts.length > 1 ? parts[1].toLowerCase() : '';
}

function parseDate(dateStr: string | undefined): Date {
  if (!dateStr) return new Date();
  const parsed = new Date(dateStr);
  return isNaN(parsed.getTime()) ? new Date() : parsed;
}

function decodeHeader(header: string): string {
  // Handle encoded headers (=?UTF-8?Q?...?= or =?UTF-8?B?...?=)
  return header.replace(/=\?([^?]+)\?([BQ])\?([^?]+)\?=/gi, (_, charset, encoding, text) => {
    try {
      if (encoding.toUpperCase() === 'B') {
        return Buffer.from(text, 'base64').toString('utf-8');
      } else {
        return text.replace(/_/g, ' ').replace(/=([0-9A-F]{2})/gi, (_: string, hex: string) =>
          String.fromCharCode(parseInt(hex, 16))
        );
      }
    } catch {
      return text;
    }
  });
}

function parseBody(content: string, contentType?: string): { text?: string; html?: string } {
  const isHtml = contentType?.toLowerCase().includes('text/html');
  return isHtml ? { html: content } : { text: content };
}

/**
 * Parse MIME multipart content to extract body and attachments
 */
function parseMimeContent(
  content: string,
  contentType?: string
): { body: { text?: string; html?: string }; attachments: Attachment[] } {
  const attachments: Attachment[] = [];
  let text: string | undefined;
  let html: string | undefined;

  // Check if this is multipart content
  if (!contentType?.toLowerCase().includes('multipart/')) {
    // Not multipart - simple body
    return {
      body: parseBody(content, contentType),
      attachments: [],
    };
  }

  // Extract boundary from content-type
  const boundaryMatch = contentType.match(/boundary=["']?([^"'\s;]+)["']?/i);
  if (!boundaryMatch) {
    return {
      body: parseBody(content, contentType),
      attachments: [],
    };
  }

  const boundary = boundaryMatch[1];
  const parts = splitMimeParts(content, boundary);

  for (const partContent of parts) {
    const parsed = parseMimePart(partContent);
    if (!parsed) continue;

    const { partHeaders, partBody, isAttachment, filename, mimeType, encoding } = parsed;

    if (isAttachment && filename) {
      // This is an attachment
      const decodedContent = decodePartContent(partBody, encoding);
      attachments.push({
        filename: decodeHeader(filename),
        contentType: mimeType || 'application/octet-stream',
        size: decodedContent.length,
        content: decodedContent,
      });
    } else if (mimeType?.includes('multipart/')) {
      // Nested multipart - recursively parse
      const nested = parseMimeContent(partBody, partHeaders['content-type']);
      if (nested.body.text && !text) text = nested.body.text;
      if (nested.body.html && !html) html = nested.body.html;
      attachments.push(...nested.attachments);
    } else if (mimeType?.includes('text/plain') && !text) {
      text = decodePartContent(partBody, encoding).toString('utf-8');
    } else if (mimeType?.includes('text/html') && !html) {
      html = decodePartContent(partBody, encoding).toString('utf-8');
    }
  }

  return { body: { text, html }, attachments };
}

/**
 * Split MIME content by boundary
 */
function splitMimeParts(content: string, boundary: string): string[] {
  const parts: string[] = [];
  const delimiter = `--${boundary}`;
  const endDelimiter = `--${boundary}--`;

  // Split by boundary
  const segments = content.split(delimiter);

  for (let i = 1; i < segments.length; i++) {
    let part = segments[i];

    // Skip the ending delimiter segment
    if (part.trim().startsWith('--') || part.trim() === '') {
      continue;
    }

    // Remove trailing delimiter markers
    const endIndex = part.indexOf(endDelimiter);
    if (endIndex !== -1) {
      part = part.substring(0, endIndex);
    }

    // Remove leading newlines
    part = part.replace(/^[\r\n]+/, '');

    if (part.trim()) {
      parts.push(part);
    }
  }

  return parts;
}

/**
 * Parse a single MIME part
 */
function parseMimePart(partContent: string): {
  partHeaders: Record<string, string>;
  partBody: string;
  isAttachment: boolean;
  filename?: string;
  mimeType?: string;
  encoding?: string;
} | null {
  const lines = partContent.split(/\r?\n/);
  const partHeaders: Record<string, string> = {};
  let headerEndIndex = 0;

  // Parse part headers
  let currentHeader = '';
  let currentValue = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line === '') {
      if (currentHeader) {
        partHeaders[currentHeader.toLowerCase()] = currentValue.trim();
      }
      headerEndIndex = i + 1;
      break;
    }

    if (/^\s/.test(line)) {
      currentValue += ' ' + line.trim();
      continue;
    }

    if (currentHeader) {
      partHeaders[currentHeader.toLowerCase()] = currentValue.trim();
    }

    const colonIndex = line.indexOf(':');
    if (colonIndex > 0) {
      currentHeader = line.substring(0, colonIndex);
      currentValue = line.substring(colonIndex + 1).trim();
    }
  }

  const partBody = lines.slice(headerEndIndex).join('\n');
  const contentType = partHeaders['content-type'] || '';
  const contentDisposition = partHeaders['content-disposition'] || '';
  const encoding = partHeaders['content-transfer-encoding'] || '';

  // Check if this is an attachment
  const isAttachment =
    contentDisposition.toLowerCase().includes('attachment') ||
    contentDisposition.toLowerCase().includes('inline');

  // Extract filename
  let filename: string | undefined;
  const filenameMatch =
    contentDisposition.match(/filename\*?=["']?(?:utf-8'')?([^"';\s]+)["']?/i) ||
    contentType.match(/name=["']?([^"';\s]+)["']?/i);
  if (filenameMatch) {
    filename = decodeURIComponent(filenameMatch[1]);
  }

  // Extract MIME type
  const mimeTypeMatch = contentType.match(/^([^;\s]+)/);
  const mimeType = mimeTypeMatch ? mimeTypeMatch[1].toLowerCase() : undefined;

  return {
    partHeaders,
    partBody,
    isAttachment: isAttachment || !!filename,
    filename,
    mimeType,
    encoding: encoding.toLowerCase(),
  };
}

/**
 * Decode MIME part content based on encoding
 */
function decodePartContent(content: string, encoding?: string): Buffer {
  if (!encoding || encoding === '7bit' || encoding === '8bit') {
    return Buffer.from(content, 'utf-8');
  }

  if (encoding === 'base64') {
    // Remove whitespace from base64 content
    const cleaned = content.replace(/[\r\n\s]/g, '');
    try {
      return Buffer.from(cleaned, 'base64');
    } catch {
      return Buffer.from(content, 'utf-8');
    }
  }

  if (encoding === 'quoted-printable') {
    return decodeQuotedPrintable(content);
  }

  return Buffer.from(content, 'utf-8');
}

/**
 * Decode quoted-printable encoded content
 */
function decodeQuotedPrintable(content: string): Buffer {
  const decoded = content
    // Handle soft line breaks
    .replace(/=\r?\n/g, '')
    // Decode hex sequences
    .replace(/=([0-9A-F]{2})/gi, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );
  return Buffer.from(decoded, 'utf-8');
}

function parseGraphAttachments(attachments: unknown[] | undefined): Attachment[] {
  if (!attachments) return [];
  return attachments.map((att: unknown) => {
    const a = att as Record<string, unknown>;
    return {
      filename: (a.name as string) || 'unknown',
      contentType: (a.contentType as string) || 'application/octet-stream',
      size: (a.size as number) || 0,
    };
  });
}

function parseGmailBody(payload: Record<string, unknown> | undefined): { text?: string; html?: string } {
  if (!payload) return {};

  const parts = payload.parts as Array<Record<string, unknown>> | undefined;
  if (parts) {
    let text: string | undefined;
    let html: string | undefined;

    for (const part of parts) {
      const mimeType = part.mimeType as string;
      const body = part.body as { data?: string } | undefined;
      if (body?.data) {
        const decoded = Buffer.from(body.data, 'base64').toString('utf-8');
        if (mimeType === 'text/plain') text = decoded;
        if (mimeType === 'text/html') html = decoded;
      }
    }
    return { text, html };
  }

  const body = payload.body as { data?: string } | undefined;
  if (body?.data) {
    const decoded = Buffer.from(body.data, 'base64').toString('utf-8');
    const mimeType = payload.mimeType as string;
    return mimeType === 'text/html' ? { html: decoded } : { text: decoded };
  }

  return {};
}

function parseGmailAttachments(payload: Record<string, unknown> | undefined): Attachment[] {
  if (!payload) return [];

  const parts = payload.parts as Array<Record<string, unknown>> | undefined;
  if (!parts) return [];

  return parts
    .filter(part => part.filename && (part.filename as string).length > 0)
    .map(part => ({
      filename: part.filename as string,
      contentType: (part.mimeType as string) || 'application/octet-stream',
      size: (part.body as { size?: number })?.size || 0,
    }));
}

function normalizeAuthResult(result: string): AuthResult['result'] {
  const normalized = result.toLowerCase();
  const validResults: AuthResult['result'][] = ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'];
  return validResults.includes(normalized as AuthResult['result'])
    ? (normalized as AuthResult['result'])
    : 'none';
}

function generateMessageId(): string {
  return `<${Date.now()}.${Math.random().toString(36).substring(2)}@swordfish.local>`;
}
