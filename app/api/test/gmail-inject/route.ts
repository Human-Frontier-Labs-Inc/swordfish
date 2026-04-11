/**
 * Test Gmail Injection API
 * Inserts test emails directly into the Gmail inbox using the stored OAuth token.
 * Emails appear as if they arrived from external senders.
 * Then triggers a sync so the detection pipeline processes them.
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getAccessToken } from '@/lib/oauth/token-manager';

interface TestGmailEmail {
  from: string;
  fromName?: string;
  subject: string;
  bodyText: string;
  bodyHtml?: string;
  headers?: Record<string, string>;
}

function buildMimeMessage(email: TestGmailEmail, to: string): string {
  const boundary = `boundary_${Date.now()}`;
  const fromHeader = email.fromName
    ? `${email.fromName} <${email.from}>`
    : email.from;

  const authResults = email.headers?.['authentication-results'] || 'spf=none; dkim=none; dmarc=none';

  const parts = [
    `From: ${fromHeader}`,
    `To: ${to}`,
    `Subject: ${email.subject}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <test-${Date.now()}-${Math.random().toString(36).slice(2)}@${email.from.split('@')[1]}>`,
    `MIME-Version: 1.0`,
    `Authentication-Results: ${authResults}`,
    // Add any extra headers
    ...Object.entries(email.headers || {})
      .filter(([k]) => k !== 'authentication-results')
      .map(([k, v]) => `${k}: ${v}`),
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset="UTF-8"',
    '',
    email.bodyText,
    `--${boundary}`,
    'Content-Type: text/html; charset="UTF-8"',
    '',
    email.bodyHtml || `<p>${email.bodyText.replace(/\n/g, '<br>')}</p>`,
    `--${boundary}--`,
  ];

  return parts.join('\r\n');
}

export async function GET() {
  const { userId, orgId } = await auth();
  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  const tenantId = orgId || `personal_${userId}`;

  try {
    const accessToken = await getAccessToken(tenantId, 'gmail');

    // List recent inbox messages
    const listRes = await fetch(
      'https://gmail.googleapis.com/gmail/v1/users/me/messages?labelIds=INBOX&maxResults=10',
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    const listData = await listRes.json();

    // Get subject + labels for each
    const messages = [];
    for (const msg of (listData.messages || []).slice(0, 10)) {
      const detail = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}?format=metadata&metadataHeaders=Subject&metadataHeaders=From`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      ).then(r => r.json());

      const subject = detail.payload?.headers?.find((h: Record<string, string>) => h.name === 'Subject')?.value || '(no subject)';
      const from = detail.payload?.headers?.find((h: Record<string, string>) => h.name === 'From')?.value || '(unknown)';

      messages.push({
        id: msg.id,
        subject,
        from,
        labels: detail.labelIds,
        internalDate: new Date(parseInt(detail.internalDate)).toISOString(),
      });
    }

    return NextResponse.json({ count: listData.resultSizeEstimate, messages });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  const { userId, orgId } = await auth();
  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const tenantId = orgId || `personal_${userId}`;

  try {
    const body = await request.json();
    const { emails } = body as { emails: TestGmailEmail[] };

    if (!emails?.length) {
      return NextResponse.json({ error: 'Provide an array of emails' }, { status: 400 });
    }

    // Get the Gmail access token
    const accessToken = await getAccessToken(tenantId, 'gmail');

    // Get the connected email address
    const profile = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/profile', {
      headers: { Authorization: `Bearer ${accessToken}` },
    }).then(r => r.json());

    const toAddress = profile.emailAddress;
    const results = [];

    for (const email of emails) {
      const mime = buildMimeMessage(email, toAddress);
      // Base64url encode the MIME message
      const encoded = Buffer.from(mime)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');

      // Insert into Gmail inbox (not send — insert makes it appear as received)
      const response = await fetch(
        'https://gmail.googleapis.com/gmail/v1/users/me/messages/import?internalDateSource=dateHeader',
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            raw: encoded,
            labelIds: ['INBOX', 'UNREAD'],
          }),
        }
      );

      const result = await response.json();

      if (!response.ok) {
        results.push({ subject: email.subject, error: result.error?.message || 'Failed', status: response.status });
      } else {
        results.push({ subject: email.subject, gmailId: result.id, threadId: result.threadId });
      }
    }

    return NextResponse.json({ success: true, to: toAddress, results });
  } catch (error) {
    console.error('Gmail inject error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
