/**
 * Test Email Injection API
 * Injects test emails into the detection pipeline for QA purposes.
 * Only available in development/testing environments.
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import type { ParsedEmail, EmailAddress } from '@/lib/detection/types';

export async function POST(request: NextRequest) {
  // Auth required
  const { userId, orgId } = await auth();
  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const tenantId = orgId || `personal_${userId}`;

  try {
    const body = await request.json();
    const { emails } = body as { emails: TestEmail[] };

    if (!emails || !Array.isArray(emails) || emails.length === 0) {
      return NextResponse.json({ error: 'Provide an array of emails' }, { status: 400 });
    }

    const results = [];

    for (const email of emails) {
      const parseAddr = (addr: string, name?: string): EmailAddress => {
        const domain = addr.split('@')[1] || 'unknown';
        return { address: addr, displayName: name, domain };
      };

      const parsed: ParsedEmail = {
        messageId: email.messageId || `test-${Date.now()}-${Math.random().toString(36).slice(2)}@test.local`,
        subject: email.subject,
        from: parseAddr(email.fromAddress, email.fromName),
        to: [parseAddr(email.to)],
        date: new Date(email.date || Date.now()),
        headers: email.headers || {},
        body: {
          text: email.bodyText || '',
          html: email.bodyHtml || '',
        },
        attachments: (email.attachments || []).map(a => ({
          filename: a.filename,
          contentType: a.contentType,
          size: a.size || 0,
        })),
        rawHeaders: Object.entries(email.headers || {})
          .map(([k, v]) => `${k}: ${v}`)
          .join('\r\n'),
      };

      // Run full detection pipeline
      const verdict = await analyzeEmail(parsed, tenantId, {
        skipLLM: email.skipLLM ?? true,
      });

      // Store in database so it appears in the UI
      await storeVerdict(tenantId, parsed.messageId, verdict, parsed);

      results.push({
        messageId: parsed.messageId,
        subject: parsed.subject,
        from: parsed.from.address,
        verdict: verdict.verdict,
        score: verdict.overallScore,
        signals: verdict.signals.length,
      });
    }

    return NextResponse.json({ success: true, results });
  } catch (error) {
    console.error('Test email injection error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

interface TestEmail {
  messageId?: string;
  subject: string;
  fromAddress: string;
  fromName?: string;
  to: string;
  date?: string;
  bodyText?: string;
  bodyHtml?: string;
  headers?: Record<string, string>;
  attachments?: Array<{
    filename: string;
    contentType: string;
    size?: number;
  }>;
  skipLLM?: boolean;
}
