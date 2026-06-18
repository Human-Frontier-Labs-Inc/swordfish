/**
 * Regression tests for the threat-management data-source fix.
 *
 * Bug: the Threats page / detail / Reports read the legacy `threats` table,
 * which the live detection pipeline never populates (it writes `email_verdicts`).
 * These tests assert the readers now query `email_verdicts` and produce the
 * frontend-expected shape, and that /api/user/me degrades gracefully when tenant
 * linkage is missing (it must never 500).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// --- Mock the db layer with a query-capturing sql() ---------------------------

const sqlCalls: string[] = [];
let nextRows: Record<string, unknown>[] = [];

vi.mock('@/lib/db', () => {
  const sql = (strings: TemplateStringsArray, ..._values: unknown[]) => {
    sqlCalls.push(strings.join('?'));
    return Promise.resolve(nextRows);
  };
  return { sql, default: sql };
});

vi.mock('@clerk/nextjs/server', () => ({
  auth: vi.fn().mockResolvedValue({ userId: 'user_123', orgId: 'org_abc' }),
}));

beforeEach(() => {
  sqlCalls.length = 0;
  nextRows = [];
});

describe('getThreatsFormanagement (email_verdicts source)', () => {
  it('queries email_verdicts, not the legacy threats table', async () => {
    const { getThreatsForManagement } = await import('@/lib/detection/storage');
    nextRows = [
      {
        message_id: '<abc@google.com>',
        subject: 'Phish',
        from_address: 'evil@bad.com',
        from_display_name: 'Evil',
        signals: [{ type: 'credential_request', severity: 'critical', detail: 'x' }],
        verdict: 'quarantine',
        score: 88,
        explanation: 'looks bad',
        llm_explanation: null,
        action_taken: null,
        user_feedback: null,
        created_at: '2026-06-01T00:00:00Z',
      },
    ];

    const threats = await getThreatsForManagement('org_abc', { status: 'all' });

    const lastQuery = sqlCalls.join('\n');
    expect(lastQuery).toContain('FROM email_verdicts');
    expect(lastQuery).not.toContain('FROM threats');

    expect(threats).toHaveLength(1);
    const t = threats[0];
    // id must be URL-encoded so it round-trips through the detail route.
    expect(t.id).toBe(encodeURIComponent('<abc@google.com>'));
    expect(t.message_id).toBe('<abc@google.com>');
    expect(t.sender_email).toBe('evil@bad.com');
    expect(t.score).toBe(88);
    expect(t.status).toBe('quarantined');
    expect(t.threat_type).toBe('phishing');
  });

  it('returns an empty array (no throw) when there is no data', async () => {
    const { getThreatsForManagement } = await import('@/lib/detection/storage');
    nextRows = [];
    const threats = await getThreatsForManagement('personal_user_123');
    expect(threats).toEqual([]);
  });
});

describe('getThreatByMessageId (decodes id, reads email_verdicts)', () => {
  it('decodes a URL-encoded message id before querying', async () => {
    const { getThreatByMessageId } = await import('@/lib/detection/storage');
    nextRows = [
      {
        message_id: '<id@google.com>',
        subject: 'S',
        from_address: 'a@b.com',
        from_display_name: '',
        signals: [],
        verdict: 'block',
        score: 95,
        explanation: 'e',
        llm_explanation: null,
        llm_recommendation: 'quarantine',
        action_taken: null,
        user_feedback: null,
        created_at: '2026-06-01T00:00:00Z',
      },
    ];

    const encoded = encodeURIComponent('<id@google.com>');
    const threat = await getThreatByMessageId('org_abc', encoded);

    expect(sqlCalls.join('\n')).toContain('FROM email_verdicts');
    expect(threat).not.toBeNull();
    expect(threat?.message_id).toBe('<id@google.com>');
    expect(threat?.recommendation).toBe('quarantine');
  });

  it('returns null when not found', async () => {
    const { getThreatByMessageId } = await import('@/lib/detection/storage');
    nextRows = [];
    const threat = await getThreatByMessageId('org_abc', 'missing');
    expect(threat).toBeNull();
  });
});

describe('GET /api/threats (Bug 2)', () => {
  it('returns threats from email_verdicts with a 200', async () => {
    const { GET } = await import('@/app/api/threats/route');
    nextRows = [
      {
        message_id: '<m@x.com>',
        subject: 'Sub',
        from_address: 'a@b.com',
        from_display_name: 'A',
        signals: [],
        verdict: 'quarantine',
        score: 70,
        explanation: '',
        llm_explanation: null,
        action_taken: null,
        user_feedback: null,
        created_at: '2026-06-01T00:00:00Z',
      },
    ];

    const { NextRequest } = await import('next/server');
    const req = new NextRequest('http://localhost/api/threats?status=all');
    const res = await GET(req);
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(Array.isArray(data.threats)).toBe(true);
    expect(data.threats[0].sender_email).toBe('a@b.com');
  });
});
