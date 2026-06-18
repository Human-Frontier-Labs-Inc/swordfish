/**
 * /api/analyze persistence + remediation tests — P0-15
 *
 * Verifies the route now persists every verdict and, for quarantine/block
 * verdicts, enqueues mailbox remediation via autoRemediate (the same path the
 * provider webhooks use). Previously these were TODO comments.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';

vi.mock('@clerk/nextjs/server', () => ({
  auth: vi.fn(),
}));

vi.mock('@/lib/api/rate-limit', () => ({
  rateLimit: vi.fn().mockReturnValue({ success: true, remaining: 9 }),
}));

vi.mock('@/lib/detection/pipeline', () => ({
  analyzeEmail: vi.fn(),
  quickCheck: vi.fn(),
}));

vi.mock('@/lib/detection/storage', () => ({
  storeVerdict: vi.fn().mockResolvedValue('verdict-id'),
}));

vi.mock('@/lib/workers/remediation', () => ({
  autoRemediate: vi.fn().mockResolvedValue({ success: true }),
}));

// Programmable integrations lookup
let connectedIntegration: { id: string; type: string } | null = { id: 'integ-1', type: 'o365' };
vi.mock('@/lib/db', () => {
  const sql = (strings: TemplateStringsArray) => {
    const q = strings.join(' ').replace(/\s+/g, ' ');
    if (q.includes('FROM integrations')) {
      return Promise.resolve(connectedIntegration ? [connectedIntegration] : []);
    }
    return Promise.resolve([]);
  };
  return { sql, default: sql };
});

import { auth } from '@clerk/nextjs/server';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import { autoRemediate } from '@/lib/workers/remediation';
import { POST } from '@/app/api/analyze/route';

const authMock = auth as unknown as ReturnType<typeof vi.fn>;
const analyzeMock = analyzeEmail as unknown as ReturnType<typeof vi.fn>;
const storeVerdictMock = storeVerdict as unknown as ReturnType<typeof vi.fn>;
const autoRemediateMock = autoRemediate as unknown as ReturnType<typeof vi.fn>;

const parsedEmail = {
  messageId: 'msg-abc',
  subject: 'Test',
  from: { address: 'a@b.com', domain: 'b.com' },
  to: [{ address: 'c@d.com', domain: 'd.com' }],
  date: new Date(),
  headers: {},
  body: { text: 'hi' },
  attachments: [],
  rawHeaders: '',
};

function baseVerdict(overrides: Record<string, unknown>) {
  return {
    messageId: 'msg-abc',
    tenantId: 'org_123',
    verdict: 'pass',
    overallScore: 10,
    confidence: 0.9,
    signals: [],
    layerResults: [],
    processingTimeMs: 100,
    analyzedAt: new Date(),
    ...overrides,
  };
}

function makeRequest() {
  return new NextRequest('http://localhost/api/analyze', {
    method: 'POST',
    body: JSON.stringify({ parsed: parsedEmail }),
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('/api/analyze persistence + remediation (P0-15)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    connectedIntegration = { id: 'integ-1', type: 'o365' };
    authMock.mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
  });

  it('persists every verdict via storeVerdict', async () => {
    analyzeMock.mockResolvedValue(baseVerdict({ verdict: 'pass' }));
    const res = await POST(makeRequest());
    expect(res.status).toBe(200);
    expect(storeVerdictMock).toHaveBeenCalledTimes(1);
    expect(storeVerdictMock).toHaveBeenCalledWith('org_123', 'msg-abc', expect.any(Object), expect.any(Object));
  });

  it('does NOT remediate a pass verdict', async () => {
    analyzeMock.mockResolvedValue(baseVerdict({ verdict: 'pass' }));
    await POST(makeRequest());
    expect(autoRemediateMock).not.toHaveBeenCalled();
  });

  it('enqueues remediation for a quarantine verdict with a connected integration', async () => {
    analyzeMock.mockResolvedValue(baseVerdict({ verdict: 'quarantine', overallScore: 75 }));
    const res = await POST(makeRequest());
    expect(res.status).toBe(200);
    expect(autoRemediateMock).toHaveBeenCalledTimes(1);
    expect(autoRemediateMock).toHaveBeenCalledWith(
      expect.objectContaining({
        tenantId: 'org_123',
        integrationId: 'integ-1',
        integrationType: 'o365',
        verdict: 'quarantine',
        score: 75,
      })
    );
  });

  it('enqueues remediation for a block verdict', async () => {
    analyzeMock.mockResolvedValue(baseVerdict({ verdict: 'block', overallScore: 95 }));
    await POST(makeRequest());
    expect(autoRemediateMock).toHaveBeenCalledWith(
      expect.objectContaining({ verdict: 'block', score: 95 })
    );
  });

  it('no-ops remediation when the tenant has no connected mailbox', async () => {
    connectedIntegration = null; // no integration rows
    analyzeMock.mockResolvedValue(baseVerdict({ verdict: 'quarantine', overallScore: 75 }));
    const res = await POST(makeRequest());
    expect(res.status).toBe(200); // still returns the verdict
    expect(storeVerdictMock).toHaveBeenCalled();
    expect(autoRemediateMock).not.toHaveBeenCalled();
  });

  it('still returns the verdict if persistence throws', async () => {
    storeVerdictMock.mockRejectedValueOnce(new Error('db down'));
    analyzeMock.mockResolvedValue(baseVerdict({ verdict: 'pass' }));
    const res = await POST(makeRequest());
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.verdict).toBe('pass');
  });
});
