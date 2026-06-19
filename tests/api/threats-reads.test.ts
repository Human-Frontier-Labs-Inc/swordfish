/**
 * Route-level coverage for the repointed threats read endpoints ([id], search,
 * feed). The list route is covered by threats-data-source.test.ts.
 *
 * These endpoints were repointed off the legacy `threats` table onto
 * `email_verdicts` (commits 7e35c70 / 9cc2baa / 084dde9, merged as 04cc8ce) and
 * had no route tests, so a regression would be invisible. This file mocks
 * `@/lib/db` and asserts what a mock CAN honestly prove:
 *   - the routes query email_verdicts (not the legacy threats table);
 *   - response shape + that the id is URL-encoded (round-trips through [id]);
 *   - status/threat_type are JS-derived (via mapVerdictRowToThreat) for [id] +
 *     feed's threat list, for rows exercising different derivation branches;
 *   - search filters produce the right WHERE fragments AND bound params (query
 *     construction), and the deprecated integration_type filter is dropped;
 *   - pagination/count + feed-stats shape.
 *
 * What this CANNOT prove (the SQL CASE never executes under a mock): that the
 * raw CASE in search/feed-stats computes the same values as the JS derivation.
 * That parity is covered by threats-case-parity.integration.test.ts (DB-gated).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';

interface CapturedCall {
  query: string;
  params: unknown[];
}

// vi.hoisted so the capture storage exists before the vi.mock factory runs.
const harness = vi.hoisted(() => {
  const queryCalls: CapturedCall[] = [];
  // Rows the mock returns. Either a flat array (every query) or a router over
  // the query text so count / list / facet / stats queries can differ.
  let rowsProvider:
    | Record<string, unknown>[]
    | ((text: string) => Record<string, unknown>[]) = [];
  const resolveRows = (text: string): Record<string, unknown>[] =>
    typeof rowsProvider === 'function' ? rowsProvider(text) : rowsProvider;
  return {
    queryCalls,
    setRows: (r: typeof rowsProvider) => {
      rowsProvider = r;
    },
    resolveRows,
  };
});

vi.mock('@clerk/nextjs/server', () => ({
  auth: vi.fn().mockResolvedValue({ userId: 'user_123', orgId: 'org_abc' }),
}));

vi.mock('@/lib/db', () => {
  const dispatch = (text: string, params: unknown[]) => {
    harness.queryCalls.push({ query: text, params });
    return harness.resolveRows(text);
  };
  // sql is callable three ways:
  //   tagged template: sql`SELECT ...`           (strings = TemplateStringsArray)
  //   array form:      sql([text, ...params])    (used by search + feed-stats)
  //   sql.transaction([...]) over the array form (returns array of row arrays)
  const sql = (stringsOrArr: unknown, ...values: unknown[]) => {
    if (Array.isArray(stringsOrArr)) {
      return Promise.resolve(
        dispatch(stringsOrArr[0] as string, stringsOrArr.slice(1))
      );
    }
    return Promise.resolve(
      dispatch((stringsOrArr as TemplateStringsArray).join('?'), values)
    );
  };
  (sql as unknown as { transaction: (q: Promise<unknown>[]) => Promise<unknown[]> }).transaction = (
    queries: Promise<unknown>[]
  ) => Promise.all(queries);
  return { sql, default: sql };
});

import { GET as searchGet, POST as searchPost } from '@/app/api/threats/search/route';
import { GET as feedGet } from '@/app/api/threats/feed/route';

function req(url: string, init?: RequestInit): NextRequest {
  return new NextRequest(new URL(url, 'http://localhost'), init);
}

function allSql(): string {
  return harness.queryCalls.map((c) => c.query).join('\n');
}

function allParams(): unknown[] {
  return harness.queryCalls.flatMap((c) => c.params);
}

/**
 * A verdict row. Defaults exercise deriveThreatStatus -> 'quarantined' and
 * deriveThreatType -> 'phishing' (credential_request signal, quarantine verdict).
 */
function verdictRow(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    message_id: '<phish@google.com>',
    subject: 'Reset your password',
    from_address: 'evil@bad.com',
    from_display_name: 'Evil Corp',
    signals: [{ type: 'credential_request', severity: 'critical', detail: 'login form' }],
    verdict: 'quarantine',
    score: 88,
    explanation: 'credential phishing',
    llm_explanation: null,
    action_taken: null,
    user_feedback: null,
    created_at: '2026-06-01T00:00:00Z',
    ...overrides,
  };
}

beforeEach(() => {
  harness.queryCalls.length = 0;
  harness.setRows([]);
});

describe('GET /api/threats/[id] (email_verdicts source)', () => {
  // [id] lives under a bracketed segment; resolve it dynamically.
  async function detail(id: string) {
    const mod = await import('@/app/api/threats/[id]/route');
    return mod.GET(
      req(`http://localhost/api/threats/${encodeURIComponent(id)}`),
      { params: Promise.resolve({ id: encodeURIComponent(id) }) }
    );
  }

  it('returns 404 when the threat is not found', async () => {
    harness.setRows([]);
    const res = await detail('<missing@google.com>');
    expect(res.status).toBe(404);
  });

  it('returns 200 with email_verdicts-sourced, JS-derived fields + encoded id', async () => {
    harness.setRows([verdictRow()]);
    const res = await detail('<phish@google.com>');
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(allSql()).toContain('FROM email_verdicts');
    // id round-trips: URL-encoded message_id.
    expect(data.threat.id).toBe(encodeURIComponent('<phish@google.com>'));
    expect(data.threat.messageId).toBe('<phish@google.com>');
    expect(data.threat.senderEmail).toBe('evil@bad.com');
    expect(data.threat.score).toBe(88);
    // status is JS-derived via mapVerdictRowToThreat -> deriveThreatStatus.
    expect(data.threat.status).toBe('quarantined');
  });

  it('JS-derives released status from action_taken', async () => {
    harness.setRows([verdictRow({ action_taken: 'released' })]);
    const res = await detail('<phish@google.com>');
    const data = await res.json();
    expect(data.threat.status).toBe('released');
  });

  it('JS-derives deleted status from action_taken', async () => {
    harness.setRows([verdictRow({ action_taken: 'deleted' })]);
    const res = await detail('<phish@google.com>');
    const data = await res.json();
    expect(data.threat.status).toBe('deleted');
  });
});

describe('GET/POST /api/threats/search (query construction)', () => {
  beforeEach(() => {
    // Router: count -> total row, feed/stats aggregates -> [], main SELECT -> row.
    harness.setRows((text) => {
      if (/as\s+total\b/i.test(text)) return [{ total: 1 }];
      if (/GROUP\s+BY/i.test(text)) return [];
      return [verdictRow()];
    });
  });

  it('queries email_verdicts (not legacy threats) and embeds the derivation CASE', async () => {
    const res = await searchGet(req('http://localhost/api/threats/search'));
    expect(res.status).toBe(200);

    const sql = allSql();
    expect(sql).toContain('FROM email_verdicts');
    expect(sql).not.toContain('FROM threats');
    // status + threat_type CASE derivation is in the generated SQL.
    expect(sql).toContain("ev.action_taken IN ('released'");
    expect(sql).toContain("credential_request");
    // Scoped to threatening verdicts (matches getThreatsForManagement).
    expect(sql).toContain("ev.verdict IN ('suspicious', 'quarantine', 'block')");
  });

  it('applies the status filter as a bound param (no raw interpolation)', async () => {
    await searchGet(req('http://localhost/api/threats/search?status=quarantined,released'));
    expect(allSql()).toContain('= ANY($');
    expect(allParams()).toContainEqual(['quarantined', 'released']);
  });

  it('applies threatTypes + score filters as bound params', async () => {
    await searchGet(
      req('http://localhost/api/threats/search?types=phishing,bec&scoreMin=50&scoreMax=90')
    );
    const params = allParams();
    expect(params).toContainEqual(['phishing', 'bec']);
    expect(params).toContain(50);
    expect(params).toContain(90);
  });

  it('applies the free-text query as a bound ILIKE param', async () => {
    await searchPost(
      req('http://localhost/api/threats/search', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ query: 'invoice' }),
      })
    );
    expect(allSql()).toContain('ILIKE $');
    expect(allParams()).toContain('%invoice%');
  });

  it('DROPS the deprecated integration_type filter (no bound param, never applied)', async () => {
    await searchGet(req('http://localhost/api/threats/search?integration=gmail'));
    // integration_type is intentionally unsupported on email_verdicts; the value
    // must not leak into the query as a filter.
    expect(allParams()).not.toContain('gmail');
  });

  it('returns 200 with threats/pagination/aggregations shape + encoded ids', async () => {
    const res = await searchGet(req('http://localhost/api/threats/search'));
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(Array.isArray(data.threats)).toBe(true);
    expect(data.threats).toHaveLength(1);
    expect(data.threats[0].id).toBe(encodeURIComponent('<phish@google.com>'));
    expect(data.pagination).toHaveProperty('total');
    expect(data.pagination).toHaveProperty('totalPages');
    expect(data.pagination).toHaveProperty('hasMore');
    expect(data.aggregations).not.toBeUndefined();
  });
});

describe('GET /api/threats/feed (poll mode)', () => {
  beforeEach(() => {
    harness.setRows((text) => {
      // getThreatFeedStats (status counts CASE) -- one aggregate row.
      if (text.includes('avg_score')) {
        return [
          {
            quarantined: 2,
            released: 1,
            deleted: 0,
            last_24h: 3,
            last_hour: 1,
            latest_threat: null,
            avg_score: 81,
          },
        ];
      }
      // Processing-throughput stats (already email_verdicts).
      if (text.includes('total_processed')) {
        return [{ total_processed: 5, passed: 3, blocked: 2, avg_latency: 42 }];
      }
      // getRecentManagedThreats SELECT.
      return [verdictRow()];
    });
  });

  it('returns 200 with threats + stats, sourced from email_verdicts', async () => {
    const res = await feedGet(req('http://localhost/api/threats/feed'));
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(allSql()).toContain('FROM email_verdicts');
    expect(Array.isArray(data.threats)).toBe(true);
    expect(data.threats).toHaveLength(1);
    // Feed threat list is JS-derived via mapVerdictRowToThreat.
    expect(data.threats[0].status).toBe('quarantined');
    expect(data.threats[0].threat_type).toBe('phishing');
    // Stats shape (counts CASE + processing throughput).
    expect(data.stats.threats.quarantined).toBe(2);
    expect(data.stats.threats.released).toBe(1);
    expect(data.stats.processing.totalLastHour).toBe(5);
    expect(data.stats.processing.blocked).toBe(2);
  });

  it('JS-derives feed threat status from action_taken', async () => {
    harness.setRows((text) =>
      text.includes('avg_score') || text.includes('total_processed') ? [] : [verdictRow({ action_taken: 'deleted' })]
    );
    const res = await feedGet(req('http://localhost/api/threats/feed'));
    const data = await res.json();
    expect(data.threats[0].status).toBe('deleted');
  });
});
