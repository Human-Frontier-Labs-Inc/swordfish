/**
 * Regression test for the admin list endpoints (audit/threats/tenants/users).
 *
 * Bug: each endpoint built a `conditions`/`params` array from the query-string
 * filters but never interpolated it into the SQL — so every admin filter was
 * silently ignored. `be08cf6` removed the linter-visible dead `whereClause`
 * string, but the underlying `conditions`/`params` arrays survived because
 * `.push()` counts as "usage" to `no-unused-vars`. The `threats` route was
 * worse: it built that array by string-concatenating raw user input
 * (`'${status}'`, `ILIKE '%${search}%'`) — a latent SQL-injection vector that
 * was only inert because the array was unused.
 *
 * Fix: execute the list + count queries via `sql.query(text, params)` with the
 * WHERE clause applied; all values are `$N`-bound (injection-safe).
 *
 * This test mocks `@/lib/db` so every `sql.query(text, params)` call is
 * CAPTURED, then asserts the generated SQL contains the expected WHERE
 * fragment and that the bound params are present — i.e. it proves a filter
 * actually narrows the query (and that no raw user input leaks into the text).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';

interface CapturedCall {
  query: string;
  params: unknown[];
}

// vi.hoisted so the capturing storage exists before the vi.mock factory runs.
const { queryCalls, tagged } = vi.hoisted(() => {
  const queryCalls: CapturedCall[] = [];
  const tagged = vi.fn();
  return { queryCalls, tagged };
});

vi.mock('@clerk/nextjs/server', () => ({
  // org:admin grants MSP access in every route without depending on a DB row.
  auth: vi.fn().mockResolvedValue({ userId: 'u1', orgRole: 'org:admin' }),
}));

vi.mock('@/lib/api/rate-limit', () => ({
  rateLimit: vi.fn().mockReturnValue({ success: true, remaining: 9 }),
}));

vi.mock('@/lib/db', () => {
  // Tagged-template calls (e.g. the access-check query) resolve to [].
  // sql.query(text, params) is captured; count queries return a total row,
  // list queries return no rows.
  const proxy = new Proxy(tagged, {
    apply: () => Promise.resolve([]),
    get: (_target, prop) => {
      if (prop === 'then') return undefined;
      if (prop === 'query') {
        return (query: string, params?: unknown[]) => {
          queryCalls.push({ query, params: params ?? [] });
          return Promise.resolve(
            /as\s+total\b/i.test(query) ? [{ total: 7 }] : []
          );
        };
      }
      return tagged;
    },
  });
  return {
    sql: proxy as unknown as typeof import('@/lib/db')['sql'],
    default: proxy,
  };
});

import { GET as getAudit } from '@/app/api/admin/audit/route';
import { GET as getThreats } from '@/app/api/admin/threats/route';
import { GET as getTenants } from '@/app/api/admin/tenants/route';
import { GET as getUsers } from '@/app/api/admin/users/route';

function req(queryString: string): NextRequest {
  return new NextRequest(new URL(queryString, 'http://localhost'));
}

/** The non-count (list) sql.query call — count queries contain `as total`. */
function listQuery(): CapturedCall | undefined {
  const lists = queryCalls.filter((c) => !/as\s+total\b/i.test(c.query));
  return lists[lists.length - 1];
}

function requireListQuery(): CapturedCall {
  const q = listQuery();
  if (!q) throw new Error('expected a list sql.query call but found none');
  return q;
}

beforeEach(() => {
  queryCalls.length = 0;
});

describe('admin list endpoints — filters are applied to the SQL', () => {
  it('audit: tenantId + action narrow the query and bind params', async () => {
    const res = await getAudit(req('/api/admin/audit?tenantId=t-42&action=login'));
    expect(res.status).toBe(200);

    const q = requireListQuery();
    expect(q.query).toMatch(/\bWHERE\b/i);
    expect(q.query).toContain('al.tenant_id = $');
    expect(q.query).toContain('al.action = $');
    expect(q.params).toContain('t-42');
    expect(q.params).toContain('login');
  });

  it('tenants: plan + search narrow the query and bind params', async () => {
    const res = await getTenants(req('/api/admin/tenants?plan=pro&search=acme'));
    expect(res.status).toBe(200);

    const q = requireListQuery();
    expect(q.query).toMatch(/\bWHERE\b/i);
    expect(q.query).toContain('t.plan = $');
    expect(q.params).toContain('pro');
    expect(q.params).toContain('%acme%');
  });

  it('users: role + tenantId narrow the query and bind params', async () => {
    const res = await getUsers(req('/api/admin/users?role=msp_admin&tenantId=t-9'));
    expect(res.status).toBe(200);

    const q = requireListQuery();
    expect(q.query).toMatch(/\bWHERE\b/i);
    expect(q.query).toContain('u.role = $');
    expect(q.params).toContain('msp_admin');
    expect(q.params).toContain('t-9');
  });

  it('threats: verdict + search narrow the query with NO raw string interpolation', async () => {
    const res = await getThreats(req('/api/admin/threats?verdict=phishing&search=invoice'));
    expect(res.status).toBe(200);

    const q = requireListQuery();
    expect(q.query).toMatch(/\bWHERE\b/i);
    expect(q.query).toContain('t.verdict = $');
    expect(q.query).toContain('ILIKE $');
    expect(q.params).toContain('phishing');
    expect(q.params).toContain('%invoice%');

    // Regression guard for the removed injection landmine: raw user input must
    // never appear literally in the query text — only as a bound $N parameter.
    expect(q.query).not.toContain("invoice'");
    expect(q.query).not.toContain("'invoice");
    expect(q.query).not.toContain("'phishing");
  });

  it('audit: with no filters, the list query has no WHERE clause', async () => {
    const res = await getAudit(req('/api/admin/audit'));
    expect(res.status).toBe(200);

    const q = requireListQuery();
    expect(q.query).not.toMatch(/\bWHERE\b/i);
  });
});
