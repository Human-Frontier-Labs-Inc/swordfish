/**
 * MSP cross-tenant authorization regression tests — P0-8
 *
 * Guards against the `is_msp_user` god-mode defect: an MSP user must only see
 * tenants explicitly granted to their MSP organization via `msp_tenant_access`.
 * A user from MSP-org-A must be DENIED a tenant they lack access to.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';

vi.mock('@clerk/nextjs/server', () => ({
  auth: vi.fn(),
}));

// Programmable SQL mock: routes each query to a handler based on its text.
const sqlHandlers: Array<{ match: (q: string) => boolean; rows: (q: string, vals: unknown[]) => unknown[] }> = [];
function resetSql() {
  sqlHandlers.length = 0;
}
function whenSql(match: (q: string) => boolean, rows: (q: string, vals: unknown[]) => unknown[]) {
  sqlHandlers.push({ match, rows });
}

vi.mock('@/lib/db', () => {
  const sql = (strings: TemplateStringsArray, ...values: unknown[]) => {
    const q = strings.join(' ? ').replace(/\s+/g, ' ').trim();
    for (const h of sqlHandlers) {
      if (h.match(q)) return Promise.resolve(h.rows(q, values));
    }
    return Promise.resolve([]);
  };
  return { sql, default: sql };
});

import { auth } from '@clerk/nextjs/server';
import { GET } from '@/app/api/msp/tenants/route';

const authMock = auth as unknown as ReturnType<typeof vi.fn>;

function makeRequest(query = ''): NextRequest {
  return new NextRequest(`http://localhost/api/msp/tenants${query}`);
}

describe('GET /api/msp/tenants — msp_tenant_access authorization (P0-8)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetSql();
  });

  it('returns ONLY tenants joined via msp_tenant_access for the MSP org', async () => {
    authMock.mockResolvedValue({ userId: 'clerk_user_mspA', orgId: 'org_mspA' });

    // user is an MSP user with no home tenant
    whenSql((q) => q.includes('FROM users WHERE clerk_user_id'), () => [
      { is_msp_user: true, tenant_id: null },
    ]);
    // resolve MSP org from clerk org id
    whenSql((q) => q.includes('FROM msp_organizations WHERE clerk_org_id'), () => [
      { id: 'msp-org-a-uuid' },
    ]);
    // the JOIN through msp_tenant_access returns ONLY granted tenants
    whenSql(
      (q) => q.includes('INNER JOIN msp_tenant_access') && q.startsWith('SELECT t.id'),
      () => [
        { id: 'tenant-granted-1', name: 'Client One', domain: 'one.com', plan: 'pro', status: 'active', created_at: '2026-01-01', user_count: 5 },
      ]
    );
    whenSql((q) => q.includes('INNER JOIN msp_tenant_access') && q.includes('COUNT(*)'), () => [
      { count: 1 },
    ]);

    const res = await GET(makeRequest());
    expect(res.status).toBe(200);
    const data = await res.json();

    expect(data.tenants).toHaveLength(1);
    expect(data.tenants[0].id).toBe('tenant-granted-1');
    expect(data.tenants[0].role).toBe('msp_admin');
    expect(data.total).toBe(1);
  });

  it('DENIES a tenant the MSP org lacks access to (god-mode regression)', async () => {
    // MSP-org-A user. The join returns NO rows for a tenant they were not granted.
    authMock.mockResolvedValue({ userId: 'clerk_user_mspA', orgId: 'org_mspA' });

    whenSql((q) => q.includes('FROM users WHERE clerk_user_id'), () => [
      { is_msp_user: true, tenant_id: null },
    ]);
    whenSql((q) => q.includes('FROM msp_organizations WHERE clerk_org_id'), () => [
      { id: 'msp-org-a-uuid' },
    ]);
    // msp_tenant_access grants nothing for tenant-of-org-B -> empty result set
    whenSql((q) => q.includes('INNER JOIN msp_tenant_access') && q.startsWith('SELECT t.id'), () => []);
    whenSql((q) => q.includes('INNER JOIN msp_tenant_access') && q.includes('COUNT(*)'), () => [{ count: 0 }]);

    const res = await GET(makeRequest());
    expect(res.status).toBe(200);
    const data = await res.json();

    // The previously-vulnerable behavior would have returned ALL tenants here.
    expect(data.tenants).toHaveLength(0);
    expect(data.total).toBe(0);
  });

  it('returns nothing when an is_msp_user has no registered MSP org', async () => {
    authMock.mockResolvedValue({ userId: 'clerk_user_x', orgId: 'org_not_msp' });

    whenSql((q) => q.includes('FROM users WHERE clerk_user_id'), () => [
      { is_msp_user: true, tenant_id: null },
    ]);
    // No MSP org row for this clerk org
    whenSql((q) => q.includes('FROM msp_organizations WHERE clerk_org_id'), () => []);

    const res = await GET(makeRequest());
    const data = await res.json();
    expect(data.tenants).toHaveLength(0);
    expect(data.total).toBe(0);
  });

  it('a non-MSP user only sees their own tenant', async () => {
    authMock.mockResolvedValue({ userId: 'clerk_user_reg', orgId: 'org_client' });

    whenSql((q) => q.includes('FROM users WHERE clerk_user_id'), () => [
      { is_msp_user: false, tenant_id: 'tenant-self-uuid' },
    ]);
    whenSql(
      (q) => q.startsWith('SELECT t.id') && q.includes('WHERE t.id') && !q.includes('msp_tenant_access'),
      () => [
        { id: 'tenant-self-uuid', name: 'My Org', domain: 'self.com', plan: 'starter', status: 'active', created_at: '2026-01-01', user_count: 3 },
      ]
    );

    const res = await GET(makeRequest());
    const data = await res.json();
    expect(data.tenants).toHaveLength(1);
    expect(data.tenants[0].id).toBe('tenant-self-uuid');
    expect(data.tenants[0].role).toBe('tenant_admin');
  });

  it('returns 401 when unauthenticated', async () => {
    authMock.mockResolvedValue({ userId: null, orgId: null });
    const res = await GET(makeRequest());
    expect(res.status).toBe(401);
  });
});
