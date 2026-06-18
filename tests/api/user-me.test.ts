/**
 * Regression test for Bug 1: GET /api/user/me must never 500.
 *
 * Previously the route did `LEFT JOIN tenants t ON safe_uuid(u.tenant_id) = t.id`,
 * which threw a 500 whenever the safe_uuid() function was absent or tenant_id was
 * NULL/non-UUID (org users created by setup-account never get a tenant_id). The
 * fix resolves the tenant in app code and degrades gracefully.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

let userRows: Record<string, unknown>[] = [];
let tenantRows: Record<string, unknown>[] = [];
let tenantQueryShouldThrow = false;

vi.mock('@/lib/db', () => {
  const sql = (strings: TemplateStringsArray, ..._values: unknown[]) => {
    const text = strings.join(' ');
    if (text.includes('FROM users')) {
      return Promise.resolve(userRows);
    }
    if (text.includes('FROM tenants')) {
      if (tenantQueryShouldThrow) {
        return Promise.reject(new Error('function safe_uuid(text) does not exist'));
      }
      return Promise.resolve(tenantRows);
    }
    return Promise.resolve([]);
  };
  return { sql, default: sql };
});

const authMock = vi.fn();
vi.mock('@clerk/nextjs/server', () => ({
  auth: () => authMock(),
}));

beforeEach(() => {
  userRows = [];
  tenantRows = [];
  tenantQueryShouldThrow = false;
  authMock.mockResolvedValue({ userId: 'user_123', orgId: 'org_abc' });
});

describe('GET /api/user/me', () => {
  it('returns 401 when unauthenticated', async () => {
    authMock.mockResolvedValueOnce({ userId: null, orgId: null });
    const { GET } = await import('@/app/api/user/me/route');
    const res = await GET();
    expect(res.status).toBe(401);
  });

  it('returns needsSetup when the user is not in the DB', async () => {
    userRows = [];
    const { GET } = await import('@/app/api/user/me/route');
    const res = await GET();
    const data = await res.json();
    expect(res.status).toBe(200);
    expect(data.needsSetup).toBe(true);
    expect(data.user).toBeNull();
  });

  it('does NOT 500 when tenant_id is NULL (org user without tenant link)', async () => {
    userRows = [
      {
        id: 'u1',
        email: 'a@b.com',
        name: 'A',
        role: 'tenant_admin',
        tenant_id: null,
        is_msp_user: false,
        status: 'active',
      },
    ];
    // Tenant resolved by clerk_org_id fallback.
    tenantRows = [
      { id: 'tenant-uuid', name: 'Acme', clerk_org_id: 'org_abc', domain: 'acme.com', plan: 'pro' },
    ];

    const { GET } = await import('@/app/api/user/me/route');
    const res = await GET();
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data.user.tenantName).toBe('Acme');
    expect(data.user.plan).toBe('pro');
  });

  it('does NOT 500 when the tenant lookup itself throws (missing safe_uuid)', async () => {
    userRows = [
      {
        id: 'u1',
        email: 'a@b.com',
        name: 'A',
        role: 'tenant_admin',
        tenant_id: 'not-a-uuid',
        is_msp_user: false,
        status: 'active',
      },
    ];
    tenantQueryShouldThrow = true;

    const { GET } = await import('@/app/api/user/me/route');
    const res = await GET();
    const data = await res.json();

    // Degrades gracefully: 200 with a null tenant, never a 500.
    expect(res.status).toBe(200);
    expect(data.user).not.toBeNull();
    expect(data.user.tenantName).toBeNull();
  });
});
