/**
 * Tenant Isolation Tests
 * TDD: Ensure strict data isolation between tenants
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock Clerk auth
vi.mock('@clerk/nextjs/server', () => ({
  auth: vi.fn().mockReturnValue({ userId: 'user_123', orgId: null }),
  currentUser: vi.fn().mockResolvedValue({ id: 'user_123' }),
}));

// Mock database
vi.mock('@/lib/db', () => ({
  sql: vi.fn().mockImplementation(() => Promise.resolve([])),
}));

describe('Tenant Isolation', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
  });

  describe('getTenantId helper', () => {
    it('should return orgId when user is in organization', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: 'user_123', orgId: 'org_abc' } as any);

      const { getTenantId } = await import('@/lib/auth/tenant');
      const tenantId = await getTenantId();

      expect(tenantId).toBe('org_abc');
    });

    it('should return personal_userId when not in organization', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: 'user_123', orgId: null } as any);

      const { getTenantId } = await import('@/lib/auth/tenant');
      const tenantId = await getTenantId();

      expect(tenantId).toBe('personal_user_123');
    });

    it('should throw when user is not authenticated', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: null, orgId: null } as any);

      const { getTenantId } = await import('@/lib/auth/tenant');

      await expect(getTenantId()).rejects.toThrow('Unauthorized');
    });
  });

  describe('verifyTenantAccess', () => {
    it('should return true when tenant matches', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: 'user_123', orgId: 'org_abc' } as any);

      const { verifyTenantAccess } = await import('@/lib/auth/tenant');
      const hasAccess = await verifyTenantAccess('org_abc');

      expect(hasAccess).toBe(true);
    });

    it('should return false when tenant does not match', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: 'user_123', orgId: 'org_abc' } as any);

      const { verifyTenantAccess } = await import('@/lib/auth/tenant');
      const hasAccess = await verifyTenantAccess('org_different');

      expect(hasAccess).toBe(false);
    });

    it('should return false for null tenant', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: 'user_123', orgId: 'org_abc' } as any);

      const { verifyTenantAccess } = await import('@/lib/auth/tenant');
      const hasAccess = await verifyTenantAccess(null as unknown as string);

      expect(hasAccess).toBe(false);
    });
  });

  describe('assertTenantAccess', () => {
    it('should not throw when tenant matches', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: 'user_123', orgId: 'org_abc' } as any);

      const { assertTenantAccess } = await import('@/lib/auth/tenant');

      await expect(assertTenantAccess('org_abc')).resolves.not.toThrow();
    });

    it('should throw TenantAccessDenied when tenant does not match', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: 'user_123', orgId: 'org_abc' } as any);

      const { assertTenantAccess, TenantAccessDenied } = await import('@/lib/auth/tenant');

      await expect(assertTenantAccess('org_different')).rejects.toThrow(TenantAccessDenied);
    });
  });

  describe('withTenantScope', () => {
    it('should add tenant_id filter to query results', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: 'user_123', orgId: 'org_abc' } as any);

      const { sql } = await import('@/lib/db');
      vi.mocked(sql).mockResolvedValue([
        { id: '1', tenant_id: 'org_abc', name: 'Test' },
        { id: '2', tenant_id: 'org_different', name: 'Other' }, // Should be filtered
      ] as any);

      const { withTenantScope } = await import('@/lib/auth/tenant');
      const results = await withTenantScope(async (tenantId) => {
        // In real usage, tenantId would be used in the SQL query
        const all = await sql`SELECT * FROM threats`;
        return all.filter((r: { tenant_id: string }) => r.tenant_id === tenantId);
      });

      expect(results).toHaveLength(1);
      expect(results[0].tenant_id).toBe('org_abc');
    });

    it('should pass tenant ID to callback', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: 'user_123', orgId: 'org_abc' } as any);

      const { withTenantScope } = await import('@/lib/auth/tenant');
      const callback = vi.fn().mockResolvedValue([]);

      await withTenantScope(callback);

      expect(callback).toHaveBeenCalledWith('org_abc');
    });
  });

  describe('resource access checks', () => {
    it('should verify threat belongs to tenant before access', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: 'user_123', orgId: 'org_abc' } as any);

      const { sql } = await import('@/lib/db');
      vi.mocked(sql).mockResolvedValue([{ id: 'threat-1', tenant_id: 'org_abc' }] as any);

      const { verifyResourceAccess } = await import('@/lib/auth/tenant');
      const hasAccess = await verifyResourceAccess('threats', 'threat-1');

      expect(hasAccess).toBe(true);
    });

    it('should deny access to threat from different tenant', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: 'user_123', orgId: 'org_abc' } as any);

      const { sql } = await import('@/lib/db');
      vi.mocked(sql).mockResolvedValue([{ id: 'threat-1', tenant_id: 'org_different' }] as any);

      const { verifyResourceAccess } = await import('@/lib/auth/tenant');
      const hasAccess = await verifyResourceAccess('threats', 'threat-1');

      expect(hasAccess).toBe(false);
    });

    it('should return false for non-existent resource', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: 'user_123', orgId: 'org_abc' } as any);

      const { sql } = await import('@/lib/db');
      vi.mocked(sql).mockResolvedValue([] as any);

      const { verifyResourceAccess } = await import('@/lib/auth/tenant');
      const hasAccess = await verifyResourceAccess('threats', 'non-existent');

      expect(hasAccess).toBe(false);
    });
  });

  describe('MSP cross-tenant access', () => {
    it('should allow MSP admin to access managed tenant', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({
        userId: 'user_msp_admin',
        orgId: 'org_msp',
        sessionClaims: { role: 'msp_admin' },
      } as any);

      const { sql } = await import('@/lib/db');
      // Mock MSP tenant relationship
      vi.mocked(sql).mockResolvedValue([
        { msp_tenant_id: 'org_msp', managed_tenant_id: 'org_client' },
      ] as any);

      const { verifyMSPAccess } = await import('@/lib/auth/tenant');
      const hasAccess = await verifyMSPAccess('org_client');

      expect(hasAccess).toBe(true);
    });

    it('should deny MSP admin access to unmanaged tenant', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({
        userId: 'user_msp_admin',
        orgId: 'org_msp',
        sessionClaims: { role: 'msp_admin' },
      } as any);

      const { sql } = await import('@/lib/db');
      // No MSP relationship
      vi.mocked(sql).mockResolvedValue([] as any);

      const { verifyMSPAccess } = await import('@/lib/auth/tenant');
      const hasAccess = await verifyMSPAccess('org_unmanaged');

      expect(hasAccess).toBe(false);
    });

    it('should log cross-tenant access for audit', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({
        userId: 'user_msp_admin',
        orgId: 'org_msp',
        sessionClaims: { role: 'msp_admin' },
      } as any);

      const { sql } = await import('@/lib/db');
      vi.mocked(sql).mockResolvedValue([] as any); // For audit log insert

      const { logCrossTenantAccess } = await import('@/lib/auth/tenant');
      await logCrossTenantAccess('org_client', 'view_threats');

      // Verify audit log insert was called
      expect(sql).toHaveBeenCalled();
    });
  });

  describe('tenant context middleware', () => {
    it('should set tenant context in request headers', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: 'user_123', orgId: 'org_abc' } as any);

      const { createTenantContext } = await import('@/lib/auth/tenant');
      const context = await createTenantContext();

      expect(context.tenantId).toBe('org_abc');
      expect(context.userId).toBe('user_123');
    });

    it('should include request ID for tracing', async () => {
      const { auth } = await import('@clerk/nextjs/server');
      vi.mocked(auth).mockReturnValue({ userId: 'user_123', orgId: 'org_abc' } as any);

      const { createTenantContext } = await import('@/lib/auth/tenant');
      const context = await createTenantContext();

      expect(context.requestId).toBeDefined();
      expect(typeof context.requestId).toBe('string');
    });
  });
});
