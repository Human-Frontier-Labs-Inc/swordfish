/**
 * Audit Logging Tests
 * TDD: Security and compliance audit trail
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import {
  AuditLogger,
  createAuditLogger,
  AuditAction,
  AuditEntry,
  AuditCategory,
} from '@/lib/monitoring/audit';

// Mock database
vi.mock('@/lib/db', () => ({
  sql: vi.fn().mockResolvedValue([]),
}));

describe('Audit Logging', () => {
  let auditLogger: AuditLogger;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T12:00:00.000Z'));
    vi.clearAllMocks();
    auditLogger = createAuditLogger();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('AuditAction', () => {
    it('should have authentication actions', () => {
      expect(AuditAction.LOGIN).toBe('auth.login');
      expect(AuditAction.LOGOUT).toBe('auth.logout');
      expect(AuditAction.LOGIN_FAILED).toBe('auth.login_failed');
    });

    it('should have data actions', () => {
      expect(AuditAction.CREATE).toBe('data.create');
      expect(AuditAction.READ).toBe('data.read');
      expect(AuditAction.UPDATE).toBe('data.update');
      expect(AuditAction.DELETE).toBe('data.delete');
    });

    it('should have security actions', () => {
      expect(AuditAction.THREAT_RELEASED).toBe('security.threat_released');
      expect(AuditAction.POLICY_CHANGED).toBe('security.policy_changed');
      expect(AuditAction.PERMISSION_CHANGED).toBe('security.permission_changed');
    });

    it('should have integration actions', () => {
      expect(AuditAction.INTEGRATION_CONNECTED).toBe('integration.connected');
      expect(AuditAction.INTEGRATION_DISCONNECTED).toBe('integration.disconnected');
    });
  });

  describe('AuditCategory', () => {
    it('should have standard categories', () => {
      expect(AuditCategory.AUTHENTICATION).toBe('authentication');
      expect(AuditCategory.AUTHORIZATION).toBe('authorization');
      expect(AuditCategory.DATA_ACCESS).toBe('data_access');
      expect(AuditCategory.CONFIGURATION).toBe('configuration');
      expect(AuditCategory.SECURITY).toBe('security');
    });
  });

  describe('Logging entries', () => {
    it('should log authentication events', async () => {
      const { sql } = await import('@/lib/db');

      await auditLogger.log({
        action: AuditAction.LOGIN,
        category: AuditCategory.AUTHENTICATION,
        tenantId: 'org-abc',
        userId: 'user-123',
        details: { method: 'oauth', provider: 'google' },
      });

      expect(sql).toHaveBeenCalled();
    });

    it('should log data access events', async () => {
      const { sql } = await import('@/lib/db');

      await auditLogger.log({
        action: AuditAction.READ,
        category: AuditCategory.DATA_ACCESS,
        tenantId: 'org-abc',
        userId: 'user-123',
        resourceType: 'threat',
        resourceId: 'threat-456',
      });

      expect(sql).toHaveBeenCalled();
    });

    it('should log security events', async () => {
      const { sql } = await import('@/lib/db');

      await auditLogger.log({
        action: AuditAction.THREAT_RELEASED,
        category: AuditCategory.SECURITY,
        tenantId: 'org-abc',
        userId: 'user-123',
        resourceType: 'threat',
        resourceId: 'threat-456',
        details: { reason: 'False positive' },
      });

      expect(sql).toHaveBeenCalled();
    });

    it('should include IP address when provided', async () => {
      const { sql } = await import('@/lib/db');

      await auditLogger.log({
        action: AuditAction.LOGIN,
        category: AuditCategory.AUTHENTICATION,
        tenantId: 'org-abc',
        userId: 'user-123',
        ipAddress: '192.168.1.100',
      });

      const callArgs = vi.mocked(sql).mock.calls[0];
      expect(JSON.stringify(callArgs)).toContain('192.168.1.100');
    });

    it('should include user agent when provided', async () => {
      const { sql } = await import('@/lib/db');

      await auditLogger.log({
        action: AuditAction.LOGIN,
        category: AuditCategory.AUTHENTICATION,
        tenantId: 'org-abc',
        userId: 'user-123',
        userAgent: 'Mozilla/5.0 Chrome/120.0',
      });

      expect(sql).toHaveBeenCalled();
    });
  });

  describe('Entry format', () => {
    it('should generate unique entry ID', async () => {
      const entry = await auditLogger.log({
        action: AuditAction.LOGIN,
        category: AuditCategory.AUTHENTICATION,
        tenantId: 'org-abc',
        userId: 'user-123',
      });

      expect(entry.id).toMatch(/^aud_/);
    });

    it('should include timestamp', async () => {
      const entry = await auditLogger.log({
        action: AuditAction.LOGIN,
        category: AuditCategory.AUTHENTICATION,
        tenantId: 'org-abc',
        userId: 'user-123',
      });

      expect(entry.timestamp).toBe('2024-01-01T12:00:00.000Z');
    });
  });

  describe('Convenience methods', () => {
    it('should have logLogin helper', async () => {
      const entry = await auditLogger.logLogin('org-abc', 'user-123', {
        method: 'oauth',
        success: true,
      });

      expect(entry.action).toBe(AuditAction.LOGIN);
      expect(entry.category).toBe(AuditCategory.AUTHENTICATION);
    });

    it('should have logDataAccess helper', async () => {
      const entry = await auditLogger.logDataAccess(
        'org-abc',
        'user-123',
        AuditAction.READ,
        'threat',
        'threat-123'
      );

      expect(entry.action).toBe(AuditAction.READ);
      expect(entry.resourceType).toBe('threat');
    });

    it('should have logSecurityEvent helper', async () => {
      const entry = await auditLogger.logSecurityEvent(
        'org-abc',
        'user-123',
        AuditAction.THREAT_RELEASED,
        { threatId: 'threat-123', reason: 'False positive' }
      );

      expect(entry.action).toBe(AuditAction.THREAT_RELEASED);
      expect(entry.category).toBe(AuditCategory.SECURITY);
    });

    it('should have logConfigChange helper', async () => {
      const entry = await auditLogger.logConfigChange('org-abc', 'user-123', 'policy', 'pol-123', {
        field: 'rules',
        oldValue: '[]',
        newValue: '[{"action":"block"}]',
      });

      expect(entry.action).toBe(AuditAction.UPDATE);
      expect(entry.category).toBe(AuditCategory.CONFIGURATION);
    });
  });

  describe('Query capabilities', () => {
    it('should query by tenant', async () => {
      const { sql } = await import('@/lib/db');
      vi.mocked(sql).mockResolvedValue([
        { id: 'aud_1', tenant_id: 'org-abc' },
        { id: 'aud_2', tenant_id: 'org-abc' },
      ] as any);

      const entries = await auditLogger.query({ tenantId: 'org-abc' });

      expect(entries).toHaveLength(2);
    });

    it('should query by date range', async () => {
      const { sql } = await import('@/lib/db');
      vi.mocked(sql).mockResolvedValue([{ id: 'aud_1' }] as any);

      await auditLogger.query({
        tenantId: 'org-abc',
        from: new Date('2024-01-01'),
        to: new Date('2024-01-31'),
      });

      expect(sql).toHaveBeenCalled();
    });

    it('should query by action', async () => {
      const { sql } = await import('@/lib/db');
      vi.mocked(sql).mockResolvedValue([{ id: 'aud_1', action: 'auth.login' }] as any);

      await auditLogger.query({
        tenantId: 'org-abc',
        action: AuditAction.LOGIN,
      });

      expect(sql).toHaveBeenCalled();
    });

    it('should query by user', async () => {
      const { sql } = await import('@/lib/db');
      vi.mocked(sql).mockResolvedValue([{ id: 'aud_1', user_id: 'user-123' }] as any);

      await auditLogger.query({
        tenantId: 'org-abc',
        userId: 'user-123',
      });

      expect(sql).toHaveBeenCalled();
    });
  });

  describe('Compliance support', () => {
    it('should support retention policy metadata', async () => {
      const entry = await auditLogger.log({
        action: AuditAction.LOGIN,
        category: AuditCategory.AUTHENTICATION,
        tenantId: 'org-abc',
        userId: 'user-123',
        retentionDays: 365,
      });

      expect(entry.retentionDays).toBe(365);
    });

    it('should flag sensitive operations', async () => {
      const entry = await auditLogger.logSecurityEvent(
        'org-abc',
        'user-123',
        AuditAction.THREAT_RELEASED,
        { threatId: 'threat-123' }
      );

      expect(entry.sensitive).toBe(true);
    });
  });
});
