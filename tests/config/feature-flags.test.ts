/**
 * Feature Flags Tests
 * TDD: RED phase - Write failing tests first
 *
 * Feature flag system for safe feature rollouts with instant rollback,
 * percentage-based rollouts, and tenant-specific targeting.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  FeatureFlags,
  FeatureFlagConfig,
  Flag,
  FlagValue,
  EvaluationContext,
  RolloutStrategy,
  FlagOverride,
  FlagAuditLog,
} from '../../lib/config/feature-flags';

describe('Feature Flags', () => {
  let flags: FeatureFlags;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('Configuration', () => {
    it('should accept feature flags configuration', () => {
      const config: FeatureFlagConfig = {
        defaultEnabled: false,
        cacheTtl: 60000,
        auditLog: true,
      };

      flags = new FeatureFlags(config);
      expect(flags.getConfig()).toEqual(config);
    });

    it('should use default values for optional parameters', () => {
      flags = new FeatureFlags();
      const config = flags.getConfig();

      expect(config.defaultEnabled).toBe(false);
      expect(config.cacheTtl).toBe(0);
      expect(config.auditLog).toBe(false);
    });
  });

  describe('Flag Definition', () => {
    beforeEach(() => {
      flags = new FeatureFlags();
    });

    it('should define a simple boolean flag', () => {
      flags.define({
        key: 'new-dashboard',
        name: 'New Dashboard',
        description: 'Enable the new dashboard UI',
        enabled: true,
      });

      const flag = flags.getFlag('new-dashboard');
      expect(flag?.key).toBe('new-dashboard');
      expect(flag?.enabled).toBe(true);
    });

    it('should define a flag with variants', () => {
      flags.define({
        key: 'checkout-flow',
        name: 'Checkout Flow',
        description: 'A/B test checkout flow',
        enabled: true,
        variants: [
          { key: 'control', value: 'classic' },
          { key: 'treatment', value: 'streamlined' },
        ],
        defaultVariant: 'control',
      });

      const flag = flags.getFlag('checkout-flow');
      expect(flag?.variants).toHaveLength(2);
      expect(flag?.defaultVariant).toBe('control');
    });

    it('should define a flag with rollout strategy', () => {
      flags.define({
        key: 'ai-detection',
        name: 'AI Detection',
        enabled: true,
        rollout: {
          strategy: RolloutStrategy.PERCENTAGE,
          percentage: 25,
        },
      });

      const flag = flags.getFlag('ai-detection');
      expect(flag?.rollout?.strategy).toBe(RolloutStrategy.PERCENTAGE);
      expect(flag?.rollout?.percentage).toBe(25);
    });

    it('should prevent duplicate flag definitions', () => {
      flags.define({ key: 'feature-a', name: 'Feature A', enabled: true });

      expect(() => flags.define({
        key: 'feature-a',
        name: 'Feature A Duplicate',
        enabled: false,
      })).toThrow('Flag already defined');
    });

    it('should list all defined flags', () => {
      flags.define({ key: 'feature-a', name: 'A', enabled: true });
      flags.define({ key: 'feature-b', name: 'B', enabled: false });

      const all = flags.listFlags();
      expect(all).toHaveLength(2);
      expect(all.map(f => f.key)).toContain('feature-a');
      expect(all.map(f => f.key)).toContain('feature-b');
    });
  });

  describe('Flag Evaluation', () => {
    beforeEach(() => {
      flags = new FeatureFlags();
    });

    it('should evaluate simple boolean flag', () => {
      flags.define({ key: 'feature-a', name: 'A', enabled: true });
      flags.define({ key: 'feature-b', name: 'B', enabled: false });

      expect(flags.isEnabled('feature-a')).toBe(true);
      expect(flags.isEnabled('feature-b')).toBe(false);
    });

    it('should return default for undefined flag', () => {
      flags = new FeatureFlags({ defaultEnabled: false });
      expect(flags.isEnabled('unknown-flag')).toBe(false);

      flags = new FeatureFlags({ defaultEnabled: true });
      expect(flags.isEnabled('unknown-flag')).toBe(true);
    });

    it('should evaluate flag with context', () => {
      flags.define({
        key: 'beta-feature',
        name: 'Beta Feature',
        enabled: true,
        targeting: {
          rules: [
            {
              attribute: 'plan',
              operator: 'equals',
              value: 'enterprise',
            },
          ],
        },
      });

      const enterpriseContext: EvaluationContext = { plan: 'enterprise' };
      const freeContext: EvaluationContext = { plan: 'free' };

      expect(flags.isEnabled('beta-feature', enterpriseContext)).toBe(true);
      expect(flags.isEnabled('beta-feature', freeContext)).toBe(false);
    });

    it('should evaluate percentage rollout consistently', () => {
      flags.define({
        key: 'gradual-rollout',
        name: 'Gradual Rollout',
        enabled: true,
        rollout: {
          strategy: RolloutStrategy.PERCENTAGE,
          percentage: 50,
        },
      });

      // Same user should always get same result
      const context: EvaluationContext = { userId: 'user-123' };
      const result1 = flags.isEnabled('gradual-rollout', context);
      const result2 = flags.isEnabled('gradual-rollout', context);

      expect(result1).toBe(result2);
    });

    it('should evaluate flag variants', () => {
      flags.define({
        key: 'experiment',
        name: 'Experiment',
        enabled: true,
        variants: [
          { key: 'control', value: { buttonColor: 'blue' } },
          { key: 'treatment', value: { buttonColor: 'green' } },
        ],
        defaultVariant: 'control',
      });

      const value = flags.getValue('experiment');
      expect(['blue', 'green']).toContain((value as { buttonColor: string }).buttonColor);
    });

    it('should respect tenant-specific targeting', () => {
      flags.define({
        key: 'premium-feature',
        name: 'Premium Feature',
        enabled: true,
        targeting: {
          tenants: {
            include: ['tenant-premium'],
            exclude: ['tenant-trial'],
          },
        },
      });

      expect(flags.isEnabled('premium-feature', { tenantId: 'tenant-premium' })).toBe(true);
      expect(flags.isEnabled('premium-feature', { tenantId: 'tenant-trial' })).toBe(false);
      expect(flags.isEnabled('premium-feature', { tenantId: 'tenant-other' })).toBe(false);
    });

    it('should respect user-specific targeting', () => {
      flags.define({
        key: 'internal-tool',
        name: 'Internal Tool',
        enabled: true,
        targeting: {
          users: {
            include: ['admin@company.com', 'dev@company.com'],
          },
        },
      });

      expect(flags.isEnabled('internal-tool', { userId: 'admin@company.com' })).toBe(true);
      expect(flags.isEnabled('internal-tool', { userId: 'user@example.com' })).toBe(false);
    });
  });

  describe('Rollout Strategies', () => {
    beforeEach(() => {
      flags = new FeatureFlags();
    });

    it('should support ALL strategy (100% rollout)', () => {
      flags.define({
        key: 'feature',
        name: 'Feature',
        enabled: true,
        rollout: { strategy: RolloutStrategy.ALL },
      });

      expect(flags.isEnabled('feature', { userId: 'any-user' })).toBe(true);
    });

    it('should support NONE strategy (0% rollout)', () => {
      flags.define({
        key: 'feature',
        name: 'Feature',
        enabled: true,
        rollout: { strategy: RolloutStrategy.NONE },
      });

      expect(flags.isEnabled('feature', { userId: 'any-user' })).toBe(false);
    });

    it('should support PERCENTAGE strategy with consistent hashing', () => {
      flags.define({
        key: 'feature',
        name: 'Feature',
        enabled: true,
        rollout: { strategy: RolloutStrategy.PERCENTAGE, percentage: 50 },
      });

      // Test multiple users
      const results: boolean[] = [];
      for (let i = 0; i < 100; i++) {
        results.push(flags.isEnabled('feature', { userId: `user-${i}` }));
      }

      // Should have roughly 50% enabled (allow ±15% variance)
      const enabledCount = results.filter(r => r).length;
      expect(enabledCount).toBeGreaterThan(35);
      expect(enabledCount).toBeLessThan(65);
    });

    it('should support GRADUAL strategy with time-based rollout', () => {
      const now = Date.now();
      vi.setSystemTime(now);

      flags.define({
        key: 'gradual-feature',
        name: 'Gradual Feature',
        enabled: true,
        rollout: {
          strategy: RolloutStrategy.GRADUAL,
          startTime: now,
          endTime: now + 86400000, // 24 hours
          startPercentage: 0,
          endPercentage: 100,
        },
      });

      // At start, should be ~0%
      const initialResults = Array(20).fill(null).map((_, i) =>
        flags.isEnabled('gradual-feature', { userId: `user-${i}` })
      );
      const initialEnabled = initialResults.filter(r => r).length;
      expect(initialEnabled).toBeLessThan(5);

      // At 50% through, should be ~50%
      vi.setSystemTime(now + 43200000);
      const midResults = Array(100).fill(null).map((_, i) =>
        flags.isEnabled('gradual-feature', { userId: `user-mid-${i}` })
      );
      const midEnabled = midResults.filter(r => r).length;
      expect(midEnabled).toBeGreaterThan(35);
      expect(midEnabled).toBeLessThan(65);
    });
  });

  describe('Overrides', () => {
    beforeEach(() => {
      flags = new FeatureFlags();
      flags.define({ key: 'feature', name: 'Feature', enabled: false });
    });

    it('should support user-level overrides', () => {
      flags.setOverride({
        flagKey: 'feature',
        userId: 'special-user',
        enabled: true,
      });

      expect(flags.isEnabled('feature', { userId: 'special-user' })).toBe(true);
      expect(flags.isEnabled('feature', { userId: 'normal-user' })).toBe(false);
    });

    it('should support tenant-level overrides', () => {
      flags.setOverride({
        flagKey: 'feature',
        tenantId: 'special-tenant',
        enabled: true,
      });

      expect(flags.isEnabled('feature', { tenantId: 'special-tenant' })).toBe(true);
      expect(flags.isEnabled('feature', { tenantId: 'normal-tenant' })).toBe(false);
    });

    it('should support global overrides', () => {
      flags.setOverride({
        flagKey: 'feature',
        enabled: true,
      });

      expect(flags.isEnabled('feature')).toBe(true);
    });

    it('should prioritize overrides: user > tenant > global', () => {
      flags.setOverride({ flagKey: 'feature', enabled: true }); // global
      flags.setOverride({ flagKey: 'feature', tenantId: 'tenant-1', enabled: false }); // tenant
      flags.setOverride({ flagKey: 'feature', userId: 'user-1', enabled: true }); // user

      // User override wins
      expect(flags.isEnabled('feature', { userId: 'user-1', tenantId: 'tenant-1' })).toBe(true);

      // Tenant override applies when no user override
      expect(flags.isEnabled('feature', { userId: 'user-2', tenantId: 'tenant-1' })).toBe(false);

      // Global override applies when no tenant/user override
      expect(flags.isEnabled('feature', { userId: 'user-2', tenantId: 'tenant-2' })).toBe(true);
    });

    it('should remove overrides', () => {
      flags.setOverride({ flagKey: 'feature', userId: 'user-1', enabled: true });
      expect(flags.isEnabled('feature', { userId: 'user-1' })).toBe(true);

      flags.removeOverride('feature', { userId: 'user-1' });
      expect(flags.isEnabled('feature', { userId: 'user-1' })).toBe(false);
    });

    it('should list active overrides', () => {
      flags.setOverride({ flagKey: 'feature', userId: 'user-1', enabled: true });
      flags.setOverride({ flagKey: 'feature', tenantId: 'tenant-1', enabled: true });

      const overrides = flags.getOverrides('feature');
      expect(overrides).toHaveLength(2);
    });
  });

  describe('Flag Updates', () => {
    beforeEach(() => {
      flags = new FeatureFlags();
      flags.define({ key: 'feature', name: 'Feature', enabled: false });
    });

    it('should update flag enabled state', () => {
      flags.update('feature', { enabled: true });
      expect(flags.isEnabled('feature')).toBe(true);
    });

    it('should update flag rollout percentage', () => {
      flags.define({
        key: 'rollout-test',
        name: 'Rollout Test',
        enabled: true,
        rollout: { strategy: RolloutStrategy.PERCENTAGE, percentage: 10 },
      });

      flags.update('rollout-test', {
        rollout: { strategy: RolloutStrategy.PERCENTAGE, percentage: 90 },
      });

      const flag = flags.getFlag('rollout-test');
      expect(flag?.rollout?.percentage).toBe(90);
    });

    it('should delete a flag', () => {
      flags.delete('feature');
      expect(flags.getFlag('feature')).toBeUndefined();
    });

    it('should emit change events', () => {
      const changeHandler = vi.fn();
      flags.on('change', changeHandler);

      flags.update('feature', { enabled: true });

      expect(changeHandler).toHaveBeenCalledWith({
        key: 'feature',
        previousValue: expect.objectContaining({ enabled: false }),
        newValue: expect.objectContaining({ enabled: true }),
      });
    });
  });

  describe('Audit Logging', () => {
    beforeEach(() => {
      flags = new FeatureFlags({ auditLog: true });
      flags.define({ key: 'feature', name: 'Feature', enabled: false });
    });

    it('should log flag evaluations', () => {
      flags.isEnabled('feature', { userId: 'user-1' });
      flags.isEnabled('feature', { userId: 'user-2' });

      const logs = flags.getAuditLogs('feature');
      expect(logs.length).toBeGreaterThanOrEqual(2);
    });

    it('should log flag changes', () => {
      flags.update('feature', { enabled: true });

      const logs = flags.getAuditLogs('feature');
      const changeLogs = logs.filter(l => l.action === 'update');
      expect(changeLogs.length).toBe(1);
      expect(changeLogs[0].changes).toEqual({ enabled: true });
    });

    it('should include timestamp and actor in logs', () => {
      const now = Date.now();
      vi.setSystemTime(now);

      flags.update('feature', { enabled: true }, { actor: 'admin@example.com' });

      const logs = flags.getAuditLogs('feature');
      expect(logs[0].timestamp.getTime()).toBe(now);
      expect(logs[0].actor).toBe('admin@example.com');
    });

    it('should limit log retention', () => {
      flags = new FeatureFlags({ auditLog: true, maxAuditLogs: 10 });
      flags.define({ key: 'feature', name: 'Feature', enabled: false });

      // Generate many evaluations
      for (let i = 0; i < 20; i++) {
        flags.isEnabled('feature', { userId: `user-${i}` });
      }

      const logs = flags.getAuditLogs('feature');
      expect(logs.length).toBeLessThanOrEqual(10);
    });
  });

  describe('Caching', () => {
    it('should cache evaluation results', () => {
      flags = new FeatureFlags({ cacheTtl: 5000 });
      flags.define({ key: 'feature', name: 'Feature', enabled: true });

      // First call
      const result1 = flags.isEnabled('feature', { userId: 'user-1' });

      // Update flag (should not affect cached result yet)
      flags.update('feature', { enabled: false });

      // Second call (should return cached result)
      const result2 = flags.isEnabled('feature', { userId: 'user-1' });

      expect(result1).toBe(true);
      expect(result2).toBe(true);

      // Advance past cache TTL
      vi.advanceTimersByTime(5001);

      // Third call (should get fresh result)
      const result3 = flags.isEnabled('feature', { userId: 'user-1' });
      expect(result3).toBe(false);
    });

    it('should invalidate cache on update', () => {
      flags = new FeatureFlags({ cacheTtl: 60000 });
      flags.define({ key: 'feature', name: 'Feature', enabled: true });

      flags.isEnabled('feature');
      flags.update('feature', { enabled: false }, { invalidateCache: true });

      expect(flags.isEnabled('feature')).toBe(false);
    });
  });

  describe('Integration', () => {
    it('should support complex targeting rules', () => {
      flags = new FeatureFlags();
      flags.define({
        key: 'advanced-feature',
        name: 'Advanced Feature',
        enabled: true,
        targeting: {
          rules: [
            {
              attribute: 'plan',
              operator: 'in',
              value: ['enterprise', 'business'],
            },
            {
              attribute: 'country',
              operator: 'equals',
              value: 'US',
            },
          ],
          matchAll: true, // AND logic
        },
      });

      // Both conditions met
      expect(flags.isEnabled('advanced-feature', {
        plan: 'enterprise',
        country: 'US',
      })).toBe(true);

      // Only plan condition met
      expect(flags.isEnabled('advanced-feature', {
        plan: 'enterprise',
        country: 'UK',
      })).toBe(false);

      // Only country condition met
      expect(flags.isEnabled('advanced-feature', {
        plan: 'free',
        country: 'US',
      })).toBe(false);
    });

    it('should export flag configuration', () => {
      flags = new FeatureFlags();
      flags.define({ key: 'feature-a', name: 'A', enabled: true });
      flags.define({ key: 'feature-b', name: 'B', enabled: false });

      const exported = flags.export();

      expect(exported.flags).toHaveLength(2);
      expect(exported.version).toBeDefined();
    });

    it('should import flag configuration', () => {
      flags = new FeatureFlags();

      const config = {
        version: '1.0.0',
        flags: [
          { key: 'imported-a', name: 'Imported A', enabled: true },
          { key: 'imported-b', name: 'Imported B', enabled: false },
        ],
      };

      flags.import(config);

      expect(flags.isEnabled('imported-a')).toBe(true);
      expect(flags.isEnabled('imported-b')).toBe(false);
    });
  });
});
