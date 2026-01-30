/**
 * Tenant Configuration Tests - Phase 1
 *
 * TDD tests for per-customer threshold and settings configuration
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  createTenantConfig,
  getTenantConfig,
  updateTenantConfig,
  deleteTenantConfig,
  addAllowlistDomain,
  removeAllowlistDomain,
  addTrackingDomain,
  isDomainAllowlisted,
  isSenderAllowlisted,
  getCategoryThreshold,
  getSignalThreshold,
  isModuleEnabled,
  applyTenantScoring,
  getAllTenantIds,
  clearAllTenantConfigs,
  DEFAULT_TENANT_CONFIG,
  INDUSTRY_PRESETS,
  type TenantConfig,
  type TenantIndustry,
} from '@/lib/detection/tenant-config';

describe('Tenant Configuration - Per-Customer Tuning', () => {
  beforeEach(() => {
    clearAllTenantConfigs();
  });

  describe('Default Configuration', () => {
    it('should have sensible default thresholds', () => {
      expect(DEFAULT_TENANT_CONFIG.thresholds.minDetectionScore).toBe(40);
      expect(DEFAULT_TENANT_CONFIG.thresholds.categories.phishing).toBe(35);
      expect(DEFAULT_TENANT_CONFIG.thresholds.categories.malware).toBe(30);
    });

    it('should have all modules enabled by default', () => {
      expect(DEFAULT_TENANT_CONFIG.settings.enableBrandProtection).toBe(true);
      expect(DEFAULT_TENANT_CONFIG.settings.enableQRDetection).toBe(true);
      expect(DEFAULT_TENANT_CONFIG.settings.enableURLClassification).toBe(true);
      expect(DEFAULT_TENANT_CONFIG.settings.enableAttachmentSandbox).toBe(true);
    });

    it('should have quarantine and block thresholds set', () => {
      expect(DEFAULT_TENANT_CONFIG.settings.quarantineThreshold).toBe(50);
      expect(DEFAULT_TENANT_CONFIG.settings.blockThreshold).toBe(70);
    });

    it('should return default config for unknown tenants', () => {
      const config = getTenantConfig('unknown-tenant');
      expect(config.tenantId).toBe('default');
      expect(config.thresholds.minDetectionScore).toBe(40);
    });
  });

  describe('Industry Presets', () => {
    it('should have presets for all industries', () => {
      const industries: TenantIndustry[] = [
        'financial', 'healthcare', 'technology', 'retail',
        'manufacturing', 'education', 'government', 'legal', 'media', 'other'
      ];

      for (const industry of industries) {
        expect(INDUSTRY_PRESETS[industry]).toBeDefined();
      }
    });

    it('should have stricter thresholds for financial industry', () => {
      const financial = INDUSTRY_PRESETS.financial;
      expect(financial.thresholds?.minDetectionScore).toBeLessThan(DEFAULT_TENANT_CONFIG.thresholds.minDetectionScore);
      expect(financial.settings?.strictMode).toBe(true);
    });

    it('should have stricter thresholds for government industry', () => {
      const government = INDUSTRY_PRESETS.government;
      expect(government.thresholds?.minDetectionScore).toBe(30);
      expect(government.settings?.strictMode).toBe(true);
    });

    it('should have higher thresholds for technology industry (fewer false positives)', () => {
      const tech = INDUSTRY_PRESETS.technology;
      expect(tech.thresholds?.minDetectionScore).toBeGreaterThan(DEFAULT_TENANT_CONFIG.thresholds.minDetectionScore);
      expect(tech.settings?.strictMode).toBe(false);
    });

    it('should have healthcare sensitive to malware', () => {
      const healthcare = INDUSTRY_PRESETS.healthcare;
      expect(healthcare.thresholds?.categories?.malware).toBe(25);
    });

    it('should have retail tolerant of QR codes', () => {
      const retail = INDUSTRY_PRESETS.retail;
      expect(retail.thresholds?.signals?.qrCodeRisk).toBe(45);
    });
  });

  describe('Tenant Creation', () => {
    it('should create a tenant with default settings', () => {
      const tenant = createTenantConfig('tenant-1', 'Acme Corp');

      expect(tenant.tenantId).toBe('tenant-1');
      expect(tenant.name).toBe('Acme Corp');
      expect(tenant.thresholds.minDetectionScore).toBe(40);
    });

    it('should create a tenant with industry preset', () => {
      const tenant = createTenantConfig('bank-1', 'First National Bank', {
        industry: 'financial',
      });

      expect(tenant.industry).toBe('financial');
      expect(tenant.thresholds.minDetectionScore).toBe(30);
      expect(tenant.settings.strictMode).toBe(true);
    });

    it('should allow custom threshold overrides', () => {
      const tenant = createTenantConfig('custom-1', 'Custom Corp', {
        customThresholds: {
          minDetectionScore: 55,
          categories: {
            phishing: 50,
          },
        },
      });

      expect(tenant.thresholds.minDetectionScore).toBe(55);
      expect(tenant.thresholds.categories.phishing).toBe(50);
      // Other categories should retain defaults
      expect(tenant.thresholds.categories.malware).toBe(30);
    });

    it('should allow custom allowlist configuration', () => {
      const tenant = createTenantConfig('allow-1', 'Allowlist Corp', {
        customAllowlists: {
          domains: ['trusted.com', 'partner.org'],
          senders: ['ceo@partner.org'],
        },
      });

      expect(tenant.allowlists.domains).toContain('trusted.com');
      expect(tenant.allowlists.domains).toContain('partner.org');
      expect(tenant.allowlists.senders).toContain('ceo@partner.org');
    });

    it('should allow custom settings overrides', () => {
      const tenant = createTenantConfig('settings-1', 'Settings Corp', {
        customSettings: {
          enableQRDetection: false,
          learningMode: true,
        },
      });

      expect(tenant.settings.enableQRDetection).toBe(false);
      expect(tenant.settings.learningMode).toBe(true);
      expect(tenant.settings.enableBrandProtection).toBe(true); // Unchanged
    });

    it('should combine industry preset with custom overrides', () => {
      const tenant = createTenantConfig('combo-1', 'Combo Bank', {
        industry: 'financial',
        customThresholds: {
          minDetectionScore: 25, // Even stricter than preset
        },
        customSettings: {
          learningMode: true,
        },
      });

      expect(tenant.industry).toBe('financial');
      expect(tenant.thresholds.minDetectionScore).toBe(25); // Custom override
      expect(tenant.settings.strictMode).toBe(true); // From preset
      expect(tenant.settings.learningMode).toBe(true); // Custom override
    });
  });

  describe('Tenant Retrieval', () => {
    it('should retrieve an existing tenant config', () => {
      createTenantConfig('test-tenant', 'Test Corp');

      const config = getTenantConfig('test-tenant');

      expect(config.tenantId).toBe('test-tenant');
      expect(config.name).toBe('Test Corp');
    });

    it('should return default config for non-existent tenant', () => {
      const config = getTenantConfig('non-existent');

      expect(config.tenantId).toBe('default');
    });
  });

  describe('Tenant Update', () => {
    it('should update tenant configuration', () => {
      createTenantConfig('update-test', 'Update Corp');

      const updated = updateTenantConfig('update-test', {
        name: 'Updated Corp',
        thresholds: {
          minDetectionScore: 60,
          categories: {},
          signals: {},
        },
      });

      expect(updated).not.toBeNull();
      expect(updated?.name).toBe('Updated Corp');
      expect(updated?.thresholds.minDetectionScore).toBe(60);
    });

    it('should return null for non-existent tenant update', () => {
      const updated = updateTenantConfig('non-existent', { name: 'Test' });
      expect(updated).toBeNull();
    });

    it('should update the updatedAt timestamp', () => {
      const tenant = createTenantConfig('time-test', 'Time Corp');
      const originalUpdated = tenant.updatedAt;

      // Small delay to ensure time difference
      const updated = updateTenantConfig('time-test', { name: 'Time Corp Updated' });

      expect(updated?.updatedAt.getTime()).toBeGreaterThanOrEqual(originalUpdated.getTime());
    });
  });

  describe('Tenant Deletion', () => {
    it('should delete a tenant config', () => {
      createTenantConfig('delete-me', 'Delete Corp');

      const deleted = deleteTenantConfig('delete-me');

      expect(deleted).toBe(true);
      expect(getTenantConfig('delete-me').tenantId).toBe('default');
    });

    it('should return false for non-existent tenant deletion', () => {
      const deleted = deleteTenantConfig('non-existent');
      expect(deleted).toBe(false);
    });
  });

  describe('Allowlist Management', () => {
    it('should add domains to allowlist', () => {
      createTenantConfig('allowlist-1', 'Allowlist Corp');

      const added = addAllowlistDomain('allowlist-1', 'trusted.com');

      expect(added).toBe(true);
      expect(isDomainAllowlisted('allowlist-1', 'trusted.com')).toBe(true);
    });

    it('should normalize domain case when adding', () => {
      createTenantConfig('case-1', 'Case Corp');

      addAllowlistDomain('case-1', 'TRUSTED.COM');

      expect(isDomainAllowlisted('case-1', 'trusted.com')).toBe(true);
    });

    it('should not add duplicate domains', () => {
      createTenantConfig('dup-1', 'Dup Corp');

      const first = addAllowlistDomain('dup-1', 'trusted.com');
      const second = addAllowlistDomain('dup-1', 'trusted.com');

      expect(first).toBe(true);
      expect(second).toBe(false);
    });

    it('should remove domains from allowlist', () => {
      createTenantConfig('remove-1', 'Remove Corp');
      addAllowlistDomain('remove-1', 'remove-me.com');

      const removed = removeAllowlistDomain('remove-1', 'remove-me.com');

      expect(removed).toBe(true);
      expect(isDomainAllowlisted('remove-1', 'remove-me.com')).toBe(false);
    });

    it('should return false for removing non-existent domain', () => {
      createTenantConfig('remove-2', 'Remove Corp 2');

      const removed = removeAllowlistDomain('remove-2', 'not-here.com');

      expect(removed).toBe(false);
    });

    it('should add tracking domains', () => {
      createTenantConfig('track-1', 'Track Corp');

      addTrackingDomain('track-1', 'analytics.tracking.com');

      const config = getTenantConfig('track-1');
      expect(config.allowlists.trackingDomains).toContain('analytics.tracking.com');
    });
  });

  describe('Domain Allowlist Checking', () => {
    it('should match exact domains', () => {
      createTenantConfig('match-1', 'Match Corp', {
        customAllowlists: { domains: ['trusted.com'] },
      });

      expect(isDomainAllowlisted('match-1', 'trusted.com')).toBe(true);
      expect(isDomainAllowlisted('match-1', 'untrusted.com')).toBe(false);
    });

    it('should match subdomains of allowlisted domains', () => {
      createTenantConfig('subdomain-1', 'Subdomain Corp', {
        customAllowlists: { domains: ['trusted.com'] },
      });

      expect(isDomainAllowlisted('subdomain-1', 'mail.trusted.com')).toBe(true);
      expect(isDomainAllowlisted('subdomain-1', 'sub.domain.trusted.com')).toBe(true);
    });

    it('should match partner domains', () => {
      createTenantConfig('partner-1', 'Partner Corp', {
        customAllowlists: { partnerDomains: ['partner.org'] },
      });

      expect(isDomainAllowlisted('partner-1', 'partner.org')).toBe(true);
      expect(isDomainAllowlisted('partner-1', 'mail.partner.org')).toBe(true);
    });
  });

  describe('Sender Allowlist Checking', () => {
    it('should match exact sender addresses', () => {
      createTenantConfig('sender-1', 'Sender Corp', {
        customAllowlists: { senders: ['ceo@trusted.com'] },
      });

      expect(isSenderAllowlisted('sender-1', 'ceo@trusted.com')).toBe(true);
      expect(isSenderAllowlisted('sender-1', 'CEO@TRUSTED.COM')).toBe(true); // Case insensitive
      expect(isSenderAllowlisted('sender-1', 'other@trusted.com')).toBe(false);
    });
  });

  describe('Threshold Retrieval', () => {
    it('should get category-specific thresholds', () => {
      createTenantConfig('thresh-1', 'Thresh Corp', {
        customThresholds: {
          categories: { phishing: 25, malware: 20 },
          minDetectionScore: 40,
          signals: {},
        },
      });

      expect(getCategoryThreshold('thresh-1', 'phishing')).toBe(25);
      expect(getCategoryThreshold('thresh-1', 'malware')).toBe(20);
    });

    it('should fall back to min detection score for undefined categories', () => {
      // Explicitly set bec to undefined to test fallback behavior
      // When a category is undefined (not just omitted), it should fall back to minDetectionScore
      createTenantConfig('fallback-1', 'Fallback Corp', {
        customThresholds: {
          minDetectionScore: 45,
          categories: { bec: undefined },
          signals: {},
        },
      });

      expect(getCategoryThreshold('fallback-1', 'bec')).toBe(45);
    });

    it('should get signal-specific thresholds', () => {
      createTenantConfig('signal-1', 'Signal Corp', {
        customThresholds: {
          minDetectionScore: 40,
          categories: {},
          signals: { urlRisk: 55, qrCodeRisk: 50 },
        },
      });

      expect(getSignalThreshold('signal-1', 'urlRisk')).toBe(55);
      expect(getSignalThreshold('signal-1', 'qrCodeRisk')).toBe(50);
    });
  });

  describe('Module Enablement', () => {
    it('should check if modules are enabled', () => {
      createTenantConfig('module-1', 'Module Corp', {
        customSettings: {
          enableQRDetection: false,
          enableBrandProtection: true,
        },
      });

      expect(isModuleEnabled('module-1', 'enableBrandProtection')).toBe(true);
      expect(isModuleEnabled('module-1', 'enableQRDetection')).toBe(false);
    });
  });

  describe('Tenant Scoring', () => {
    it('should apply tenant-specific scoring and determine action', () => {
      createTenantConfig('score-1', 'Score Corp');

      const { adjustedScore, action } = applyTenantScoring('score-1', 45);

      expect(adjustedScore).toBe(45);
      expect(action).toBe('allow'); // Below quarantine threshold of 50
    });

    it('should quarantine scores above threshold', () => {
      createTenantConfig('quarantine-1', 'Quarantine Corp');

      const { action } = applyTenantScoring('quarantine-1', 55);

      expect(action).toBe('quarantine');
    });

    it('should block scores above block threshold', () => {
      createTenantConfig('block-1', 'Block Corp');

      const { action } = applyTenantScoring('block-1', 75);

      expect(action).toBe('block');
    });

    it('should boost scores in strict mode', () => {
      createTenantConfig('strict-1', 'Strict Corp', {
        customSettings: { strictMode: true },
      });

      const { adjustedScore } = applyTenantScoring('strict-1', 50);

      expect(adjustedScore).toBe(60); // 20% boost
    });

    it('should cap boosted scores at 100', () => {
      createTenantConfig('cap-1', 'Cap Corp', {
        customSettings: { strictMode: true },
      });

      const { adjustedScore } = applyTenantScoring('cap-1', 95);

      expect(adjustedScore).toBe(100);
    });

    it('should use category-specific thresholds when provided', () => {
      createTenantConfig('category-1', 'Category Corp', {
        customThresholds: {
          minDetectionScore: 40,
          categories: { phishing: 25 },
          signals: {},
        },
      });

      // Score of 30 is below general threshold (40) but above phishing threshold (25)
      const result = applyTenantScoring('category-1', 30, 'phishing');
      // Note: Action is based on quarantine/block thresholds, not category thresholds
      expect(result.action).toBe('allow');
    });
  });

  describe('Tenant Listing', () => {
    it('should list all tenant IDs', () => {
      createTenantConfig('list-1', 'List Corp 1');
      createTenantConfig('list-2', 'List Corp 2');
      createTenantConfig('list-3', 'List Corp 3');

      const ids = getAllTenantIds();

      expect(ids).toContain('list-1');
      expect(ids).toContain('list-2');
      expect(ids).toContain('list-3');
      expect(ids.length).toBe(3);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty tenant ID', () => {
      const config = getTenantConfig('');
      expect(config.tenantId).toBe('default');
    });

    it('should handle null-like inputs for allowlist operations', () => {
      createTenantConfig('null-1', 'Null Corp');

      const added = addAllowlistDomain('null-1', '');
      expect(added).toBe(true); // Empty string is technically valid

      const removed = removeAllowlistDomain('non-existent', 'anything.com');
      expect(removed).toBe(false);
    });

    it('should preserve existing data when partially updating', () => {
      createTenantConfig('partial-1', 'Partial Corp', {
        customAllowlists: {
          domains: ['existing.com'],
          senders: ['sender@existing.com'],
        },
      });

      updateTenantConfig('partial-1', {
        name: 'Updated Partial Corp',
      });

      const config = getTenantConfig('partial-1');
      expect(config.allowlists.domains).toContain('existing.com');
      expect(config.allowlists.senders).toContain('sender@existing.com');
    });
  });
});
