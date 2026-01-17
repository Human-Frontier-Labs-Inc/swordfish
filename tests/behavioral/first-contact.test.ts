/**
 * First Contact Detection Tests
 * Tests for detecting first-time external senders and lookalike contacts
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  FirstContactDetector,
  type FirstContactResult,
  type FirstContactConfig,
  type SenderProfile,
} from '@/lib/behavioral/first-contact';
import {
  LookalikeDetector,
  type LookalikeResult,
  type LookalikeMatch,
} from '@/lib/behavioral/lookalike-detector';

// Mock database
vi.mock('@/lib/db', () => ({
  sql: vi.fn().mockImplementation(async () => []),
}));

// Mock domain age service
vi.mock('@/lib/threat-intel/domain/age', () => ({
  checkDomainAge: vi.fn().mockImplementation(async (domain: string) => {
    const ages: Record<string, number> = {
      'old-company.com': 3650, // 10 years
      'established-partner.com': 1825, // 5 years
      'new-startup.io': 30, // 30 days
      'brand-new.xyz': 5, // 5 days
      'suspicious-lookalike.net': 7, // 7 days
      'company.com': 5000,
      'trusted.com': 3000,
    };
    return {
      domain,
      ageInDays: ages[domain] ?? 365,
      createdDate: null,
      riskLevel: (ages[domain] ?? 365) <= 7 ? 'critical' : (ages[domain] ?? 365) <= 30 ? 'high' : 'low',
      riskScore: 0,
      indicators: [],
    };
  }),
}));

describe('FirstContactDetector', () => {
  let detector: FirstContactDetector;
  const testTenantId = 'test-tenant-001';

  beforeEach(() => {
    detector = new FirstContactDetector();
    vi.clearAllMocks();
  });

  describe('First-Time External Sender Detection', () => {
    it('should detect first-time external sender', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'unknown@external-company.com',
        senderDisplayName: 'John External',
        recipientEmail: 'employee@company.com',
        organizationDomain: 'company.com',
      });

      expect(result.isFirstContact).toBe(true);
      expect(result.isExternalSender).toBe(true);
    });

    it('should not flag internal senders as first contact', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'colleague@company.com',
        senderDisplayName: 'Internal Colleague',
        recipientEmail: 'employee@company.com',
        organizationDomain: 'company.com',
      });

      expect(result.isFirstContact).toBe(false);
      expect(result.isExternalSender).toBe(false);
    });

    it('should track contact history', async () => {
      // First email from sender
      const firstResult = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'vendor@supplier.com',
        senderDisplayName: 'Vendor Support',
        recipientEmail: 'procurement@company.com',
        organizationDomain: 'company.com',
      });

      expect(firstResult.isFirstContact).toBe(true);

      // Record the contact
      await detector.recordContact({
        tenantId: testTenantId,
        senderEmail: 'vendor@supplier.com',
        recipientEmail: 'procurement@company.com',
        firstContactAt: new Date(),
      });

      // Subsequent email should not be first contact
      const secondResult = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'vendor@supplier.com',
        senderDisplayName: 'Vendor Support',
        recipientEmail: 'procurement@company.com',
        organizationDomain: 'company.com',
      });

      expect(secondResult.isFirstContact).toBe(false);
      expect(secondResult.priorContactCount).toBeGreaterThan(0);
    });

    it('should handle multiple organization domains', async () => {
      const multiDomainDetector = new FirstContactDetector({
        organizationDomains: ['company.com', 'company.io', 'company-corp.com'],
      });

      const result = await multiDomainDetector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'colleague@company.io',
        senderDisplayName: 'Internal Colleague',
        recipientEmail: 'employee@company.com',
        organizationDomain: 'company.com',
      });

      expect(result.isExternalSender).toBe(false);
    });
  });

  describe('Lookalike Contact Detection (Levenshtein Distance)', () => {
    let lookalikeDetector: LookalikeDetector;

    beforeEach(() => {
      lookalikeDetector = new LookalikeDetector();
    });

    it('should detect lookalike of known contact via Levenshtein', async () => {
      const knownContacts = [
        { email: 'john.smith@partner.com', displayName: 'John Smith' },
        { email: 'jane.doe@supplier.com', displayName: 'Jane Doe' },
      ];

      const result = await lookalikeDetector.detectLookalike(
        'john.smlth@partner.com', // 'i' replaced with 'l'
        'John Smith',
        knownContacts
      );

      expect(result.isLookalike).toBe(true);
      expect(result.matchedContact?.email).toBe('john.smith@partner.com');
      expect(result.levenshteinDistance).toBeLessThanOrEqual(2);
    });

    it('should detect domain lookalike via Levenshtein', async () => {
      const knownContacts = [
        { email: 'ceo@acme-corp.com', displayName: 'CEO' },
      ];

      const result = await lookalikeDetector.detectLookalike(
        'ceo@acme-c0rp.com', // 'o' replaced with '0'
        'CEO',
        knownContacts
      );

      expect(result.isLookalike).toBe(true);
      expect(result.domainSimilarity).toBeGreaterThan(0.8);
    });

    it('should calculate correct Levenshtein distance', () => {
      expect(lookalikeDetector.levenshteinDistance('kitten', 'sitting')).toBe(3);
      expect(lookalikeDetector.levenshteinDistance('hello', 'hello')).toBe(0);
      expect(lookalikeDetector.levenshteinDistance('abc', 'def')).toBe(3);
      expect(lookalikeDetector.levenshteinDistance('', 'test')).toBe(4);
    });

    it('should not flag significantly different emails as lookalikes', async () => {
      const knownContacts = [
        { email: 'john@company.com', displayName: 'John' },
      ];

      const result = await lookalikeDetector.detectLookalike(
        'sarah@different.org',
        'Sarah',
        knownContacts
      );

      expect(result.isLookalike).toBe(false);
    });

    it('should detect homoglyph attacks', async () => {
      const knownContacts = [
        { email: 'admin@microsoft.com', displayName: 'Admin' },
      ];

      // Using Cyrillic characters that look like Latin
      const result = await lookalikeDetector.detectLookalike(
        'admin@micrоsoft.com', // 'o' is Cyrillic
        'Admin',
        knownContacts
      );

      expect(result.isLookalike).toBe(true);
      expect(result.homoglyphDetected).toBe(true);
    });

    it('should detect common homoglyph substitutions', () => {
      const substitutions = lookalikeDetector.getHomoglyphSubstitutions();

      expect(substitutions['a']).toContain('а'); // Cyrillic a
      expect(substitutions['o']).toContain('о'); // Cyrillic o
      expect(substitutions['e']).toContain('е'); // Cyrillic e
      expect(substitutions['0']).toContain('O');
      expect(substitutions['1']).toContain('l');
    });

    it('should normalize homoglyphs for comparison', () => {
      const normalized = lookalikeDetector.normalizeHomoglyphs('micrоsоft');

      expect(normalized).toBe('microsoft');
    });
  });

  describe('Domain Age Correlation', () => {
    it('should increase risk score for new domains', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'sales@brand-new.xyz',
        senderDisplayName: 'Sales Team',
        recipientEmail: 'employee@company.com',
        organizationDomain: 'company.com',
      });

      expect(result.domainAge).toBeLessThan(30);
      // Domain is 5 days old, which is <= 7 days (critical threshold)
      expect(result.domainAgeRisk).toBe('critical');
      expect(result.riskScore).toBeGreaterThan(50);
    });

    it('should lower risk score for established domains', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'contact@old-company.com',
        senderDisplayName: 'Contact',
        recipientEmail: 'employee@company.com',
        organizationDomain: 'company.com',
      });

      expect(result.domainAge).toBeGreaterThan(1000);
      expect(result.domainAgeRisk).toBe('low');
    });

    it('should flag very new domain as critical risk', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'urgent@brand-new.xyz', // 5 days old
        senderDisplayName: 'Urgent Request',
        recipientEmail: 'finance@company.com',
        organizationDomain: 'company.com',
      });

      expect(result.domainAge).toBeLessThan(10);
      expect(result.domainAgeRisk).toBe('critical');
    });
  });

  describe('Risk Score Calculation', () => {
    it('should calculate combined risk score for first contact', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'unknown@new-startup.io',
        senderDisplayName: 'Unknown Sender',
        recipientEmail: 'employee@company.com',
        organizationDomain: 'company.com',
      });

      expect(result.riskScore).toBeDefined();
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(100);
    });

    it('should factor in all risk components', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'ceo@brand-new.xyz', // New domain, potential impersonation
        senderDisplayName: 'John CEO',
        recipientEmail: 'finance@company.com',
        organizationDomain: 'company.com',
        knownVIPs: [
          { email: 'john.ceo@company.com', displayName: 'John CEO', role: 'executive' },
        ],
      });

      expect(result.riskFactors).toContain('first_contact');
      expect(result.riskFactors).toContain('new_domain');
      expect(result.riskFactors).toContain('potential_impersonation');
      expect(result.riskScore).toBeGreaterThan(70);
    });
  });

  describe('VIP Sender Extra Scrutiny', () => {
    it('should detect CEO impersonation attempt', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'john.ceo@external-domain.com',
        senderDisplayName: 'John Smith CEO',
        recipientEmail: 'finance@company.com',
        organizationDomain: 'company.com',
        knownVIPs: [
          { email: 'john.smith@company.com', displayName: 'John Smith', role: 'executive', title: 'CEO' },
        ],
      });

      expect(result.isVIPImpersonation).toBe(true);
      expect(result.matchedVIP?.title).toBe('CEO');
      expect(result.riskScore).toBeGreaterThan(80);
    });

    it('should detect CFO impersonation via display name', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'randomuser@gmail.com',
        senderDisplayName: 'Jane Doe - CFO',
        recipientEmail: 'accounts@company.com',
        organizationDomain: 'company.com',
        knownVIPs: [
          { email: 'jane.doe@company.com', displayName: 'Jane Doe', role: 'finance', title: 'CFO' },
        ],
      });

      expect(result.isVIPImpersonation).toBe(true);
      expect(result.impersonationType).toBe('display_name_spoof');
    });

    it('should apply extra scrutiny to emails targeting executives', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'external@unknown.com',
        senderDisplayName: 'External Contact',
        recipientEmail: 'ceo@company.com',
        organizationDomain: 'company.com',
        recipientIsVIP: true,
      });

      expect(result.targetingVIP).toBe(true);
      expect(result.riskScore).toBeGreaterThan(result.baseRiskScore);
    });

    it('should detect executive title keywords in external sender', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'support@external.com',
        senderDisplayName: 'CEO Office',
        recipientEmail: 'employee@company.com',
        organizationDomain: 'company.com',
      });

      expect(result.hasExecutiveTitleKeyword).toBe(true);
      expect(result.riskFactors).toContain('executive_title_in_external');
    });
  });

  describe('Supplier/Vendor First Contact Detection', () => {
    it('should identify potential vendor impersonation', async () => {
      const knownVendors = [
        { domain: 'acme-supplies.com', name: 'ACME Supplies' },
        { domain: 'trusted-vendor.com', name: 'Trusted Vendor' },
      ];

      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'billing@acme-suppllies.com', // Typo in domain
        senderDisplayName: 'ACME Supplies Billing',
        recipientEmail: 'accounts@company.com',
        organizationDomain: 'company.com',
        knownVendors,
      });

      expect(result.isVendorLookalike).toBe(true);
      expect(result.matchedVendor?.name).toBe('ACME Supplies');
      expect(result.riskFactors).toContain('vendor_impersonation');
    });

    it('should flag first contact from vendor lookalike domain', async () => {
      const knownVendors = [
        { domain: 'microsoft.com', name: 'Microsoft' },
      ];

      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'support@micros0ft.com',
        senderDisplayName: 'Microsoft Support',
        recipientEmail: 'it@company.com',
        organizationDomain: 'company.com',
        knownVendors,
      });

      expect(result.isVendorLookalike).toBe(true);
      expect(result.riskScore).toBeGreaterThan(70);
    });

    it('should allow legitimate first contact from verified vendor', async () => {
      const knownVendors = [
        { domain: 'new-vendor.com', name: 'New Vendor', verified: true },
      ];

      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'sales@new-vendor.com',
        senderDisplayName: 'New Vendor Sales',
        recipientEmail: 'procurement@company.com',
        organizationDomain: 'company.com',
        knownVendors,
        isVerifiedVendor: true,
      });

      expect(result.isFirstContact).toBe(true);
      expect(result.isVerifiedVendor).toBe(true);
      expect(result.riskScore).toBeLessThan(30);
    });
  });

  describe('Whitelist for Expected First Contacts', () => {
    it('should allow whitelisted first contacts', async () => {
      const whitelist = [
        { domain: 'expected-partner.com', reason: 'New partnership', addedBy: 'admin' },
        { email: 'contact@approved-sender.com', reason: 'Pre-approved', addedBy: 'manager' },
      ];

      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'intro@expected-partner.com',
        senderDisplayName: 'Expected Partner',
        recipientEmail: 'employee@company.com',
        organizationDomain: 'company.com',
        firstContactWhitelist: whitelist,
      });

      expect(result.isWhitelisted).toBe(true);
      expect(result.whitelistReason).toBe('New partnership');
      expect(result.riskScore).toBe(0);
    });

    it('should match whitelist by email address', async () => {
      const whitelist = [
        { email: 'specific@sender.com', reason: 'Expected contact', addedBy: 'user' },
      ];

      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'specific@sender.com',
        senderDisplayName: 'Specific Sender',
        recipientEmail: 'employee@company.com',
        organizationDomain: 'company.com',
        firstContactWhitelist: whitelist,
      });

      expect(result.isWhitelisted).toBe(true);
    });

    it('should not whitelist lookalike of whitelisted domain', async () => {
      const whitelist = [
        { domain: 'partner.com', reason: 'Partner', addedBy: 'admin' },
      ];

      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'contact@partn3r.com', // Lookalike
        senderDisplayName: 'Partner Contact',
        recipientEmail: 'employee@company.com',
        organizationDomain: 'company.com',
        firstContactWhitelist: whitelist,
      });

      expect(result.isWhitelisted).toBe(false);
      expect(result.isLookalike).toBe(true);
    });

    it('should support temporary whitelist entries', async () => {
      const now = new Date();
      const whitelist = [
        {
          domain: 'temp-partner.com',
          reason: 'Temporary access',
          addedBy: 'admin',
          expiresAt: new Date(now.getTime() + 86400000), // 24 hours from now
        },
      ];

      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'contact@temp-partner.com',
        senderDisplayName: 'Temp Partner',
        recipientEmail: 'employee@company.com',
        organizationDomain: 'company.com',
        firstContactWhitelist: whitelist,
      });

      expect(result.isWhitelisted).toBe(true);
      expect(result.whitelistExpiry).toBeDefined();
    });
  });

  describe('Integration with Detection Pipeline', () => {
    it('should return pipeline-compatible result format', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'unknown@external.com',
        senderDisplayName: 'Unknown',
        recipientEmail: 'employee@company.com',
        organizationDomain: 'company.com',
      });

      expect(result.signals).toBeDefined();
      expect(Array.isArray(result.signals)).toBe(true);

      if (result.signals.length > 0) {
        expect(result.signals[0].type).toBeDefined();
        expect(result.signals[0].severity).toBeDefined();
        expect(result.signals[0].score).toBeDefined();
        expect(result.signals[0].detail).toBeDefined();
      }
    });

    it('should generate appropriate signals for first contact', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'unknown@new-domain.xyz',
        senderDisplayName: 'Unknown Sender',
        recipientEmail: 'employee@company.com',
        organizationDomain: 'company.com',
      });

      const signalTypes = result.signals.map(s => s.type);
      expect(signalTypes).toContain('first_contact');
    });

    it('should generate VIP impersonation signals', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'ceo@external.com',
        senderDisplayName: 'John Smith CEO',
        recipientEmail: 'finance@company.com',
        organizationDomain: 'company.com',
        knownVIPs: [
          { email: 'john.smith@company.com', displayName: 'John Smith', role: 'executive', title: 'CEO' },
        ],
      });

      const signalTypes = result.signals.map(s => s.type);
      expect(signalTypes).toContain('first_contact_vip_impersonation');
    });

    it('should be callable from main detection pipeline', async () => {
      // This tests the interface compatibility
      const analysisInput = {
        tenantId: testTenantId,
        senderEmail: 'test@external.com',
        senderDisplayName: 'Test Sender',
        recipientEmail: 'recipient@company.com',
        organizationDomain: 'company.com',
      };

      const result = await detector.analyzeContact(analysisInput);

      // Result should be usable by pipeline
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(100);
      expect(typeof result.isFirstContact).toBe('boolean');
    });

    it('should provide confidence scores for decisions', async () => {
      const result = await detector.analyzeContact({
        tenantId: testTenantId,
        senderEmail: 'unknown@suspicious.xyz',
        senderDisplayName: 'Unknown',
        recipientEmail: 'employee@company.com',
        organizationDomain: 'company.com',
      });

      expect(result.confidence).toBeGreaterThanOrEqual(0);
      expect(result.confidence).toBeLessThanOrEqual(1);
    });
  });
});

describe('LookalikeDetector Homoglyph Detection', () => {
  let detector: LookalikeDetector;

  beforeEach(() => {
    detector = new LookalikeDetector();
  });

  it('should detect Cyrillic character substitutions', () => {
    const original = 'microsoft';
    const spoofed = 'micrоsоft'; // Cyrillic 'o'

    expect(detector.hasHomoglyphs(spoofed)).toBe(true);
    expect(detector.normalizeHomoglyphs(spoofed)).toBe(original);
  });

  it('should detect number-letter substitutions', () => {
    expect(detector.hasHomoglyphs('g00gle')).toBe(true);
    expect(detector.hasHomoglyphs('app1e')).toBe(true);
  });

  it('should detect mixed script attacks', () => {
    const hasMixedScript = detector.detectMixedScript('pаypal'); // Cyrillic 'a'

    expect(hasMixedScript).toBe(true);
  });

  it('should provide similarity score between strings', () => {
    const similarity = detector.calculateSimilarity('microsoft', 'micros0ft');

    expect(similarity).toBeGreaterThan(0.8);
    expect(similarity).toBeLessThan(1);
  });

  it('should handle empty strings gracefully', () => {
    expect(detector.hasHomoglyphs('')).toBe(false);
    expect(detector.normalizeHomoglyphs('')).toBe('');
    expect(detector.levenshteinDistance('', '')).toBe(0);
  });
});

describe('FirstContactDetector Configuration', () => {
  it('should allow custom risk thresholds', () => {
    const config: FirstContactConfig = {
      domainAgeThresholds: {
        critical: 7,   // 7 days
        high: 30,      // 30 days
        medium: 90,    // 90 days
      },
      lookalikeThreshold: 2, // Levenshtein distance
      vipImpersonationWeight: 1.5,
      newDomainWeight: 1.2,
    };

    const detector = new FirstContactDetector(config);

    expect(detector.getConfig().domainAgeThresholds.critical).toBe(7);
  });

  it('should use sensible defaults', () => {
    const detector = new FirstContactDetector();
    const config = detector.getConfig();

    expect(config.domainAgeThresholds).toBeDefined();
    expect(config.lookalikeThreshold).toBeDefined();
  });
});
