/**
 * Domain Age Detection Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  checkDomainAge,
  quickDomainAgeRisk,
  checkMultipleDomainAges,
} from '@/lib/threat-intel/domain/age';

// Mock the WHOIS module with all exports
vi.mock('@/lib/threat-intel/domain/whois', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/threat-intel/domain/whois')>();
  return {
    ...actual,
    lookupWhois: vi.fn(),
  };
});

describe('Domain Age Detection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('checkDomainAge', () => {
    it('should return low risk for trusted domains', async () => {
      const result = await checkDomainAge('google.com');

      expect(result.domain).toBe('google.com');
      expect(result.riskLevel).toBe('low');
      expect(result.riskScore).toBeLessThan(0.3);
      expect(result.indicators).toContain('trusted_domain');
    });

    it('should return low risk for subdomains of trusted domains', async () => {
      const result = await checkDomainAge('mail.google.com');

      expect(result.riskLevel).toBe('low');
      expect(result.indicators).toContain('trusted_domain');
    });

    it('should handle domains with suspicious TLDs', async () => {
      const { lookupWhois } = await import('@/lib/threat-intel/domain/whois');
      const mockLookupWhois = lookupWhois as ReturnType<typeof vi.fn>;

      mockLookupWhois.mockResolvedValue({
        domain: 'suspicious.xyz',
        createdDate: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000), // 60 days old
        registrar: 'Test Registrar',
      });

      const result = await checkDomainAge('suspicious.xyz');

      expect(result.indicators.some(i => i.startsWith('suspicious_tld'))).toBe(true);
      expect(result.riskScore).toBeGreaterThan(0.3);
    });

    it('should flag newly registered domains as high risk', async () => {
      const { lookupWhois } = await import('@/lib/threat-intel/domain/whois');
      const mockLookupWhois = lookupWhois as ReturnType<typeof vi.fn>;

      mockLookupWhois.mockResolvedValue({
        domain: 'brandnew.com',
        createdDate: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000), // 5 days old
        registrar: 'Test Registrar',
      });

      const result = await checkDomainAge('brandnew.com');

      expect(result.ageInDays).toBeLessThan(7);
      expect(result.riskLevel).toBe('critical');
      expect(result.riskScore).toBeGreaterThan(0.9);
      expect(result.indicators).toContain('newly_registered_critical');
    });

    it('should mark mature domains as low risk', async () => {
      const { lookupWhois } = await import('@/lib/threat-intel/domain/whois');
      const mockLookupWhois = lookupWhois as ReturnType<typeof vi.fn>;

      mockLookupWhois.mockResolvedValue({
        domain: 'established.com',
        createdDate: new Date(Date.now() - 3 * 365 * 24 * 60 * 60 * 1000), // 3 years old
        registrar: 'Test Registrar',
      });

      const result = await checkDomainAge('established.com');

      expect(result.ageInDays).toBeGreaterThan(365);
      expect(result.riskLevel).toBe('low');
      expect(result.indicators).toContain('mature_domain');
    });

    it('should handle WHOIS lookup errors gracefully', async () => {
      const { lookupWhois } = await import('@/lib/threat-intel/domain/whois');
      const mockLookupWhois = lookupWhois as ReturnType<typeof vi.fn>;

      mockLookupWhois.mockRejectedValue(new Error('WHOIS lookup failed'));

      const result = await checkDomainAge('unknown.com');

      expect(result.riskLevel).toBe('unknown');
      expect(result.indicators).toContain('whois_lookup_failed');
    });

    it('should detect privacy-protected registrations', async () => {
      const { lookupWhois } = await import('@/lib/threat-intel/domain/whois');
      const mockLookupWhois = lookupWhois as ReturnType<typeof vi.fn>;

      mockLookupWhois.mockResolvedValue({
        domain: 'private.com',
        createdDate: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000), // 45 days old
        registrar: 'Test Registrar',
        registrant: {
          name: 'REDACTED FOR PRIVACY',
          organization: 'Privacy Protection Service',
        },
      });

      const result = await checkDomainAge('private.com');

      expect(result.indicators).toContain('privacy_protected');
    });
  });

  describe('quickDomainAgeRisk', () => {
    it('should return low for trusted domains', () => {
      const result = quickDomainAgeRisk('microsoft.com');

      expect(result.riskLevel).toBe('low');
      expect(result.reason).toBe('trusted_domain');
    });

    it('should return high for suspicious TLDs', () => {
      const result = quickDomainAgeRisk('suspicious.tk');

      expect(result.riskLevel).toBe('high');
      expect(result.reason).toContain('suspicious_tld');
    });

    it('should detect numeric patterns', () => {
      const result = quickDomainAgeRisk('domain12345.com');

      expect(result.riskLevel).toBe('medium');
      expect(result.reason).toBe('numeric_pattern');
    });

    it('should detect long domains', () => {
      const result = quickDomainAgeRisk('this-is-a-very-very-very-long-domain-name.com');

      expect(result.riskLevel).toBe('medium');
      expect(result.reason).toBe('long_domain');
    });

    it('should detect excessive hyphens', () => {
      // Use a shorter domain with excessive hyphens
      const result = quickDomainAgeRisk('a-b-c-d-e.com');

      expect(result.riskLevel).toBe('medium');
      expect(result.reason).toBe('excessive_hyphens');
    });
  });

  describe('checkMultipleDomainAges', () => {
    it('should check multiple domains in parallel', async () => {
      const { lookupWhois } = await import('@/lib/threat-intel/domain/whois');
      const mockLookupWhois = lookupWhois as ReturnType<typeof vi.fn>;

      mockLookupWhois.mockResolvedValue({
        domain: 'test.com',
        createdDate: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
        registrar: 'Test',
      });

      const domains = ['google.com', 'test.com', 'example.org'];
      const results = await checkMultipleDomainAges(domains);

      expect(results.size).toBe(3);
      expect(results.has('google.com')).toBe(true);
      expect(results.has('test.com')).toBe(true);
      expect(results.has('example.org')).toBe(true);
    });

    it('should deduplicate domains', async () => {
      const { lookupWhois } = await import('@/lib/threat-intel/domain/whois');
      const mockLookupWhois = lookupWhois as ReturnType<typeof vi.fn>;

      mockLookupWhois.mockResolvedValue({
        domain: 'test.com',
        createdDate: new Date(),
        registrar: 'Test',
      });

      const domains = ['test.com', 'sub.test.com', 'TEST.COM'];
      const results = await checkMultipleDomainAges(domains);

      // All should resolve to test.com
      expect(results.has('test.com')).toBe(true);
    });
  });
});

// WHOIS Lookup tests are in a separate file to avoid mock interference
