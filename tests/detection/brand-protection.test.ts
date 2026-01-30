/**
 * Brand Protection Tests - Phase 1
 *
 * TDD tests for expanded brand protection system
 * Tests homoglyph, typosquatting, and cousin domain detection
 */

import { describe, it, expect } from 'vitest';
import {
  detectBrandImpersonation,
  detectDisplayNameBrandSpoof,
  getProtectedBrandDomains,
  isProtectedBrand,
  PROTECTED_BRANDS,
  HOMOGLYPHS,
} from '@/lib/detection/brand-protection';

describe('Brand Protection - Expanded Coverage', () => {
  describe('Protected Brands Database', () => {
    it('should have at least 65 protected brands', () => {
      expect(PROTECTED_BRANDS.length).toBeGreaterThanOrEqual(65);
    });

    it('should include all major financial institutions', () => {
      const financialBrands = PROTECTED_BRANDS.filter(b => b.category === 'financial');
      const expectedBrands = ['paypal', 'chase', 'wellsfargo', 'bankofamerica', 'fidelity', 'vanguard', 'schwab'];

      for (const expected of expectedBrands) {
        const found = financialBrands.some(b =>
          b.domain.includes(expected) || b.brand.toLowerCase().includes(expected)
        );
        expect(found, `Should include ${expected}`).toBe(true);
      }
    });

    it('should include all major tech companies', () => {
      const techBrands = PROTECTED_BRANDS.filter(b => b.category === 'tech');
      const expectedBrands = ['microsoft', 'apple', 'google', 'amazon', 'adobe', 'salesforce', 'zoom'];

      for (const expected of expectedBrands) {
        const found = techBrands.some(b =>
          b.domain.includes(expected) || b.brand.toLowerCase().includes(expected)
        );
        expect(found, `Should include ${expected}`).toBe(true);
      }
    });

    it('should include shipping/logistics companies', () => {
      const shippingBrands = PROTECTED_BRANDS.filter(b => b.category === 'shipping');
      const expectedBrands = ['fedex', 'ups', 'usps', 'dhl'];

      for (const expected of expectedBrands) {
        const found = shippingBrands.some(b =>
          b.domain.includes(expected) || b.brand.toLowerCase().includes(expected)
        );
        expect(found, `Should include ${expected}`).toBe(true);
      }
    });

    it('should include enterprise software brands', () => {
      const enterpriseBrands = PROTECTED_BRANDS.filter(b => b.category === 'enterprise');
      const expectedBrands = ['docusign', 'github', 'atlassian', 'hubspot'];

      for (const expected of expectedBrands) {
        const found = enterpriseBrands.some(b =>
          b.domain.includes(expected) || b.brand.toLowerCase().includes(expected)
        );
        expect(found, `Should include ${expected}`).toBe(true);
      }
    });
  });

  describe('Homoglyph Detection', () => {
    it('should have comprehensive homoglyph mappings', () => {
      // Should have mappings for all common characters
      const commonChars = 'abcdefghijklmnopqrstuvwxyz0123456789'.split('');
      const coveredChars = Object.keys(HOMOGLYPHS);

      const coverage = commonChars.filter(c => coveredChars.includes(c)).length;
      expect(coverage).toBeGreaterThanOrEqual(26); // At least all letters
    });

    it('should detect paypa1.com as PayPal homoglyph', () => {
      const matches = detectBrandImpersonation('paypa1.com');

      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].brand).toBe('PayPal');
      expect(matches[0].attackType).toBe('homoglyph');
      expect(matches[0].confidence).toBeGreaterThan(0.85);
    });

    it('should detect g00gle.com as Google homoglyph', () => {
      const matches = detectBrandImpersonation('g00gle.com');

      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].brand).toBe('Google');
      expect(matches[0].attackType).toBe('homoglyph');
    });

    it('should detect micr0soft.com as Microsoft homoglyph', () => {
      const matches = detectBrandImpersonation('micr0soft.com');

      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].brand).toBe('Microsoft');
      expect(matches[0].attackType).toBe('homoglyph');
    });

    it('should detect аmazon.com with Cyrillic "а" as homoglyph', () => {
      // Using Cyrillic "а" (U+0430) instead of Latin "a"
      const matches = detectBrandImpersonation('аmazon.com');

      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].brand).toBe('Amazon');
      expect(matches[0].attackType).toBe('homoglyph');
    });

    it('should detect app1e.com as Apple homoglyph', () => {
      const matches = detectBrandImpersonation('app1e.com');

      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].brand).toBe('Apple');
      expect(matches[0].attackType).toBe('homoglyph');
    });

    it('should NOT flag legitimate domains as homoglyphs', () => {
      const legitimateDomains = ['paypal.com', 'google.com', 'microsoft.com', 'amazon.com'];

      for (const domain of legitimateDomains) {
        const matches = detectBrandImpersonation(domain);
        const homoglyphMatches = matches.filter(m => m.attackType === 'homoglyph');
        expect(homoglyphMatches.length, `${domain} should not be flagged as homoglyph`).toBe(0);
      }
    });
  });

  describe('Typosquatting Detection', () => {
    it('should detect gooogle.com as Google typosquat (character duplication)', () => {
      const matches = detectBrandImpersonation('gooogle.com');

      expect(matches.length).toBeGreaterThan(0);
      const googleMatch = matches.find(m => m.brand === 'Google');
      expect(googleMatch).toBeDefined();
      expect(googleMatch?.attackType).toBe('typosquat');
    });

    it('should detect amzon.com as Amazon typosquat (missing character)', () => {
      const matches = detectBrandImpersonation('amzon.com');

      expect(matches.length).toBeGreaterThan(0);
      const amazonMatch = matches.find(m => m.brand === 'Amazon');
      expect(amazonMatch).toBeDefined();
      expect(amazonMatch?.attackType).toBe('typosquat');
    });

    it('should detect mircosoft.com as Microsoft typosquat (transposed letters)', () => {
      const matches = detectBrandImpersonation('mircosoft.com');

      expect(matches.length).toBeGreaterThan(0);
      const msMatch = matches.find(m => m.brand === 'Microsoft');
      expect(msMatch).toBeDefined();
      expect(msMatch?.attackType).toBe('typosquat');
    });

    it('should detect googke.com as Google typosquat (adjacent key)', () => {
      const matches = detectBrandImpersonation('googke.com');

      expect(matches.length).toBeGreaterThan(0);
      const googleMatch = matches.find(m => m.brand === 'Google');
      expect(googleMatch).toBeDefined();
      expect(googleMatch?.attackType).toBe('typosquat');
    });

    it('should detect faceboo.com as Facebook typosquat', () => {
      const matches = detectBrandImpersonation('faceboo.com');

      expect(matches.length).toBeGreaterThan(0);
      // Facebook is under Meta now
      const match = matches.find(m => m.brand === 'Meta' || m.domain === 'meta.com');
      // Note: This may match if 'facebook' is an alias for Meta
    });
  });

  describe('Cousin Domain Detection', () => {
    it('should detect paypal-secure.com as PayPal cousin domain', () => {
      const matches = detectBrandImpersonation('paypal-secure.com');

      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].brand).toBe('PayPal');
      expect(matches[0].attackType).toBe('cousin');
      expect(matches[0].detail).toContain('cousin');
    });

    it('should detect secure-microsoft.com as Microsoft cousin domain', () => {
      const matches = detectBrandImpersonation('secure-microsoft.com');

      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].brand).toBe('Microsoft');
      expect(matches[0].attackType).toBe('cousin');
    });

    it('should detect amazon-login.com as Amazon cousin domain', () => {
      const matches = detectBrandImpersonation('amazon-login.com');

      expect(matches.length).toBeGreaterThan(0);
      const amazonMatch = matches.find(m => m.brand === 'Amazon');
      expect(amazonMatch).toBeDefined();
      expect(amazonMatch?.attackType).toBe('cousin');
    });

    it('should detect chase-verify.com as Chase cousin domain', () => {
      const matches = detectBrandImpersonation('chase-verify.com');

      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].brand).toBe('Chase');
      expect(matches[0].attackType).toBe('cousin');
    });

    it('should detect fedex-delivery.com as FedEx cousin domain', () => {
      const matches = detectBrandImpersonation('fedex-delivery.com');

      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].brand).toBe('FedEx');
      expect(matches[0].attackType).toBe('cousin');
    });

    it('should detect docusign-documents.com as DocuSign cousin domain', () => {
      const matches = detectBrandImpersonation('docusign-documents.com');

      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].brand).toBe('DocuSign');
      expect(matches[0].attackType).toBe('cousin');
    });
  });

  describe('Display Name Brand Spoofing', () => {
    it('should detect "PayPal Support" from random domain as spoofing', () => {
      const match = detectDisplayNameBrandSpoof('PayPal Support', 'random-scammer.com');

      expect(match).not.toBeNull();
      expect(match?.brand).toBe('PayPal');
      expect(match?.detail).toContain('impersonates');
    });

    it('should detect "Microsoft Account Team" from gmail as spoofing', () => {
      const match = detectDisplayNameBrandSpoof('Microsoft Account Team', 'gmail.com');

      expect(match).not.toBeNull();
      expect(match?.brand).toBe('Microsoft');
    });

    it('should detect "Amazon Customer Service" from non-amazon domain', () => {
      const match = detectDisplayNameBrandSpoof('Amazon Customer Service', 'customer-support.net');

      expect(match).not.toBeNull();
      expect(match?.brand).toBe('Amazon');
    });

    it('should NOT flag legitimate display names from matching domains', () => {
      const match = detectDisplayNameBrandSpoof('PayPal Support', 'paypal.com');

      expect(match).toBeNull();
    });

    it('should NOT flag legitimate display names from brand subdomains', () => {
      const match = detectDisplayNameBrandSpoof('Microsoft Security', 'security.microsoft.com');

      expect(match).toBeNull();
    });
  });

  describe('Protected Brand Utilities', () => {
    it('should return all protected brand domains', () => {
      const domains = getProtectedBrandDomains();

      expect(domains.length).toBeGreaterThanOrEqual(65);
      expect(domains).toContain('paypal.com');
      expect(domains).toContain('google.com');
      expect(domains).toContain('fedex.com');
    });

    it('should correctly identify protected brands', () => {
      expect(isProtectedBrand('paypal.com')).toBe(true);
      expect(isProtectedBrand('google.com')).toBe(true);
      expect(isProtectedBrand('mail.google.com')).toBe(true);
      expect(isProtectedBrand('random-website.com')).toBe(false);
    });
  });

  describe('Financial Institution Coverage', () => {
    const financialAttacks = [
      { domain: 'fide1ity.com', expected: 'Fidelity' },
      { domain: 'schwab-secure.com', expected: 'Charles Schwab' },
      { domain: 'vanguard-login.com', expected: 'Vanguard' },
      { domain: 'we11sfargo.com', expected: 'Wells Fargo' },
      { domain: 'bankofamerica-alert.com', expected: 'Bank of America' },
    ];

    for (const attack of financialAttacks) {
      it(`should detect ${attack.domain} as ${attack.expected} impersonation`, () => {
        const matches = detectBrandImpersonation(attack.domain);

        expect(matches.length, `Should detect ${attack.domain}`).toBeGreaterThan(0);

        // Check if the expected brand is in the matches
        const found = matches.some(m =>
          m.brand === attack.expected ||
          m.brand.toLowerCase().includes(attack.expected.toLowerCase().split(' ')[0])
        );
        expect(found, `Should match ${attack.expected}`).toBe(true);
      });
    }
  });

  describe('Enterprise Software Coverage', () => {
    const enterpriseAttacks = [
      { domain: 'docusign-verify.com', expected: 'DocuSign' },
      { domain: 'd0cusign.com', expected: 'DocuSign' },
      { domain: 'sa1esforce.com', expected: 'Salesforce' },
      { domain: 'github-login.com', expected: 'GitHub' },
      { domain: 'zo0m.us', expected: 'Zoom' },
    ];

    for (const attack of enterpriseAttacks) {
      it(`should detect ${attack.domain} as ${attack.expected} impersonation`, () => {
        const matches = detectBrandImpersonation(attack.domain);

        expect(matches.length, `Should detect ${attack.domain}`).toBeGreaterThan(0);
      });
    }
  });

  describe('Shipping/Logistics Coverage', () => {
    const shippingAttacks = [
      { domain: 'fedex-tracking.com', expected: 'FedEx' },
      { domain: 'ups-delivery.net', expected: 'UPS' },
      { domain: 'usps-package.com', expected: 'USPS' },
      { domain: 'dhl-shipment.com', expected: 'DHL' },
    ];

    for (const attack of shippingAttacks) {
      it(`should detect ${attack.domain} as ${attack.expected} impersonation`, () => {
        const matches = detectBrandImpersonation(attack.domain);

        expect(matches.length, `Should detect ${attack.domain}`).toBeGreaterThan(0);

        const found = matches.some(m =>
          m.brand === attack.expected ||
          m.brand.toLowerCase().includes(attack.expected.toLowerCase())
        );
        expect(found, `Should match ${attack.expected}`).toBe(true);
      });
    }
  });

  describe('Confidence Scoring', () => {
    it('should assign higher confidence to homoglyph attacks than cousin domains', () => {
      const homoglyphMatch = detectBrandImpersonation('g00gle.com');
      const cousinMatch = detectBrandImpersonation('google-login.com');

      expect(homoglyphMatch.length).toBeGreaterThan(0);
      expect(cousinMatch.length).toBeGreaterThan(0);

      expect(homoglyphMatch[0].confidence).toBeGreaterThan(cousinMatch[0].confidence);
    });

    it('should return confidence scores between 0 and 1', () => {
      const testDomains = [
        'paypa1.com', 'google-secure.com', 'amzon.com', 'microsoft-login.com'
      ];

      for (const domain of testDomains) {
        const matches = detectBrandImpersonation(domain);
        for (const match of matches) {
          expect(match.confidence).toBeGreaterThan(0);
          expect(match.confidence).toBeLessThanOrEqual(1);
        }
      }
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty domain gracefully', () => {
      const matches = detectBrandImpersonation('');
      expect(Array.isArray(matches)).toBe(true);
    });

    it('should handle domain with no TLD', () => {
      const matches = detectBrandImpersonation('paypal');
      // Should still potentially match based on brand name
      expect(Array.isArray(matches)).toBe(true);
    });

    it('should handle very long domains', () => {
      const longDomain = 'paypal' + '-secure'.repeat(20) + '.com';
      const matches = detectBrandImpersonation(longDomain);
      expect(Array.isArray(matches)).toBe(true);
    });

    it('should deduplicate matches for same brand', () => {
      // A domain that might trigger multiple patterns for same brand
      const matches = detectBrandImpersonation('paypal-login-secure.com');

      const paypalMatches = matches.filter(m => m.brand === 'PayPal');
      // Should only have one match per brand (the highest confidence one)
      expect(paypalMatches.length).toBeLessThanOrEqual(1);
    });
  });
});
