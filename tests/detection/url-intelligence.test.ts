/**
 * URL Intelligence Tests - Phase 2
 *
 * TDD tests for enhanced URL analysis including:
 * - Domain age intelligence
 * - Lookalike domain detection
 * - URL obfuscation detection
 * - Redirect chain analysis
 * - WHOIS/DNS integration
 *
 * Expected Impact: +5 detection points
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  analyzeDomainAge,
  detectLookalikeDomain,
  detectURLObfuscation,
  analyzeRedirectChain,
  getURLIntelligence,
  type DomainAgeResult,
  type LookalikeResult,
  type ObfuscationResult,
  type RedirectChainResult,
  type URLIntelligenceResult,
} from '@/lib/detection/url-intelligence';

describe('URL Intelligence - Phase 2', () => {
  describe('Domain Age Intelligence', () => {
    it('should flag domains less than 30 days old as high risk', () => {
      const result = analyzeDomainAge('newdomain.com', {
        createdDate: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000), // 15 days ago
        registrar: 'Unknown Registrar',
      });

      expect(result.isNewDomain).toBe(true);
      expect(result.ageDays).toBeLessThan(30);
      expect(result.riskScore).toBeGreaterThanOrEqual(7);
      expect(result.signals).toContain('newly_registered_domain');
    });

    it('should flag domains 30-90 days old as medium risk', () => {
      const result = analyzeDomainAge('mediumnewdomain.com', {
        createdDate: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000), // 60 days ago
        registrar: 'GoDaddy',
      });

      expect(result.isNewDomain).toBe(true);
      expect(result.ageDays).toBeGreaterThanOrEqual(30);
      expect(result.ageDays).toBeLessThan(90);
      expect(result.riskScore).toBeGreaterThanOrEqual(4);
      expect(result.riskScore).toBeLessThan(7);
    });

    it('should trust domains older than 90 days', () => {
      const result = analyzeDomainAge('olddomain.com', {
        createdDate: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000), // 1 year ago
        registrar: 'MarkMonitor',
      });

      expect(result.isNewDomain).toBe(false);
      expect(result.riskScore).toBeLessThanOrEqual(2);
    });

    it('should flag privacy-protected WHOIS as slightly higher risk', () => {
      const result = analyzeDomainAge('privatedomain.com', {
        createdDate: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000),
        registrar: 'Domains By Proxy',
        privacyProtected: true,
      });

      expect(result.riskScore).toBeGreaterThan(1);
      expect(result.signals).toContain('privacy_protected_whois');
    });

    it('should trust well-known registrars', () => {
      const result = analyzeDomainAge('corporatedomain.com', {
        createdDate: new Date(Date.now() - 200 * 24 * 60 * 60 * 1000),
        registrar: 'MarkMonitor Inc',
      });

      expect(result.signals).toContain('reputable_registrar');
      expect(result.riskScore).toBeLessThanOrEqual(1);
    });

    it('should handle unknown WHOIS data gracefully', () => {
      const result = analyzeDomainAge('unknowndomain.com', {});

      expect(result.isNewDomain).toBe(false);
      expect(result.ageDays).toBe(-1); // Unknown
      expect(result.riskScore).toBeGreaterThanOrEqual(3); // Moderate risk when unknown
    });
  });

  describe('Lookalike Domain Detection', () => {
    it('should detect homoglyph attacks (similar-looking characters)', () => {
      // Using latin characters that look like cyrillic
      const result = detectLookalikeDomain('gооgle.com'); // 'o' replaced with cyrillic 'о'

      expect(result.isLookalike).toBe(true);
      expect(result.targetDomain).toBe('google.com');
      expect(result.technique).toBe('homoglyph');
      expect(result.riskScore).toBeGreaterThanOrEqual(9);
    });

    it('should detect character substitution (0 for o, 1 for l)', () => {
      const result = detectLookalikeDomain('g00gle.com');

      expect(result.isLookalike).toBe(true);
      expect(result.targetDomain).toBe('google.com');
      expect(result.technique).toBe('character_substitution');
      expect(result.riskScore).toBeGreaterThanOrEqual(8);
    });

    it('should detect character addition (extra letter)', () => {
      const result = detectLookalikeDomain('gooogle.com');

      expect(result.isLookalike).toBe(true);
      expect(result.targetDomain).toBe('google.com');
      expect(result.technique).toBe('character_addition');
    });

    it('should detect character omission', () => {
      const result = detectLookalikeDomain('gogle.com');

      expect(result.isLookalike).toBe(true);
      expect(result.targetDomain).toBe('google.com');
      expect(result.technique).toBe('character_omission');
    });

    it('should detect transposition attacks', () => {
      const result = detectLookalikeDomain('gogole.com');

      expect(result.isLookalike).toBe(true);
      expect(result.targetDomain).toBe('google.com');
      expect(result.technique).toBe('transposition');
    });

    it('should detect hyphen insertion attacks', () => {
      const result = detectLookalikeDomain('pay-pal.com');

      expect(result.isLookalike).toBe(true);
      expect(result.targetDomain).toBe('paypal.com');
      expect(result.technique).toBe('hyphen_insertion');
    });

    it('should detect TLD substitution', () => {
      const result = detectLookalikeDomain('google.co'); // Missing 'm'

      expect(result.isLookalike).toBe(true);
      expect(result.targetDomain).toBe('google.com');
      expect(result.technique).toBe('tld_substitution');
    });

    it('should detect subdomain impersonation', () => {
      const result = detectLookalikeDomain('login.microsoft.attacker.com');

      expect(result.isLookalike).toBe(true);
      expect(result.targetDomain).toBe('microsoft.com');
      expect(result.technique).toBe('subdomain_impersonation');
      expect(result.riskScore).toBeGreaterThanOrEqual(8);
    });

    it('should NOT flag legitimate domains', () => {
      const result = detectLookalikeDomain('genuinecompany.com');

      expect(result.isLookalike).toBe(false);
      expect(result.riskScore).toBe(0);
    });

    it('should detect Microsoft lookalikes', () => {
      const result = detectLookalikeDomain('micros0ft.com');

      expect(result.isLookalike).toBe(true);
      expect(result.targetDomain).toBe('microsoft.com');
    });

    it('should detect Amazon lookalikes', () => {
      const result = detectLookalikeDomain('arnazon.com');

      expect(result.isLookalike).toBe(true);
      expect(result.targetDomain).toBe('amazon.com');
    });

    it('should detect Apple lookalikes', () => {
      const result = detectLookalikeDomain('app1e.com');

      expect(result.isLookalike).toBe(true);
      expect(result.targetDomain).toBe('apple.com');
    });

    it('should detect bank lookalikes', () => {
      const result = detectLookalikeDomain('chasee.com');

      expect(result.isLookalike).toBe(true);
      expect(result.targetDomain).toBe('chase.com');
    });
  });

  describe('URL Obfuscation Detection', () => {
    it('should detect percent-encoded URLs', () => {
      // %2e = '.'
      const result = detectURLObfuscation('https://evil%2ecom/login');

      expect(result.isObfuscated).toBe(true);
      expect(result.technique).toBe('percent_encoding');
      expect(result.riskScore).toBeGreaterThanOrEqual(6);
    });

    it('should detect double encoding', () => {
      // %252e = %2e = '.'
      const result = detectURLObfuscation('https://evil%252ecom/login');

      expect(result.isObfuscated).toBe(true);
      expect(result.technique).toBe('double_encoding');
      expect(result.riskScore).toBeGreaterThanOrEqual(8);
    });

    it('should detect unicode normalization attacks', () => {
      // Using unicode characters that normalize to different values
      const result = detectURLObfuscation('https://ｅｖｉｌ.com/login'); // fullwidth chars

      expect(result.isObfuscated).toBe(true);
      expect(result.technique).toBe('unicode_normalization');
      expect(result.riskScore).toBeGreaterThanOrEqual(7);
    });

    it('should detect @ symbol in URL (credential prefix attack)', () => {
      const result = detectURLObfuscation('https://google.com@evil.com/login');

      expect(result.isObfuscated).toBe(true);
      expect(result.technique).toBe('credential_prefix');
      expect(result.riskScore).toBeGreaterThanOrEqual(9);
      expect(result.decodedUrl).toContain('evil.com');
    });

    it('should detect IP address in decimal format', () => {
      // 2130706433 = 127.0.0.1
      const result = detectURLObfuscation('http://2130706433/login');

      expect(result.isObfuscated).toBe(true);
      expect(result.technique).toBe('decimal_ip');
      expect(result.riskScore).toBeGreaterThanOrEqual(8);
    });

    it('should detect hex-encoded IP', () => {
      // 0x7f.0x00.0x00.0x01 = 127.0.0.1
      const result = detectURLObfuscation('http://0x7f.0x00.0x00.0x01/login');

      expect(result.isObfuscated).toBe(true);
      expect(result.technique).toBe('hex_ip');
      expect(result.riskScore).toBeGreaterThanOrEqual(8);
    });

    it('should detect URL shortener chains', () => {
      const result = detectURLObfuscation('https://bit.ly/abc123?url=https://tinyurl.com/xyz789');

      expect(result.isObfuscated).toBe(true);
      expect(result.technique).toBe('shortener_chain');
      expect(result.riskScore).toBeGreaterThanOrEqual(5);
    });

    it('should detect base64 encoded payloads in URLs', () => {
      const result = detectURLObfuscation(
        'https://example.com/redirect?url=aHR0cHM6Ly9ldmlsLmNvbS9sb2dpbg=='
      );

      expect(result.isObfuscated).toBe(true);
      expect(result.technique).toBe('base64_payload');
      expect(result.riskScore).toBeGreaterThanOrEqual(6);
    });

    it('should NOT flag normal URLs', () => {
      const result = detectURLObfuscation('https://www.google.com/search?q=test');

      expect(result.isObfuscated).toBe(false);
      expect(result.riskScore).toBe(0);
    });

    it('should NOT flag legitimate percent encoding', () => {
      // Space encoded as %20 in query string is normal
      const result = detectURLObfuscation('https://example.com/search?q=hello%20world');

      expect(result.isObfuscated).toBe(false);
    });
  });

  describe('Redirect Chain Analysis', () => {
    it('should flag long redirect chains as suspicious', () => {
      const result = analyzeRedirectChain([
        'https://link1.com/redirect',
        'https://link2.com/redirect',
        'https://link3.com/redirect',
        'https://link4.com/redirect',
        'https://final.com/target',
      ]);

      expect(result.isSuspicious).toBe(true);
      expect(result.chainLength).toBe(5);
      expect(result.riskScore).toBeGreaterThanOrEqual(6);
      expect(result.signals).toContain('long_redirect_chain');
    });

    it('should flag redirect chains through URL shorteners', () => {
      const result = analyzeRedirectChain([
        'https://bit.ly/abc',
        'https://tinyurl.com/xyz',
        'https://final.com/target',
      ]);

      expect(result.isSuspicious).toBe(true);
      expect(result.signals).toContain('multiple_shorteners');
      expect(result.riskScore).toBeGreaterThanOrEqual(5);
    });

    it('should flag redirect to different TLD', () => {
      const result = analyzeRedirectChain([
        'https://company.com/link',
        'https://company.ru/malicious',
      ]);

      expect(result.isSuspicious).toBe(true);
      expect(result.signals).toContain('tld_change');
      expect(result.riskScore).toBeGreaterThanOrEqual(4);
    });

    it('should flag HTTPS to HTTP downgrade', () => {
      const result = analyzeRedirectChain([
        'https://secure.com/link',
        'http://insecure.com/target',
      ]);

      expect(result.isSuspicious).toBe(true);
      expect(result.signals).toContain('https_downgrade');
      expect(result.riskScore).toBeGreaterThanOrEqual(5);
    });

    it('should flag redirect to IP address', () => {
      const result = analyzeRedirectChain([
        'https://example.com/link',
        'http://192.168.1.1/target',
      ]);

      expect(result.isSuspicious).toBe(true);
      expect(result.signals).toContain('redirect_to_ip');
      expect(result.riskScore).toBeGreaterThanOrEqual(6);
    });

    it('should NOT flag normal redirect chains', () => {
      const result = analyzeRedirectChain([
        'https://company.com/link',
        'https://company.com/target',
      ]);

      expect(result.isSuspicious).toBe(false);
      expect(result.riskScore).toBeLessThanOrEqual(1);
    });

    it('should flag redirect chain ending at suspicious TLD', () => {
      const result = analyzeRedirectChain([
        'https://company.com/link',
        'https://target.tk/phishing',
      ]);

      expect(result.isSuspicious).toBe(true);
      expect(result.signals).toContain('suspicious_final_tld');
    });

    it('should handle empty redirect chain', () => {
      const result = analyzeRedirectChain([]);

      expect(result.isSuspicious).toBe(false);
      expect(result.chainLength).toBe(0);
      expect(result.riskScore).toBe(0);
    });

    it('should handle single URL (no redirects)', () => {
      const result = analyzeRedirectChain(['https://example.com/direct']);

      expect(result.isSuspicious).toBe(false);
      expect(result.chainLength).toBe(1);
      expect(result.riskScore).toBe(0);
    });
  });

  describe('Comprehensive URL Intelligence', () => {
    it('should combine all intelligence sources', async () => {
      const result = await getURLIntelligence('https://g00gle.com/login', {
        checkDomainAge: true,
        checkLookalike: true,
        checkObfuscation: true,
      });

      expect(result.url).toBe('https://g00gle.com/login');
      expect(result.overallRiskScore).toBeGreaterThan(0);
      expect(result.signals.length).toBeGreaterThan(0);
      expect(result.lookalike?.isLookalike).toBe(true);
    });

    it('should flag highly suspicious URLs with combined indicators', async () => {
      const result = await getURLIntelligence('https://micr0s0ft.com@evil.com/login', {
        checkLookalike: true,
        checkObfuscation: true,
      });

      expect(result.overallRiskScore).toBeGreaterThanOrEqual(9);
      expect(result.verdict).toBe('malicious');
    });

    it('should clear legitimate URLs', async () => {
      const result = await getURLIntelligence('https://www.microsoft.com/products', {
        checkLookalike: true,
        checkObfuscation: true,
      });

      expect(result.overallRiskScore).toBeLessThanOrEqual(2);
      expect(result.verdict).toBe('safe');
    });

    it('should handle invalid URLs gracefully', async () => {
      const result = await getURLIntelligence('not-a-valid-url', {
        checkLookalike: true,
      });

      expect(result.parseError).toBe(true);
      expect(result.overallRiskScore).toBeGreaterThanOrEqual(5);
    });

    it('should provide detailed breakdown', async () => {
      const result = await getURLIntelligence('https://paypa1.com/login', {
        checkDomainAge: true,
        checkLookalike: true,
        checkObfuscation: true,
      });

      expect(result.breakdown).toBeDefined();
      expect(result.breakdown.lookalike).toBeDefined();
      expect(result.lookalike?.targetDomain).toBe('paypal.com');
    });
  });

  describe('High-Risk TLD Detection', () => {
    it('should flag free TLDs commonly used in phishing', () => {
      const result = detectLookalikeDomain('login-microsoft.tk');

      expect(result.signals).toContain('high_risk_tld');
      expect(result.riskScore).toBeGreaterThanOrEqual(5);
    });

    it('should flag recently abused TLDs', () => {
      const domains = [
        'secure-login.ml',
        'account-verify.ga',
        'update-info.cf',
        'reset-password.gq',
      ];

      for (const domain of domains) {
        const result = detectLookalikeDomain(domain);
        expect(result.signals).toContain('high_risk_tld');
      }
    });
  });

  describe('Brand Keyword Detection', () => {
    it('should detect brand keywords in non-brand domains', () => {
      const result = detectLookalikeDomain('microsoft-login.malicious.com');

      expect(result.isLookalike).toBe(true);
      expect(result.signals).toContain('brand_keyword_in_domain');
      expect(result.targetDomain).toBe('microsoft.com');
    });

    it('should detect multiple brand keywords', () => {
      const result = detectLookalikeDomain('amazon-paypal-secure.fake.com');

      expect(result.isLookalike).toBe(true);
      expect(result.signals).toContain('multiple_brand_keywords');
    });

    it('should NOT flag legitimate brand subdomains', () => {
      const result = detectLookalikeDomain('login.microsoft.com');

      expect(result.isLookalike).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should handle very long URLs', () => {
      const longUrl = 'https://example.com/' + 'a'.repeat(2000);
      const result = detectURLObfuscation(longUrl);

      expect(result.signals).toContain('excessive_url_length');
      expect(result.riskScore).toBeGreaterThanOrEqual(3);
    });

    it('should handle URLs with many query parameters', () => {
      const params = Array.from({ length: 50 }, (_, i) => `param${i}=value${i}`).join('&');
      const url = `https://example.com/page?${params}`;
      const result = detectURLObfuscation(url);

      expect(result.signals).toContain('excessive_parameters');
    });

    it('should handle internationalized domain names', () => {
      // Legitimate IDN
      const result = detectLookalikeDomain('münchen.de'); // German city

      // Should not flag legitimate foreign language domains
      // But should analyze carefully
      expect(result.signals).toContain('internationalized_domain');
    });

    it('should handle null/undefined inputs', () => {
      // @ts-expect-error - Testing runtime behavior
      const result1 = detectURLObfuscation(null);
      expect(result1.isObfuscated).toBe(false);

      // @ts-expect-error - Testing runtime behavior
      const result2 = detectLookalikeDomain(undefined);
      expect(result2.isLookalike).toBe(false);
    });
  });
});
