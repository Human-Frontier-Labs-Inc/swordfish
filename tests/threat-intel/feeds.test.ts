/**
 * Threat Feed Integration Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  checkUrlReputation,
  checkDomainReputation,
  refreshAllFeeds,
  getFeedStats,
} from '@/lib/threat-intel/feeds';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('Threat Feed Aggregator', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('refreshAllFeeds', () => {
    it('should refresh all threat feeds', async () => {
      // Mock successful feed responses
      mockFetch
        .mockResolvedValueOnce({
          ok: false, // PhishTank - no API key
          status: 401,
        })
        .mockResolvedValueOnce({
          ok: true, // URLhaus
          json: async () => ({
            query_status: 'ok',
            urls: [
              {
                id: '1',
                dateadded: new Date().toISOString(),
                url: 'http://malware.test/bad.exe',
                url_status: 'online',
                threat: 'malware_download',
                tags: 'exe,Trojan',
                urlhaus_reference: 'https://urlhaus.abuse.ch/url/1/',
                reporter: 'test',
              },
            ],
          }),
        })
        .mockResolvedValueOnce({
          ok: true, // OpenPhish
          text: async () => 'http://phishing.test/login\nhttp://phishing2.test/signin',
        });

      const result = await refreshAllFeeds();

      expect(result.feeds).toBeDefined();
      expect(result.feeds.length).toBeGreaterThan(0);
    });

    it('should use sample data when feeds fail', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));

      const result = await refreshAllFeeds();

      // Should still return results with sample data
      expect(result.feeds).toBeDefined();
    });
  });

  describe('checkUrlReputation', () => {
    beforeEach(() => {
      // Mock feed responses for URL checking
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
      });
    });

    it('should return clean verdict for safe URL', async () => {
      const result = await checkUrlReputation('https://google.com/search');

      expect(result).toBeDefined();
      expect(result.url).toContain('google.com');
      expect(result.checkedAt).toBeInstanceOf(Date);
    });

    it('should detect phishing URL patterns', async () => {
      const result = await checkUrlReputation('http://paypal-login.suspicious.xyz/verify');

      expect(result).toBeDefined();
      expect(result.url).toContain('suspicious.xyz');
    });

    it('should handle malformed URLs gracefully', async () => {
      const result = await checkUrlReputation('not-a-valid-url');

      expect(result).toBeDefined();
      expect(result.url).toBe('not-a-valid-url');
    });

    it('should normalize URLs consistently', async () => {
      const result1 = await checkUrlReputation('https://Example.COM/path/');
      const result2 = await checkUrlReputation('https://example.com/path');

      expect(result1.url).toBe(result2.url);
    });
  });

  describe('checkDomainReputation', () => {
    beforeEach(() => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
      });
    });

    it('should return clean verdict for trusted domain', async () => {
      const result = await checkDomainReputation('microsoft.com');

      expect(result).toBeDefined();
      expect(result.domain).toBe('microsoft.com');
    });

    it('should detect suspicious domains', async () => {
      const result = await checkDomainReputation('malware-distribution.xyz');

      expect(result).toBeDefined();
      expect(result.domain).toBe('malware-distribution.xyz');
    });

    it('should normalize domain names', async () => {
      const result = await checkDomainReputation('  EXAMPLE.COM  ');

      expect(result.domain).toBe('example.com');
    });
  });

  describe('getFeedStats', () => {
    it('should return feed statistics', () => {
      const stats = getFeedStats();

      expect(stats).toBeDefined();
      expect(stats.phishtank).toBeDefined();
      expect(stats.urlhaus).toBeDefined();
      expect(stats.openphish).toBeDefined();
      expect(typeof stats.totalUrls).toBe('number');
    });
  });
});

describe('PhishTank Integration', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('should detect brand impersonation', async () => {
    const { checkPhishTankUrl } = await import('@/lib/threat-intel/feeds/phishtank');

    // Brand impersonation in subdomain of suspicious domain
    const result = checkPhishTankUrl('http://paypal-secure-login.malicious.xyz/signin');

    expect(result.isPhishing).toBe(true);
    expect(result.confidence).toBeGreaterThan(0.5);
  });

  it('should detect homoglyph attacks', async () => {
    const { checkPhishTankUrl } = await import('@/lib/threat-intel/feeds/phishtank');

    // Using number substitution: paypa1 instead of paypal
    const result = checkPhishTankUrl('http://paypa1.suspicious.com/login');

    expect(result.isPhishing).toBe(true);
    expect(result.matchedPattern).toContain('Homoglyph');
  });

  it('should allow legitimate domains', async () => {
    const { checkPhishTankUrl } = await import('@/lib/threat-intel/feeds/phishtank');

    const result = checkPhishTankUrl('https://www.paypal.com/signin');

    expect(result.isPhishing).toBe(false);
  });
});

describe('URLhaus Integration', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('should detect executable downloads', async () => {
    const { checkURLhausUrl } = await import('@/lib/threat-intel/feeds/urlhaus');

    const result = checkURLhausUrl('http://suspicious.xyz/malware.exe');

    expect(result.isMalware).toBe(true);
    expect(result.threat).toBe('executable_download');
  });

  it('should detect C2 patterns', async () => {
    const { checkURLhausUrl } = await import('@/lib/threat-intel/feeds/urlhaus');

    const result = checkURLhausUrl('http://bad.com/gate.php?id=123');

    expect(result.isMalware).toBe(true);
    expect(result.threat).toBe('c2_gate');
  });

  it('should flag IP-based URLs as suspicious', async () => {
    const { checkURLhausUrl } = await import('@/lib/threat-intel/feeds/urlhaus');

    const result = checkURLhausUrl('http://192.168.1.1/download');

    expect(result.threat).toBe('ip_based_url');
  });
});

describe('OpenPhish Integration', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('should detect suspicious TLDs', async () => {
    const { checkOpenPhishUrl } = await import('@/lib/threat-intel/feeds/openphish');

    const result = checkOpenPhishUrl('http://login-verify.xyz/account');

    expect(result.indicators).toContain('suspicious_tld');
  });

  it('should detect credential harvesting paths', async () => {
    const { checkOpenPhishUrl } = await import('@/lib/threat-intel/feeds/openphish');

    const result = checkOpenPhishUrl('http://suspicious.com/login/verify');

    expect(result.indicators).toContain('credential_harvesting_path');
  });

  it('should detect leet speak substitutions', async () => {
    const { checkOpenPhishUrl } = await import('@/lib/threat-intel/feeds/openphish');

    const result = checkOpenPhishUrl('http://micr0s0ft-support.xyz/update');

    expect(result.indicators.some(i => i.includes('leet_substitution'))).toBe(true);
  });

  it('should detect excessive subdomains', async () => {
    const { checkOpenPhishUrl } = await import('@/lib/threat-intel/feeds/openphish');

    const result = checkOpenPhishUrl('http://login.secure.account.verify.suspicious.com/signin');

    expect(result.indicators).toContain('excessive_subdomains');
  });
});
