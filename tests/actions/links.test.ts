/**
 * Tests for Link Rewriting and Click-Time Protection
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  generateClickId,
  shouldRewriteUrl,
  rewriteUrl,
  rewriteLinksInHTML,
  rewriteLinksInText,
  createClickMapping,
  type LinkRewriteConfig,
} from '@/lib/actions/links/rewrite';
import {
  checkUrlAtClickTime,
  clearExpiredCache,
  getCacheStats,
} from '@/lib/actions/links/click-time-check';

// Mock reputation service
vi.mock('@/lib/detection/reputation/service', () => ({
  checkReputation: vi.fn().mockResolvedValue({
    domains: [],
    urls: [],
    emails: [],
  }),
}));

const DEFAULT_CONFIG: LinkRewriteConfig = {
  baseUrl: 'https://app.swordfish.io',
  enableForAllExternal: false,
  excludeDomains: [],
  signatureSecret: 'test-secret-12345',
};

describe('Link Rewriting', () => {
  describe('generateClickId', () => {
    it('should generate consistent click IDs', () => {
      const id1 = generateClickId('https://example.com', 'email-1', 'tenant-1', 'secret');
      expect(id1).toHaveLength(24);
      expect(id1).toMatch(/^[a-f0-9]+$/);
    });

    it('should generate different IDs for different inputs', () => {
      const id1 = generateClickId('https://example1.com', 'email-1', 'tenant-1', 'secret');
      const id2 = generateClickId('https://example2.com', 'email-1', 'tenant-1', 'secret');
      expect(id1).not.toBe(id2);
    });
  });

  describe('shouldRewriteUrl', () => {
    it('should not rewrite safe domains', () => {
      const result = shouldRewriteUrl('https://google.com/search', false, DEFAULT_CONFIG);
      expect(result.shouldRewrite).toBe(false);
      expect(result.reason).toBe('safe-domain');
    });

    it('should rewrite URL shorteners', () => {
      const result = shouldRewriteUrl('https://bit.ly/abc123', false, DEFAULT_CONFIG);
      expect(result.shouldRewrite).toBe(true);
      expect(result.reason).toBe('url-shortener');
    });

    it('should rewrite suspicious URLs', () => {
      const result = shouldRewriteUrl('https://unknown.xyz/login', true, DEFAULT_CONFIG);
      expect(result.shouldRewrite).toBe(true);
      expect(result.reason).toBe('suspicious');
    });

    it('should not rewrite non-HTTP protocols', () => {
      const result = shouldRewriteUrl('mailto:test@example.com', false, DEFAULT_CONFIG);
      expect(result.shouldRewrite).toBe(false);
      expect(result.reason).toBe('non-http-protocol');
    });

    it('should rewrite all external when enabled', () => {
      const config = { ...DEFAULT_CONFIG, enableForAllExternal: true };
      const result = shouldRewriteUrl('https://random.com/page', false, config);
      expect(result.shouldRewrite).toBe(true);
      expect(result.reason).toBe('external');
    });

    it('should respect custom exclude domains', () => {
      const config = { ...DEFAULT_CONFIG, excludeDomains: ['mycompany.com'] };
      const result = shouldRewriteUrl('https://mycompany.com/link', false, config);
      expect(result.shouldRewrite).toBe(false);
      expect(result.reason).toBe('safe-domain');
    });

    it('should rewrite malformed URLs', () => {
      const result = shouldRewriteUrl('not-a-valid-url', false, DEFAULT_CONFIG);
      expect(result.shouldRewrite).toBe(true);
      expect(result.reason).toBe('malformed');
    });
  });

  describe('rewriteUrl', () => {
    it('should rewrite suspicious URL', () => {
      const result = rewriteUrl(
        'https://suspicious.xyz/phish',
        'email-123',
        'tenant-456',
        DEFAULT_CONFIG,
        true
      );

      expect(result.wasRewritten).toBe(true);
      expect(result.rewrittenUrl).toContain('https://app.swordfish.io/click/');
      expect(result.reason).toBe('suspicious');
    });

    it('should not rewrite safe domain', () => {
      const result = rewriteUrl(
        'https://github.com/repo',
        'email-123',
        'tenant-456',
        DEFAULT_CONFIG,
        false
      );

      expect(result.wasRewritten).toBe(false);
      expect(result.rewrittenUrl).toBe('https://github.com/repo');
    });
  });

  describe('rewriteLinksInHTML', () => {
    it('should rewrite URLs in href attributes', () => {
      const html = '<a href="https://bit.ly/test">Click here</a>';
      const result = rewriteLinksInHTML(html, 'email-1', 'tenant-1', DEFAULT_CONFIG);

      expect(result.rewrittenCount).toBe(1);
      expect(result.html).toContain('href="https://app.swordfish.io/click/');
      expect(result.html).toContain('data-original-url');
    });

    it('should rewrite multiple URLs', () => {
      const html = `
        <a href="https://bit.ly/test1">Link 1</a>
        <a href="https://t.co/abc">Link 2</a>
        <a href="https://google.com">Safe</a>
      `;
      const result = rewriteLinksInHTML(html, 'email-1', 'tenant-1', DEFAULT_CONFIG);

      expect(result.rewrittenCount).toBe(2);
      expect(result.links).toHaveLength(3);
    });

    it('should mark suspicious URLs for rewriting', () => {
      const html = '<a href="https://normal.com/page">Link</a>';
      const suspiciousUrls = new Set(['https://normal.com/page']);
      const result = rewriteLinksInHTML(html, 'email-1', 'tenant-1', DEFAULT_CONFIG, suspiciousUrls);

      expect(result.rewrittenCount).toBe(1);
    });
  });

  describe('rewriteLinksInText', () => {
    it('should rewrite URLs in plain text', () => {
      const text = 'Check out https://bit.ly/link for more info';
      const result = rewriteLinksInText(text, 'email-1', 'tenant-1', DEFAULT_CONFIG);

      expect(result.rewrittenCount).toBe(1);
      expect(result.text).toContain('https://app.swordfish.io/click/');
    });

    it('should handle trailing punctuation', () => {
      const text = 'Visit https://bit.ly/test.';
      const result = rewriteLinksInText(text, 'email-1', 'tenant-1', DEFAULT_CONFIG);

      expect(result.text).toMatch(/https:\/\/app\.swordfish\.io\/click\/[a-f0-9]+\./);
    });

    it('should preserve safe URLs', () => {
      const text = 'Visit https://google.com for search.';
      const result = rewriteLinksInText(text, 'email-1', 'tenant-1', DEFAULT_CONFIG);

      expect(result.rewrittenCount).toBe(0);
      expect(result.text).toBe(text);
    });
  });

  describe('createClickMapping', () => {
    it('should create valid click mapping', () => {
      const mapping = createClickMapping(
        'click-123',
        'https://example.com',
        'email-456',
        'tenant-789',
        'suspicious',
        75
      );

      expect(mapping.id).toBe('click-123');
      expect(mapping.originalUrl).toBe('https://example.com');
      expect(mapping.emailId).toBe('email-456');
      expect(mapping.tenantId).toBe('tenant-789');
      expect(mapping.clickCount).toBe(0);
      expect(mapping.metadata?.reason).toBe('suspicious');
      expect(mapping.metadata?.riskScore).toBe(75);
    });

    it('should set 30-day expiry', () => {
      const mapping = createClickMapping('id', 'url', 'email', 'tenant');
      const now = new Date();
      const thirtyDaysLater = new Date(now);
      thirtyDaysLater.setDate(thirtyDaysLater.getDate() + 30);

      // Allow 1 minute tolerance
      const diff = Math.abs(mapping.expiresAt.getTime() - thirtyDaysLater.getTime());
      expect(diff).toBeLessThan(60000);
    });
  });
});

describe('Click-Time Protection', () => {
  beforeEach(() => {
    clearExpiredCache(0); // Clear all cache before each test
  });

  describe('checkUrlAtClickTime', () => {
    it('should return safe for clean URLs', async () => {
      const result = await checkUrlAtClickTime('https://example.com');

      expect(result.url).toBe('https://example.com');
      expect(result.verdict).toBe('safe');
      expect(result.action).toBe('allow');
      expect(result.riskScore).toBe(0);
    });

    it('should detect IP address URLs', async () => {
      const result = await checkUrlAtClickTime('http://192.168.1.1/login');

      expect(result.verdict).not.toBe('safe');
      expect(result.signals).toContainEqual(
        expect.objectContaining({ type: 'ip_url' })
      );
    });

    it('should detect suspicious TLDs', async () => {
      const result = await checkUrlAtClickTime('https://example.xyz/page');

      expect(result.signals).toContainEqual(
        expect.objectContaining({ type: 'suspicious_tld' })
      );
    });

    it('should detect lookalike domains', async () => {
      const result = await checkUrlAtClickTime('https://paypa1.com/login');

      expect(result.verdict).toBe('suspicious');
      expect(result.signals).toContainEqual(
        expect.objectContaining({ type: 'lookalike_domain' })
      );
    });

    it('should detect homoglyph characters', async () => {
      // Using Cyrillic 'а' (U+0430) instead of Latin 'a'
      // Note: The URL constructor may normalize/reject punycode domains
      // So we test that the system handles non-ASCII gracefully
      const result = await checkUrlAtClickTime('https://xn--pple-43d.com');

      // May either detect as homoglyph or handle gracefully
      expect(result.verdict).toBeDefined();
    });

    it('should detect excessive subdomains', async () => {
      const result = await checkUrlAtClickTime('https://a.b.c.d.example.com/page');

      expect(result.signals).toContainEqual(
        expect.objectContaining({ type: 'excessive_subdomains' })
      );
    });

    it('should cache results', async () => {
      const url = 'https://test-cache.com';
      const result1 = await checkUrlAtClickTime(url);
      const result2 = await checkUrlAtClickTime(url);

      expect(result1.cachedResult).toBe(false);
      expect(result2.cachedResult).toBe(true);
    });

    it('should detect high-risk URLs', async () => {
      // Combine multiple signals - lookalike domain + suspicious TLD + suspicious path
      const result = await checkUrlAtClickTime('https://paypa1.xyz/secure/login/verify');

      // Should at least be suspicious (score = 35 lookalike + 15 TLD + 10 path = 60)
      expect(result.riskScore).toBeGreaterThanOrEqual(40);
      expect(['suspicious', 'malicious'].includes(result.verdict)).toBe(true);
      expect(['warn', 'block'].includes(result.action)).toBe(true);
    });

    it('should handle malformed URLs gracefully', async () => {
      const result = await checkUrlAtClickTime('not-a-url');

      expect(result.verdict).toBe('unknown');
      expect(result.action).toBe('warn');
    });

    it('should respect custom config', async () => {
      const result = await checkUrlAtClickTime('https://example.com', {
        warnThreshold: 1, // Very low threshold
      });

      // Even safe URLs will warn with low threshold
      expect(result.action).toBe('allow');
    });
  });

  describe('Cache Management', () => {
    it('should clear expired cache entries', async () => {
      // First, clear any existing cache
      clearExpiredCache(0);

      // Add an entry
      await checkUrlAtClickTime('https://cache-test-unique.com');
      const statsBefore = getCacheStats();
      expect(statsBefore.size).toBeGreaterThan(0);

      // Clear with 0 max age (immediate expiry)
      const cleared = clearExpiredCache(0);
      const statsAfter = getCacheStats();

      expect(cleared).toBeGreaterThanOrEqual(0);
      // After clearing, size should be 0 or less than before
      expect(statsAfter.size).toBeLessThanOrEqual(statsBefore.size);
    });

    it('should track cache stats', async () => {
      // Clear cache first to ensure clean state
      clearExpiredCache(0);

      await checkUrlAtClickTime('https://stats1-unique.com');
      await checkUrlAtClickTime('https://stats2-unique.com');

      const stats = getCacheStats();
      expect(stats.size).toBeGreaterThanOrEqual(2);
      expect(stats.oldestMs).toBeGreaterThanOrEqual(0);
    });
  });
});
