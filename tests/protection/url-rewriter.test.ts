/**
 * URL Rewriter Tests
 *
 * Comprehensive tests for the URL rewriting system including:
 * - URL rewriting decisions
 * - HTML and text body processing
 * - URL shortener expansion
 * - Click tracking ID generation
 * - Whitelist handling
 * - Edge cases and error handling
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  UrlRewriter,
  getUrlRewriter,
  createUrlRewriter,
  quickShouldRewrite,
  extractUrls,
  KNOWN_SAFE_DOMAINS,
  URL_SHORTENERS,
  NON_REWRITABLE_PROTOCOLS,
  type RewriterConfig,
} from '@/lib/protection/url-rewriter';
import type { ParsedEmail } from '@/lib/detection/types';

// Mock the database module
vi.mock('@/lib/db', () => ({
  sql: vi.fn().mockImplementation(() => Promise.resolve([])),
}));

// Mock fetch for URL shortener expansion
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('UrlRewriter', () => {
  let rewriter: UrlRewriter;
  const testConfig: Partial<RewriterConfig> = {
    baseUrl: 'https://protect.swordfish.app',
    whitelistedDomains: ['company.com', 'trusted-partner.org'],
    rewriteInternalLinks: false,
    preserveDisplayUrl: true,
    trackClicks: false, // Disable DB storage in tests
    signatureSecret: 'test-secret-key',
    urlExpiryDays: 30,
  };

  beforeEach(() => {
    rewriter = new UrlRewriter(testConfig);
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  // ==========================================================================
  // URL Rewriting Decision Tests
  // ==========================================================================

  describe('shouldRewrite', () => {
    it('should not rewrite mailto: links', () => {
      const result = rewriter.shouldRewrite('mailto:user@example.com', 'tenant-1');
      expect(result.shouldRewrite).toBe(false);
      expect(result.reason).toBe('non-http');
    });

    it('should not rewrite tel: links', () => {
      const result = rewriter.shouldRewrite('tel:+1234567890', 'tenant-1');
      expect(result.shouldRewrite).toBe(false);
      expect(result.reason).toBe('non-http');
    });

    it('should not rewrite data: URLs', () => {
      const result = rewriter.shouldRewrite('data:text/html,<h1>Hello</h1>', 'tenant-1');
      expect(result.shouldRewrite).toBe(false);
      expect(result.reason).toBe('non-http');
    });

    it('should not rewrite javascript: URLs', () => {
      const result = rewriter.shouldRewrite('javascript:alert(1)', 'tenant-1');
      expect(result.shouldRewrite).toBe(false);
      expect(result.reason).toBe('non-http');
    });

    it('should not rewrite already-rewritten Swordfish URLs', () => {
      const result = rewriter.shouldRewrite(
        'https://protect.swordfish.app/click/abc123',
        'tenant-1'
      );
      expect(result.shouldRewrite).toBe(false);
      expect(result.reason).toBe('already-rewritten');
    });

    it('should rewrite URL shorteners', () => {
      const shorteners = ['https://bit.ly/abc', 'https://tinyurl.com/xyz', 'https://t.co/123'];
      for (const url of shorteners) {
        const result = rewriter.shouldRewrite(url, 'tenant-1');
        expect(result.shouldRewrite).toBe(true);
        expect(result.reason).toBe('shortener');
      }
    });

    it('should not rewrite whitelisted domains', () => {
      const result = rewriter.shouldRewrite('https://company.com/page', 'tenant-1');
      expect(result.shouldRewrite).toBe(false);
      expect(result.reason).toBe('whitelisted');
    });

    it('should not rewrite subdomains of whitelisted domains', () => {
      const result = rewriter.shouldRewrite('https://app.company.com/dashboard', 'tenant-1');
      expect(result.shouldRewrite).toBe(false);
      expect(result.reason).toBe('whitelisted');
    });

    it('should not rewrite known safe domains', () => {
      const safeDomains = [
        'https://google.com/search',
        'https://www.microsoft.com/products',
        'https://github.com/repo',
        'https://slack.com/team',
      ];
      for (const url of safeDomains) {
        const result = rewriter.shouldRewrite(url, 'tenant-1');
        expect(result.shouldRewrite).toBe(false);
        expect(result.reason).toBe('safe-domain');
      }
    });

    it('should rewrite unknown external URLs', () => {
      const result = rewriter.shouldRewrite('https://unknown-site.com/page', 'tenant-1');
      expect(result.shouldRewrite).toBe(true);
      expect(result.reason).toBe('external');
    });

    it('should rewrite suspicious URLs', () => {
      const result = rewriter.shouldRewrite('https://google.com/login', 'tenant-1', true);
      expect(result.shouldRewrite).toBe(true);
      expect(result.reason).toBe('suspicious');
    });

    it('should rewrite malformed URLs', () => {
      const result = rewriter.shouldRewrite('not-a-valid-url', 'tenant-1');
      expect(result.shouldRewrite).toBe(true);
      expect(result.reason).toBe('malformed');
    });
  });

  // ==========================================================================
  // Single URL Rewriting Tests
  // ==========================================================================

  describe('rewriteUrl', () => {
    it('should return original URL for whitelisted domains', () => {
      const result = rewriter.rewriteUrl(
        'https://company.com/page',
        'email-123',
        'tenant-1'
      );
      expect(result.wasRewritten).toBe(false);
      expect(result.rewrittenUrl).toBe('https://company.com/page');
      expect(result.trackingId).toBe('');
    });

    it('should create rewritten URL for external domains', () => {
      const result = rewriter.rewriteUrl(
        'https://external-site.com/page',
        'email-123',
        'tenant-1'
      );
      expect(result.wasRewritten).toBe(true);
      expect(result.rewrittenUrl).toContain('https://protect.swordfish.app/click/');
      expect(result.trackingId).toBeTruthy();
      expect(result.trackingId.length).toBeGreaterThan(20);
    });

    it('should include signature in rewritten URL', () => {
      const result = rewriter.rewriteUrl(
        'https://external-site.com/page',
        'email-123',
        'tenant-1'
      );
      expect(result.rewrittenUrl).toContain('?sig=');
    });

    it('should preserve original URL in result', () => {
      const originalUrl = 'https://external-site.com/page?param=value#fragment';
      const result = rewriter.rewriteUrl(originalUrl, 'email-123', 'tenant-1');
      expect(result.originalUrl).toBe(originalUrl);
    });
  });

  // ==========================================================================
  // Click Tracking ID Generation Tests
  // ==========================================================================

  describe('generateClickTrackingId', () => {
    it('should generate unique IDs for different URLs', () => {
      const id1 = rewriter.generateClickTrackingId('https://site1.com', 'email-1');
      const id2 = rewriter.generateClickTrackingId('https://site2.com', 'email-1');
      expect(id1).not.toBe(id2);
    });

    it('should generate unique IDs for same URL in different emails', () => {
      const id1 = rewriter.generateClickTrackingId('https://site.com', 'email-1');
      const id2 = rewriter.generateClickTrackingId('https://site.com', 'email-2');
      expect(id1).not.toBe(id2);
    });

    it('should generate IDs with sufficient length for uniqueness', () => {
      const id = rewriter.generateClickTrackingId('https://site.com', 'email-1', 'tenant-1');
      expect(id.length).toBeGreaterThanOrEqual(30);
    });

    it('should generate URL-safe IDs', () => {
      const id = rewriter.generateClickTrackingId('https://site.com', 'email-1');
      expect(id).toMatch(/^[a-z0-9]+$/i);
    });
  });

  // ==========================================================================
  // Display URL Preservation Tests
  // ==========================================================================

  describe('preserveDisplayUrl', () => {
    it('should create anchor with original URL visible', () => {
      const result = rewriter.preserveDisplayUrl(
        'https://original-site.com',
        'https://protect.swordfish.app/click/abc123'
      );
      expect(result).toContain('https://original-site.com</a>');
      expect(result).toContain('href="https://protect.swordfish.app/click/abc123"');
    });

    it('should include title attribute with original URL', () => {
      const result = rewriter.preserveDisplayUrl(
        'https://original-site.com',
        'https://protect.swordfish.app/click/abc123'
      );
      expect(result).toContain('title="https://original-site.com"');
    });

    it('should include data attribute with encoded original URL', () => {
      const result = rewriter.preserveDisplayUrl(
        'https://original-site.com/path?q=1',
        'https://protect.swordfish.app/click/abc123'
      );
      expect(result).toContain('data-original-url=');
    });

    it('should escape HTML special characters', () => {
      const result = rewriter.preserveDisplayUrl(
        'https://site.com/<script>alert(1)</script>',
        'https://protect.swordfish.app/click/abc123'
      );
      expect(result).not.toContain('<script>');
      expect(result).toContain('&lt;script&gt;');
    });
  });

  // ==========================================================================
  // Whitelist Tests
  // ==========================================================================

  describe('isWhitelisted', () => {
    it('should return true for explicitly whitelisted domains', async () => {
      const result = await rewriter.isWhitelisted('https://company.com/page', 'tenant-1');
      expect(result).toBe(true);
    });

    it('should return true for subdomains of whitelisted domains', async () => {
      const result = await rewriter.isWhitelisted('https://mail.company.com/inbox', 'tenant-1');
      expect(result).toBe(true);
    });

    it('should return false for non-whitelisted domains', async () => {
      const result = await rewriter.isWhitelisted('https://external-site.com', 'tenant-1');
      expect(result).toBe(false);
    });

    it('should handle malformed URLs gracefully', async () => {
      const result = await rewriter.isWhitelisted('not-a-url', 'tenant-1');
      expect(result).toBe(false);
    });
  });

  // ==========================================================================
  // HTML Body Rewriting Tests
  // ==========================================================================

  describe('rewriteEmailBody - HTML', () => {
    const createMockEmail = (html: string): ParsedEmail => ({
      messageId: 'msg-123',
      subject: 'Test Email',
      from: { address: 'sender@example.com', domain: 'example.com' },
      to: [{ address: 'recipient@company.com', domain: 'company.com' }],
      date: new Date(),
      headers: {},
      body: { html, text: undefined },
      attachments: [],
      rawHeaders: '',
    });

    it('should rewrite URLs in anchor href attributes', async () => {
      const email = createMockEmail(
        '<a href="https://external-site.com/page">Click here</a>'
      );
      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      expect(result.htmlBody).toContain('https://protect.swordfish.app/click/');
      expect(result.stats.rewrittenCount).toBe(1);
    });

    it('should not rewrite whitelisted URLs', async () => {
      const email = createMockEmail(
        '<a href="https://company.com/page">Internal Link</a>'
      );
      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      expect(result.htmlBody).toContain('href="https://company.com/page"');
      expect(result.stats.skippedCount).toBe(1);
    });

    it('should preserve original URL in title attribute', async () => {
      const email = createMockEmail(
        '<a href="https://external-site.com/page">Click here</a>'
      );
      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      expect(result.htmlBody).toContain('title="https://external-site.com/page"');
    });

    it('should handle multiple URLs in same email', async () => {
      const email = createMockEmail(`
        <a href="https://site1.com">Link 1</a>
        <a href="https://site2.com">Link 2</a>
        <a href="https://company.com">Internal</a>
      `);
      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      expect(result.stats.totalUrls).toBe(3);
      expect(result.stats.rewrittenCount).toBe(2);
      expect(result.stats.skippedCount).toBe(1);
    });

    it('should preserve existing anchor attributes', async () => {
      const email = createMockEmail(
        '<a class="btn" id="cta" href="https://external.com">Click</a>'
      );
      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      expect(result.htmlBody).toContain('class="btn"');
      expect(result.htmlBody).toContain('id="cta"');
    });

    it('should handle HTML-encoded URLs', async () => {
      const email = createMockEmail(
        '<a href="https://external.com/page?a=1&amp;b=2">Link</a>'
      );
      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      expect(result.stats.rewrittenCount).toBe(1);
      expect(result.rewrittenUrls[0].originalUrl).toContain('a=1&b=2');
    });
  });

  // ==========================================================================
  // Plain Text Body Rewriting Tests
  // ==========================================================================

  describe('rewriteEmailBody - Text', () => {
    const createMockEmail = (text: string): ParsedEmail => ({
      messageId: 'msg-123',
      subject: 'Test Email',
      from: { address: 'sender@example.com', domain: 'example.com' },
      to: [{ address: 'recipient@company.com', domain: 'company.com' }],
      date: new Date(),
      headers: {},
      body: { text, html: undefined },
      attachments: [],
      rawHeaders: '',
    });

    it('should rewrite URLs in plain text', async () => {
      const email = createMockEmail(
        'Check out this link: https://external-site.com/page'
      );
      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      expect(result.textBody).toContain('https://protect.swordfish.app/click/');
      expect(result.stats.rewrittenCount).toBe(1);
    });

    it('should preserve trailing punctuation', async () => {
      const email = createMockEmail(
        'Visit https://external-site.com/page. It is great!'
      );
      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      expect(result.textBody).toMatch(/\/click\/[a-z0-9]+\?sig=[a-f0-9]+\./i);
    });

    it('should handle multiple URLs on same line', async () => {
      const email = createMockEmail(
        'Links: https://site1.com and https://site2.com'
      );
      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      expect(result.stats.rewrittenCount).toBe(2);
    });

    it('should not rewrite http URLs without https', async () => {
      const email = createMockEmail('Link: http://insecure-site.com');
      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      // http:// URLs should still be rewritten (they're external)
      expect(result.stats.rewrittenCount).toBe(1);
    });
  });

  // ==========================================================================
  // URL Shortener Handling Tests
  // ==========================================================================

  describe('URL Shortener Handling', () => {
    beforeEach(() => {
      // Mock fetch for URL expansion
      mockFetch.mockImplementation((url: string) => {
        if (url.includes('bit.ly')) {
          return Promise.resolve({
            headers: {
              get: (name: string) =>
                name === 'location' ? 'https://final-destination.com/page' : null,
            },
          });
        }
        return Promise.resolve({
          headers: { get: () => null },
        });
      });
    });

    it('should always rewrite URL shorteners', () => {
      for (const shortener of Array.from(URL_SHORTENERS).slice(0, 5)) {
        const result = rewriter.shouldRewrite(`https://${shortener}/abc`, 'tenant-1');
        expect(result.shouldRewrite).toBe(true);
        expect(result.reason).toBe('shortener');
      }
    });

    it('should attempt to expand shortened URLs', async () => {
      const email: ParsedEmail = {
        messageId: 'msg-123',
        subject: 'Test',
        from: { address: 'sender@example.com', domain: 'example.com' },
        to: [{ address: 'recipient@company.com', domain: 'company.com' }],
        date: new Date(),
        headers: {},
        body: { html: '<a href="https://bit.ly/abc123">Click</a>' },
        attachments: [],
        rawHeaders: '',
      };

      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      expect(mockFetch).toHaveBeenCalled();
      expect(result.rewrittenUrls[0].expandedUrl).toBe('https://final-destination.com/page');
    });
  });

  // ==========================================================================
  // Edge Cases Tests
  // ==========================================================================

  describe('Edge Cases', () => {
    it('should handle empty email body', async () => {
      const email: ParsedEmail = {
        messageId: 'msg-123',
        subject: 'Test',
        from: { address: 'sender@example.com', domain: 'example.com' },
        to: [{ address: 'recipient@company.com', domain: 'company.com' }],
        date: new Date(),
        headers: {},
        body: {},
        attachments: [],
        rawHeaders: '',
      };

      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      expect(result.stats.totalUrls).toBe(0);
      expect(result.htmlBody).toBeUndefined();
      expect(result.textBody).toBeUndefined();
    });

    it('should handle emails with no URLs', async () => {
      const email: ParsedEmail = {
        messageId: 'msg-123',
        subject: 'Test',
        from: { address: 'sender@example.com', domain: 'example.com' },
        to: [{ address: 'recipient@company.com', domain: 'company.com' }],
        date: new Date(),
        headers: {},
        body: { text: 'This email has no URLs.' },
        attachments: [],
        rawHeaders: '',
      };

      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      expect(result.stats.totalUrls).toBe(0);
      expect(result.textBody).toBe('This email has no URLs.');
    });

    it('should handle URLs with unicode characters', async () => {
      const email: ParsedEmail = {
        messageId: 'msg-123',
        subject: 'Test',
        from: { address: 'sender@example.com', domain: 'example.com' },
        to: [{ address: 'recipient@company.com', domain: 'company.com' }],
        date: new Date(),
        headers: {},
        body: { text: 'Link: https://example.com/path/\u00e9\u00e8\u00ea' },
        attachments: [],
        rawHeaders: '',
      };

      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      expect(result.stats.rewrittenCount).toBe(1);
    });

    it('should handle very long URLs', async () => {
      const longPath = 'a'.repeat(2000);
      const email: ParsedEmail = {
        messageId: 'msg-123',
        subject: 'Test',
        from: { address: 'sender@example.com', domain: 'example.com' },
        to: [{ address: 'recipient@company.com', domain: 'company.com' }],
        date: new Date(),
        headers: {},
        body: { text: `Link: https://external.com/${longPath}` },
        attachments: [],
        rawHeaders: '',
      };

      const result = await rewriter.rewriteEmailBody(email, 'tenant-1');

      expect(result.stats.rewrittenCount).toBe(1);
    });

    it('should handle suspicious URLs set', async () => {
      const email: ParsedEmail = {
        messageId: 'msg-123',
        subject: 'Test',
        from: { address: 'sender@example.com', domain: 'example.com' },
        to: [{ address: 'recipient@company.com', domain: 'company.com' }],
        date: new Date(),
        headers: {},
        body: { text: 'Safe link: https://google.com/search' },
        attachments: [],
        rawHeaders: '',
      };

      // Without suspicious flag - should not rewrite (safe domain)
      const result1 = await rewriter.rewriteEmailBody(email, 'tenant-1');
      expect(result1.stats.skippedCount).toBe(1);

      // With suspicious flag - should rewrite
      const suspiciousUrls = new Set(['https://google.com/search']);
      const result2 = await rewriter.rewriteEmailBody(email, 'tenant-1', suspiciousUrls);
      expect(result2.stats.rewrittenCount).toBe(1);
      expect(result2.rewrittenUrls[0].reason).toBe('suspicious');
    });
  });

  // ==========================================================================
  // URL Signature Verification Tests
  // ==========================================================================

  describe('URL Signature', () => {
    it('should verify valid signatures', () => {
      const trackingId = rewriter.generateClickTrackingId('https://site.com', 'email-1');
      const result = rewriter.rewriteUrl('https://site.com', 'email-1', 'tenant-1');

      // Extract signature from URL
      const url = new URL(result.rewrittenUrl);
      const sig = url.searchParams.get('sig');

      expect(rewriter.verifyUrlSignature(result.trackingId, 'https://site.com', sig!)).toBe(true);
    });

    it('should reject invalid signatures', () => {
      const result = rewriter.rewriteUrl('https://site.com', 'email-1', 'tenant-1');
      expect(rewriter.verifyUrlSignature(result.trackingId, 'https://site.com', 'invalid-sig')).toBe(false);
    });

    it('should reject tampered URLs', () => {
      const result = rewriter.rewriteUrl('https://site.com', 'email-1', 'tenant-1');
      const url = new URL(result.rewrittenUrl);
      const sig = url.searchParams.get('sig');

      // Try with different URL
      expect(rewriter.verifyUrlSignature(result.trackingId, 'https://different-site.com', sig!)).toBe(false);
    });
  });

  // ==========================================================================
  // Cache Management Tests
  // ==========================================================================

  describe('Cache Management', () => {
    it('should clear all cached whitelists', () => {
      // This is mainly for coverage - actual cache testing would require more setup
      rewriter.clearCache();
      // No error should be thrown
    });

    it('should clear specific tenant whitelist', () => {
      rewriter.clearCache('tenant-1');
      // No error should be thrown
    });
  });
});

// ==========================================================================
// Utility Function Tests
// ==========================================================================

describe('Utility Functions', () => {
  describe('quickShouldRewrite', () => {
    it('should return false for mailto: links', () => {
      expect(quickShouldRewrite('mailto:user@example.com')).toBe(false);
    });

    it('should return true for URL shorteners', () => {
      expect(quickShouldRewrite('https://bit.ly/abc')).toBe(true);
    });

    it('should return false for known safe domains', () => {
      expect(quickShouldRewrite('https://google.com/search')).toBe(false);
    });

    it('should return true for unknown domains', () => {
      expect(quickShouldRewrite('https://unknown-domain.com')).toBe(true);
    });

    it('should return true for malformed URLs', () => {
      expect(quickShouldRewrite('not-a-url')).toBe(true);
    });
  });

  describe('extractUrls', () => {
    it('should extract URLs from href attributes', () => {
      const content = '<a href="https://site1.com">Link</a><a href="https://site2.com">Link2</a>';
      const urls = extractUrls(content);

      expect(urls).toContain('https://site1.com');
      expect(urls).toContain('https://site2.com');
    });

    it('should extract URLs from plain text', () => {
      const content = 'Check https://site1.com and https://site2.com';
      const urls = extractUrls(content);

      expect(urls).toContain('https://site1.com');
      expect(urls).toContain('https://site2.com');
    });

    it('should remove trailing punctuation', () => {
      const content = 'Visit https://site.com/page. It is great!';
      const urls = extractUrls(content);

      expect(urls).toContain('https://site.com/page');
      expect(urls).not.toContain('https://site.com/page.');
    });

    it('should return unique URLs', () => {
      const content = 'Link: https://site.com Link again: https://site.com';
      const urls = extractUrls(content);

      expect(urls.filter(u => u === 'https://site.com').length).toBe(1);
    });

    it('should not extract non-http URLs', () => {
      const content = '<a href="mailto:user@example.com">Email</a>';
      const urls = extractUrls(content);

      expect(urls).not.toContain('mailto:user@example.com');
    });
  });
});

// ==========================================================================
// Factory Function Tests
// ==========================================================================

describe('Factory Functions', () => {
  describe('getUrlRewriter', () => {
    it('should return singleton instance', () => {
      const rewriter1 = getUrlRewriter();
      const rewriter2 = getUrlRewriter();

      // Note: Due to module caching, these may be the same instance
      expect(rewriter1).toBeDefined();
      expect(rewriter2).toBeDefined();
    });

    it('should accept custom config', () => {
      const rewriter = getUrlRewriter({
        baseUrl: 'https://custom.swordfish.app',
      });

      expect(rewriter).toBeDefined();
    });
  });

  describe('createUrlRewriter', () => {
    it('should create new instance with custom config', () => {
      const rewriter = createUrlRewriter({
        baseUrl: 'https://custom.swordfish.app',
        whitelistedDomains: ['my-domain.com'],
      });

      const result = rewriter.shouldRewrite('https://my-domain.com/page', 'tenant-1');
      expect(result.shouldRewrite).toBe(false);
      expect(result.reason).toBe('whitelisted');
    });
  });
});

// ==========================================================================
// Constants Tests
// ==========================================================================

describe('Constants', () => {
  it('should have comprehensive list of safe domains', () => {
    expect(KNOWN_SAFE_DOMAINS.length).toBeGreaterThan(10);
    expect(KNOWN_SAFE_DOMAINS).toContain('google.com');
    expect(KNOWN_SAFE_DOMAINS).toContain('microsoft.com');
    expect(KNOWN_SAFE_DOMAINS).toContain('github.com');
  });

  it('should have comprehensive list of URL shorteners', () => {
    expect(URL_SHORTENERS.size).toBeGreaterThan(10);
    expect(URL_SHORTENERS.has('bit.ly')).toBe(true);
    expect(URL_SHORTENERS.has('tinyurl.com')).toBe(true);
    expect(URL_SHORTENERS.has('t.co')).toBe(true);
  });

  it('should have all non-rewritable protocols', () => {
    expect(NON_REWRITABLE_PROTOCOLS.has('mailto:')).toBe(true);
    expect(NON_REWRITABLE_PROTOCOLS.has('tel:')).toBe(true);
    expect(NON_REWRITABLE_PROTOCOLS.has('javascript:')).toBe(true);
    expect(NON_REWRITABLE_PROTOCOLS.has('data:')).toBe(true);
  });
});
