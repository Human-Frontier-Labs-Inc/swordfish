/**
 * Rewritten URLs Database Module Tests
 *
 * Tests for database operations, URL ID generation, and statistics
 * for the URL rewriting system.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock the database module before importing the module under test
vi.mock('@/lib/db', () => {
  const mockSql = vi.fn().mockImplementation(() => Promise.resolve([]));
  return { sql: mockSql };
});

import {
  generateUrlId,
  generateShortUrlId,
  isValidUrlId,
  storeRewrittenUrl,
  batchStoreRewrittenUrls,
  lookupOriginalUrl,
  recordUrlClick,
  getRewrittenUrl,
  getRewrittenUrlsForEmail,
  cleanupExpiredUrls,
  extendUrlExpiration,
  getExpiringUrls,
  getRewriteStats,
  getExcludedDomains,
  getExcludedPatterns,
  updateExclusions,
  searchRewrittenUrls,
} from '@/lib/protection/rewritten-urls';
import { sql } from '@/lib/db';

// Get the mocked sql function
const mockSql = vi.mocked(sql);

describe('URL ID Generation', () => {
  describe('generateUrlId', () => {
    it('should generate unique IDs for different URLs', () => {
      const id1 = generateUrlId('https://site1.com', 'email-1', 'tenant-1');
      const id2 = generateUrlId('https://site2.com', 'email-1', 'tenant-1');
      expect(id1).not.toBe(id2);
    });

    it('should generate unique IDs for same URL in different emails', () => {
      const id1 = generateUrlId('https://site.com', 'email-1', 'tenant-1');
      const id2 = generateUrlId('https://site.com', 'email-2', 'tenant-1');
      expect(id1).not.toBe(id2);
    });

    it('should generate IDs with sufficient length', () => {
      const id = generateUrlId('https://site.com', 'email-1', 'tenant-1');
      expect(id.length).toBeGreaterThanOrEqual(30);
    });

    it('should generate URL-safe IDs', () => {
      const id = generateUrlId('https://site.com', 'email-1', 'tenant-1');
      expect(id).toMatch(/^[a-z0-9]+$/i);
    });

    it('should be deterministic-ish (contains randomness)', () => {
      // Two calls with same params should produce different results due to timestamp/random
      const id1 = generateUrlId('https://site.com', 'email-1', 'tenant-1');
      const id2 = generateUrlId('https://site.com', 'email-1', 'tenant-1');
      expect(id1).not.toBe(id2);
    });
  });

  describe('generateShortUrlId', () => {
    it('should generate shorter IDs', () => {
      const shortId = generateShortUrlId('https://site.com', 'email-1');
      const longId = generateUrlId('https://site.com', 'email-1', 'tenant-1');
      expect(shortId.length).toBeLessThan(longId.length);
    });

    it('should generate IDs around 20 characters', () => {
      const id = generateShortUrlId('https://site.com', 'email-1');
      expect(id.length).toBe(20);
    });

    it('should generate URL-safe IDs', () => {
      const id = generateShortUrlId('https://site.com', 'email-1');
      expect(id).toMatch(/^[a-z0-9]+$/i);
    });
  });

  describe('isValidUrlId', () => {
    it('should validate correct IDs', () => {
      expect(isValidUrlId('abc123def456ghi789jkl')).toBe(true);
      expect(isValidUrlId('ABCDEF1234567890abcdef')).toBe(true);
    });

    it('should reject too short IDs', () => {
      expect(isValidUrlId('abc123')).toBe(false);
    });

    it('should reject too long IDs', () => {
      expect(isValidUrlId('a'.repeat(50))).toBe(false);
    });

    it('should reject IDs with special characters', () => {
      expect(isValidUrlId('abc-123-def-456-ghi')).toBe(false);
      expect(isValidUrlId('abc_123_def_456_ghi')).toBe(false);
      expect(isValidUrlId('abc.123.def.456.ghi')).toBe(false);
    });
  });
});

describe('Database Operations', () => {
  beforeEach(() => {
    mockSql.mockReset();
  });

  describe('storeRewrittenUrl', () => {
    it('should store URL with all required fields', async () => {
      mockSql.mockResolvedValueOnce([{ id: 'test-id' }]);

      const result = await storeRewrittenUrl({
        id: 'test-id',
        tenantId: 'tenant-1',
        emailId: 'email-1',
        originalUrl: 'https://example.com',
      });

      expect(result).toBe(true);
      expect(mockSql).toHaveBeenCalled();
    });

    it('should store URL with expanded URL', async () => {
      mockSql.mockResolvedValueOnce([{ id: 'test-id' }]);

      const result = await storeRewrittenUrl({
        id: 'test-id',
        tenantId: 'tenant-1',
        emailId: 'email-1',
        originalUrl: 'https://bit.ly/abc',
        expandedUrl: 'https://example.com/full-path',
      });

      expect(result).toBe(true);
    });

    it('should store URL with metadata', async () => {
      mockSql.mockResolvedValueOnce([{ id: 'test-id' }]);

      const result = await storeRewrittenUrl({
        id: 'test-id',
        tenantId: 'tenant-1',
        emailId: 'email-1',
        originalUrl: 'https://example.com',
        metadata: { reason: 'external', riskScore: 50 },
      });

      expect(result).toBe(true);
    });

    it('should handle database errors gracefully', async () => {
      mockSql.mockRejectedValueOnce(new Error('Database error'));

      const result = await storeRewrittenUrl({
        id: 'test-id',
        tenantId: 'tenant-1',
        emailId: 'email-1',
        originalUrl: 'https://example.com',
      });

      expect(result).toBe(false);
    });
  });

  describe('batchStoreRewrittenUrls', () => {
    it('should store multiple URLs', async () => {
      mockSql.mockResolvedValue([{ id: 'test-id' }]);

      const result = await batchStoreRewrittenUrls([
        { id: 'id-1', tenantId: 'tenant-1', emailId: 'email-1', originalUrl: 'https://site1.com' },
        { id: 'id-2', tenantId: 'tenant-1', emailId: 'email-1', originalUrl: 'https://site2.com' },
      ]);

      expect(result.stored).toBe(2);
      expect(result.errors.length).toBe(0);
    });

    it('should handle empty array', async () => {
      const result = await batchStoreRewrittenUrls([]);

      expect(result.stored).toBe(0);
      expect(result.skipped).toBe(0);
      expect(result.errors.length).toBe(0);
    });

    it('should track skipped duplicates', async () => {
      mockSql.mockResolvedValueOnce([{ id: 'id-1' }]); // First succeeds
      mockSql.mockResolvedValueOnce([]); // Second is duplicate (no rows returned)

      const result = await batchStoreRewrittenUrls([
        { id: 'id-1', tenantId: 'tenant-1', emailId: 'email-1', originalUrl: 'https://site1.com' },
        { id: 'id-2', tenantId: 'tenant-1', emailId: 'email-1', originalUrl: 'https://site2.com' },
      ]);

      expect(result.stored).toBe(1);
      expect(result.skipped).toBe(1);
    });
  });

  describe('lookupOriginalUrl', () => {
    it('should return URL details when found', async () => {
      mockSql.mockResolvedValueOnce([
        {
          id: 'test-id',
          tenant_id: 'tenant-1',
          email_id: 'email-1',
          original_url: 'https://example.com',
          expanded_url: null,
          created_at: new Date(),
          clicked_at: null,
          expires_at: new Date(Date.now() + 86400000), // Tomorrow
          click_count: 0,
          click_verdict: null,
          metadata: {},
        },
      ]);

      const result = await lookupOriginalUrl('test-id');

      expect(result.found).toBe(true);
      expect(result.expired).toBe(false);
      expect(result.originalUrl).toBe('https://example.com');
    });

    it('should mark expired URLs', async () => {
      mockSql.mockResolvedValueOnce([
        {
          id: 'test-id',
          tenant_id: 'tenant-1',
          email_id: 'email-1',
          original_url: 'https://example.com',
          expanded_url: null,
          created_at: new Date(),
          clicked_at: null,
          expires_at: new Date(Date.now() - 86400000), // Yesterday
          click_count: 0,
          click_verdict: null,
          metadata: {},
        },
      ]);

      const result = await lookupOriginalUrl('test-id');

      expect(result.found).toBe(true);
      expect(result.expired).toBe(true);
    });

    it('should return not found for missing URLs', async () => {
      mockSql.mockResolvedValueOnce([]);

      const result = await lookupOriginalUrl('nonexistent-id');

      expect(result.found).toBe(false);
      expect(result.originalUrl).toBeNull();
    });
  });

  describe('recordUrlClick', () => {
    it('should record click and return original URL', async () => {
      mockSql.mockResolvedValueOnce([
        {
          original_url: 'https://example.com',
          expanded_url: null,
          is_first_click: true,
        },
      ]);

      const result = await recordUrlClick('test-id', 'safe');

      expect(result.success).toBe(true);
      expect(result.originalUrl).toBe('https://example.com');
      expect(result.isFirstClick).toBe(true);
    });

    it('should record click with metadata', async () => {
      mockSql.mockResolvedValueOnce([
        {
          original_url: 'https://example.com',
          expanded_url: null,
          is_first_click: false,
        },
      ]);

      const result = await recordUrlClick('test-id', 'suspicious', {
        userAgent: 'Mozilla/5.0',
        ip: '192.168.1.1',
      });

      expect(result.success).toBe(true);
      expect(result.isFirstClick).toBe(false);
    });

    it('should return failure for expired or missing URLs', async () => {
      mockSql.mockResolvedValueOnce([]);

      const result = await recordUrlClick('expired-id');

      expect(result.success).toBe(false);
      expect(result.originalUrl).toBeNull();
    });
  });

  describe('getRewrittenUrl', () => {
    it('should return full URL record', async () => {
      const mockRecord = {
        id: 'test-id',
        tenant_id: 'tenant-1',
        email_id: 'email-1',
        original_url: 'https://example.com',
        expanded_url: 'https://expanded.com',
        created_at: new Date('2024-01-01'),
        clicked_at: new Date('2024-01-02'),
        expires_at: new Date('2024-02-01'),
        click_count: 5,
        click_verdict: 'safe',
        metadata: { reason: 'external' },
      };
      mockSql.mockResolvedValueOnce([mockRecord]);

      const result = await getRewrittenUrl('test-id');

      expect(result).not.toBeNull();
      expect(result!.id).toBe('test-id');
      expect(result!.originalUrl).toBe('https://example.com');
      expect(result!.expandedUrl).toBe('https://expanded.com');
      expect(result!.clickCount).toBe(5);
      expect(result!.clickVerdict).toBe('safe');
    });

    it('should return null for missing URL', async () => {
      mockSql.mockResolvedValueOnce([]);

      const result = await getRewrittenUrl('nonexistent-id');

      expect(result).toBeNull();
    });
  });

  describe('getRewrittenUrlsForEmail', () => {
    it('should return all URLs for an email', async () => {
      mockSql.mockResolvedValueOnce([
        {
          id: 'id-1',
          tenant_id: 'tenant-1',
          email_id: 'email-1',
          original_url: 'https://site1.com',
          expanded_url: null,
          created_at: new Date(),
          clicked_at: null,
          expires_at: new Date(),
          click_count: 0,
          click_verdict: null,
          metadata: {},
        },
        {
          id: 'id-2',
          tenant_id: 'tenant-1',
          email_id: 'email-1',
          original_url: 'https://site2.com',
          expanded_url: null,
          created_at: new Date(),
          clicked_at: null,
          expires_at: new Date(),
          click_count: 0,
          click_verdict: null,
          metadata: {},
        },
      ]);

      const result = await getRewrittenUrlsForEmail('email-1', 'tenant-1');

      expect(result.length).toBe(2);
      expect(result[0].originalUrl).toBe('https://site1.com');
      expect(result[1].originalUrl).toBe('https://site2.com');
    });

    it('should return empty array for email with no URLs', async () => {
      mockSql.mockResolvedValueOnce([]);

      const result = await getRewrittenUrlsForEmail('email-no-urls', 'tenant-1');

      expect(result.length).toBe(0);
    });
  });
});

describe('Expiration Handling', () => {
  beforeEach(() => {
    mockSql.mockReset();
  });

  describe('cleanupExpiredUrls', () => {
    it('should delete expired URLs and return count', async () => {
      mockSql.mockResolvedValueOnce([{ id: '1' }, { id: '2' }, { id: '3' }]);

      const result = await cleanupExpiredUrls();

      expect(result.deletedCount).toBe(3);
    });

    it('should handle no expired URLs', async () => {
      mockSql.mockResolvedValueOnce([]);

      const result = await cleanupExpiredUrls();

      expect(result.deletedCount).toBe(0);
    });
  });

  describe('extendUrlExpiration', () => {
    it('should extend expiration for multiple URLs', async () => {
      mockSql.mockResolvedValueOnce([{ id: 'id-1' }, { id: 'id-2' }]);

      const result = await extendUrlExpiration(['id-1', 'id-2'], 30);

      expect(result).toBe(2);
    });

    it('should return 0 for empty array', async () => {
      const result = await extendUrlExpiration([]);

      expect(result).toBe(0);
    });
  });

  describe('getExpiringUrls', () => {
    it('should return URLs expiring within threshold', async () => {
      mockSql.mockResolvedValueOnce([
        {
          id: 'id-1',
          tenant_id: 'tenant-1',
          email_id: 'email-1',
          original_url: 'https://example.com',
          expanded_url: null,
          created_at: new Date(),
          clicked_at: new Date(),
          expires_at: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000), // 3 days
          click_count: 1,
          click_verdict: 'safe',
          metadata: {},
        },
      ]);

      const result = await getExpiringUrls('tenant-1', 7);

      expect(result.length).toBe(1);
    });
  });
});

describe('Statistics & Analytics', () => {
  beforeEach(() => {
    mockSql.mockReset();
  });

  describe('getRewriteStats', () => {
    it('should return comprehensive statistics', async () => {
      // Mock totals query
      mockSql.mockResolvedValueOnce([
        {
          total_urls: 100,
          total_clicks: 50,
          unique_urls_clicked: 30,
          malicious_clicks: 5,
          suspicious_clicks: 10,
          blocked_clicks: 3,
          safe_clicks: 32,
          avg_clicks: 1.67,
        },
      ]);

      // Mock top domains query
      mockSql.mockResolvedValueOnce([
        { domain: 'example.com', clicks: 20 },
        { domain: 'test.com', clicks: 10 },
      ]);

      // Mock daily clicks query
      mockSql.mockResolvedValueOnce([
        { date: '2024-01-01', clicks: 10 },
        { date: '2024-01-02', clicks: 15 },
      ]);

      // Mock expiring count query
      mockSql.mockResolvedValueOnce([{ count: 5 }]);

      const result = await getRewriteStats('tenant-1', 'month');

      expect(result.period).toBe('month');
      expect(result.totalUrlsRewritten).toBe(100);
      expect(result.totalClicks).toBe(50);
      expect(result.uniqueUrlsClicked).toBe(30);
      expect(result.maliciousClicks).toBe(5);
      expect(result.suspiciousClicks).toBe(10);
      expect(result.blockedClicks).toBe(3);
      expect(result.safeClicks).toBe(32);
      expect(result.topClickedDomains.length).toBe(2);
      expect(result.clicksByDay.length).toBe(2);
      expect(result.expiringUrlsCount).toBe(5);
    });

    it('should handle different periods', async () => {
      mockSql.mockResolvedValue([{}]); // Default empty responses

      await getRewriteStats('tenant-1', 'day');
      await getRewriteStats('tenant-1', 'week');
      await getRewriteStats('tenant-1', '90days');

      expect(mockSql).toHaveBeenCalled();
    });
  });
});

describe('Exclusion Management', () => {
  beforeEach(() => {
    mockSql.mockReset();
  });

  describe('getExcludedDomains', () => {
    it('should return list of excluded domains', async () => {
      mockSql.mockResolvedValueOnce([
        { value: 'company.com' },
        { value: 'partner.org' },
      ]);

      const result = await getExcludedDomains('tenant-1');

      expect(result).toContain('company.com');
      expect(result).toContain('partner.org');
    });

    it('should return empty array when no exclusions', async () => {
      mockSql.mockResolvedValueOnce([]);

      const result = await getExcludedDomains('tenant-1');

      expect(result.length).toBe(0);
    });
  });

  describe('getExcludedPatterns', () => {
    it('should return list of excluded patterns', async () => {
      mockSql.mockResolvedValueOnce([
        { value: '.*\\.internal\\.com' },
        { value: 'https://safe-.*' },
      ]);

      const result = await getExcludedPatterns('tenant-1');

      expect(result.length).toBe(2);
    });
  });

  describe('updateExclusions', () => {
    it('should add new domains', async () => {
      mockSql.mockResolvedValue([{ id: 'new-policy-id' }]);

      const result = await updateExclusions('tenant-1', {
        addDomains: ['new-domain.com', 'another-domain.org'],
      });

      expect(result.domainsAdded).toBe(2);
    });

    it('should remove existing domains', async () => {
      mockSql.mockResolvedValueOnce([{ id: 'deleted-1' }, { id: 'deleted-2' }]);

      const result = await updateExclusions('tenant-1', {
        removeDomains: ['old-domain.com', 'deprecated.org'],
      });

      expect(result.domainsRemoved).toBe(2);
    });

    it('should handle mixed add/remove', async () => {
      mockSql.mockResolvedValueOnce([{ id: 'new-1' }]); // Add
      mockSql.mockResolvedValueOnce([{ id: 'deleted-1' }]); // Remove

      const result = await updateExclusions('tenant-1', {
        addDomains: ['new-domain.com'],
        removeDomains: ['old-domain.com'],
      });

      expect(result.domainsAdded).toBe(1);
      expect(result.domainsRemoved).toBe(1);
    });

    it('should add and remove patterns', async () => {
      mockSql.mockResolvedValueOnce([{ id: 'new-pattern' }]); // Add pattern
      mockSql.mockResolvedValueOnce([{ id: 'deleted-pattern' }]); // Remove pattern

      const result = await updateExclusions('tenant-1', {
        addPatterns: ['.*\\.safe\\.com'],
        removePatterns: ['.*\\.old\\.com'],
      });

      expect(result.patternsAdded).toBe(1);
      expect(result.patternsRemoved).toBe(1);
    });
  });
});

describe('Search & Query', () => {
  beforeEach(() => {
    mockSql.mockReset();
  });

  describe('searchRewrittenUrls', () => {
    it('should search by URL pattern', async () => {
      mockSql.mockResolvedValueOnce([
        {
          id: 'id-1',
          tenant_id: 'tenant-1',
          email_id: 'email-1',
          original_url: 'https://example.com/search',
          expanded_url: null,
          created_at: new Date(),
          clicked_at: null,
          expires_at: new Date(),
          click_count: 0,
          click_verdict: null,
          metadata: {},
        },
      ]);
      mockSql.mockResolvedValueOnce([{ total: 1 }]);

      const result = await searchRewrittenUrls({
        tenantId: 'tenant-1',
        query: 'example.com',
      });

      expect(result.urls.length).toBe(1);
      expect(result.total).toBe(1);
    });

    it('should filter by verdict', async () => {
      mockSql.mockResolvedValueOnce([]);
      mockSql.mockResolvedValueOnce([{ total: 0 }]);

      const result = await searchRewrittenUrls({
        tenantId: 'tenant-1',
        verdict: 'malicious',
      });

      expect(result.urls.length).toBe(0);
    });

    it('should filter by email ID', async () => {
      mockSql.mockResolvedValueOnce([]);
      mockSql.mockResolvedValueOnce([{ total: 0 }]);

      const result = await searchRewrittenUrls({
        tenantId: 'tenant-1',
        emailId: 'specific-email-id',
      });

      expect(mockSql).toHaveBeenCalled();
    });

    it('should support pagination', async () => {
      mockSql.mockResolvedValueOnce([]);
      mockSql.mockResolvedValueOnce([{ total: 100 }]);

      const result = await searchRewrittenUrls({
        tenantId: 'tenant-1',
        limit: 10,
        offset: 20,
      });

      expect(result.total).toBe(100);
    });
  });
});
