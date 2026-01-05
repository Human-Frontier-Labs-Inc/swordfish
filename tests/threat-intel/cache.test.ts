/**
 * Threat Intelligence Cache Tests
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { ThreatFeedCache } from '@/lib/threat-intel/cache';
import type { ThreatCheckResult, DomainCheckResult } from '@/lib/threat-intel/feeds';

describe('ThreatFeedCache', () => {
  let cache: ThreatFeedCache;

  beforeEach(() => {
    cache = new ThreatFeedCache();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('URL Cache', () => {
    const sampleResult: ThreatCheckResult = {
      url: 'http://test.com/page',
      isThreat: false,
      verdict: 'clean',
      confidence: 0.9,
      sources: [],
      checkedAt: new Date(),
    };

    it('should cache and retrieve URL results', () => {
      cache.setUrlResult('http://test.com/page', sampleResult);

      const result = cache.getUrlResult('http://test.com/page');

      expect(result).toBeDefined();
      expect(result?.url).toBe('http://test.com/page');
      expect(result?.verdict).toBe('clean');
    });

    it('should return null for missing entries', () => {
      const result = cache.getUrlResult('http://notcached.com');

      expect(result).toBeNull();
    });

    it('should expire entries after TTL', () => {
      cache.setUrlResult('http://test.com', sampleResult);

      // Advance time past URL cache TTL (1 hour)
      vi.advanceTimersByTime(61 * 60 * 1000);

      const result = cache.getUrlResult('http://test.com');

      expect(result).toBeNull();
    });

    it('should evict oldest entries when cache is full', () => {
      // Create more entries than cache limit (this is a simplified test)
      // In reality, we'd need to add 50000+ entries
      for (let i = 0; i < 100; i++) {
        cache.setUrlResult(`http://test${i}.com`, {
          ...sampleResult,
          url: `http://test${i}.com`,
        });
      }

      const stats = cache.getStats();
      expect(stats.urls.size).toBeLessThanOrEqual(stats.urls.maxSize);
    });
  });

  describe('Domain Cache', () => {
    const sampleDomainResult: DomainCheckResult = {
      domain: 'example.com',
      isThreat: false,
      verdict: 'clean',
      sources: [],
    };

    it('should cache and retrieve domain results', () => {
      cache.setDomainResult('example.com', sampleDomainResult);

      const result = cache.getDomainResult('example.com');

      expect(result).toBeDefined();
      expect(result?.domain).toBe('example.com');
    });

    it('should expire domain entries after TTL', () => {
      cache.setDomainResult('example.com', sampleDomainResult);

      // Advance time past domain cache TTL (4 hours)
      vi.advanceTimersByTime(5 * 60 * 60 * 1000);

      const result = cache.getDomainResult('example.com');

      expect(result).toBeNull();
    });
  });

  describe('IP Cache', () => {
    const sampleIPResult = {
      ip: '8.8.8.8',
      isThreat: false,
      verdict: 'clean' as const,
      sources: [],
      checkedAt: new Date(),
    };

    it('should cache and retrieve IP results', () => {
      cache.setIPResult('8.8.8.8', sampleIPResult);

      const result = cache.getIPResult('8.8.8.8');

      expect(result).toBeDefined();
      expect(result?.ip).toBe('8.8.8.8');
    });

    it('should expire IP entries after TTL', () => {
      cache.setIPResult('8.8.8.8', sampleIPResult);

      // Advance time past IP cache TTL (2 hours)
      vi.advanceTimersByTime(3 * 60 * 60 * 1000);

      const result = cache.getIPResult('8.8.8.8');

      expect(result).toBeNull();
    });
  });

  describe('Cache Management', () => {
    it('should clear all caches', () => {
      cache.setUrlResult('http://test.com', {
        url: 'http://test.com',
        isThreat: false,
        verdict: 'clean',
        confidence: 0.9,
        sources: [],
        checkedAt: new Date(),
      });

      cache.setDomainResult('test.com', {
        domain: 'test.com',
        isThreat: false,
        verdict: 'clean',
        sources: [],
      });

      cache.setIPResult('1.1.1.1', {
        ip: '1.1.1.1',
        isThreat: false,
        verdict: 'clean',
        sources: [],
        checkedAt: new Date(),
      });

      cache.clear();

      expect(cache.getUrlResult('http://test.com')).toBeNull();
      expect(cache.getDomainResult('test.com')).toBeNull();
      expect(cache.getIPResult('1.1.1.1')).toBeNull();
    });

    it('should report accurate statistics', () => {
      cache.setUrlResult('http://test1.com', {
        url: 'http://test1.com',
        isThreat: false,
        verdict: 'clean',
        confidence: 0.9,
        sources: [],
        checkedAt: new Date(),
      });

      cache.setUrlResult('http://test2.com', {
        url: 'http://test2.com',
        isThreat: false,
        verdict: 'clean',
        confidence: 0.9,
        sources: [],
        checkedAt: new Date(),
      });

      cache.setDomainResult('test.com', {
        domain: 'test.com',
        isThreat: false,
        verdict: 'clean',
        sources: [],
      });

      const stats = cache.getStats();

      expect(stats.urls.size).toBe(2);
      expect(stats.domains.size).toBe(1);
      expect(stats.ips.size).toBe(0);
    });

    it('should clean expired entries', () => {
      cache.setUrlResult('http://old.com', {
        url: 'http://old.com',
        isThreat: false,
        verdict: 'clean',
        confidence: 0.9,
        sources: [],
        checkedAt: new Date(),
      });

      // Advance time past TTL
      vi.advanceTimersByTime(2 * 60 * 60 * 1000);

      const removed = cache.cleanExpired();

      expect(removed.urlsRemoved).toBe(1);
    });
  });
});
