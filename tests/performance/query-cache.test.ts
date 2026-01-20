/**
 * Query Cache Tests
 * TDD: In-memory caching for database queries
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import {
  QueryCache,
  createQueryCache,
  CacheEntry,
  CacheConfig,
  CacheStats,
} from '@/lib/performance/query-cache';

describe('Query Cache', () => {
  let cache: QueryCache;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T12:00:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    if (cache) {
      cache.clear();
    }
  });

  describe('Cache creation', () => {
    it('should create cache with default config', () => {
      cache = createQueryCache();

      const stats = cache.getStats();
      expect(stats.maxSize).toBe(1000);
      expect(stats.defaultTTL).toBe(300000); // 5 minutes
    });

    it('should create cache with custom config', () => {
      cache = createQueryCache({
        maxSize: 500,
        defaultTTL: 60000,
      });

      const stats = cache.getStats();
      expect(stats.maxSize).toBe(500);
      expect(stats.defaultTTL).toBe(60000);
    });

    it('should validate config constraints', () => {
      expect(() =>
        createQueryCache({
          maxSize: 0,
        })
      ).toThrow('maxSize must be positive');
    });

    it('should require positive TTL', () => {
      expect(() =>
        createQueryCache({
          defaultTTL: -1,
        })
      ).toThrow('defaultTTL must be positive');
    });
  });

  describe('Basic cache operations', () => {
    beforeEach(() => {
      cache = createQueryCache({
        maxSize: 100,
        defaultTTL: 60000,
      });
    });

    it('should set and get values', () => {
      cache.set('key1', { data: 'value1' });

      const result = cache.get('key1');
      expect(result).toEqual({ data: 'value1' });
    });

    it('should return undefined for missing keys', () => {
      const result = cache.get('nonexistent');

      expect(result).toBeUndefined();
    });

    it('should check if key exists', () => {
      cache.set('key1', 'value1');

      expect(cache.has('key1')).toBe(true);
      expect(cache.has('nonexistent')).toBe(false);
    });

    it('should delete entries', () => {
      cache.set('key1', 'value1');
      cache.delete('key1');

      expect(cache.has('key1')).toBe(false);
    });

    it('should clear all entries', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.clear();

      const stats = cache.getStats();
      expect(stats.size).toBe(0);
    });
  });

  describe('TTL (Time-To-Live)', () => {
    beforeEach(() => {
      cache = createQueryCache({
        maxSize: 100,
        defaultTTL: 1000, // 1 second
      });
    });

    it('should expire entries after TTL', () => {
      cache.set('key1', 'value1');

      // Advance time past TTL
      vi.advanceTimersByTime(1001);

      const result = cache.get('key1');
      expect(result).toBeUndefined();
    });

    it('should not expire entries before TTL', () => {
      cache.set('key1', 'value1');

      // Advance time but not past TTL
      vi.advanceTimersByTime(500);

      const result = cache.get('key1');
      expect(result).toBe('value1');
    });

    it('should support custom TTL per entry', () => {
      cache.set('key1', 'value1', { ttl: 500 });
      cache.set('key2', 'value2', { ttl: 2000 });

      vi.advanceTimersByTime(600);

      expect(cache.get('key1')).toBeUndefined();
      expect(cache.get('key2')).toBe('value2');
    });

    it('should refresh TTL on access when configured', () => {
      cache = createQueryCache({
        maxSize: 100,
        defaultTTL: 1000,
        refreshOnAccess: true,
      });

      cache.set('key1', 'value1');

      // Access at 800ms
      vi.advanceTimersByTime(800);
      cache.get('key1'); // Should refresh TTL

      // Should still exist at 1200ms (800 + 400)
      vi.advanceTimersByTime(400);
      expect(cache.get('key1')).toBe('value1');
    });
  });

  describe('LRU eviction', () => {
    beforeEach(() => {
      cache = createQueryCache({
        maxSize: 3,
        defaultTTL: 60000,
      });
    });

    it('should evict least recently used when full', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.set('key3', 'value3');

      // Access key1 to make it recently used
      cache.get('key1');

      // Add new entry, should evict key2 (least recently used)
      cache.set('key4', 'value4');

      expect(cache.has('key1')).toBe(true); // Accessed
      expect(cache.has('key2')).toBe(false); // Evicted
      expect(cache.has('key3')).toBe(true);
      expect(cache.has('key4')).toBe(true);
    });

    it('should update access order on get', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.set('key3', 'value3');

      // Access in order: key1, key3
      cache.get('key1');
      cache.get('key3');

      // key2 is now least recently used
      cache.set('key4', 'value4');

      expect(cache.has('key2')).toBe(false);
    });

    it('should track eviction count', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.set('key3', 'value3');
      cache.set('key4', 'value4'); // Evicts key1
      cache.set('key5', 'value5'); // Evicts key2

      const stats = cache.getStats();
      expect(stats.evictions).toBe(2);
    });
  });

  describe('Cache statistics', () => {
    beforeEach(() => {
      cache = createQueryCache({
        maxSize: 100,
        defaultTTL: 60000,
      });
    });

    it('should track hits and misses', () => {
      cache.set('key1', 'value1');

      cache.get('key1'); // Hit
      cache.get('key1'); // Hit
      cache.get('nonexistent'); // Miss

      const stats = cache.getStats();
      expect(stats.hits).toBe(2);
      expect(stats.misses).toBe(1);
    });

    it('should calculate hit rate', () => {
      cache.set('key1', 'value1');

      cache.get('key1'); // Hit
      cache.get('key1'); // Hit
      cache.get('key1'); // Hit
      cache.get('nonexistent'); // Miss

      const stats = cache.getStats();
      expect(stats.hitRate).toBe(0.75); // 3/4
    });

    it('should track current size', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.set('key3', 'value3');

      const stats = cache.getStats();
      expect(stats.size).toBe(3);
    });

    it('should track expired count', () => {
      cache = createQueryCache({
        maxSize: 100,
        defaultTTL: 100,
      });

      cache.set('key1', 'value1');
      cache.set('key2', 'value2');

      vi.advanceTimersByTime(101);

      // Trigger expiry check
      cache.get('key1');
      cache.get('key2');

      const stats = cache.getStats();
      expect(stats.expired).toBe(2);
    });

    it('should provide comprehensive stats', () => {
      const stats = cache.getStats();

      expect(stats).toHaveProperty('maxSize');
      expect(stats).toHaveProperty('size');
      expect(stats).toHaveProperty('hits');
      expect(stats).toHaveProperty('misses');
      expect(stats).toHaveProperty('hitRate');
      expect(stats).toHaveProperty('evictions');
      expect(stats).toHaveProperty('expired');
      expect(stats).toHaveProperty('defaultTTL');
    });

    it('should reset stats', () => {
      cache.set('key1', 'value1');
      cache.get('key1');
      cache.get('nonexistent');

      cache.resetStats();

      const stats = cache.getStats();
      expect(stats.hits).toBe(0);
      expect(stats.misses).toBe(0);
    });
  });

  describe('Cache key generation', () => {
    beforeEach(() => {
      cache = createQueryCache();
    });

    it('should generate consistent keys for same query', () => {
      const key1 = cache.generateKey('SELECT * FROM users', [1, 'test']);
      const key2 = cache.generateKey('SELECT * FROM users', [1, 'test']);

      expect(key1).toBe(key2);
    });

    it('should generate different keys for different queries', () => {
      const key1 = cache.generateKey('SELECT * FROM users', []);
      const key2 = cache.generateKey('SELECT * FROM posts', []);

      expect(key1).not.toBe(key2);
    });

    it('should generate different keys for different params', () => {
      const key1 = cache.generateKey('SELECT * FROM users WHERE id = $1', [1]);
      const key2 = cache.generateKey('SELECT * FROM users WHERE id = $1', [2]);

      expect(key1).not.toBe(key2);
    });

    it('should handle null and undefined params', () => {
      const key1 = cache.generateKey('SELECT * FROM users', [null, 'test']);
      const key2 = cache.generateKey('SELECT * FROM users', [null, 'different']);
      const key3 = cache.generateKey('SELECT * FROM users', []);

      // Different values should produce different keys
      expect(key1).not.toBe(key2);
      expect(key1).not.toBe(key3);
    });
  });

  describe('Cache patterns', () => {
    beforeEach(() => {
      cache = createQueryCache({
        maxSize: 100,
        defaultTTL: 60000,
      });
    });

    it('should support getOrSet pattern', async () => {
      let fetchCount = 0;
      const fetcher = async () => {
        fetchCount++;
        return { data: 'fetched' };
      };

      const result1 = await cache.getOrSet('key1', fetcher);
      const result2 = await cache.getOrSet('key1', fetcher);

      expect(result1).toEqual({ data: 'fetched' });
      expect(result2).toEqual({ data: 'fetched' });
      expect(fetchCount).toBe(1); // Only fetched once
    });

    it('should handle async fetcher errors', async () => {
      const fetcher = async () => {
        throw new Error('Fetch failed');
      };

      await expect(cache.getOrSet('key1', fetcher)).rejects.toThrow('Fetch failed');
    });

    it('should not cache failed fetches', async () => {
      let fetchCount = 0;
      const fetcher = async () => {
        fetchCount++;
        if (fetchCount === 1) {
          throw new Error('First fetch failed');
        }
        return { data: 'success' };
      };

      await expect(cache.getOrSet('key1', fetcher)).rejects.toThrow();

      const result = await cache.getOrSet('key1', fetcher);
      expect(result).toEqual({ data: 'success' });
      expect(fetchCount).toBe(2);
    });
  });

  describe('Cache invalidation', () => {
    beforeEach(() => {
      cache = createQueryCache({
        maxSize: 100,
        defaultTTL: 60000,
      });
    });

    it('should invalidate by prefix', () => {
      cache.set('users:1', { name: 'Alice' });
      cache.set('users:2', { name: 'Bob' });
      cache.set('posts:1', { title: 'Hello' });

      cache.invalidateByPrefix('users:');

      expect(cache.has('users:1')).toBe(false);
      expect(cache.has('users:2')).toBe(false);
      expect(cache.has('posts:1')).toBe(true);
    });

    it('should invalidate by pattern', () => {
      cache.set('users:1:profile', { name: 'Alice' });
      cache.set('users:1:settings', { theme: 'dark' });
      cache.set('users:2:profile', { name: 'Bob' });

      cache.invalidateByPattern(/users:\d+:profile/);

      expect(cache.has('users:1:profile')).toBe(false);
      expect(cache.has('users:1:settings')).toBe(true);
      expect(cache.has('users:2:profile')).toBe(false);
    });

    it('should track invalidation count', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.set('key3', 'value3');

      cache.invalidateByPrefix('key');

      const stats = cache.getStats();
      expect(stats.invalidations).toBe(3);
    });
  });

  describe('Namespaced caching', () => {
    beforeEach(() => {
      cache = createQueryCache({
        maxSize: 100,
        defaultTTL: 60000,
      });
    });

    it('should support namespaces', () => {
      const usersCache = cache.namespace('users');
      const postsCache = cache.namespace('posts');

      usersCache.set('1', { name: 'Alice' });
      postsCache.set('1', { title: 'Hello' });

      expect(usersCache.get('1')).toEqual({ name: 'Alice' });
      expect(postsCache.get('1')).toEqual({ title: 'Hello' });
    });

    it('should isolate namespaces', () => {
      const usersCache = cache.namespace('users');
      const postsCache = cache.namespace('posts');

      usersCache.set('1', 'user data');
      postsCache.set('1', 'post data');

      usersCache.delete('1');

      expect(usersCache.has('1')).toBe(false);
      expect(postsCache.has('1')).toBe(true);
    });

    it('should clear namespace without affecting others', () => {
      const usersCache = cache.namespace('users');
      const postsCache = cache.namespace('posts');

      usersCache.set('1', 'user');
      postsCache.set('1', 'post');

      usersCache.clear();

      expect(usersCache.has('1')).toBe(false);
      expect(postsCache.has('1')).toBe(true);
    });
  });

  describe('Memory management', () => {
    it('should estimate memory usage', () => {
      cache = createQueryCache({
        maxSize: 100,
        defaultTTL: 60000,
      });

      cache.set('key1', { data: 'a'.repeat(1000) });
      cache.set('key2', { data: 'b'.repeat(2000) });

      const stats = cache.getStats();
      expect(stats.estimatedMemoryBytes).toBeGreaterThan(3000);
    });

    it('should support memory-based eviction', () => {
      cache = createQueryCache({
        maxSize: 100,
        defaultTTL: 60000,
        maxMemoryBytes: 5000,
      });

      // Add entries that exceed memory limit
      cache.set('key1', { data: 'a'.repeat(2000) });
      cache.set('key2', { data: 'b'.repeat(2000) });
      cache.set('key3', { data: 'c'.repeat(2000) }); // Should trigger eviction

      const stats = cache.getStats();
      expect(stats.estimatedMemoryBytes).toBeLessThanOrEqual(5000);
    });
  });

  describe('Serialization', () => {
    beforeEach(() => {
      cache = createQueryCache({
        maxSize: 100,
        defaultTTL: 60000,
      });
    });

    it('should export cache to JSON', () => {
      cache.set('key1', { data: 'value1' });
      cache.set('key2', { data: 'value2' });

      const exported = cache.toJSON();

      expect(exported).toHaveProperty('entries');
      expect(exported.entries).toHaveLength(2);
    });

    it('should import cache from JSON', () => {
      const data = {
        entries: [
          { key: 'key1', value: { data: 'value1' }, expires: Date.now() + 60000 },
          { key: 'key2', value: { data: 'value2' }, expires: Date.now() + 60000 },
        ],
      };

      cache.fromJSON(data);

      expect(cache.get('key1')).toEqual({ data: 'value1' });
      expect(cache.get('key2')).toEqual({ data: 'value2' });
    });

    it('should skip expired entries on import', () => {
      const data = {
        entries: [
          { key: 'key1', value: 'value1', expires: Date.now() + 60000 },
          { key: 'key2', value: 'value2', expires: Date.now() - 1000 }, // Expired
        ],
      };

      cache.fromJSON(data);

      expect(cache.has('key1')).toBe(true);
      expect(cache.has('key2')).toBe(false);
    });
  });
});
