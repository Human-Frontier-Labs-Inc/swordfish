/**
 * Query Cache Module
 *
 * In-memory caching for database queries with LRU eviction,
 * TTL support, namespacing, and comprehensive statistics.
 */

import { createHash } from 'crypto';

/**
 * Cache configuration
 */
export interface CacheConfig {
  maxSize: number;
  defaultTTL: number;
  refreshOnAccess: boolean;
  maxMemoryBytes?: number;
}

/**
 * Cache entry
 */
export interface CacheEntry<T = unknown> {
  key: string;
  value: T;
  expires: number;
  createdAt: number;
  accessedAt: number;
  accessCount: number;
  sizeBytes: number;
}

/**
 * Cache statistics
 */
export interface CacheStats {
  maxSize: number;
  size: number;
  hits: number;
  misses: number;
  hitRate: number;
  evictions: number;
  expired: number;
  invalidations: number;
  defaultTTL: number;
  estimatedMemoryBytes: number;
}

/**
 * Serialized cache data
 */
interface SerializedCache {
  entries: Array<{
    key: string;
    value: unknown;
    expires: number;
  }>;
}

/**
 * Cache set options
 */
interface SetOptions {
  ttl?: number;
}

/**
 * Namespaced cache interface
 */
interface NamespacedCache {
  get<T = unknown>(key: string): T | undefined;
  set<T>(key: string, value: T, options?: SetOptions): void;
  has(key: string): boolean;
  delete(key: string): void;
  clear(): void;
}

/**
 * Estimate size of a value in bytes
 */
function estimateSize(value: unknown): number {
  try {
    const json = JSON.stringify(value);
    return json.length * 2; // Approximate UTF-16 size
  } catch {
    return 100; // Default size for non-serializable values
  }
}

/**
 * Query Cache class
 */
export class QueryCache {
  private config: CacheConfig;
  private entries: Map<string, CacheEntry> = new Map();
  private accessOrder: string[] = [];
  private hits: number = 0;
  private misses: number = 0;
  private evictions: number = 0;
  private expired: number = 0;
  private invalidations: number = 0;

  constructor(config: Partial<CacheConfig> = {}) {
    // Validate config
    const maxSize = config.maxSize ?? 1000;
    const defaultTTL = config.defaultTTL ?? 300000;

    if (maxSize <= 0) {
      throw new Error('maxSize must be positive');
    }

    if (defaultTTL <= 0) {
      throw new Error('defaultTTL must be positive');
    }

    this.config = {
      maxSize,
      defaultTTL,
      refreshOnAccess: config.refreshOnAccess ?? false,
      maxMemoryBytes: config.maxMemoryBytes,
    };
  }

  /**
   * Get a value from the cache
   */
  get<T = unknown>(key: string): T | undefined {
    const entry = this.entries.get(key);

    if (!entry) {
      this.misses++;
      return undefined;
    }

    // Check if expired
    if (Date.now() > entry.expires) {
      this.entries.delete(key);
      this.accessOrder = this.accessOrder.filter((k) => k !== key);
      this.expired++;
      this.misses++;
      return undefined;
    }

    this.hits++;
    entry.accessedAt = Date.now();
    entry.accessCount++;

    // Refresh TTL on access if configured
    if (this.config.refreshOnAccess) {
      entry.expires = Date.now() + this.config.defaultTTL;
    }

    // Update access order for LRU
    this.updateAccessOrder(key);

    return entry.value as T;
  }

  /**
   * Set a value in the cache
   */
  set<T>(key: string, value: T, options: SetOptions = {}): void {
    const now = Date.now();
    const ttl = options.ttl ?? this.config.defaultTTL;
    const sizeBytes = estimateSize(value);

    // Check if we need to evict for size
    if (!this.entries.has(key)) {
      this.ensureCapacity();
    }

    // Check memory limit
    if (this.config.maxMemoryBytes) {
      this.ensureMemoryLimit(sizeBytes);
    }

    const entry: CacheEntry = {
      key,
      value,
      expires: now + ttl,
      createdAt: now,
      accessedAt: now,
      accessCount: 0,
      sizeBytes,
    };

    this.entries.set(key, entry);
    this.updateAccessOrder(key);
  }

  /**
   * Check if a key exists in the cache
   */
  has(key: string): boolean {
    const entry = this.entries.get(key);
    if (!entry) return false;

    // Check if expired
    if (Date.now() > entry.expires) {
      this.entries.delete(key);
      this.accessOrder = this.accessOrder.filter((k) => k !== key);
      this.expired++;
      return false;
    }

    return true;
  }

  /**
   * Delete an entry from the cache
   */
  delete(key: string): void {
    this.entries.delete(key);
    this.accessOrder = this.accessOrder.filter((k) => k !== key);
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.entries.clear();
    this.accessOrder = [];
  }

  /**
   * Get or set a value using a fetcher function
   */
  async getOrSet<T>(key: string, fetcher: () => Promise<T>, options?: SetOptions): Promise<T> {
    const cached = this.get<T>(key);
    if (cached !== undefined) {
      return cached;
    }

    const value = await fetcher();
    this.set(key, value, options);
    return value;
  }

  /**
   * Generate a cache key from query and params
   */
  generateKey(query: string, params: unknown[]): string {
    const input = JSON.stringify({ query, params });
    return createHash('sha256').update(input).digest('hex').slice(0, 16);
  }

  /**
   * Invalidate entries by prefix
   */
  invalidateByPrefix(prefix: string): void {
    const keysToDelete: string[] = [];

    for (const key of this.entries.keys()) {
      if (key.startsWith(prefix)) {
        keysToDelete.push(key);
      }
    }

    for (const key of keysToDelete) {
      this.entries.delete(key);
      this.accessOrder = this.accessOrder.filter((k) => k !== key);
      this.invalidations++;
    }
  }

  /**
   * Invalidate entries by pattern
   */
  invalidateByPattern(pattern: RegExp): void {
    const keysToDelete: string[] = [];

    for (const key of this.entries.keys()) {
      if (pattern.test(key)) {
        keysToDelete.push(key);
      }
    }

    for (const key of keysToDelete) {
      this.entries.delete(key);
      this.accessOrder = this.accessOrder.filter((k) => k !== key);
      this.invalidations++;
    }
  }

  /**
   * Create a namespaced cache
   */
  namespace(ns: string): NamespacedCache {
    const prefix = `${ns}:`;

    return {
      get: <T = unknown>(key: string): T | undefined => {
        return this.get<T>(prefix + key);
      },
      set: <T>(key: string, value: T, options?: SetOptions): void => {
        this.set(prefix + key, value, options);
      },
      has: (key: string): boolean => {
        return this.has(prefix + key);
      },
      delete: (key: string): void => {
        this.delete(prefix + key);
      },
      clear: (): void => {
        this.invalidateByPrefix(prefix);
      },
    };
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    const total = this.hits + this.misses;
    let estimatedMemoryBytes = 0;

    for (const entry of this.entries.values()) {
      estimatedMemoryBytes += entry.sizeBytes;
    }

    return {
      maxSize: this.config.maxSize,
      size: this.entries.size,
      hits: this.hits,
      misses: this.misses,
      hitRate: total > 0 ? this.hits / total : 0,
      evictions: this.evictions,
      expired: this.expired,
      invalidations: this.invalidations,
      defaultTTL: this.config.defaultTTL,
      estimatedMemoryBytes,
    };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.hits = 0;
    this.misses = 0;
    this.evictions = 0;
    this.expired = 0;
    this.invalidations = 0;
  }

  /**
   * Export cache to JSON
   */
  toJSON(): SerializedCache {
    const entries: SerializedCache['entries'] = [];

    for (const entry of this.entries.values()) {
      entries.push({
        key: entry.key,
        value: entry.value,
        expires: entry.expires,
      });
    }

    return { entries };
  }

  /**
   * Import cache from JSON
   */
  fromJSON(data: SerializedCache): void {
    const now = Date.now();

    for (const item of data.entries) {
      // Skip expired entries
      if (item.expires <= now) {
        continue;
      }

      const ttl = item.expires - now;
      this.set(item.key, item.value, { ttl });
    }
  }

  private updateAccessOrder(key: string): void {
    // Remove existing position
    this.accessOrder = this.accessOrder.filter((k) => k !== key);
    // Add to end (most recently used)
    this.accessOrder.push(key);
  }

  private ensureCapacity(): void {
    while (this.entries.size >= this.config.maxSize && this.accessOrder.length > 0) {
      // Remove least recently used
      const lruKey = this.accessOrder.shift()!;
      this.entries.delete(lruKey);
      this.evictions++;
    }
  }

  private ensureMemoryLimit(newEntrySize: number): void {
    if (!this.config.maxMemoryBytes) return;

    let currentMemory = 0;
    for (const entry of this.entries.values()) {
      currentMemory += entry.sizeBytes;
    }

    while (
      currentMemory + newEntrySize > this.config.maxMemoryBytes &&
      this.accessOrder.length > 0
    ) {
      const lruKey = this.accessOrder.shift()!;
      const entry = this.entries.get(lruKey);
      if (entry) {
        currentMemory -= entry.sizeBytes;
        this.entries.delete(lruKey);
        this.evictions++;
      }
    }
  }
}

/**
 * Create a query cache instance
 */
export function createQueryCache(config?: Partial<CacheConfig>): QueryCache {
  return new QueryCache(config);
}
