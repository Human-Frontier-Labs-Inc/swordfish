/**
 * DNS Resolver with Caching
 * Provides DNS lookups for SPF, DKIM, and DMARC validation with TTL-based caching
 */

import type { DNSResolver, DNSCache } from './types';

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

/**
 * In-memory DNS cache with TTL support
 */
export class MemoryDNSCache implements DNSCache {
  private cache: Map<string, CacheEntry<string[]>> = new Map();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(cleanupIntervalMs: number = 60000) {
    // Periodic cleanup of expired entries
    if (typeof setInterval !== 'undefined') {
      this.cleanupInterval = setInterval(() => this.cleanup(), cleanupIntervalMs);
    }
  }

  async get(key: string): Promise<string[] | null> {
    const entry = this.cache.get(key);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }

    return entry.value;
  }

  async set(key: string, value: string[], ttl: number): Promise<void> {
    this.cache.set(key, {
      value,
      expiresAt: Date.now() + (ttl * 1000),
    });
  }

  async delete(key: string): Promise<void> {
    this.cache.delete(key);
  }

  async clear(): Promise<void> {
    this.cache.clear();
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
      }
    }
  }

  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.cache.clear();
  }

  size(): number {
    return this.cache.size;
  }
}

/**
 * Mock DNS data for testing
 */
export interface MockDNSData {
  txt?: Record<string, string[]>;
  a?: Record<string, string[]>;
  aaaa?: Record<string, string[]>;
  mx?: Record<string, Array<{ priority: number; exchange: string }>>;
}

/**
 * Mock DNS Resolver for testing
 */
export class MockDNSResolver implements DNSResolver {
  private data: MockDNSData;
  private errors: Map<string, Error> = new Map();

  constructor(data: MockDNSData = {}) {
    this.data = data;
  }

  setData(data: MockDNSData): void {
    this.data = { ...this.data, ...data };
  }

  setTxtRecord(domain: string, records: string[]): void {
    if (!this.data.txt) this.data.txt = {};
    this.data.txt[domain.toLowerCase()] = records;
  }

  setARecord(domain: string, ips: string[]): void {
    if (!this.data.a) this.data.a = {};
    this.data.a[domain.toLowerCase()] = ips;
  }

  setAAAARecord(domain: string, ips: string[]): void {
    if (!this.data.aaaa) this.data.aaaa = {};
    this.data.aaaa[domain.toLowerCase()] = ips;
  }

  setMxRecord(domain: string, records: Array<{ priority: number; exchange: string }>): void {
    if (!this.data.mx) this.data.mx = {};
    this.data.mx[domain.toLowerCase()] = records;
  }

  setError(domain: string, error: Error): void {
    this.errors.set(domain.toLowerCase(), error);
  }

  clearError(domain: string): void {
    this.errors.delete(domain.toLowerCase());
  }

  async resolveTxt(domain: string): Promise<string[]> {
    const normalizedDomain = domain.toLowerCase();

    const error = this.errors.get(normalizedDomain);
    if (error) throw error;

    return this.data.txt?.[normalizedDomain] || [];
  }

  async resolveA(domain: string): Promise<string[]> {
    const normalizedDomain = domain.toLowerCase();

    const error = this.errors.get(normalizedDomain);
    if (error) throw error;

    return this.data.a?.[normalizedDomain] || [];
  }

  async resolveAAAA(domain: string): Promise<string[]> {
    const normalizedDomain = domain.toLowerCase();

    const error = this.errors.get(normalizedDomain);
    if (error) throw error;

    return this.data.aaaa?.[normalizedDomain] || [];
  }

  async resolveMx(domain: string): Promise<Array<{ priority: number; exchange: string }>> {
    const normalizedDomain = domain.toLowerCase();

    const error = this.errors.get(normalizedDomain);
    if (error) throw error;

    return this.data.mx?.[normalizedDomain] || [];
  }
}

/**
 * Caching DNS Resolver wrapper
 */
export class CachingDNSResolver implements DNSResolver {
  private resolver: DNSResolver;
  private cache: DNSCache;
  private defaultTTL: number;

  constructor(
    resolver: DNSResolver,
    cache: DNSCache = new MemoryDNSCache(),
    defaultTTL: number = 300 // 5 minutes
  ) {
    this.resolver = resolver;
    this.cache = cache;
    this.defaultTTL = defaultTTL;
  }

  async resolveTxt(domain: string): Promise<string[]> {
    const cacheKey = `txt:${domain.toLowerCase()}`;

    const cached = await this.cache.get(cacheKey);
    if (cached) return cached;

    const result = await this.resolver.resolveTxt(domain);
    await this.cache.set(cacheKey, result, this.defaultTTL);

    return result;
  }

  async resolveA(domain: string): Promise<string[]> {
    const cacheKey = `a:${domain.toLowerCase()}`;

    const cached = await this.cache.get(cacheKey);
    if (cached) return cached;

    const result = await this.resolver.resolveA(domain);
    await this.cache.set(cacheKey, result, this.defaultTTL);

    return result;
  }

  async resolveAAAA(domain: string): Promise<string[]> {
    const cacheKey = `aaaa:${domain.toLowerCase()}`;

    const cached = await this.cache.get(cacheKey);
    if (cached) return cached;

    const result = await this.resolver.resolveAAAA(domain);
    await this.cache.set(cacheKey, result, this.defaultTTL);

    return result;
  }

  async resolveMx(domain: string): Promise<Array<{ priority: number; exchange: string }>> {
    const cacheKey = `mx:${domain.toLowerCase()}`;

    const cached = await this.cache.get(cacheKey);
    if (cached) {
      // Parse cached MX records
      return cached.map(entry => {
        const [priority, exchange] = entry.split(':');
        return { priority: parseInt(priority, 10), exchange };
      });
    }

    const result = await this.resolver.resolveMx(domain);

    // Serialize MX records for caching
    const serialized = result.map(r => `${r.priority}:${r.exchange}`);
    await this.cache.set(cacheKey, serialized, this.defaultTTL);

    return result;
  }

  async clearCache(): Promise<void> {
    await this.cache.clear();
  }
}

/**
 * Production DNS Resolver using Node.js dns module (when available)
 * Falls back to mock for browser/edge environments
 */
export class ProductionDNSResolver implements DNSResolver {
  private dnsModule: typeof import('dns') | null = null;

  constructor() {
    // Try to load dns module (Node.js only)
    try {
      // Dynamic import for Node.js
      if (typeof process !== 'undefined' && process.versions?.node) {
        // This will be resolved at build time or runtime
        this.dnsModule = require('dns');
      }
    } catch {
      // dns module not available (browser/edge)
      this.dnsModule = null;
    }
  }

  async resolveTxt(domain: string): Promise<string[]> {
    if (!this.dnsModule) {
      throw new Error('DNS resolution not available in this environment');
    }

    return new Promise((resolve, reject) => {
      this.dnsModule!.resolveTxt(domain, (err, records) => {
        if (err) {
          if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') {
            resolve([]);
          } else {
            reject(err);
          }
        } else {
          // DNS TXT records are returned as arrays of strings
          resolve(records.map(r => r.join('')));
        }
      });
    });
  }

  async resolveA(domain: string): Promise<string[]> {
    if (!this.dnsModule) {
      throw new Error('DNS resolution not available in this environment');
    }

    return new Promise((resolve, reject) => {
      this.dnsModule!.resolve4(domain, (err, addresses) => {
        if (err) {
          if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') {
            resolve([]);
          } else {
            reject(err);
          }
        } else {
          resolve(addresses);
        }
      });
    });
  }

  async resolveAAAA(domain: string): Promise<string[]> {
    if (!this.dnsModule) {
      throw new Error('DNS resolution not available in this environment');
    }

    return new Promise((resolve, reject) => {
      this.dnsModule!.resolve6(domain, (err, addresses) => {
        if (err) {
          if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') {
            resolve([]);
          } else {
            reject(err);
          }
        } else {
          resolve(addresses);
        }
      });
    });
  }

  async resolveMx(domain: string): Promise<Array<{ priority: number; exchange: string }>> {
    if (!this.dnsModule) {
      throw new Error('DNS resolution not available in this environment');
    }

    return new Promise((resolve, reject) => {
      this.dnsModule!.resolveMx(domain, (err, addresses) => {
        if (err) {
          if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') {
            resolve([]);
          } else {
            reject(err);
          }
        } else {
          resolve(addresses);
        }
      });
    });
  }
}

/**
 * Create the appropriate DNS resolver for the current environment
 */
export function createDNSResolver(cache?: DNSCache): CachingDNSResolver {
  const baseResolver = new ProductionDNSResolver();
  return new CachingDNSResolver(
    baseResolver,
    cache || new MemoryDNSCache()
  );
}

/**
 * Create a mock DNS resolver for testing
 */
export function createMockDNSResolver(data?: MockDNSData): MockDNSResolver {
  return new MockDNSResolver(data);
}
