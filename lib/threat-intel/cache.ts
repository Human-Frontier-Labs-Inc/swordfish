/**
 * Threat Intelligence Cache
 * In-memory cache with TTL for threat feed results
 */

import type { ThreatCheckResult, DomainCheckResult } from './feeds';

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
}

// Cache TTLs
const URL_CACHE_TTL = 60 * 60 * 1000; // 1 hour
const DOMAIN_CACHE_TTL = 4 * 60 * 60 * 1000; // 4 hours
const IP_CACHE_TTL = 2 * 60 * 60 * 1000; // 2 hours

// Max cache sizes
const MAX_URL_CACHE = 50000;
const MAX_DOMAIN_CACHE = 20000;
const MAX_IP_CACHE = 10000;

export class ThreatFeedCache {
  private urlCache: Map<string, CacheEntry<ThreatCheckResult>> = new Map();
  private domainCache: Map<string, CacheEntry<DomainCheckResult>> = new Map();
  private ipCache: Map<string, CacheEntry<IPCheckResult>> = new Map();

  /**
   * Get cached URL result
   */
  getUrlResult(url: string): ThreatCheckResult | null {
    const entry = this.urlCache.get(url);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.urlCache.delete(url);
      return null;
    }

    return entry.data;
  }

  /**
   * Set cached URL result
   */
  setUrlResult(url: string, result: ThreatCheckResult): void {
    // Evict oldest entries if cache is full
    if (this.urlCache.size >= MAX_URL_CACHE) {
      this.evictOldest(this.urlCache);
    }

    this.urlCache.set(url, {
      data: result,
      expiresAt: Date.now() + URL_CACHE_TTL,
    });
  }

  /**
   * Get cached domain result
   */
  getDomainResult(domain: string): DomainCheckResult | null {
    const entry = this.domainCache.get(domain);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.domainCache.delete(domain);
      return null;
    }

    return entry.data;
  }

  /**
   * Set cached domain result
   */
  setDomainResult(domain: string, result: DomainCheckResult): void {
    if (this.domainCache.size >= MAX_DOMAIN_CACHE) {
      this.evictOldest(this.domainCache);
    }

    this.domainCache.set(domain, {
      data: result,
      expiresAt: Date.now() + DOMAIN_CACHE_TTL,
    });
  }

  /**
   * Get cached IP result
   */
  getIPResult(ip: string): IPCheckResult | null {
    const entry = this.ipCache.get(ip);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.ipCache.delete(ip);
      return null;
    }

    return entry.data;
  }

  /**
   * Set cached IP result
   */
  setIPResult(ip: string, result: IPCheckResult): void {
    if (this.ipCache.size >= MAX_IP_CACHE) {
      this.evictOldest(this.ipCache);
    }

    this.ipCache.set(ip, {
      data: result,
      expiresAt: Date.now() + IP_CACHE_TTL,
    });
  }

  /**
   * Clear all caches
   */
  clear(): void {
    this.urlCache.clear();
    this.domainCache.clear();
    this.ipCache.clear();
  }

  /**
   * Get cache statistics
   */
  getStats(): {
    urls: { size: number; maxSize: number };
    domains: { size: number; maxSize: number };
    ips: { size: number; maxSize: number };
  } {
    return {
      urls: { size: this.urlCache.size, maxSize: MAX_URL_CACHE },
      domains: { size: this.domainCache.size, maxSize: MAX_DOMAIN_CACHE },
      ips: { size: this.ipCache.size, maxSize: MAX_IP_CACHE },
    };
  }

  /**
   * Evict oldest entries from cache
   */
  private evictOldest<T>(cache: Map<string, CacheEntry<T>>): void {
    // Remove 10% of entries
    const toRemove = Math.ceil(cache.size * 0.1);
    const entries = Array.from(cache.entries());
    entries.sort((a, b) => a[1].expiresAt - b[1].expiresAt);

    for (let i = 0; i < toRemove && i < entries.length; i++) {
      cache.delete(entries[i][0]);
    }
  }

  /**
   * Clean expired entries
   */
  cleanExpired(): {
    urlsRemoved: number;
    domainsRemoved: number;
    ipsRemoved: number;
  } {
    const now = Date.now();
    let urlsRemoved = 0;
    let domainsRemoved = 0;
    let ipsRemoved = 0;

    for (const [key, entry] of this.urlCache) {
      if (now > entry.expiresAt) {
        this.urlCache.delete(key);
        urlsRemoved++;
      }
    }

    for (const [key, entry] of this.domainCache) {
      if (now > entry.expiresAt) {
        this.domainCache.delete(key);
        domainsRemoved++;
      }
    }

    for (const [key, entry] of this.ipCache) {
      if (now > entry.expiresAt) {
        this.ipCache.delete(key);
        ipsRemoved++;
      }
    }

    return { urlsRemoved, domainsRemoved, ipsRemoved };
  }
}

// IP check result type
export interface IPCheckResult {
  ip: string;
  isThreat: boolean;
  verdict: 'clean' | 'malicious' | 'suspicious' | 'unknown';
  sources: Array<{
    list: string;
    category?: string;
    description?: string;
  }>;
  geolocation?: {
    country?: string;
    countryCode?: string;
    region?: string;
    city?: string;
    isp?: string;
    org?: string;
  };
  checkedAt: Date;
}

// Create singleton instance
export const threatCache = new ThreatFeedCache();
