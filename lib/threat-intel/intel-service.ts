/**
 * Threat Intelligence Feeds Service
 *
 * Aggregates intelligence from multiple threat feeds for URLs, domains, and IPs
 */

import {
  executeWithFallback,
  getDefaultUrlCheckResult,
  getDefaultDomainCheckResult,
  getDefaultIpCheckResult,
  type FallbackConfig,
  DEFAULT_FALLBACK_CONFIG,
} from './fallback';
import { loggers } from '@/lib/logging/logger';

const log = loggers.threatIntel;

/**
 * Per-service cache TTL configuration
 * Different data types have different update frequencies:
 * - Domain info: Changes infrequently, safe to cache longer
 * - URL reputation: Can change as URLs get blacklisted
 * - IP reputation: Changes frequently, needs shorter TTL
 */
export interface CacheTtlConfig {
  /** URL reputation cache TTL in ms (default: 1 hour) */
  urlTtlMs?: number;
  /** Domain reputation cache TTL in ms (default: 24 hours - rarely changes) */
  domainTtlMs?: number;
  /** IP reputation cache TTL in ms (default: 15 minutes - changes frequently) */
  ipTtlMs?: number;
}

/**
 * Default cache TTLs optimized for each data type
 */
export const DEFAULT_CACHE_TTLS: Required<CacheTtlConfig> = {
  urlTtlMs: 3600000,      // 1 hour - URLs can get blacklisted
  domainTtlMs: 86400000,  // 24 hours - domain info rarely changes
  ipTtlMs: 900000,        // 15 minutes - IP reputation changes frequently
};

export interface ThreatIntelConfig {
  apiKey: string;
  baseUrl?: string;
  feeds?: string[];
  /** @deprecated Use cacheTtls instead for per-service TTLs */
  cacheTtlMs?: number;
  /** Per-service cache TTL configuration */
  cacheTtls?: CacheTtlConfig;
  fallbackConfig?: Partial<FallbackConfig>;
}

export interface UrlCheckResult {
  url: string;
  isMalicious: boolean;
  threatTypes: string[];
  riskScore: number;
  lastSeen?: string;
  sources?: string[];
}

export interface DomainCheckResult {
  domain: string;
  isSuspicious: boolean;
  reputationScore: number;
  categories: string[];
  registrar?: string;
  ageDays: number;
}

export interface IpCheckResult {
  ip: string;
  isProxy: boolean;
  isTor: boolean;
  isDatacenter: boolean;
  abuseConfidence: number;
  country?: string;
}

export interface AggregatedIntelligence {
  indicator: string;
  consensusScore: number;
  isMalicious: boolean;
  sources: Array<{
    name: string;
    verdict: boolean;
    confidence: number;
  }>;
}

interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

export class ThreatIntelService {
  private config: ThreatIntelConfig;
  private urlCache: Map<string, CacheEntry<UrlCheckResult>> = new Map();
  private domainCache: Map<string, CacheEntry<DomainCheckResult>> = new Map();
  private ipCache: Map<string, CacheEntry<IpCheckResult>> = new Map();
  private cacheTtls: Required<CacheTtlConfig>;
  private fallbackConfig: FallbackConfig;

  constructor(config: ThreatIntelConfig) {
    this.config = {
      ...config,
      baseUrl: config.baseUrl || 'https://api.threatintel.example.com/v1',
      feeds: config.feeds || ['default'],
    };
    // Support both legacy single TTL and new per-service TTLs
    if (config.cacheTtls) {
      this.cacheTtls = { ...DEFAULT_CACHE_TTLS, ...config.cacheTtls };
    } else if (config.cacheTtlMs) {
      // Legacy: Use same TTL for all caches
      this.cacheTtls = {
        urlTtlMs: config.cacheTtlMs,
        domainTtlMs: config.cacheTtlMs,
        ipTtlMs: config.cacheTtlMs,
      };
    } else {
      // Default: Use optimized per-service TTLs
      this.cacheTtls = { ...DEFAULT_CACHE_TTLS };
    }
    this.fallbackConfig = { ...DEFAULT_FALLBACK_CONFIG, ...config.fallbackConfig };
  }

  /**
   * Check URL against threat intelligence feeds
   * Uses fallback when API is unavailable
   */
  async checkUrl(url: string): Promise<UrlCheckResult> {
    // Check cache first
    const cached = this.urlCache.get(url);
    if (cached && Date.now() - cached.timestamp < this.cacheTtls.urlTtlMs) {
      return cached.data;
    }

    const { data: result } = await executeWithFallback(
      'threat-intel-service',
      async () => {
        const response = await fetch(`${this.config.baseUrl}/url/check`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'api-key': this.config.apiKey,
          },
          body: JSON.stringify({ url }),
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        return {
          url: data.url || url,
          isMalicious: data.threat_types?.length > 0 || data.risk_score > 70,
          threatTypes: data.threat_types || [],
          riskScore: data.risk_score || 0,
          lastSeen: data.last_seen,
        } as UrlCheckResult;
      },
      () => getDefaultUrlCheckResult(url),
      this.fallbackConfig
    );

    // Cache result
    this.urlCache.set(url, {
      data: result,
      timestamp: Date.now(),
    });

    return result;
  }

  /**
   * Check domain reputation
   * Uses fallback when API is unavailable
   */
  async checkDomain(domain: string): Promise<DomainCheckResult> {
    // Check cache first
    const cached = this.domainCache.get(domain);
    if (cached && Date.now() - cached.timestamp < this.cacheTtls.domainTtlMs) {
      return cached.data;
    }

    const { data: result } = await executeWithFallback(
      'threat-intel-service',
      async () => {
        const response = await fetch(`${this.config.baseUrl}/domain/check`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'api-key': this.config.apiKey,
          },
          body: JSON.stringify({ domain }),
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        return {
          domain: data.domain || domain,
          isSuspicious: data.reputation_score < 30 || data.categories?.length > 0,
          reputationScore: data.reputation_score || 50,
          categories: data.categories || [],
          registrar: data.registrar,
          ageDays: data.age_days || 0,
        } as DomainCheckResult;
      },
      () => getDefaultDomainCheckResult(domain),
      this.fallbackConfig
    );

    // Cache result
    this.domainCache.set(domain, {
      data: result,
      timestamp: Date.now(),
    });

    return result;
  }

  /**
   * Check IP reputation
   * Uses fallback when API is unavailable
   */
  async checkIp(ip: string): Promise<IpCheckResult> {
    // Check cache first
    const cached = this.ipCache.get(ip);
    if (cached && Date.now() - cached.timestamp < this.cacheTtls.ipTtlMs) {
      return cached.data;
    }

    const { data: result } = await executeWithFallback(
      'threat-intel-service',
      async () => {
        const response = await fetch(`${this.config.baseUrl}/ip/check`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'api-key': this.config.apiKey,
          },
          body: JSON.stringify({ ip }),
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        return {
          ip: data.ip || ip,
          isProxy: data.is_proxy || false,
          isTor: data.is_tor || false,
          isDatacenter: data.is_datacenter || false,
          abuseConfidence: data.abuse_confidence || 0,
          country: data.country,
        } as IpCheckResult;
      },
      () => getDefaultIpCheckResult(ip),
      this.fallbackConfig
    );

    // Cache result
    this.ipCache.set(ip, {
      data: result,
      timestamp: Date.now(),
    });

    return result;
  }

  /**
   * Aggregate intelligence from multiple feeds
   */
  async aggregateIntelligence(indicator: string): Promise<AggregatedIntelligence> {
    const feeds = this.config.feeds || ['default'];
    const sources: AggregatedIntelligence['sources'] = [];

    // Query each feed
    for (const feed of feeds) {
      try {
        const response = await fetch(`${this.config.baseUrl}/feeds/${feed}/check`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'api-key': this.config.apiKey,
          },
          body: JSON.stringify({ indicator }),
        });

        const data = await response.json();
        sources.push({
          name: data.source || feed,
          verdict: data.malicious || false,
          confidence: data.confidence || 0.5,
        });
      } catch {
        // Skip failed feeds
        sources.push({
          name: feed,
          verdict: false,
          confidence: 0,
        });
      }
    }

    // Calculate consensus
    const maliciousCount = sources.filter(s => s.verdict).length;
    const consensusScore = (maliciousCount / sources.length) * 100;

    return {
      indicator,
      consensusScore,
      isMalicious: consensusScore > 50,
      sources,
    };
  }

  /**
   * Batch check multiple indicators
   * Returns a map of indicator -> result with unknown status for failed checks
   */
  async batchCheck(indicators: string[]): Promise<Map<string, boolean | 'unknown'>> {
    const results = new Map<string, boolean | 'unknown'>();

    // Process in parallel
    await Promise.all(
      indicators.map(async (indicator) => {
        try {
          const intel = await this.aggregateIntelligence(indicator);
          results.set(indicator, intel.isMalicious);
        } catch {
          // SECURITY FIX: Do NOT default to safe (false) on error
          // Instead, mark as 'unknown' so callers can handle appropriately
          results.set(indicator, 'unknown');
          log.warn('Batch check failed, marking as unknown', { indicator });
        }
      })
    );

    return results;
  }

  /**
   * Get threat categories for an indicator
   */
  async getCategories(indicator: string): Promise<string[]> {
    const response = await fetch(`${this.config.baseUrl}/categories/${encodeURIComponent(indicator)}`, {
      method: 'GET',
      headers: {
        'api-key': this.config.apiKey,
      },
    });

    const data = await response.json();
    return data.categories || [];
  }

  /**
   * Clear all caches
   */
  clearCache(): void {
    this.urlCache.clear();
    this.domainCache.clear();
    this.ipCache.clear();
  }

  /**
   * Get current cache TTL configuration
   */
  getCacheTtls(): Required<CacheTtlConfig> {
    return { ...this.cacheTtls };
  }

  /**
   * Get cache statistics for monitoring
   */
  getCacheStats(): {
    urlCacheSize: number;
    domainCacheSize: number;
    ipCacheSize: number;
    urlTtlMs: number;
    domainTtlMs: number;
    ipTtlMs: number;
  } {
    return {
      urlCacheSize: this.urlCache.size,
      domainCacheSize: this.domainCache.size,
      ipCacheSize: this.ipCache.size,
      ...this.cacheTtls,
    };
  }
}
