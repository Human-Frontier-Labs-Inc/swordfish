/**
 * Threat Intelligence Feeds Service
 *
 * Aggregates intelligence from multiple threat feeds for URLs, domains, and IPs
 */

export interface ThreatIntelConfig {
  apiKey: string;
  baseUrl?: string;
  feeds?: string[];
  cacheTtlMs?: number;
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
  private cacheTtlMs: number;

  constructor(config: ThreatIntelConfig) {
    this.config = {
      ...config,
      baseUrl: config.baseUrl || 'https://api.threatintel.example.com/v1',
      feeds: config.feeds || ['default'],
    };
    this.cacheTtlMs = config.cacheTtlMs || 3600000; // 1 hour default
  }

  /**
   * Check URL against threat intelligence feeds
   */
  async checkUrl(url: string): Promise<UrlCheckResult> {
    // Check cache first
    const cached = this.urlCache.get(url);
    if (cached && Date.now() - cached.timestamp < this.cacheTtlMs) {
      return cached.data;
    }

    const response = await fetch(`${this.config.baseUrl}/url/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': this.config.apiKey,
      },
      body: JSON.stringify({ url }),
    });

    const data = await response.json();

    const result: UrlCheckResult = {
      url: data.url,
      isMalicious: data.threat_types?.length > 0 || data.risk_score > 70,
      threatTypes: data.threat_types || [],
      riskScore: data.risk_score || 0,
      lastSeen: data.last_seen,
    };

    // Cache result
    this.urlCache.set(url, {
      data: result,
      timestamp: Date.now(),
    });

    return result;
  }

  /**
   * Check domain reputation
   */
  async checkDomain(domain: string): Promise<DomainCheckResult> {
    // Check cache first
    const cached = this.domainCache.get(domain);
    if (cached && Date.now() - cached.timestamp < this.cacheTtlMs) {
      return cached.data;
    }

    const response = await fetch(`${this.config.baseUrl}/domain/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': this.config.apiKey,
      },
      body: JSON.stringify({ domain }),
    });

    const data = await response.json();

    const result: DomainCheckResult = {
      domain: data.domain,
      isSuspicious: data.reputation_score < 30 || data.categories?.length > 0,
      reputationScore: data.reputation_score || 50,
      categories: data.categories || [],
      registrar: data.registrar,
      ageDays: data.age_days || 0,
    };

    // Cache result
    this.domainCache.set(domain, {
      data: result,
      timestamp: Date.now(),
    });

    return result;
  }

  /**
   * Check IP reputation
   */
  async checkIp(ip: string): Promise<IpCheckResult> {
    // Check cache first
    const cached = this.ipCache.get(ip);
    if (cached && Date.now() - cached.timestamp < this.cacheTtlMs) {
      return cached.data;
    }

    const response = await fetch(`${this.config.baseUrl}/ip/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': this.config.apiKey,
      },
      body: JSON.stringify({ ip }),
    });

    const data = await response.json();

    const result: IpCheckResult = {
      ip: data.ip,
      isProxy: data.is_proxy || false,
      isTor: data.is_tor || false,
      isDatacenter: data.is_datacenter || false,
      abuseConfidence: data.abuse_confidence || 0,
      country: data.country,
    };

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
   */
  async batchCheck(indicators: string[]): Promise<Map<string, boolean>> {
    const results = new Map<string, boolean>();

    // Process in parallel
    await Promise.all(
      indicators.map(async (indicator) => {
        try {
          const intel = await this.aggregateIntelligence(indicator);
          results.set(indicator, intel.isMalicious);
        } catch {
          results.set(indicator, false); // Default to safe on error
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
}
