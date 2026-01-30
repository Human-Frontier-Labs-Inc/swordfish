/**
 * Phase 4b: Multi-layer Threat Intelligence Integration
 *
 * Aggregates intelligence from multiple threat feeds with consensus voting:
 * - VirusTotal
 * - URLhaus
 * - PhishTank
 * - OpenPhish
 *
 * Expected Impact: +2.5 detection points
 */

import type { Signal } from './types';

// ============================================================================
// Types & Interfaces
// ============================================================================

export interface ThreatIntelOptions {
  feeds: string[];
  mockResponses?: Record<string, FeedResponse>;
  cacheTtlMs?: number;
  forceRefresh?: boolean;
}

export interface FeedResponse {
  verdict: 'clean' | 'suspicious' | 'malicious';
  score: number;
  reliability?: number;
  category?: string;
  malwareFamily?: string;
  tags?: string[];
}

export interface ThreatIntelSource {
  feed: string;
  verdict: FeedResponse['verdict'];
  score: number;
  reliability: number;
  category?: string;
  malwareFamily?: string;
  tags?: string[];
}

export interface ThreatIntelResult {
  url: string;
  consensusScore: number;
  confidence: number;
  agreementRatio: number;
  sources: ThreatIntelSource[];
  disagreement: boolean;
  fromCache: boolean;
  checkedAt: Date;
}

// ============================================================================
// Constants
// ============================================================================

/**
 * Default reliability scores for threat feeds
 */
const FEED_RELIABILITY: Record<string, number> = {
  virustotal: 0.95,
  urlhaus: 0.85,
  phishtank: 0.80,
  openphish: 0.75,
  default: 0.5,
};

/**
 * Cache TTL defaults (5 minutes for real-time balance)
 */
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;

// ============================================================================
// Cache Implementation
// ============================================================================

interface CacheEntry {
  result: ThreatIntelResult;
  expiresAt: number;
}

const threatIntelCache = new Map<string, CacheEntry>();

/**
 * Get cached result for URL
 */
function getCachedResult(url: string, ttlMs: number): ThreatIntelResult | null {
  const entry = threatIntelCache.get(url);
  if (!entry) return null;

  if (Date.now() > entry.expiresAt) {
    threatIntelCache.delete(url);
    return null;
  }

  return { ...entry.result, fromCache: true };
}

/**
 * Cache a threat intel result
 */
function setCacheResult(url: string, result: ThreatIntelResult, ttlMs: number): void {
  threatIntelCache.set(url, {
    result,
    expiresAt: Date.now() + ttlMs,
  });
}

/**
 * Clear cache for a specific URL
 */
export function clearThreatIntelCache(url: string): void {
  threatIntelCache.delete(url);
}

/**
 * Get the cache instance (for testing)
 */
export function getThreatIntelCache(): Map<string, CacheEntry> {
  return threatIntelCache;
}

// ============================================================================
// Feed Query Functions (Mock implementations for testing)
// ============================================================================

/**
 * Query VirusTotal for URL
 */
async function queryVirusTotal(url: string): Promise<FeedResponse> {
  // In production, this would call the actual VirusTotal API
  // For now, return a simulated response based on URL patterns
  const isSuspicious = url.includes('malicious') || url.includes('phishing') || url.includes('bad');

  return {
    verdict: isSuspicious ? 'malicious' : 'clean',
    score: isSuspicious ? 85 : 10,
    reliability: FEED_RELIABILITY.virustotal,
    category: isSuspicious ? 'phishing' : undefined,
  };
}

/**
 * Query URLhaus for URL
 */
async function queryURLhaus(url: string): Promise<FeedResponse> {
  const isSuspicious = url.includes('malicious') || url.includes('malware') || url.includes('bad');

  return {
    verdict: isSuspicious ? 'malicious' : 'clean',
    score: isSuspicious ? 90 : 5,
    reliability: FEED_RELIABILITY.urlhaus,
    category: isSuspicious ? 'malware' : undefined,
    tags: isSuspicious ? ['malware_download'] : undefined,
  };
}

/**
 * Query PhishTank for URL
 */
async function queryPhishTank(url: string): Promise<FeedResponse> {
  const isSuspicious = url.includes('phishing') || url.includes('bad');

  return {
    verdict: isSuspicious ? 'malicious' : 'clean',
    score: isSuspicious ? 95 : 5,
    reliability: FEED_RELIABILITY.phishtank,
    category: isSuspicious ? 'phishing' : undefined,
  };
}

/**
 * Query OpenPhish for URL
 */
async function queryOpenPhish(url: string): Promise<FeedResponse> {
  const isSuspicious = url.includes('phishing') || url.includes('bad');

  return {
    verdict: isSuspicious ? 'malicious' : 'clean',
    score: isSuspicious ? 80 : 5,
    reliability: FEED_RELIABILITY.openphish,
    category: isSuspicious ? 'phishing' : undefined,
  };
}

/**
 * Get the appropriate feed query function
 */
function getFeedQuerier(feed: string): (url: string) => Promise<FeedResponse> {
  switch (feed.toLowerCase()) {
    case 'virustotal':
      return queryVirusTotal;
    case 'urlhaus':
      return queryURLhaus;
    case 'phishtank':
      return queryPhishTank;
    case 'openphish':
      return queryOpenPhish;
    default:
      // Return a default low-reliability querier
      return async () => ({
        verdict: 'clean' as const,
        score: 0,
        reliability: FEED_RELIABILITY.default,
      });
  }
}

// ============================================================================
// Core Aggregation Function
// ============================================================================

/**
 * Aggregate threat intelligence from multiple feeds with consensus voting
 */
export async function aggregateThreatIntelligence(
  url: string,
  options: ThreatIntelOptions
): Promise<ThreatIntelResult> {
  const {
    feeds,
    mockResponses,
    cacheTtlMs = DEFAULT_CACHE_TTL_MS,
    forceRefresh = false,
  } = options;

  // Check cache unless forced refresh
  if (!forceRefresh) {
    const cached = getCachedResult(url, cacheTtlMs);
    if (cached) {
      return cached;
    }
  }

  // Query all feeds
  const sources: ThreatIntelSource[] = [];

  for (const feed of feeds) {
    let response: FeedResponse;

    if (mockResponses && mockResponses[feed]) {
      // Use mock response for testing
      response = mockResponses[feed];
    } else {
      // Query the actual feed
      const querier = getFeedQuerier(feed);
      response = await querier(url);
    }

    sources.push({
      feed,
      verdict: response.verdict,
      score: response.score,
      reliability: response.reliability ?? FEED_RELIABILITY[feed] ?? FEED_RELIABILITY.default,
      category: response.category,
      malwareFamily: response.malwareFamily,
      tags: response.tags,
    });
  }

  // Calculate consensus score using weighted average
  const consensusScore = calculateWeightedConsensus(sources);

  // Calculate agreement ratio
  const { agreementRatio, disagreement } = calculateAgreement(sources);

  // Calculate confidence based on agreement and source count
  const confidence = calculateConfidence(sources, agreementRatio);

  const result: ThreatIntelResult = {
    url,
    consensusScore,
    confidence,
    agreementRatio,
    sources,
    disagreement,
    fromCache: false,
    checkedAt: new Date(),
  };

  // Cache the result
  setCacheResult(url, result, cacheTtlMs);

  return result;
}

/**
 * Calculate weighted consensus score from all sources
 */
function calculateWeightedConsensus(sources: ThreatIntelSource[]): number {
  if (sources.length === 0) return 0;

  let weightedSum = 0;
  let totalWeight = 0;

  for (const source of sources) {
    const weight = source.reliability;
    weightedSum += source.score * weight;
    totalWeight += weight;
  }

  return totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;
}

/**
 * Calculate agreement ratio between sources
 */
function calculateAgreement(sources: ThreatIntelSource[]): {
  agreementRatio: number;
  disagreement: boolean;
} {
  if (sources.length <= 1) {
    return { agreementRatio: 1, disagreement: false };
  }

  const verdicts = sources.map(s => s.verdict);
  const maliciousCount = verdicts.filter(v => v === 'malicious').length;
  const cleanCount = verdicts.filter(v => v === 'clean').length;
  const suspiciousCount = verdicts.filter(v => v === 'suspicious').length;

  const maxCount = Math.max(maliciousCount, cleanCount, suspiciousCount);
  const agreementRatio = maxCount / sources.length;

  // Disagreement occurs when there's no clear majority (less than 70% agreement)
  const disagreement = agreementRatio < 0.7;

  return { agreementRatio, disagreement };
}

/**
 * Calculate confidence based on agreement and source reliability
 */
function calculateConfidence(sources: ThreatIntelSource[], agreementRatio: number): number {
  if (sources.length === 0) return 0;

  // Base confidence from agreement ratio
  let confidence = agreementRatio;

  // Adjust by average reliability of sources
  const avgReliability = sources.reduce((sum, s) => sum + s.reliability, 0) / sources.length;
  confidence *= avgReliability;

  // Boost confidence for multiple sources
  if (sources.length >= 3) {
    confidence = Math.min(1, confidence * 1.1);
  }

  return Math.round(confidence * 100) / 100;
}

// ============================================================================
// Signal Conversion
// ============================================================================

/**
 * Convert threat intelligence result to detection signals
 */
export function convertThreatIntelToSignals(result: ThreatIntelResult): Signal[] {
  const signals: Signal[] = [];

  // Main consensus signal
  if (result.consensusScore > 0) {
    const severity = result.consensusScore >= 80 ? 'critical' :
                     result.consensusScore >= 50 ? 'warning' : 'info';

    signals.push({
      type: 'threat_intel_consensus',
      severity,
      score: Math.round(result.consensusScore * 0.4), // Scale to detection score
      detail: `Threat intel consensus: ${result.consensusScore}/100 (${result.sources.length} sources)`,
      metadata: {
        consensusScore: result.consensusScore,
        sourceCount: result.sources.length,
        agreementRatio: result.agreementRatio,
        confidence: result.confidence,
      },
    });
  }

  // Source-specific signals
  for (const source of result.sources) {
    // Malware family detection
    if (source.malwareFamily) {
      signals.push({
        type: 'threat_intel_malware_family',
        severity: 'critical',
        score: 35,
        detail: `Malware family detected: ${source.malwareFamily} (${source.feed})`,
        metadata: {
          malwareFamily: source.malwareFamily,
          feed: source.feed,
        },
      });
    }

    // Threat tags
    if (source.tags && source.tags.length > 0) {
      signals.push({
        type: 'threat_intel_tags',
        severity: 'warning',
        score: 20,
        detail: `Threat tags: ${source.tags.join(', ')} (${source.feed})`,
        metadata: {
          tags: source.tags,
          feed: source.feed,
        },
      });
    }

    // High-confidence malicious verdict from reputable source
    if (source.verdict === 'malicious' && source.reliability >= 0.8 && source.score >= 80) {
      signals.push({
        type: 'threat_intel_high_confidence',
        severity: 'critical',
        score: 30,
        detail: `High-confidence malicious verdict from ${source.feed} (${source.score}/100)`,
        metadata: {
          feed: source.feed,
          score: source.score,
          reliability: source.reliability,
          category: source.category,
        },
      });
    }
  }

  // Disagreement warning
  if (result.disagreement) {
    signals.push({
      type: 'threat_intel_disagreement',
      severity: 'info',
      score: 5,
      detail: `Threat feeds disagree (agreement: ${Math.round(result.agreementRatio * 100)}%)`,
      metadata: {
        agreementRatio: result.agreementRatio,
      },
    });
  }

  return signals;
}
