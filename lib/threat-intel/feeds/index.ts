/**
 * Threat Feed Aggregator
 * Combines multiple threat intelligence feeds for comprehensive URL/domain checking
 */

import { fetchPhishTankFeed, checkPhishTankUrl, type PhishTankEntry } from './phishtank';
import { fetchURLhausFeed, checkURLhausUrl, type URLhausEntry } from './urlhaus';
import { fetchOpenPhishFeed, checkOpenPhishUrl } from './openphish';
import { ThreatFeedCache } from '../cache';

export interface ThreatCheckResult {
  url: string;
  isThreat: boolean;
  verdict: 'clean' | 'malicious' | 'suspicious' | 'unknown';
  confidence: number;
  sources: ThreatSource[];
  checkedAt: Date;
}

export interface ThreatSource {
  feed: 'phishtank' | 'urlhaus' | 'openphish' | 'local';
  matchType: 'exact' | 'domain' | 'pattern';
  category?: string;
  description?: string;
  reportedAt?: Date;
  verified?: boolean;
}

export interface DomainCheckResult {
  domain: string;
  isThreat: boolean;
  verdict: 'clean' | 'malicious' | 'suspicious' | 'unknown';
  sources: ThreatSource[];
}

// Initialize cache
const cache = new ThreatFeedCache();

// Feed refresh intervals (in ms)
const REFRESH_INTERVALS = {
  phishtank: 6 * 60 * 60 * 1000,  // 6 hours
  urlhaus: 60 * 60 * 1000,         // 1 hour (updates frequently)
  openphish: 12 * 60 * 60 * 1000,  // 12 hours
};

// Last refresh timestamps
const lastRefresh: Record<string, number> = {
  phishtank: 0,
  urlhaus: 0,
  openphish: 0,
};

// In-memory threat sets for fast lookup
const phishtankUrls = new Set<string>();
const urlhausUrls = new Set<string>();
const openphishUrls = new Set<string>();

// Threat entries with metadata
const phishtankEntries: Map<string, PhishTankEntry> = new Map();
const urlhausEntries: Map<string, URLhausEntry> = new Map();

/**
 * Initialize and refresh all threat feeds
 */
export async function refreshAllFeeds(): Promise<{
  success: boolean;
  feeds: { feed: string; count: number; error?: string }[];
}> {
  const results: { feed: string; count: number; error?: string }[] = [];
  const now = Date.now();

  // Refresh PhishTank
  if (now - lastRefresh.phishtank > REFRESH_INTERVALS.phishtank) {
    try {
      const entries = await fetchPhishTankFeed();
      phishtankEntries.clear();
      phishtankUrls.clear();
      for (const entry of entries) {
        const normalizedUrl = normalizeUrl(entry.url);
        phishtankUrls.add(normalizedUrl);
        phishtankEntries.set(normalizedUrl, entry);
      }
      lastRefresh.phishtank = now;
      results.push({ feed: 'phishtank', count: entries.length });
    } catch (error) {
      results.push({ feed: 'phishtank', count: 0, error: String(error) });
    }
  }

  // Refresh URLhaus
  if (now - lastRefresh.urlhaus > REFRESH_INTERVALS.urlhaus) {
    try {
      const entries = await fetchURLhausFeed();
      urlhausEntries.clear();
      urlhausUrls.clear();
      for (const entry of entries) {
        const normalizedUrl = normalizeUrl(entry.url);
        urlhausUrls.add(normalizedUrl);
        urlhausEntries.set(normalizedUrl, entry);
      }
      lastRefresh.urlhaus = now;
      results.push({ feed: 'urlhaus', count: entries.length });
    } catch (error) {
      results.push({ feed: 'urlhaus', count: 0, error: String(error) });
    }
  }

  // Refresh OpenPhish
  if (now - lastRefresh.openphish > REFRESH_INTERVALS.openphish) {
    try {
      const urls = await fetchOpenPhishFeed();
      openphishUrls.clear();
      for (const url of urls) {
        openphishUrls.add(normalizeUrl(url));
      }
      lastRefresh.openphish = now;
      results.push({ feed: 'openphish', count: urls.length });
    } catch (error) {
      results.push({ feed: 'openphish', count: 0, error: String(error) });
    }
  }

  return {
    success: results.every(r => !r.error),
    feeds: results,
  };
}

/**
 * Check a URL against all threat feeds
 */
export async function checkUrlReputation(url: string): Promise<ThreatCheckResult> {
  const normalizedUrl = normalizeUrl(url);
  const domain = extractDomain(url);

  // Check cache first
  const cached = cache.getUrlResult(normalizedUrl);
  if (cached) {
    return cached;
  }

  const sources: ThreatSource[] = [];
  let isThreat = false;

  // Ensure feeds are loaded (lazy initialization)
  if (phishtankUrls.size === 0 && urlhausUrls.size === 0 && openphishUrls.size === 0) {
    await refreshAllFeeds();
  }

  // Check PhishTank (exact URL match)
  if (phishtankUrls.has(normalizedUrl)) {
    isThreat = true;
    const entry = phishtankEntries.get(normalizedUrl);
    sources.push({
      feed: 'phishtank',
      matchType: 'exact',
      category: 'phishing',
      description: entry?.target || 'Known phishing URL',
      reportedAt: entry?.submission_time ? new Date(entry.submission_time) : undefined,
      verified: entry?.verified === 'yes',
    });
  }

  // Check PhishTank domain match
  if (domain && !isThreat) {
    for (const [phishUrl, entry] of phishtankEntries) {
      if (extractDomain(phishUrl) === domain) {
        isThreat = true;
        sources.push({
          feed: 'phishtank',
          matchType: 'domain',
          category: 'phishing',
          description: `Domain matches known phishing site targeting ${entry.target || 'unknown'}`,
          verified: entry.verified === 'yes',
        });
        break;
      }
    }
  }

  // Check URLhaus (exact URL match)
  if (urlhausUrls.has(normalizedUrl)) {
    isThreat = true;
    const entry = urlhausEntries.get(normalizedUrl);
    sources.push({
      feed: 'urlhaus',
      matchType: 'exact',
      category: entry?.threat || 'malware',
      description: entry?.tags?.join(', ') || 'Known malware distribution URL',
      reportedAt: entry?.dateadded ? new Date(entry.dateadded) : undefined,
    });
  }

  // Check URLhaus domain match
  if (domain && !sources.find(s => s.feed === 'urlhaus')) {
    for (const [malwareUrl, entry] of urlhausEntries) {
      if (extractDomain(malwareUrl) === domain) {
        sources.push({
          feed: 'urlhaus',
          matchType: 'domain',
          category: entry.threat || 'malware',
          description: `Domain hosts malware: ${entry.tags?.join(', ') || 'unknown type'}`,
        });
        isThreat = true;
        break;
      }
    }
  }

  // Check OpenPhish (exact URL match)
  if (openphishUrls.has(normalizedUrl)) {
    isThreat = true;
    sources.push({
      feed: 'openphish',
      matchType: 'exact',
      category: 'phishing',
      description: 'Known phishing URL (OpenPhish)',
    });
  }

  // Determine verdict and confidence
  let verdict: ThreatCheckResult['verdict'] = 'clean';
  let confidence = 0.5;

  if (sources.length > 0) {
    const verifiedSources = sources.filter(s => s.verified);
    const multipleFeeds = new Set(sources.map(s => s.feed)).size > 1;

    if (verifiedSources.length > 0 || multipleFeeds) {
      verdict = 'malicious';
      confidence = 0.95;
    } else if (sources.some(s => s.matchType === 'exact')) {
      verdict = 'malicious';
      confidence = 0.85;
    } else {
      verdict = 'suspicious';
      confidence = 0.7;
    }
  } else {
    verdict = 'clean';
    confidence = 0.6; // Can't be 100% confident without checking all sources
  }

  const result: ThreatCheckResult = {
    url: normalizedUrl,
    isThreat,
    verdict,
    confidence,
    sources,
    checkedAt: new Date(),
  };

  // Cache the result
  cache.setUrlResult(normalizedUrl, result);

  return result;
}

/**
 * Check a domain against all threat feeds
 */
export async function checkDomainReputation(domain: string): Promise<DomainCheckResult> {
  const normalizedDomain = domain.toLowerCase().trim();

  // Check cache first
  const cached = cache.getDomainResult(normalizedDomain);
  if (cached) {
    return cached;
  }

  // Ensure feeds are loaded
  if (phishtankUrls.size === 0 && urlhausUrls.size === 0 && openphishUrls.size === 0) {
    await refreshAllFeeds();
  }

  const sources: ThreatSource[] = [];
  let isThreat = false;

  // Check if domain appears in any feed
  for (const [url, entry] of phishtankEntries) {
    if (extractDomain(url) === normalizedDomain) {
      isThreat = true;
      sources.push({
        feed: 'phishtank',
        matchType: 'domain',
        category: 'phishing',
        description: `Domain used in phishing attack targeting ${entry.target || 'unknown'}`,
        verified: entry.verified === 'yes',
      });
      break;
    }
  }

  for (const [url, entry] of urlhausEntries) {
    if (extractDomain(url) === normalizedDomain) {
      isThreat = true;
      sources.push({
        feed: 'urlhaus',
        matchType: 'domain',
        category: entry.threat || 'malware',
        description: `Domain distributes malware: ${entry.tags?.join(', ') || 'unknown'}`,
      });
      break;
    }
  }

  for (const url of openphishUrls) {
    if (extractDomain(url) === normalizedDomain) {
      isThreat = true;
      sources.push({
        feed: 'openphish',
        matchType: 'domain',
        category: 'phishing',
        description: 'Domain used in phishing attacks',
      });
      break;
    }
  }

  const result: DomainCheckResult = {
    domain: normalizedDomain,
    isThreat,
    verdict: isThreat ? (sources.some(s => s.verified) ? 'malicious' : 'suspicious') : 'clean',
    sources,
  };

  cache.setDomainResult(normalizedDomain, result);

  return result;
}

/**
 * Get feed statistics
 */
export function getFeedStats(): {
  phishtank: { count: number; lastRefresh: Date | null };
  urlhaus: { count: number; lastRefresh: Date | null };
  openphish: { count: number; lastRefresh: Date | null };
  totalUrls: number;
} {
  return {
    phishtank: {
      count: phishtankUrls.size,
      lastRefresh: lastRefresh.phishtank ? new Date(lastRefresh.phishtank) : null,
    },
    urlhaus: {
      count: urlhausUrls.size,
      lastRefresh: lastRefresh.urlhaus ? new Date(lastRefresh.urlhaus) : null,
    },
    openphish: {
      count: openphishUrls.size,
      lastRefresh: lastRefresh.openphish ? new Date(lastRefresh.openphish) : null,
    },
    totalUrls: phishtankUrls.size + urlhausUrls.size + openphishUrls.size,
  };
}

// Helper functions

function normalizeUrl(url: string): string {
  try {
    const parsed = new URL(url.toLowerCase().trim());
    // Remove trailing slash, normalize to lowercase
    return `${parsed.protocol}//${parsed.host}${parsed.pathname.replace(/\/$/, '')}${parsed.search}`;
  } catch {
    return url.toLowerCase().trim();
  }
}

function extractDomain(url: string): string | null {
  try {
    const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}
