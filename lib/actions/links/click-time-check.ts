/**
 * Click-Time URL Analysis
 * Real-time safety check when users click rewritten links
 */

import { checkReputation } from '@/lib/detection/reputation/service';

export interface ClickTimeResult {
  url: string;
  verdict: 'safe' | 'suspicious' | 'malicious' | 'blocked' | 'unknown';
  action: 'allow' | 'warn' | 'block';
  riskScore: number;
  signals: ClickTimeSignal[];
  checkDurationMs: number;
  cachedResult: boolean;
}

export interface ClickTimeSignal {
  type: string;
  severity: 'info' | 'warning' | 'critical';
  detail: string;
}

export interface ClickTimeConfig {
  enableRealTimeCheck: boolean;
  blockThreshold: number;      // Score >= this = block
  warnThreshold: number;       // Score >= this = warn
  timeoutMs: number;           // Max time for check
  cacheDurationMs: number;     // How long to cache results
}

const DEFAULT_CONFIG: ClickTimeConfig = {
  enableRealTimeCheck: true,
  blockThreshold: 80,
  warnThreshold: 40,
  timeoutMs: 3000,
  cacheDurationMs: 300000, // 5 minutes
};

// Simple in-memory cache for click-time results
const clickCache = new Map<string, { result: ClickTimeResult; timestamp: number }>();

/**
 * Perform click-time safety check on URL
 */
export async function checkUrlAtClickTime(
  url: string,
  config: Partial<ClickTimeConfig> = {}
): Promise<ClickTimeResult> {
  const startTime = performance.now();
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const signals: ClickTimeSignal[] = [];
  let riskScore = 0;

  // Check cache first
  const cacheKey = url.toLowerCase();
  const cached = clickCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < cfg.cacheDurationMs) {
    return {
      ...cached.result,
      cachedResult: true,
      checkDurationMs: performance.now() - startTime,
    };
  }

  try {
    // Parse URL for analysis
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();

    // Quick heuristic checks
    const heuristicResult = performHeuristicChecks(parsed, signals);
    riskScore += heuristicResult.score;

    // Reputation check with timeout
    if (cfg.enableRealTimeCheck) {
      try {
        const reputationPromise = checkReputation({
          domains: [hostname],
          urls: [url],
          emails: [],
        });

        const timeoutPromise = new Promise<null>((_, reject) =>
          setTimeout(() => reject(new Error('Timeout')), cfg.timeoutMs)
        );

        const reputation = await Promise.race([reputationPromise, timeoutPromise]);

        if (reputation) {
          // Check URL reputation
          for (const urlRep of reputation.urls) {
            if (urlRep.category === 'malicious') {
              riskScore += 50;
              signals.push({
                type: 'malicious_url',
                severity: 'critical',
                detail: `URL found in threat database`,
              });
            } else if (urlRep.category === 'suspicious') {
              riskScore += 25;
              signals.push({
                type: 'suspicious_url',
                severity: 'warning',
                detail: `URL has suspicious reputation`,
              });
            }
          }

          // Check domain reputation
          for (const domainRep of reputation.domains) {
            if (domainRep.category === 'malicious') {
              riskScore += 40;
              signals.push({
                type: 'malicious_domain',
                severity: 'critical',
                detail: `Domain is known malicious`,
              });
            } else if (domainRep.category === 'suspicious') {
              riskScore += 20;
              signals.push({
                type: 'suspicious_domain',
                severity: 'warning',
                detail: `Domain has suspicious reputation`,
              });
            }
          }
        }
      } catch (error) {
        // Timeout or error - continue with heuristic score
        signals.push({
          type: 'check_timeout',
          severity: 'info',
          detail: 'Real-time check timed out, using heuristics',
        });
      }
    }

    // Determine verdict and action
    const { verdict, action } = determineVerdictAndAction(riskScore, cfg);

    const result: ClickTimeResult = {
      url,
      verdict,
      action,
      riskScore: Math.min(100, riskScore),
      signals,
      checkDurationMs: performance.now() - startTime,
      cachedResult: false,
    };

    // Cache result
    clickCache.set(cacheKey, { result, timestamp: Date.now() });

    return result;
  } catch (error) {
    // Parsing error or other issue
    return {
      url,
      verdict: 'unknown',
      action: 'warn',
      riskScore: 50,
      signals: [{
        type: 'check_error',
        severity: 'warning',
        detail: 'Could not analyze URL',
      }],
      checkDurationMs: performance.now() - startTime,
      cachedResult: false,
    };
  }
}

/**
 * Perform quick heuristic checks on URL
 */
function performHeuristicChecks(
  parsed: URL,
  signals: ClickTimeSignal[]
): { score: number } {
  let score = 0;
  const hostname = parsed.hostname.toLowerCase();

  // Check for IP address URL
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    score += 30;
    signals.push({
      type: 'ip_url',
      severity: 'warning',
      detail: 'URL uses IP address instead of domain name',
    });
  }

  // Check for suspicious TLDs
  const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click'];
  if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
    score += 15;
    signals.push({
      type: 'suspicious_tld',
      severity: 'warning',
      detail: 'URL uses commonly abused domain extension',
    });
  }

  // Check for lookalike domain patterns
  const lookalikePattens = [
    /paypa[1l]/i, /app[1l]e/i, /g00g[1l]e/i, /micros0ft/i,
    /amazon[0-9]/i, /faceb00k/i, /netf[1l]ix/i,
  ];
  if (lookalikePattens.some(p => p.test(hostname))) {
    score += 35;
    signals.push({
      type: 'lookalike_domain',
      severity: 'critical',
      detail: 'Domain appears to impersonate a known brand',
    });
  }

  // Check for excessive subdomains
  const subdomainCount = hostname.split('.').length - 2;
  if (subdomainCount > 3) {
    score += 10;
    signals.push({
      type: 'excessive_subdomains',
      severity: 'info',
      detail: 'URL has unusually many subdomains',
    });
  }

  // Check for suspicious path patterns
  const suspiciousPaths = [
    /\/login\//i, /\/signin\//i, /\/verify\//i, /\/confirm\//i,
    /\/secure\//i, /\/account\//i, /\/update\//i, /\/suspend/i,
  ];
  if (suspiciousPaths.some(p => p.test(parsed.pathname))) {
    score += 10;
    signals.push({
      type: 'suspicious_path',
      severity: 'info',
      detail: 'URL path contains security-related keywords',
    });
  }

  // Check for data exfiltration patterns in query string
  if (parsed.search.length > 200) {
    score += 5;
    signals.push({
      type: 'long_query',
      severity: 'info',
      detail: 'URL has unusually long query parameters',
    });
  }

  // Check for homoglyph characters in hostname
  // eslint-disable-next-line no-control-regex
  const homoglyphPattern = /[^\x00-\x7F]/;
  if (homoglyphPattern.test(hostname)) {
    score += 40;
    signals.push({
      type: 'homoglyph',
      severity: 'critical',
      detail: 'Domain contains non-ASCII characters (possible spoofing)',
    });
  }

  return { score };
}

/**
 * Determine verdict and action based on risk score
 */
function determineVerdictAndAction(
  score: number,
  config: ClickTimeConfig
): { verdict: ClickTimeResult['verdict']; action: ClickTimeResult['action'] } {
  if (score >= config.blockThreshold) {
    return { verdict: 'malicious', action: 'block' };
  }

  if (score >= config.warnThreshold) {
    return { verdict: 'suspicious', action: 'warn' };
  }

  if (score > 0) {
    return { verdict: 'suspicious', action: 'allow' };
  }

  return { verdict: 'safe', action: 'allow' };
}

/**
 * Clear expired cache entries
 */
export function clearExpiredCache(maxAgeMs: number = 300000): number {
  const now = Date.now();
  let cleared = 0;

  for (const [key, value] of clickCache.entries()) {
    if (now - value.timestamp > maxAgeMs) {
      clickCache.delete(key);
      cleared++;
    }
  }

  return cleared;
}

/**
 * Get cache statistics
 */
export function getCacheStats(): { size: number; oldestMs: number } {
  let oldest = Date.now();

  for (const value of clickCache.values()) {
    if (value.timestamp < oldest) {
      oldest = value.timestamp;
    }
  }

  return {
    size: clickCache.size,
    oldestMs: Date.now() - oldest,
  };
}
