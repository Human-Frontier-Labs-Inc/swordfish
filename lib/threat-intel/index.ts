/**
 * Threat Intelligence Module
 * Unified interface for all threat intelligence services
 */

// Sandbox service exports
export * from './sandbox';

// Threat Intel Service exports
export * from './intel-service';

// Fallback system exports
export {
  executeWithFallback,
  executeMultipleWithFallback,
  recordSuccess,
  recordFailure,
  isCircuitOpen,
  getCircuitStatus,
  resetCircuit,
  getAllCircuitStatuses,
  getThreatIntelHealth,
  isThreatIntelDegraded,
  getDegradedServices,
  getDefaultUrlCheckResult,
  getDefaultDomainCheckResult,
  getDefaultIpCheckResult,
  DEFAULT_FALLBACK_CONFIG,
  type FallbackConfig,
  type FallbackResult,
  type CircuitState,
  type ServiceHealth,
} from './fallback';

// Feed exports
export {
  checkUrlReputation,
  checkDomainReputation,
  refreshAllFeeds,
  getFeedStats,
  type ThreatCheckResult,
  type ThreatSource,
  type DomainCheckResult,
} from './feeds';

// Domain age exports
export {
  checkDomainAge,
  quickDomainAgeRisk,
  checkMultipleDomainAges,
  type DomainAgeResult,
} from './domain/age';

// WHOIS exports
export {
  lookupWhois,
  clearWhoisCache,
  getWhoisCacheStats,
  type WhoisResult,
} from './domain/whois';

// IP blocklist exports
export {
  checkIPReputation,
  checkMultipleIPs,
  extractIPsFromHeaders,
  clearIPCache,
  getIPCacheStats,
} from './ip/blocklists';

// Cache exports
export {
  threatCache,
  ThreatFeedCache,
  type IPCheckResult,
} from './cache';

/**
 * Comprehensive threat check for an email
 * Combines URL, domain, and IP reputation checks
 */
export interface EmailThreatCheckResult {
  overallVerdict: 'clean' | 'suspicious' | 'malicious';
  riskScore: number;
  urls: {
    checked: number;
    threats: number;
    results: Array<{
      url: string;
      isThreat: boolean;
      verdict: string;
    }>;
  };
  domains: {
    checked: number;
    newDomains: number;
    threats: number;
    results: Array<{
      domain: string;
      ageInDays: number | null;
      riskLevel: string;
    }>;
  };
  ips: {
    checked: number;
    threats: number;
    results: Array<{
      ip: string;
      isThreat: boolean;
      verdict: string;
    }>;
  };
  processingTime: number;
}

/**
 * Check all threat indicators in an email
 * Uses graceful degradation when external APIs are unavailable
 */
export async function checkEmailThreats(params: {
  urls: string[];
  senderDomain: string;
  headerIPs: string[];
}): Promise<EmailThreatCheckResult> {
  const startTime = Date.now();
  let degraded = false;

  // Import functions dynamically to avoid circular deps
  const { checkUrlReputation, checkDomainReputation } = await import('./feeds');
  const { checkDomainAge } = await import('./domain/age');
  const { checkIPReputation } = await import('./ip/blocklists');

  // Check URLs in parallel with error handling
  const urlResults = await Promise.all(
    params.urls.slice(0, 50).map(async (url) => {
      try {
        return await checkUrlReputation(url);
      } catch (error) {
        degraded = true;
        console.warn(`[checkEmailThreats] URL check failed for ${url}: ${error instanceof Error ? error.message : 'Unknown error'}`);
        return { url, isThreat: false, verdict: 'unknown', sources: [] };
      }
    })
  );

  // Check sender domain age with fallback
  let domainAgeResult: { ageInDays: number | null; riskScore: number; riskLevel: string };
  try {
    domainAgeResult = await checkDomainAge(params.senderDomain);
  } catch (error) {
    degraded = true;
    console.warn(`[checkEmailThreats] Domain age check failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    domainAgeResult = { ageInDays: null, riskScore: 0, riskLevel: 'unknown' };
  }

  // Check domain reputation with fallback
  let domainReputationResult: { isThreat: boolean };
  try {
    domainReputationResult = await checkDomainReputation(params.senderDomain);
  } catch (error) {
    degraded = true;
    console.warn(`[checkEmailThreats] Domain reputation check failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    domainReputationResult = { isThreat: false };
  }

  // Check IPs in parallel with error handling
  const ipResults = await Promise.all(
    params.headerIPs.slice(0, 10).map(async (ip) => {
      try {
        return await checkIPReputation(ip);
      } catch (error) {
        degraded = true;
        console.warn(`[checkEmailThreats] IP check failed for ${ip}: ${error instanceof Error ? error.message : 'Unknown error'}`);
        return { ip, isThreat: false, verdict: 'unknown' };
      }
    })
  );

  // Calculate overall risk
  const urlThreats = urlResults.filter(r => r.isThreat);
  const ipThreats = ipResults.filter(r => r.isThreat);
  const isNewDomain = domainAgeResult.ageInDays !== null && domainAgeResult.ageInDays < 30;
  const isDomainThreat = domainReputationResult.isThreat;

  let riskScore = 0;

  // URL threats contribute 40%
  if (urlThreats.length > 0) {
    riskScore += 0.4 * (urlThreats.length / Math.max(urlResults.length, 1));
  }

  // Domain factors contribute 35%
  if (isDomainThreat) {
    riskScore += 0.25;
  }
  if (isNewDomain) {
    riskScore += 0.1 * domainAgeResult.riskScore;
  }

  // IP threats contribute 25%
  if (ipThreats.length > 0) {
    riskScore += 0.25 * (ipThreats.length / Math.max(ipResults.length, 1));
  }

  // Determine verdict
  let overallVerdict: EmailThreatCheckResult['overallVerdict'];
  if (riskScore >= 0.7 || urlThreats.length >= 2 || isDomainThreat) {
    overallVerdict = 'malicious';
  } else if (riskScore >= 0.3 || urlThreats.length > 0 || isNewDomain || ipThreats.length > 0) {
    overallVerdict = 'suspicious';
  } else {
    overallVerdict = 'clean';
  }

  // Log if system is degraded
  if (degraded) {
    console.warn('[checkEmailThreats] Operating in degraded mode - some threat intel APIs unavailable');
  }

  return {
    overallVerdict,
    riskScore: Math.min(1, riskScore),
    urls: {
      checked: urlResults.length,
      threats: urlThreats.length,
      results: urlResults.map(r => ({
        url: r.url,
        isThreat: r.isThreat,
        verdict: r.verdict,
      })),
    },
    domains: {
      checked: 1,
      newDomains: isNewDomain ? 1 : 0,
      threats: isDomainThreat ? 1 : 0,
      results: [{
        domain: params.senderDomain,
        ageInDays: domainAgeResult.ageInDays,
        riskLevel: domainAgeResult.riskLevel,
      }],
    },
    ips: {
      checked: ipResults.length,
      threats: ipThreats.length,
      results: ipResults.map(r => ({
        ip: r.ip,
        isThreat: r.isThreat,
        verdict: r.verdict,
      })),
    },
    processingTime: Date.now() - startTime,
  };
}
