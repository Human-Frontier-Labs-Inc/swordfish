/**
 * Threat Intelligence Module
 * Unified interface for all threat intelligence services
 */

// Sandbox service exports
export * from './sandbox';

// Threat Intel Service exports
export * from './intel-service';

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
 */
export async function checkEmailThreats(params: {
  urls: string[];
  senderDomain: string;
  headerIPs: string[];
}): Promise<EmailThreatCheckResult> {
  const startTime = Date.now();

  // Import functions dynamically to avoid circular deps
  const { checkUrlReputation, checkDomainReputation } = await import('./feeds');
  const { checkDomainAge } = await import('./domain/age');
  const { checkIPReputation } = await import('./ip/blocklists');

  // Check URLs in parallel
  const urlResults = await Promise.all(
    params.urls.slice(0, 50).map(url => checkUrlReputation(url)) // Limit to 50 URLs
  );

  // Check sender domain age
  const domainAgeResult = await checkDomainAge(params.senderDomain);
  const domainReputationResult = await checkDomainReputation(params.senderDomain);

  // Check IPs in parallel
  const ipResults = await Promise.all(
    params.headerIPs.slice(0, 10).map(ip => checkIPReputation(ip)) // Limit to 10 IPs
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
