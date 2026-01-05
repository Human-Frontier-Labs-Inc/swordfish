/**
 * Domain Age Detection
 * Analyzes domain registration age to identify potentially malicious newly-registered domains
 */

import { lookupWhois, type WhoisResult } from './whois';

export interface DomainAgeResult {
  domain: string;
  ageInDays: number | null;
  createdDate: Date | null;
  riskLevel: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  riskScore: number;
  indicators: string[];
  whoisData?: WhoisResult;
}

// Risk thresholds (in days)
const AGE_THRESHOLDS = {
  CRITICAL: 7,      // Less than 1 week
  HIGH: 30,         // Less than 1 month
  MEDIUM: 90,       // Less than 3 months
  LOW: 365,         // Less than 1 year
};

// Well-known legitimate domains that should bypass age checks
const TRUSTED_DOMAINS = new Set([
  'google.com',
  'microsoft.com',
  'apple.com',
  'amazon.com',
  'facebook.com',
  'twitter.com',
  'linkedin.com',
  'github.com',
  'cloudflare.com',
  'amazonaws.com',
  'azure.com',
  'salesforce.com',
  'shopify.com',
  'stripe.com',
  'zoom.us',
  'slack.com',
  'dropbox.com',
  'box.com',
  'atlassian.com',
  'zendesk.com',
]);

// Suspicious TLDs more commonly used by malicious domains
const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq',  // Free TLDs
  'xyz', 'top', 'club', 'online', 'site', 'work', 'click', 'link',
  'loan', 'win', 'racing', 'review', 'stream', 'download',
]);

/**
 * Check domain age and assess risk
 */
export async function checkDomainAge(domain: string): Promise<DomainAgeResult> {
  const normalizedDomain = extractRootDomain(domain);
  const indicators: string[] = [];

  // Check if it's a trusted domain
  if (isTrustedDomain(normalizedDomain)) {
    return {
      domain: normalizedDomain,
      ageInDays: null,
      createdDate: null,
      riskLevel: 'low',
      riskScore: 0.1,
      indicators: ['trusted_domain'],
    };
  }

  // Check TLD risk
  const tld = getTld(normalizedDomain);
  if (SUSPICIOUS_TLDS.has(tld)) {
    indicators.push(`suspicious_tld:${tld}`);
  }

  // Perform WHOIS lookup
  let whoisData: WhoisResult | undefined;
  try {
    whoisData = await lookupWhois(normalizedDomain);
  } catch (error) {
    console.error('[DomainAge] WHOIS lookup failed:', error);
    return {
      domain: normalizedDomain,
      ageInDays: null,
      createdDate: null,
      riskLevel: 'unknown',
      riskScore: 0.5,
      indicators: ['whois_lookup_failed', ...indicators],
    };
  }

  // Calculate age
  const createdDate = whoisData.createdDate;
  if (!createdDate) {
    return {
      domain: normalizedDomain,
      ageInDays: null,
      createdDate: null,
      riskLevel: 'unknown',
      riskScore: 0.5,
      indicators: ['no_creation_date', ...indicators],
      whoisData,
    };
  }

  const now = new Date();
  const ageInDays = Math.floor((now.getTime() - createdDate.getTime()) / (1000 * 60 * 60 * 24));

  // Determine risk level and score
  let riskLevel: DomainAgeResult['riskLevel'];
  let riskScore: number;

  if (ageInDays < AGE_THRESHOLDS.CRITICAL) {
    riskLevel = 'critical';
    riskScore = 0.95;
    indicators.push('newly_registered_critical');
  } else if (ageInDays < AGE_THRESHOLDS.HIGH) {
    riskLevel = 'high';
    riskScore = 0.8;
    indicators.push('newly_registered_high');
  } else if (ageInDays < AGE_THRESHOLDS.MEDIUM) {
    riskLevel = 'medium';
    riskScore = 0.5;
    indicators.push('recently_registered');
  } else if (ageInDays < AGE_THRESHOLDS.LOW) {
    riskLevel = 'low';
    riskScore = 0.3;
    indicators.push('established_domain');
  } else {
    riskLevel = 'low';
    riskScore = 0.1;
    indicators.push('mature_domain');
  }

  // Adjust score for suspicious TLD
  if (indicators.some(i => i.startsWith('suspicious_tld'))) {
    riskScore = Math.min(1, riskScore + 0.15);
    if (riskLevel === 'low' && riskScore >= 0.4) {
      riskLevel = 'medium';
    }
  }

  // Check for privacy protection (often used by malicious domains)
  if (whoisData.registrant?.name?.toLowerCase().includes('privacy') ||
      whoisData.registrant?.organization?.toLowerCase().includes('privacy') ||
      whoisData.registrant?.organization?.toLowerCase().includes('redacted')) {
    indicators.push('privacy_protected');
    // Slight increase for new domains with privacy
    if (ageInDays < AGE_THRESHOLDS.MEDIUM) {
      riskScore = Math.min(1, riskScore + 0.1);
    }
  }

  return {
    domain: normalizedDomain,
    ageInDays,
    createdDate,
    riskLevel,
    riskScore,
    indicators,
    whoisData,
  };
}

/**
 * Quick check for domain age risk (without full WHOIS)
 * Uses heuristics and cached data
 */
export function quickDomainAgeRisk(domain: string): {
  riskLevel: 'low' | 'medium' | 'high' | 'unknown';
  reason: string;
} {
  const normalizedDomain = extractRootDomain(domain);

  // Check trusted domains
  if (isTrustedDomain(normalizedDomain)) {
    return { riskLevel: 'low', reason: 'trusted_domain' };
  }

  // Check TLD
  const tld = getTld(normalizedDomain);
  if (SUSPICIOUS_TLDS.has(tld)) {
    return { riskLevel: 'high', reason: `suspicious_tld:${tld}` };
  }

  // Check for numeric patterns (often newly generated)
  if (/\d{4,}/.test(normalizedDomain)) {
    return { riskLevel: 'medium', reason: 'numeric_pattern' };
  }

  // Check for very long domains
  if (normalizedDomain.length > 30) {
    return { riskLevel: 'medium', reason: 'long_domain' };
  }

  // Check for excessive hyphens
  if ((normalizedDomain.match(/-/g) || []).length > 3) {
    return { riskLevel: 'medium', reason: 'excessive_hyphens' };
  }

  return { riskLevel: 'unknown', reason: 'needs_whois_lookup' };
}

/**
 * Extract root domain from full domain
 */
function extractRootDomain(domain: string): string {
  // Remove protocol if present
  let clean = domain.toLowerCase().trim();
  if (clean.startsWith('http://')) clean = clean.slice(7);
  if (clean.startsWith('https://')) clean = clean.slice(8);

  // Remove path and query
  clean = clean.split('/')[0].split('?')[0];

  // Handle subdomains - extract root domain
  const parts = clean.split('.');

  // Handle common second-level domains
  const secondLevelTlds = ['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'co.in'];
  const lastTwo = parts.slice(-2).join('.');

  if (secondLevelTlds.includes(lastTwo) && parts.length > 2) {
    return parts.slice(-3).join('.');
  }

  if (parts.length > 2) {
    return parts.slice(-2).join('.');
  }

  return clean;
}

/**
 * Get TLD from domain
 */
function getTld(domain: string): string {
  const parts = domain.split('.');
  return parts[parts.length - 1];
}

/**
 * Check if domain is in trusted list
 */
function isTrustedDomain(domain: string): boolean {
  const root = extractRootDomain(domain);
  return TRUSTED_DOMAINS.has(root);
}

/**
 * Batch check multiple domains
 */
export async function checkMultipleDomainAges(
  domains: string[]
): Promise<Map<string, DomainAgeResult>> {
  const results = new Map<string, DomainAgeResult>();

  // Process domains in parallel (with concurrency limit)
  const BATCH_SIZE = 5;
  const uniqueDomains = [...new Set(domains.map(d => extractRootDomain(d)))];

  for (let i = 0; i < uniqueDomains.length; i += BATCH_SIZE) {
    const batch = uniqueDomains.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(batch.map(d => checkDomainAge(d)));

    for (const result of batchResults) {
      results.set(result.domain, result);
    }
  }

  return results;
}
