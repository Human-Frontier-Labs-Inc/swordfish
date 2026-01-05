/**
 * Reputation Lookup Service
 * Checks domain, IP, and URL reputation against threat intelligence sources
 */

import { sql } from '@/lib/db';
import {
  checkUrlReputation as checkUrlThreat,
  checkDomainReputation as checkDomainThreat,
  checkDomainAge,
  checkIPReputation as checkIPThreat,
} from '@/lib/threat-intel';

export interface ReputationResult {
  entity: string;
  entityType: 'domain' | 'ip' | 'url' | 'email';
  score: number; // 0-100 (0 = malicious, 100 = trusted)
  category: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  sources: ReputationSource[];
  cached: boolean;
  lastChecked: Date;
}

export interface ReputationSource {
  name: string;
  verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  score?: number;
  details?: string;
  lastUpdated?: Date;
}

export interface ReputationCheckRequest {
  domains?: string[];
  ips?: string[];
  urls?: string[];
  emails?: string[];
}

export interface ReputationCheckResult {
  domains: ReputationResult[];
  ips: ReputationResult[];
  urls: ReputationResult[];
  emails: ReputationResult[];
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
  riskScore: number;
}

// Known malicious patterns (would be populated from threat feeds in production)
const MALICIOUS_PATTERNS = {
  domains: [
    /phishing/i,
    /malware/i,
    /hack/i,
    /scam/i,
    /fraud/i,
    /\.tk$/,
    /\.ml$/,
    /\.ga$/,
    /\.cf$/,
    /\.gq$/,
  ],
  urls: [
    /bit\.ly/i,
    /tinyurl/i,
    /t\.co/i,
    /goo\.gl/i,
    /is\.gd/i,
    /ow\.ly/i,
  ],
};

// Known safe domains
const TRUSTED_DOMAINS = new Set([
  'google.com',
  'microsoft.com',
  'apple.com',
  'amazon.com',
  'github.com',
  'linkedin.com',
  'facebook.com',
  'twitter.com',
  'dropbox.com',
  'slack.com',
  'zoom.us',
  'salesforce.com',
  'office.com',
  'outlook.com',
  'live.com',
  'hotmail.com',
  'gmail.com',
  'yahoo.com',
]);

// Freemail providers (higher scrutiny for business context)
const FREEMAIL_DOMAINS = new Set([
  'gmail.com',
  'yahoo.com',
  'hotmail.com',
  'outlook.com',
  'aol.com',
  'icloud.com',
  'protonmail.com',
  'mail.com',
  'zoho.com',
  'yandex.com',
  'gmx.com',
  'live.com',
]);

// Cache TTL in milliseconds
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Check reputation for domains, IPs, URLs, and emails
 */
export async function checkReputation(
  request: ReputationCheckRequest
): Promise<ReputationCheckResult> {
  const results: ReputationCheckResult = {
    domains: [],
    ips: [],
    urls: [],
    emails: [],
    overallRisk: 'low',
    riskScore: 0,
  };

  // Check all entities in parallel
  const [domainResults, ipResults, urlResults, emailResults] = await Promise.all([
    request.domains ? Promise.all(request.domains.map(checkDomainReputation)) : [],
    request.ips ? Promise.all(request.ips.map(checkIPReputation)) : [],
    request.urls ? Promise.all(request.urls.map(checkURLReputation)) : [],
    request.emails ? Promise.all(request.emails.map(checkEmailReputation)) : [],
  ]);

  results.domains = domainResults;
  results.ips = ipResults;
  results.urls = urlResults;
  results.emails = emailResults;

  // Calculate overall risk
  const allResults = [...domainResults, ...ipResults, ...urlResults, ...emailResults];
  if (allResults.length > 0) {
    const avgScore = allResults.reduce((sum, r) => sum + r.score, 0) / allResults.length;
    results.riskScore = 100 - avgScore;

    const hasMalicious = allResults.some(r => r.category === 'malicious');
    const hasSuspicious = allResults.some(r => r.category === 'suspicious');

    if (hasMalicious) {
      results.overallRisk = 'critical';
    } else if (hasSuspicious) {
      results.overallRisk = results.riskScore > 50 ? 'high' : 'medium';
    } else if (results.riskScore > 30) {
      results.overallRisk = 'medium';
    } else {
      results.overallRisk = 'low';
    }
  }

  return results;
}

/**
 * Check domain reputation
 */
export async function checkDomainReputation(domain: string): Promise<ReputationResult> {
  const normalizedDomain = domain.toLowerCase().trim();

  // Check cache first
  const cached = await getCachedReputation(normalizedDomain, 'domain');
  if (cached) return cached;

  const sources: ReputationSource[] = [];
  let score = 50; // Start neutral

  // Check against trusted domains
  if (TRUSTED_DOMAINS.has(normalizedDomain) ||
      Array.from(TRUSTED_DOMAINS).some(d => normalizedDomain.endsWith('.' + d))) {
    sources.push({
      name: 'trusted_list',
      verdict: 'clean',
      score: 100,
      details: 'Known trusted domain',
    });
    score = 100;
  }

  // Check against malicious patterns
  const isMaliciousPattern = MALICIOUS_PATTERNS.domains.some(pattern =>
    pattern.test(normalizedDomain)
  );
  if (isMaliciousPattern) {
    sources.push({
      name: 'pattern_match',
      verdict: 'suspicious',
      score: 20,
      details: 'Matches suspicious domain pattern',
    });
    score = Math.min(score, 20);
  }

  // Check domain age using threat intel WHOIS service
  try {
    const ageResult = await checkDomainAge(normalizedDomain);
    if (ageResult.ageInDays !== null) {
      if (ageResult.ageInDays < 30) {
        sources.push({
          name: 'domain_age',
          verdict: 'suspicious',
          score: Math.round((1 - ageResult.riskScore) * 100),
          details: `Domain is only ${ageResult.ageInDays} days old (${ageResult.riskLevel} risk)`,
        });
        score = Math.min(score, 30);
      } else if (ageResult.ageInDays > 365) {
        sources.push({
          name: 'domain_age',
          verdict: 'clean',
          score: 80,
          details: `Domain is ${Math.floor(ageResult.ageInDays / 365)} years old`,
        });
        score = Math.max(score, 70);
      }
    }

    // Add risk indicators from domain age check
    if (ageResult.indicators.length > 0) {
      for (const indicator of ageResult.indicators) {
        if (indicator.startsWith('suspicious_tld')) {
          sources.push({
            name: 'tld_analysis',
            verdict: 'suspicious',
            score: 35,
            details: `Domain uses suspicious TLD: ${indicator.split(':')[1] || 'unknown'}`,
          });
          score = Math.min(score, 35);
        }
      }
    }
  } catch (error) {
    console.error('[Reputation] Domain age check failed:', error);
  }

  // Check domain against threat feeds
  try {
    const threatResult = await checkDomainThreat(normalizedDomain);
    if (threatResult.isThreat) {
      for (const source of threatResult.sources) {
        sources.push({
          name: `threat_feed:${source.feed}`,
          verdict: source.verified ? 'malicious' : 'suspicious',
          score: source.verified ? 0 : 20,
          details: source.description || `Found in ${source.feed} (${source.matchType} match)`,
        });
      }
      score = Math.min(score, threatResult.verdict === 'malicious' ? 0 : 20);
    }
  } catch (error) {
    console.error('[Reputation] Threat feed check failed:', error);
  }

  // Check if freemail (contextual risk)
  if (FREEMAIL_DOMAINS.has(normalizedDomain)) {
    sources.push({
      name: 'freemail_check',
      verdict: 'clean',
      score: 70,
      details: 'Known freemail provider',
    });
  }

  // Check local threat database
  const localThreat = await checkLocalThreatDB(normalizedDomain, 'domain');
  if (localThreat) {
    sources.push(localThreat);
    if (localThreat.verdict === 'malicious') {
      score = Math.min(score, 0);
    } else if (localThreat.verdict === 'suspicious') {
      score = Math.min(score, 30);
    }
  }

  const result: ReputationResult = {
    entity: normalizedDomain,
    entityType: 'domain',
    score,
    category: scoreToCategory(score),
    sources,
    cached: false,
    lastChecked: new Date(),
  };

  // Cache the result
  await cacheReputation(result);

  return result;
}

/**
 * Check IP reputation
 */
export async function checkIPReputation(ip: string): Promise<ReputationResult> {
  const normalizedIP = ip.trim();

  // Check cache first
  const cached = await getCachedReputation(normalizedIP, 'ip');
  if (cached) return cached;

  const sources: ReputationSource[] = [];
  let score = 50;

  // Check if private/reserved IP
  if (isPrivateIP(normalizedIP)) {
    sources.push({
      name: 'ip_range',
      verdict: 'clean',
      score: 90,
      details: 'Private/internal IP address',
    });
    score = 90;
  }

  // Check IP against threat intelligence blocklists
  try {
    const ipThreatResult = await checkIPThreat(normalizedIP);
    if (ipThreatResult.isThreat) {
      for (const source of ipThreatResult.sources) {
        sources.push({
          name: `blocklist:${source.list}`,
          verdict: 'malicious',
          score: 0,
          details: source.description || `Listed in ${source.list}`,
        });
      }
      score = Math.min(score, 0);
    } else if (ipThreatResult.verdict === 'suspicious') {
      for (const source of ipThreatResult.sources) {
        sources.push({
          name: `ip_risk:${source.list}`,
          verdict: 'suspicious',
          score: 35,
          details: source.description,
        });
      }
      score = Math.min(score, 35);
    }

    // Add geolocation info if available
    if (ipThreatResult.geolocation?.country) {
      sources.push({
        name: 'geoip',
        verdict: 'clean',
        score: score,
        details: `Origin: ${ipThreatResult.geolocation.country}${ipThreatResult.geolocation.isp ? ` (${ipThreatResult.geolocation.isp})` : ''}`,
      });
    }
  } catch (error) {
    console.error('[Reputation] IP threat check failed:', error);
  }

  // Check local threat database
  const localThreat = await checkLocalThreatDB(normalizedIP, 'ip');
  if (localThreat) {
    sources.push(localThreat);
    if (localThreat.verdict === 'malicious') {
      score = Math.min(score, 0);
    } else if (localThreat.verdict === 'suspicious') {
      score = Math.min(score, 30);
    }
  }

  const result: ReputationResult = {
    entity: normalizedIP,
    entityType: 'ip',
    score,
    category: scoreToCategory(score),
    sources,
    cached: false,
    lastChecked: new Date(),
  };

  await cacheReputation(result);
  return result;
}

/**
 * Check URL reputation
 */
export async function checkURLReputation(url: string): Promise<ReputationResult> {
  const normalizedURL = url.toLowerCase().trim();

  // Check cache first
  const cached = await getCachedReputation(normalizedURL, 'url');
  if (cached) return cached;

  const sources: ReputationSource[] = [];
  let score = 50;

  // Parse URL
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(normalizedURL.startsWith('http') ? normalizedURL : `https://${normalizedURL}`);
  } catch {
    sources.push({
      name: 'url_parse',
      verdict: 'suspicious',
      score: 20,
      details: 'Invalid URL format',
    });

    const result: ReputationResult = {
      entity: normalizedURL,
      entityType: 'url',
      score: 20,
      category: 'suspicious',
      sources,
      cached: false,
      lastChecked: new Date(),
    };
    await cacheReputation(result);
    return result;
  }

  // Check if URL shortener
  const isShortener = MALICIOUS_PATTERNS.urls.some(pattern =>
    pattern.test(parsedUrl.hostname)
  );
  if (isShortener) {
    sources.push({
      name: 'shortener_detection',
      verdict: 'suspicious',
      score: 40,
      details: 'URL shortener detected (obscures destination)',
    });
    score = Math.min(score, 40);
  }

  // Check domain reputation
  const domainRep = await checkDomainReputation(parsedUrl.hostname);
  sources.push({
    name: 'domain_reputation',
    verdict: domainRep.category === 'unknown' ? 'unknown' : domainRep.category,
    score: domainRep.score,
    details: `Domain reputation: ${domainRep.category}`,
  });
  score = Math.min(score, domainRep.score);

  // Check for suspicious URL patterns
  const suspiciousPatterns = [
    { pattern: /login|signin|account|verify|update|secure/i, risk: 'credential_harvesting' },
    { pattern: /\.exe|\.zip|\.rar|\.scr|\.bat|\.cmd/i, risk: 'executable_download' },
    { pattern: /@.*@|%40.*%40/i, risk: 'obfuscation' },
    { pattern: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, risk: 'ip_based_url' },
  ];

  for (const { pattern, risk } of suspiciousPatterns) {
    if (pattern.test(normalizedURL)) {
      sources.push({
        name: 'pattern_analysis',
        verdict: 'suspicious',
        score: 35,
        details: `Suspicious pattern detected: ${risk}`,
      });
      score = Math.min(score, 35);
    }
  }

  // Check URL against threat feeds (PhishTank, URLhaus, OpenPhish)
  try {
    const urlThreatResult = await checkUrlThreat(normalizedURL);
    if (urlThreatResult.isThreat) {
      for (const source of urlThreatResult.sources) {
        sources.push({
          name: `threat_feed:${source.feed}`,
          verdict: source.verified ? 'malicious' : 'suspicious',
          score: source.verified ? 0 : 15,
          details: source.description || `Found in ${source.feed} threat feed`,
        });
      }
      score = Math.min(score, urlThreatResult.verdict === 'malicious' ? 0 : 15);
    }
  } catch (error) {
    console.error('[Reputation] URL threat check failed:', error);
  }

  // Check local threat database
  const localThreat = await checkLocalThreatDB(normalizedURL, 'url');
  if (localThreat) {
    sources.push(localThreat);
    if (localThreat.verdict === 'malicious') {
      score = 0;
    }
  }

  const result: ReputationResult = {
    entity: normalizedURL,
    entityType: 'url',
    score,
    category: scoreToCategory(score),
    sources,
    cached: false,
    lastChecked: new Date(),
  };

  await cacheReputation(result);
  return result;
}

/**
 * Check email reputation
 */
export async function checkEmailReputation(email: string): Promise<ReputationResult> {
  const normalizedEmail = email.toLowerCase().trim();

  // Check cache first
  const cached = await getCachedReputation(normalizedEmail, 'email');
  if (cached) return cached;

  const sources: ReputationSource[] = [];
  let score = 50;

  // Parse email
  const [localPart, domain] = normalizedEmail.split('@');
  if (!domain) {
    sources.push({
      name: 'email_parse',
      verdict: 'suspicious',
      score: 10,
      details: 'Invalid email format',
    });

    const result: ReputationResult = {
      entity: normalizedEmail,
      entityType: 'email',
      score: 10,
      category: 'suspicious',
      sources,
      cached: false,
      lastChecked: new Date(),
    };
    await cacheReputation(result);
    return result;
  }

  // Check domain reputation
  const domainRep = await checkDomainReputation(domain);
  sources.push({
    name: 'domain_reputation',
    verdict: domainRep.category === 'unknown' ? 'unknown' : domainRep.category,
    score: domainRep.score,
    details: `Email domain reputation: ${domainRep.category}`,
  });
  score = domainRep.score;

  // Check for suspicious local part patterns
  const suspiciousLocalPatterns = [
    { pattern: /^[a-z]{1,3}\d{5,}$/i, risk: 'random_looking' },
    { pattern: /^(admin|support|security|help|info|noreply|no-reply)$/i, risk: 'impersonation_target' },
    { pattern: /\+.*\+|\.{2,}/, risk: 'obfuscation' },
  ];

  for (const { pattern, risk } of suspiciousLocalPatterns) {
    if (pattern.test(localPart)) {
      sources.push({
        name: 'local_part_analysis',
        verdict: 'suspicious',
        score: 40,
        details: `Suspicious email pattern: ${risk}`,
      });
      score = Math.min(score, 40);
    }
  }

  // Check local threat database
  const localThreat = await checkLocalThreatDB(normalizedEmail, 'email');
  if (localThreat) {
    sources.push(localThreat);
    if (localThreat.verdict === 'malicious') {
      score = 0;
    }
  }

  const result: ReputationResult = {
    entity: normalizedEmail,
    entityType: 'email',
    score,
    category: scoreToCategory(score),
    sources,
    cached: false,
    lastChecked: new Date(),
  };

  await cacheReputation(result);
  return result;
}

/**
 * Add entity to local threat database
 */
export async function addToThreatDB(
  tenantId: string,
  entity: string,
  entityType: 'domain' | 'ip' | 'url' | 'email',
  verdict: 'suspicious' | 'malicious',
  source: string,
  details?: string
): Promise<void> {
  await sql`
    INSERT INTO threat_intelligence (
      tenant_id, entity, entity_type, verdict, source, details, created_at
    ) VALUES (
      ${tenantId}, ${entity.toLowerCase()}, ${entityType}, ${verdict},
      ${source}, ${details || null}, NOW()
    )
    ON CONFLICT (tenant_id, entity, entity_type)
    DO UPDATE SET
      verdict = ${verdict},
      source = ${source},
      details = ${details || null},
      updated_at = NOW()
  `;
}

/**
 * Remove entity from local threat database
 */
export async function removeFromThreatDB(
  tenantId: string,
  entity: string,
  entityType: 'domain' | 'ip' | 'url' | 'email'
): Promise<void> {
  await sql`
    DELETE FROM threat_intelligence
    WHERE tenant_id = ${tenantId}
      AND entity = ${entity.toLowerCase()}
      AND entity_type = ${entityType}
  `;
}

// Helper functions

function scoreToCategory(score: number): 'clean' | 'suspicious' | 'malicious' | 'unknown' {
  if (score >= 70) return 'clean';
  if (score >= 30) return 'suspicious';
  if (score >= 0) return 'malicious';
  return 'unknown';
}

function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;

  // 10.0.0.0/8
  if (parts[0] === 10) return true;
  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;
  // 127.0.0.0/8
  if (parts[0] === 127) return true;

  return false;
}

// checkHostingProvider and getDomainAge are now handled by threat-intel module

async function getCachedReputation(
  entity: string,
  entityType: string
): Promise<ReputationResult | null> {
  try {
    const result = await sql`
      SELECT * FROM reputation_cache
      WHERE entity = ${entity}
        AND entity_type = ${entityType}
        AND created_at > NOW() - INTERVAL '24 hours'
      LIMIT 1
    `;

    if (result.length === 0) return null;

    const cached = result[0];
    return {
      entity: cached.entity,
      entityType: cached.entity_type as 'domain' | 'ip' | 'url' | 'email',
      score: cached.score,
      category: cached.category as 'clean' | 'suspicious' | 'malicious' | 'unknown',
      sources: JSON.parse(cached.sources || '[]'),
      cached: true,
      lastChecked: new Date(cached.created_at),
    };
  } catch {
    // Table might not exist yet
    return null;
  }
}

async function cacheReputation(result: ReputationResult): Promise<void> {
  try {
    await sql`
      INSERT INTO reputation_cache (
        entity, entity_type, score, category, sources, created_at
      ) VALUES (
        ${result.entity}, ${result.entityType}, ${result.score},
        ${result.category}, ${JSON.stringify(result.sources)}, NOW()
      )
      ON CONFLICT (entity, entity_type)
      DO UPDATE SET
        score = ${result.score},
        category = ${result.category},
        sources = ${JSON.stringify(result.sources)},
        created_at = NOW()
    `;
  } catch {
    // Table might not exist yet - ignore
  }
}

async function checkLocalThreatDB(
  entity: string,
  entityType: string
): Promise<ReputationSource | null> {
  try {
    const result = await sql`
      SELECT * FROM threat_intelligence
      WHERE entity = ${entity.toLowerCase()}
        AND entity_type = ${entityType}
      LIMIT 1
    `;

    if (result.length === 0) return null;

    const threat = result[0];
    return {
      name: 'local_threat_db',
      verdict: threat.verdict as 'suspicious' | 'malicious',
      score: threat.verdict === 'malicious' ? 0 : 30,
      details: threat.details || `Reported by ${threat.source}`,
      lastUpdated: new Date(threat.updated_at || threat.created_at),
    };
  } catch {
    // Table might not exist yet
    return null;
  }
}
