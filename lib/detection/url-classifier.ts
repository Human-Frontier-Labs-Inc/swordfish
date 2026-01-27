/**
 * URL Classifier - Phase 2: Context-Aware URL Analysis
 *
 * Classifies URLs as tracking, redirect, malicious, or legitimate
 * to reduce false positives on marketing emails with tracking links.
 *
 * Expected Impact: 25% additional false positive reduction
 */

export type URLType = 'tracking' | 'redirect' | 'malicious' | 'legitimate' | 'unknown';
export type TrustLevel = 'high' | 'medium' | 'low' | 'untrusted';

export interface URLClassification {
  url: string;
  type: URLType;
  trustLevel: TrustLevel;
  reason: string;
  score: number; // 0-10 (higher = more suspicious)
  metadata?: {
    pattern?: string;
    senderMatch?: boolean;
    knownDomain?: boolean;
  };
}

/**
 * Common legitimate tracking patterns used by major email platforms
 */
const TRACKING_PATTERNS = [
  // Quora
  { pattern: /\/tc\?/i, service: 'Quora tracking', score: 0 },
  { pattern: /\/qemail\//i, service: 'Quora email', score: 0 },

  // Google Analytics & Marketing
  { pattern: /\?utm_/i, service: 'Google Analytics', score: 0 },
  { pattern: /\/click\?/i, service: 'Click tracking', score: 0 },
  { pattern: /\/track\?/i, service: 'Tracking pixel', score: 0 },
  { pattern: /\/open\?/i, service: 'Open tracking', score: 0 },

  // Mailchimp
  { pattern: /\?mc_/i, service: 'Mailchimp', score: 0 },
  { pattern: /list-manage\.com/i, service: 'Mailchimp', score: 0 },

  // SendGrid
  { pattern: /sendgrid\.net/i, service: 'SendGrid', score: 0 },
  { pattern: /\/wf\//i, service: 'SendGrid webhook', score: 0 },

  // HubSpot
  { pattern: /\?_hsenc=/i, service: 'HubSpot', score: 0 },
  { pattern: /\?_hsmi=/i, service: 'HubSpot', score: 0 },

  // LinkedIn
  { pattern: /click\.linkedin\.com/i, service: 'LinkedIn', score: 0 },
  { pattern: /linkedin\.email/i, service: 'LinkedIn', score: 0 },

  // GitHub
  { pattern: /email\.github\.com/i, service: 'GitHub', score: 0 },
  { pattern: /notifications\.github\.com/i, service: 'GitHub', score: 0 },

  // Substack
  { pattern: /substack\.com\/redirect/i, service: 'Substack', score: 0 },

  // Medium
  { pattern: /medium\.com\/m\//i, service: 'Medium', score: 0 },

  // Common redirect services
  { pattern: /bit\.ly/i, service: 'Bitly shortener', score: 1 },
  { pattern: /tinyurl\.com/i, service: 'TinyURL', score: 1 },
  { pattern: /ow\.ly/i, service: 'Hootsuite shortener', score: 1 },
];

/**
 * Suspicious URL patterns that indicate potential threats
 */
const SUSPICIOUS_PATTERNS = [
  // Dangerous protocols
  { pattern: /^javascript:/i, reason: 'JavaScript protocol', score: 10 },
  { pattern: /^data:/i, reason: 'Data protocol', score: 10 },
  { pattern: /^vbscript:/i, reason: 'VBScript protocol', score: 10 },

  // Homograph attacks
  { pattern: /xn--/i, reason: 'Punycode (potential homograph)', score: 8 },

  // Excessive subdomains
  { pattern: /^https?:\/\/([^\/]+\.){4,}/i, reason: 'Excessive subdomains', score: 7 },

  // IP addresses (unless localhost)
  { pattern: /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i, reason: 'IP-based URL', score: 6 },

  // Port numbers (non-standard)
  { pattern: /:\d{4,5}\//i, reason: 'Non-standard port', score: 5 },

  // Double extensions
  { pattern: /\.(exe|scr|bat|cmd|vbs|jar|zip|rar)\.(pdf|doc|xls|jpg|png)/i, reason: 'Double extension', score: 9 },

  // Typosquatting common domains
  { pattern: /g[o0]{2}gle/i, reason: 'Typosquatting (Google)', score: 9 },
  { pattern: /microso[f0]t/i, reason: 'Typosquatting (Microsoft)', score: 9 },
  { pattern: /amazo[n0]/i, reason: 'Typosquatting (Amazon)', score: 9 },
];

/**
 * Classify a URL based on its patterns, sender domain, and known tracking domains
 */
export function classifyURL(
  url: string,
  senderDomain: string,
  knownTrackingDomains: string[] = []
): URLClassification {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();

    // 1. Check if URL domain matches sender or known tracking domains
    const isKnownDomain = knownTrackingDomains.some(domain =>
      hostname === domain || hostname.endsWith(`.${domain}`)
    );

    if (isKnownDomain) {
      return {
        url,
        type: 'tracking',
        trustLevel: 'high',
        reason: 'URL from known tracking domain for this sender',
        score: 0,
        metadata: { knownDomain: true, senderMatch: true },
      };
    }

    // 2. Check for suspicious patterns FIRST (security priority)
    for (const { pattern, reason, score } of SUSPICIOUS_PATTERNS) {
      if (pattern.test(url)) {
        return {
          url,
          type: 'malicious',
          trustLevel: 'untrusted',
          reason,
          score,
          metadata: { pattern: pattern.source },
        };
      }
    }

    // 3. Check for legitimate tracking patterns
    for (const { pattern, service, score } of TRACKING_PATTERNS) {
      if (pattern.test(url)) {
        return {
          url,
          type: 'tracking',
          trustLevel: 'medium',
          reason: `Legitimate ${service} tracking URL`,
          score,
          metadata: { pattern: pattern.source },
        };
      }
    }

    // 4. Check if URL domain matches sender domain (same-domain links are safer)
    if (hostname === senderDomain || hostname.endsWith(`.${senderDomain}`)) {
      return {
        url,
        type: 'legitimate',
        trustLevel: 'high',
        reason: 'URL matches sender domain',
        score: 0,
        metadata: { senderMatch: true },
      };
    }

    // 5. URL shorteners (medium risk - need to check destination)
    if (/bit\.ly|tinyurl\.com|ow\.ly|goo\.gl|t\.co/i.test(hostname)) {
      return {
        url,
        type: 'redirect',
        trustLevel: 'medium',
        reason: 'URL shortener detected',
        score: 2,
      };
    }

    // 6. Default to legitimate with medium trust
    return {
      url,
      type: 'legitimate',
      trustLevel: 'medium',
      reason: 'No suspicious patterns detected',
      score: 1,
    };

  } catch (error) {
    // Invalid URL - treat as suspicious
    return {
      url,
      type: 'unknown',
      trustLevel: 'low',
      reason: `Invalid URL format: ${error instanceof Error ? error.message : 'Unknown error'}`,
      score: 5,
    };
  }
}

/**
 * Classify multiple URLs and provide aggregate analysis
 */
export interface URLAnalysisResult {
  total: number;
  byType: Record<URLType, number>;
  byTrustLevel: Record<TrustLevel, number>;
  classifications: URLClassification[];
  averageScore: number;
  maxScore: number;
  suspiciousCount: number;
}

export function classifyURLs(
  urls: string[],
  senderDomain: string,
  knownTrackingDomains: string[] = []
): URLAnalysisResult {
  const classifications = urls.map(url => classifyURL(url, senderDomain, knownTrackingDomains));

  const byType: Record<URLType, number> = {
    tracking: 0,
    redirect: 0,
    malicious: 0,
    legitimate: 0,
    unknown: 0,
  };

  const byTrustLevel: Record<TrustLevel, number> = {
    high: 0,
    medium: 0,
    low: 0,
    untrusted: 0,
  };

  let totalScore = 0;
  let maxScore = 0;
  let suspiciousCount = 0;

  for (const classification of classifications) {
    byType[classification.type]++;
    byTrustLevel[classification.trustLevel]++;
    totalScore += classification.score;
    maxScore = Math.max(maxScore, classification.score);
    if (classification.score >= 5) {
      suspiciousCount++;
    }
  }

  return {
    total: urls.length,
    byType,
    byTrustLevel,
    classifications,
    averageScore: urls.length > 0 ? totalScore / urls.length : 0,
    maxScore,
    suspiciousCount,
  };
}

/**
 * Get a scoring multiplier based on URL classification
 * Used to adjust threat scores in the detection pipeline
 */
export function getURLScoreMultiplier(classification: URLClassification): number {
  // High trust tracking URLs get significant reduction
  if (classification.type === 'tracking' && classification.trustLevel === 'high') {
    return 0.0; // Completely ignore these URLs
  }

  // Medium trust tracking URLs get moderate reduction
  if (classification.type === 'tracking' && classification.trustLevel === 'medium') {
    return 0.2; // 80% reduction
  }

  // Legitimate URLs from same domain
  if (classification.type === 'legitimate' && classification.trustLevel === 'high') {
    return 0.1; // 90% reduction
  }

  // Generic legitimate URLs
  if (classification.type === 'legitimate') {
    return 0.5; // 50% reduction
  }

  // Redirects need some scrutiny
  if (classification.type === 'redirect') {
    return 0.8; // 20% reduction
  }

  // Unknown URLs - normal scoring
  if (classification.type === 'unknown') {
    return 1.0; // No change
  }

  // Malicious URLs - increase score
  if (classification.type === 'malicious') {
    return 2.0; // Double the score
  }

  return 1.0; // Default
}
