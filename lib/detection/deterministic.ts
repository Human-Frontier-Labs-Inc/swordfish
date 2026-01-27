/**
 * Deterministic Detection Layer
 * Fast, rule-based checks that don't require external APIs
 */

import type { ParsedEmail, Signal, SignalType, LayerResult, AuthenticationResults } from './types';
import { parseAuthenticationResults } from './parser';
import { classifyURL, getURLScoreMultiplier, type URLClassification } from './url-classifier';
import { deduplicateURLSignals } from './signal-deduplicator';

// Known free email providers
const FREE_EMAIL_PROVIDERS = new Set([
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
  'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com',
  'gmx.com', 'live.com', 'msn.com', 'fastmail.com',
]);

// Known disposable email domains (sample - would be much larger in production)
const DISPOSABLE_DOMAINS = new Set([
  'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
  'throwaway.email', 'temp-mail.org', 'fakeinbox.com', 'trashmail.com',
]);

// High-value brand domains for homoglyph detection
const BRAND_DOMAINS = [
  'paypal.com', 'amazon.com', 'microsoft.com', 'apple.com', 'google.com',
  'facebook.com', 'netflix.com', 'bankofamerica.com', 'chase.com', 'wellsfargo.com',
  'dropbox.com', 'linkedin.com', 'twitter.com', 'instagram.com', 'adobe.com',
];

// Homoglyph character mappings
const HOMOGLYPHS: Record<string, string[]> = {
  'a': ['а', 'ɑ', 'α', '@'],
  'b': ['ƅ', 'Ь'],
  'c': ['с', 'ϲ', '¢'],
  'd': ['ԁ', 'ɗ'],
  'e': ['е', 'ё', '℮'],
  'g': ['ɡ', 'ց'],
  'h': ['һ', 'հ'],
  'i': ['і', 'ı', '1', 'l', '|'],
  'j': ['ј', 'ʝ'],
  'k': ['κ', 'ķ'],
  'l': ['ӏ', 'ɭ', '1', 'i', '|'],
  'm': ['м', 'ṃ'],
  'n': ['ո', 'ņ'],
  'o': ['о', 'ο', '0', 'ө'],
  'p': ['р', 'ρ'],
  'q': ['ԛ', 'գ'],
  'r': ['г', 'ɾ'],
  's': ['ѕ', 'ꜱ', '$'],
  't': ['т', 'ţ'],
  'u': ['υ', 'ս'],
  'v': ['ѵ', 'ν'],
  'w': ['ѡ', 'ω'],
  'x': ['х', 'χ'],
  'y': ['у', 'ү'],
  'z': ['ᴢ', 'ʐ'],
  '0': ['о', 'ο', 'O'],
  '1': ['l', 'i', 'I', '|'],
};

// Urgency keywords
const URGENCY_PATTERNS = [
  /urgent/i, /immediate(ly)?/i, /asap/i, /right away/i, /act now/i,
  /expires? (today|soon|immediately)/i, /limited time/i, /don't delay/i,
  /account (will be |has been )?(suspended|closed|terminated|locked)/i,
  /verify (your )?(account|identity)/i, /confirm (your )?(account|identity)/i,
  /unauthorized (access|activity|transaction)/i,
  /suspicious (activity|login|transaction)/i,
];

// Financial request patterns
const FINANCIAL_PATTERNS = [
  /wire transfer/i, /bank transfer/i, /payment request/i,
  /invoice attached/i, /pay(ment)? immediately/i,
  /update (your )?(payment|billing|bank)/i,
  /gift card/i, /bitcoin/i, /cryptocurrency/i,
];

// Credential request patterns
const CREDENTIAL_PATTERNS = [
  /enter (your )?(password|credentials|login)/i,
  /verify (your )?(password|credentials|login)/i,
  /reset (your )?(password)/i,
  /click (here |the link )?(to )?(login|sign in|verify)/i,
  /(username|password|ssn|social security)/i,
];

/**
 * Run deterministic analysis on a parsed email
 * Phase 2: Now accepts reputation context for URL classification
 */
export async function runDeterministicAnalysis(
  email: ParsedEmail,
  reputationContext?: { knownTrackingDomains: string[] }
): Promise<LayerResult> {
  const startTime = performance.now();
  const signals: Signal[] = [];

  // 1. Check authentication results (SPF/DKIM/DMARC)
  const authResults = parseAuthenticationResults(
    email.headers['authentication-results'] || ''
  );
  signals.push(...analyzeAuthentication(authResults));

  // 2. Analyze sender domain
  signals.push(...analyzeDomain(email.from.domain, email.from.displayName));

  // 3. Check header anomalies
  signals.push(...analyzeHeaders(email));

  // 4. Analyze email content
  const content = email.body.text || stripHtml(email.body.html || '');
  signals.push(...analyzeContent(content, email.subject));

  // 5. Extract and analyze URLs with context-aware classification (Phase 2)
  const urls = extractUrls(email.body.html || email.body.text || '');
  const knownTrackingDomains = reputationContext?.knownTrackingDomains || [];
  signals.push(...analyzeUrls(urls, email.from.domain, knownTrackingDomains));

  // 6. Deduplicate URL signals to prevent score inflation (Phase 2)
  const deduplicatedSignals = deduplicateURLSignals(signals);

  // Calculate overall score (0-100)
  const score = calculateScore(deduplicatedSignals);

  return {
    layer: 'deterministic',
    score,
    confidence: 0.8, // Deterministic rules have high confidence
    signals: deduplicatedSignals,
    processingTimeMs: performance.now() - startTime,
  };
}

/**
 * Analyze authentication results
 */
function analyzeAuthentication(auth: AuthenticationResults): Signal[] {
  const signals: Signal[] = [];

  // SPF
  if (auth.spf.result === 'fail') {
    signals.push({
      type: 'spf',
      severity: 'warning',
      score: 20,
      detail: 'SPF authentication failed - sender may be spoofed',
    });
  } else if (auth.spf.result === 'softfail') {
    signals.push({
      type: 'spf',
      severity: 'warning',
      score: 10,
      detail: 'SPF soft fail - sender authenticity uncertain',
    });
  } else if (auth.spf.result === 'pass') {
    signals.push({
      type: 'spf',
      severity: 'info',
      score: 0,
      detail: 'SPF authentication passed',
    });
  }

  // DKIM
  if (auth.dkim.result === 'fail') {
    signals.push({
      type: 'dkim',
      severity: 'warning',
      score: 15,
      detail: 'DKIM signature verification failed',
    });
  } else if (auth.dkim.result === 'pass') {
    signals.push({
      type: 'dkim',
      severity: 'info',
      score: 0,
      detail: 'DKIM signature verified',
    });
  }

  // DMARC
  if (auth.dmarc.result === 'fail') {
    signals.push({
      type: 'dmarc',
      severity: 'critical',
      score: 30,
      detail: 'DMARC policy check failed - high likelihood of spoofing',
    });
  } else if (auth.dmarc.result === 'pass') {
    signals.push({
      type: 'dmarc',
      severity: 'info',
      score: 0,
      detail: 'DMARC policy check passed',
    });
  }

  return signals;
}

/**
 * Analyze sender domain
 */
function analyzeDomain(domain: string, displayName?: string): Signal[] {
  const signals: Signal[] = [];

  if (!domain) return signals;

  // Check for free email provider
  if (FREE_EMAIL_PROVIDERS.has(domain)) {
    signals.push({
      type: 'free_email_provider',
      severity: 'info',
      score: 5,
      detail: `Sender using free email provider: ${domain}`,
    });
  }

  // Check for disposable email
  if (DISPOSABLE_DOMAINS.has(domain)) {
    signals.push({
      type: 'disposable_email',
      severity: 'warning',
      score: 25,
      detail: `Sender using disposable email service: ${domain}`,
    });
  }

  // Check for homoglyph attack
  const homoglyphMatch = detectHomoglyph(domain);
  if (homoglyphMatch) {
    signals.push({
      type: 'homoglyph',
      severity: 'critical',
      score: 40,
      detail: `Domain "${domain}" appears to impersonate "${homoglyphMatch}"`,
      metadata: { impersonatedDomain: homoglyphMatch },
    });
  }

  // Check for cousin domain
  const cousinMatch = detectCousinDomain(domain);
  if (cousinMatch && !homoglyphMatch) {
    signals.push({
      type: 'cousin_domain',
      severity: 'warning',
      score: 20,
      detail: `Domain "${domain}" similar to brand "${cousinMatch}"`,
      metadata: { similarBrand: cousinMatch },
    });
  }

  // Check display name spoofing (e.g., "PayPal Support" <random@gmail.com>)
  if (displayName) {
    const displayNameSpoof = detectDisplayNameSpoof(displayName, domain);
    if (displayNameSpoof) {
      signals.push({
        type: 'display_name_spoof',
        severity: 'warning',
        score: 25,
        detail: `Display name "${displayName}" may impersonate "${displayNameSpoof}" but sent from ${domain}`,
        metadata: { impersonatedBrand: displayNameSpoof },
      });
    }
  }

  return signals;
}

/**
 * Analyze email headers for anomalies
 */
function analyzeHeaders(email: ParsedEmail): Signal[] {
  const signals: Signal[] = [];

  // Check From/Reply-To mismatch
  if (email.replyTo && email.replyTo.domain !== email.from.domain) {
    signals.push({
      type: 'reply_to_mismatch',
      severity: 'warning',
      score: 15,
      detail: `Reply-To domain (${email.replyTo.domain}) differs from From domain (${email.from.domain})`,
    });
  }

  // Check for missing or suspicious headers
  if (!email.headers['message-id']) {
    signals.push({
      type: 'header_anomaly',
      severity: 'warning',
      score: 10,
      detail: 'Missing Message-ID header',
    });
  }

  return signals;
}

/**
 * Analyze email content
 */
function analyzeContent(content: string, subject: string): Signal[] {
  const signals: Signal[] = [];
  const fullText = `${subject} ${content}`;

  // Check for urgency language
  const urgencyMatches = URGENCY_PATTERNS.filter(p => p.test(fullText));
  if (urgencyMatches.length >= 2) {
    signals.push({
      type: 'urgency_language',
      severity: 'warning',
      score: 15,
      detail: `Multiple urgency indicators detected (${urgencyMatches.length} patterns)`,
    });
  }

  // Check for financial requests - HIGH RISK indicator
  const financialMatches = FINANCIAL_PATTERNS.filter(p => p.test(fullText));
  if (financialMatches.length > 0) {
    signals.push({
      type: 'financial_request',
      severity: 'critical',
      score: 35,
      detail: 'Email contains financial request language',
    });
  }

  // Check for credential requests - HIGH RISK indicator
  const credentialMatches = CREDENTIAL_PATTERNS.filter(p => p.test(fullText));
  if (credentialMatches.length > 0) {
    signals.push({
      type: 'credential_request',
      severity: 'critical',
      score: 40,
      detail: 'Email requests credentials or sensitive information',
    });
  }

  return signals;
}

/**
 * Analyze URLs in email using context-aware classification
 * Phase 2: Reduces false positives by distinguishing tracking URLs from malicious ones
 */
function analyzeUrls(urls: string[], senderDomain: string, knownTrackingDomains: string[] = []): Signal[] {
  const signals: Signal[] = [];

  for (const url of urls) {
    // Classify the URL using context-aware classifier
    const classification = classifyURL(url, senderDomain, knownTrackingDomains);

    // Skip trusted tracking URLs (score = 0)
    if (classification.type === 'tracking' && classification.trustLevel === 'high') {
      continue;
    }

    // Apply score multiplier based on URL classification
    const baseScore = classification.score;
    const multiplier = getURLScoreMultiplier(classification);
    const adjustedScore = Math.round(baseScore * multiplier);

    // Only add signal if score is significant
    if (adjustedScore > 0) {
      // Map classification type to signal type and severity
      let signalType: SignalType = 'suspicious_url';
      let severity: 'info' | 'warning' | 'critical' = 'warning';

      if (classification.type === 'malicious') {
        signalType = 'malicious_url' as SignalType;
        severity = 'critical';
      } else if (classification.type === 'redirect') {
        signalType = 'shortened_url' as SignalType;
        severity = 'info';
      } else if (classification.type === 'tracking') {
        signalType = 'tracking_url' as SignalType;
        severity = 'info';
      }

      signals.push({
        type: signalType,
        severity,
        score: adjustedScore,
        detail: classification.reason,
        metadata: {
          url: classification.url,
          urlType: classification.type,
          trustLevel: classification.trustLevel,
          originalScore: baseScore,
          multiplier,
          ...classification.metadata,
        },
      });
    }
  }

  return signals;
}

/**
 * Detect homoglyph attacks (e.g., paypa1.com vs paypal.com)
 */
function detectHomoglyph(domain: string): string | null {
  const domainLower = domain.toLowerCase();
  const domainBase = domainLower.split('.')[0];

  for (const brandDomain of BRAND_DOMAINS) {
    const brandBase = brandDomain.split('.')[0];

    // Skip if exact match
    if (domainBase === brandBase) continue;

    // Check if domain could be homoglyph of brand
    if (isHomoglyph(domainBase, brandBase)) {
      return brandDomain;
    }
  }

  return null;
}

function isHomoglyph(test: string, target: string): boolean {
  if (test.length !== target.length) return false;

  let differences = 0;
  for (let i = 0; i < test.length; i++) {
    if (test[i] !== target[i]) {
      // Check if it's a homoglyph substitution
      const targetChar = target[i];
      const testChar = test[i];

      const homoglyphsForTarget = HOMOGLYPHS[targetChar] || [];
      if (!homoglyphsForTarget.includes(testChar)) {
        differences++;
      }
    }
  }

  // Allow at most 2 character differences that are homoglyphs
  return differences <= 2 && differences > 0;
}

/**
 * Detect cousin domains (e.g., paypal-secure.com)
 */
function detectCousinDomain(domain: string): string | null {
  const domainLower = domain.toLowerCase();

  for (const brandDomain of BRAND_DOMAINS) {
    const brandBase = brandDomain.split('.')[0];

    // Check if domain contains brand name with additions
    if (domainLower.includes(brandBase) && domainLower !== brandDomain) {
      return brandDomain;
    }
  }

  return null;
}

/**
 * Detect display name spoofing
 */
function detectDisplayNameSpoof(displayName: string, domain: string): string | null {
  const nameLower = displayName.toLowerCase();

  for (const brandDomain of BRAND_DOMAINS) {
    const brandBase = brandDomain.split('.')[0];

    // Check if display name mentions brand but email is from different domain
    if (nameLower.includes(brandBase) && !domain.includes(brandBase)) {
      return brandBase;
    }
  }

  // Also check for generic authority spoofing
  const authorityTerms = ['ceo', 'cfo', 'president', 'director', 'manager', 'admin', 'support'];
  if (authorityTerms.some(term => nameLower.includes(term)) && FREE_EMAIL_PROVIDERS.has(domain)) {
    return 'authority figure';
  }

  return null;
}

/**
 * Extract URLs from content
 */
function extractUrls(content: string): string[] {
  const urlRegex = /https?:\/\/[^\s<>"']+/gi;
  const matches = content.match(urlRegex) || [];
  return [...new Set(matches)]; // Deduplicate
}

/**
 * Strip HTML tags from content
 */
function stripHtml(html: string): string {
  return html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
}

/**
 * Calculate overall score from signals
 */
function calculateScore(signals: Signal[]): number {
  const totalScore = signals.reduce((sum, signal) => sum + signal.score, 0);
  return Math.min(100, totalScore);
}
