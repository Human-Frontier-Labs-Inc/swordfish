/**
 * Executive/VIP Impersonation Detection
 * Detects attempts to impersonate executives and VIPs
 */

import { checkVIPImpersonation, findVIPByDisplayName, VIPEntry } from './vip-list';

export interface ImpersonationResult {
  isImpersonation: boolean;
  impersonationType?: ImpersonationType;
  confidence: number;
  matchedVIP?: VIPEntry;
  signals: ImpersonationSignal[];
  explanation: string;
}

export type ImpersonationType =
  | 'display_name_spoof'    // Exact/similar display name
  | 'title_spoof'           // Adding fake title (CEO, CFO)
  | 'domain_lookalike'      // Similar domain
  | 'reply_to_mismatch'     // Different reply-to address
  | 'unicode_spoof'         // Unicode homoglyph attack
  | 'cousin_domain'         // Similar domain name
  | 'free_email_executive'; // Executive name + freemail

export interface ImpersonationSignal {
  type: ImpersonationType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detail: string;
}

// Common free email providers
const FREE_EMAIL_DOMAINS = new Set([
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
  'aol.com', 'icloud.com', 'protonmail.com', 'mail.com',
  'zoho.com', 'yandex.com', 'gmx.com', 'live.com',
]);

// Executive title patterns
const EXECUTIVE_TITLE_PATTERNS = [
  /\b(?:ceo|chief executive)\b/i,
  /\b(?:cfo|chief financial)\b/i,
  /\b(?:coo|chief operating)\b/i,
  /\b(?:cto|chief technology)\b/i,
  /\b(?:cio|chief information)\b/i,
  /\b(?:president|vice president|vp)\b/i,
  /\b(?:director|managing director)\b/i,
  /\b(?:chairman|chairwoman|chair)\b/i,
  /\b(?:founder|co-founder)\b/i,
  /\b(?:owner|partner)\b/i,
];

// Unicode homoglyph map
const HOMOGLYPHS: Record<string, string[]> = {
  'a': ['а', 'ɑ', 'α', 'ą'],      // Cyrillic а, Latin alpha
  'c': ['с', 'ϲ', 'ç'],           // Cyrillic с
  'e': ['е', 'ё', 'ε', 'ę'],      // Cyrillic е
  'i': ['і', 'ι', 'ı'],           // Cyrillic і, Greek iota
  'o': ['о', 'ο', 'ø', 'ö'],      // Cyrillic о, Greek omicron
  'p': ['р', 'ρ'],                // Cyrillic р
  's': ['ѕ', 'ș'],                // Cyrillic ѕ
  'x': ['х', 'χ'],                // Cyrillic х
  'y': ['у', 'γ'],                // Cyrillic у
  'n': ['п', 'η'],                // Cyrillic п
};

/**
 * Check for impersonation attempts
 */
export async function detectImpersonation(
  tenantId: string,
  senderEmail: string,
  senderDisplayName: string,
  replyTo?: string,
  organizationDomain?: string
): Promise<ImpersonationResult> {
  const signals: ImpersonationSignal[] = [];
  let confidence = 0;
  let matchedVIP: VIPEntry | undefined;
  let impersonationType: ImpersonationType | undefined;

  const senderDomain = senderEmail.split('@')[1]?.toLowerCase() || '';

  // 1. Check VIP list impersonation
  const vipCheck = await checkVIPImpersonation(tenantId, senderEmail, senderDisplayName);
  if (vipCheck.isImpersonation && vipCheck.matchedVIP) {
    matchedVIP = vipCheck.matchedVIP;
    impersonationType = 'display_name_spoof';
    confidence = Math.max(confidence, vipCheck.confidence);
    signals.push({
      type: 'display_name_spoof',
      severity: 'critical',
      detail: vipCheck.reason || `Display name matches VIP: ${matchedVIP.displayName}`,
    });
  }

  // 2. Check for title spoofing in display name
  const titleMatch = checkTitleSpoof(senderDisplayName);
  if (titleMatch.hasTitleSpoof) {
    if (!impersonationType) impersonationType = 'title_spoof';
    confidence = Math.max(confidence, 0.6);
    signals.push({
      type: 'title_spoof',
      severity: 'high',
      detail: `Executive title in display name: ${titleMatch.matchedTitle}`,
    });
  }

  // 3. Check for free email with executive name
  if (FREE_EMAIL_DOMAINS.has(senderDomain)) {
    // Check if display name matches any VIP
    const potentialVIPs = await findVIPByDisplayName(tenantId, senderDisplayName);
    if (potentialVIPs.length > 0) {
      if (!impersonationType) impersonationType = 'free_email_executive';
      confidence = Math.max(confidence, 0.7);
      signals.push({
        type: 'free_email_executive',
        severity: 'high',
        detail: `Executive name "${senderDisplayName}" used with free email domain "${senderDomain}"`,
      });
      if (!matchedVIP) matchedVIP = potentialVIPs[0];
    }

    // Check for title in name + free email
    if (titleMatch.hasTitleSpoof) {
      confidence = Math.max(confidence, 0.75);
      signals.push({
        type: 'free_email_executive',
        severity: 'critical',
        detail: `Executive title "${titleMatch.matchedTitle}" with free email is highly suspicious`,
      });
    }
  }

  // 4. Check for reply-to mismatch
  if (replyTo && replyTo.toLowerCase() !== senderEmail.toLowerCase()) {
    const replyToDomain = replyTo.split('@')[1]?.toLowerCase();

    if (replyToDomain !== senderDomain) {
      if (!impersonationType) impersonationType = 'reply_to_mismatch';
      confidence = Math.max(confidence, 0.5);

      const severity = FREE_EMAIL_DOMAINS.has(replyToDomain || '') ? 'high' : 'medium';
      signals.push({
        type: 'reply_to_mismatch',
        severity,
        detail: `Reply-To "${replyTo}" differs from sender "${senderEmail}"`,
      });
    }
  }

  // 5. Check for domain lookalike (cousin domain)
  if (organizationDomain && senderDomain !== organizationDomain) {
    const lookalike = checkDomainLookalike(senderDomain, organizationDomain);
    if (lookalike.isLookalike) {
      if (!impersonationType) impersonationType = 'cousin_domain';
      confidence = Math.max(confidence, lookalike.confidence);
      signals.push({
        type: 'cousin_domain',
        severity: 'critical',
        detail: lookalike.explanation,
      });
    }
  }

  // 6. Check for unicode homoglyph attacks
  const unicodeCheck = checkUnicodeSpoof(senderDisplayName, senderEmail);
  if (unicodeCheck.hasSpoof) {
    if (!impersonationType) impersonationType = 'unicode_spoof';
    confidence = Math.max(confidence, 0.9);
    signals.push({
      type: 'unicode_spoof',
      severity: 'critical',
      detail: unicodeCheck.explanation,
    });
  }

  // Build explanation
  let explanation = '';
  if (signals.length === 0) {
    explanation = 'No impersonation indicators detected';
  } else if (signals.length === 1) {
    explanation = signals[0].detail;
  } else {
    explanation = `Multiple impersonation indicators: ${signals.map(s => s.type).join(', ')}`;
  }

  return {
    isImpersonation: confidence > 0.5,
    impersonationType,
    confidence,
    matchedVIP,
    signals,
    explanation,
  };
}

/**
 * Check for executive title spoofing
 */
function checkTitleSpoof(displayName: string): {
  hasTitleSpoof: boolean;
  matchedTitle?: string;
} {
  for (const pattern of EXECUTIVE_TITLE_PATTERNS) {
    const match = displayName.match(pattern);
    if (match) {
      return {
        hasTitleSpoof: true,
        matchedTitle: match[0],
      };
    }
  }
  return { hasTitleSpoof: false };
}

/**
 * Check for domain lookalike attacks
 */
function checkDomainLookalike(
  senderDomain: string,
  orgDomain: string
): {
  isLookalike: boolean;
  confidence: number;
  explanation: string;
} {
  const senderBase = senderDomain.split('.')[0];
  const orgBase = orgDomain.split('.')[0];

  // Exact base match with different TLD
  if (senderBase === orgBase && senderDomain !== orgDomain) {
    return {
      isLookalike: true,
      confidence: 0.85,
      explanation: `Lookalike domain: "${senderDomain}" mimics "${orgDomain}" with different TLD`,
    };
  }

  // Check for common typosquatting patterns
  const patterns = [
    // Missing letter
    { regex: new RegExp(`^${orgBase.slice(0, -1)}[^${orgBase.slice(-1)}]`), desc: 'missing letter' },
    // Double letter
    { regex: new RegExp(`${orgBase.replace(/(.)/g, '$1?$1?')}`), desc: 'double letter' },
    // Hyphen insertion
    { regex: new RegExp(`^${orgBase.replace(/(.)/g, '$1-?')}`), desc: 'hyphen insertion' },
  ];

  // Check Levenshtein distance
  const distance = levenshteinDistance(senderBase, orgBase);
  if (distance > 0 && distance <= 2 && senderBase.length >= 4) {
    return {
      isLookalike: true,
      confidence: distance === 1 ? 0.9 : 0.7,
      explanation: `Lookalike domain: "${senderDomain}" is ${distance} character(s) different from "${orgDomain}"`,
    };
  }

  // Check for common substitutions
  const substitutions = [
    { from: 'o', to: '0' },
    { from: 'l', to: '1' },
    { from: 'i', to: '1' },
    { from: 's', to: '5' },
    { from: 'a', to: '4' },
    { from: 'e', to: '3' },
    { from: 'rn', to: 'm' },
    { from: 'vv', to: 'w' },
  ];

  for (const { from, to } of substitutions) {
    const variant = orgBase.replace(new RegExp(from, 'g'), to);
    if (senderBase === variant) {
      return {
        isLookalike: true,
        confidence: 0.85,
        explanation: `Lookalike domain: "${senderDomain}" uses character substitution (${from}→${to})`,
      };
    }
  }

  return {
    isLookalike: false,
    confidence: 0,
    explanation: '',
  };
}

/**
 * Check for unicode homoglyph spoofing
 */
function checkUnicodeSpoof(displayName: string, email: string): {
  hasSpoof: boolean;
  explanation: string;
} {
  const textToCheck = `${displayName} ${email}`;

  // Check for non-ASCII characters that look like ASCII
  // eslint-disable-next-line no-control-regex
  const nonAscii = textToCheck.match(/[^\x00-\x7F]/g);

  if (nonAscii) {
    for (const char of nonAscii) {
      for (const [ascii, homoglyphs] of Object.entries(HOMOGLYPHS)) {
        if (homoglyphs.includes(char)) {
          return {
            hasSpoof: true,
            explanation: `Unicode homoglyph detected: "${char}" looks like "${ascii}"`,
          };
        }
      }
    }

    // Even unknown non-ASCII in email domain is suspicious
    const emailPart = email.toLowerCase();
    // eslint-disable-next-line no-control-regex
    if (/[^\x00-\x7F]/.test(emailPart)) {
      return {
        hasSpoof: true,
        explanation: 'Non-ASCII characters in email address (possible homoglyph attack)',
      };
    }
  }

  return {
    hasSpoof: false,
    explanation: '',
  };
}

/**
 * Calculate Levenshtein distance between strings
 */
function levenshteinDistance(str1: string, str2: string): number {
  const m = str1.length;
  const n = str2.length;

  const dp: number[][] = Array(m + 1)
    .fill(null)
    .map(() => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (str1[i - 1] === str2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }

  return dp[m][n];
}

/**
 * Get impersonation risk score
 */
export function calculateImpersonationRisk(result: ImpersonationResult): {
  score: number;
  level: 'low' | 'medium' | 'high' | 'critical';
} {
  if (!result.isImpersonation || result.signals.length === 0) {
    return { score: 0, level: 'low' };
  }

  // Weight signals by severity
  const severityWeights: Record<string, number> = {
    critical: 1.0,
    high: 0.7,
    medium: 0.4,
    low: 0.2,
  };

  let totalWeight = 0;
  for (const signal of result.signals) {
    totalWeight += severityWeights[signal.severity] || 0;
  }

  // Normalize score
  const score = Math.min(totalWeight / 2, 1.0);

  let level: 'low' | 'medium' | 'high' | 'critical' = 'low';
  if (score >= 0.8 || result.signals.some(s => s.severity === 'critical')) {
    level = 'critical';
  } else if (score >= 0.5) {
    level = 'high';
  } else if (score >= 0.3) {
    level = 'medium';
  }

  return { score, level };
}
