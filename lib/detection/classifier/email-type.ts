/**
 * Email Type Classification
 *
 * Classifies emails into types BEFORE threat detection runs.
 * This allows type-specific rules and scoring adjustments.
 */

import type { ParsedEmail } from '../types';
import {
  lookupSender,
  SenderCategory,
  type SenderInfo
} from './sender-registry';
import {
  detectMarketingSignals,
  type MarketingSignals
} from './marketing-signals';

/**
 * Email types that affect how threat detection is applied
 */
export type EmailType =
  | 'marketing'      // Promotional, newsletters, sales
  | 'transactional'  // Receipts, confirmations, shipping
  | 'automated'      // Alerts, notifications, system emails
  | 'personal'       // 1:1 business/personal communication
  | 'unknown';       // Cannot determine type

/**
 * Classification result with confidence
 */
export interface EmailClassification {
  type: EmailType;
  confidence: number;
  senderInfo: SenderInfo | null;
  marketingSignals: MarketingSignals;

  // Type-specific flags
  isKnownSender: boolean;
  isLikelyMarketing: boolean;
  isLikelyTransactional: boolean;
  isLikelyAutomated: boolean;

  // Score adjustments based on classification
  threatScoreModifier: number;  // Multiply threat score by this (e.g., 0.3 for marketing)
  skipBECDetection: boolean;    // Marketing emails shouldn't trigger BEC
  skipGiftCardDetection: boolean; // Marketing emails mentioning gift cards = normal
}

/**
 * Transactional email indicators
 */
const TRANSACTIONAL_SUBJECTS = [
  /order\s*(confirmation|confirmed|#|number)/i,
  /receipt\s*(for|from)/i,
  /invoice\s*(#|number|from)/i,
  /payment\s*(received|confirmed|processed)/i,
  /shipping\s*(confirmation|update|notification)/i,
  /your\s*(order|purchase|subscription)/i,
  /delivery\s*(update|notification|confirmed)/i,
  /booking\s*(confirmation|confirmed)/i,
  /reservation\s*(confirmation|confirmed)/i,
  /account\s*(created|verified|activated)/i,
  /welcome\s+to/i,
  /verify\s+your\s+email/i,
  /password\s+reset/i,
  /two-factor|2fa|verification\s+code/i,
];

/**
 * Automated notification indicators
 */
const AUTOMATED_SUBJECTS = [
  /\[alert\]|\[notification\]|\[reminder\]/i,
  /automated\s+(message|notification|alert)/i,
  /system\s+(notification|alert|message)/i,
  /do\s+not\s+reply/i,
  /this\s+is\s+an?\s+automated/i,
  /calendar\s+(invitation|reminder|event)/i,
  /meeting\s+(invitation|reminder|request)/i,
  /task\s+(assigned|completed|reminder)/i,
  /comment\s+on|mentioned\s+you|replied\s+to/i,
  /build\s+(failed|succeeded|passing)/i,
  /deployment\s+(failed|succeeded|complete)/i,
  /github|gitlab|jira|slack|trello|asana/i,
];

/**
 * Known automated/noreply sender patterns
 */
const AUTOMATED_SENDER_PATTERNS = [
  /^no[-_]?reply@/i,
  /^noreply@/i,
  /^do[-_]?not[-_]?reply@/i,
  /^notifications?@/i,
  /^alerts?@/i,
  /^system@/i,
  /^automated@/i,
  /^mailer[-_]?daemon@/i,
  /^postmaster@/i,
  /^support@/i,
  /^help@/i,
  /^info@/i,
  /^news(letter)?@/i,
  /^promo(tions)?@/i,
  /^marketing@/i,
  /^sales@/i,
  /^team@/i,
];

/**
 * Classify an email's type before threat detection
 */
export async function classifyEmailType(email: ParsedEmail): Promise<EmailClassification> {
  const senderEmail = typeof email.from === 'string'
    ? email.from
    : email.from?.address || '';
  const senderDomain = senderEmail.split('@')[1]?.toLowerCase() || '';
  const subject = email.subject || '';
  const body = (email.body.text || '') + (email.body.html || '');

  // Step 1: Look up sender in registry
  const senderInfo = await lookupSender(senderEmail, senderDomain);

  // Step 2: Detect marketing signals
  const marketingSignals = detectMarketingSignals(email);

  // Step 3: Check for transactional patterns
  const isTransactional = TRANSACTIONAL_SUBJECTS.some(p => p.test(subject));

  // Step 4: Check for automated patterns
  const isAutomated = AUTOMATED_SUBJECTS.some(p => p.test(subject)) ||
    AUTOMATED_SENDER_PATTERNS.some(p => p.test(senderEmail));

  // Step 5: Determine email type based on signals
  let type: EmailType = 'unknown';
  let confidence = 0.5;

  // Known sender takes precedence
  if (senderInfo && senderInfo.category !== SenderCategory.UNKNOWN) {
    switch (senderInfo.category) {
      case SenderCategory.MARKETING:
      case SenderCategory.RETAIL:
      case SenderCategory.ECOMMERCE:
        type = 'marketing';
        confidence = 0.9;
        break;
      case SenderCategory.TRANSACTIONAL:
      case SenderCategory.FINANCIAL:
        type = 'transactional';
        confidence = 0.9;
        break;
      case SenderCategory.AUTOMATED:
      case SenderCategory.SAAS:
        type = 'automated';
        confidence = 0.85;
        break;
      case SenderCategory.TRUSTED:
        type = 'personal';
        confidence = 0.8;
        break;
    }
  }

  // If unknown sender, use content signals
  if (type === 'unknown') {
    // Strong marketing signals
    if (marketingSignals.isMarketing && marketingSignals.confidence > 0.7) {
      type = 'marketing';
      confidence = marketingSignals.confidence;
    }
    // Transactional patterns
    else if (isTransactional) {
      type = 'transactional';
      confidence = 0.75;
    }
    // Automated patterns
    else if (isAutomated) {
      type = 'automated';
      confidence = 0.7;
    }
    // Default to personal if direct communication style
    else if (isDirectCommunication(email)) {
      type = 'personal';
      confidence = 0.6;
    }
  }

  // Calculate threat score modifier based on type
  const threatScoreModifier = calculateThreatScoreModifier(type, senderInfo, marketingSignals);

  return {
    type,
    confidence,
    senderInfo,
    marketingSignals,
    isKnownSender: senderInfo !== null && senderInfo.category !== SenderCategory.UNKNOWN,
    isLikelyMarketing: type === 'marketing' || marketingSignals.isMarketing,
    isLikelyTransactional: type === 'transactional' || isTransactional,
    isLikelyAutomated: type === 'automated' || isAutomated,
    threatScoreModifier,
    skipBECDetection: type === 'marketing' || type === 'transactional',
    skipGiftCardDetection: type === 'marketing' ||
      (senderInfo?.category === SenderCategory.RETAIL) ||
      (senderInfo?.category === SenderCategory.ECOMMERCE),
  };
}

/**
 * Check if email looks like direct 1:1 communication
 */
function isDirectCommunication(email: ParsedEmail): boolean {
  const subject = email.subject || '';
  const body = email.body.text || '';

  // Reply/forward chains suggest conversation
  if (/^(re|fw|fwd):/i.test(subject)) {
    return true;
  }

  // No unsubscribe = likely personal
  if (!body.toLowerCase().includes('unsubscribe')) {
    // Check for conversational patterns
    const conversationalPatterns = [
      /^hi\s|^hello\s|^hey\s|^dear\s/i,
      /can you|could you|would you|will you/i,
      /let me know|get back to me|reach out/i,
      /thanks|thank you|regards|best/i,
    ];

    return conversationalPatterns.some(p => p.test(body));
  }

  return false;
}

/**
 * Calculate how much to adjust threat scores based on classification
 */
function calculateThreatScoreModifier(
  type: EmailType,
  senderInfo: SenderInfo | null,
  marketingSignals: MarketingSignals
): number {
  // Known trusted senders get significant reduction
  if (senderInfo?.category === SenderCategory.TRUSTED) {
    return 0.2; // 80% reduction
  }

  // Known retail/marketing senders
  if (senderInfo?.category === SenderCategory.RETAIL ||
      senderInfo?.category === SenderCategory.ECOMMERCE ||
      senderInfo?.category === SenderCategory.MARKETING) {
    return 0.3; // 70% reduction
  }

  // Marketing emails from unknown but legitimate-looking senders
  if (type === 'marketing' && marketingSignals.isMarketing) {
    // More reduction if more marketing signals
    if (marketingSignals.signalCount >= 4) {
      return 0.4; // 60% reduction
    }
    return 0.5; // 50% reduction
  }

  // Transactional from unknown senders - moderate reduction
  if (type === 'transactional') {
    return 0.6; // 40% reduction
  }

  // Automated notifications
  if (type === 'automated') {
    return 0.7; // 30% reduction
  }

  // Personal/unknown - no reduction, full threat detection
  return 1.0;
}

/**
 * Get a human-readable explanation of the classification
 */
export function explainClassification(classification: EmailClassification): string {
  const { type, confidence, senderInfo, marketingSignals } = classification;

  const parts: string[] = [];

  parts.push(`Email classified as: ${type} (${Math.round(confidence * 100)}% confidence)`);

  if (senderInfo) {
    parts.push(`Sender: ${senderInfo.name} (${senderInfo.category})`);
  }

  if (marketingSignals.isMarketing) {
    parts.push(`Marketing indicators: ${marketingSignals.signals.join(', ')}`);
  }

  if (classification.threatScoreModifier < 1.0) {
    parts.push(`Threat score reduced by ${Math.round((1 - classification.threatScoreModifier) * 100)}%`);
  }

  return parts.join('. ');
}
