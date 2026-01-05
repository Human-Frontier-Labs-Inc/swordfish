/**
 * ML Email Classifier
 * Uses feature extraction and scoring for phishing/spam detection
 */

import type { ParsedEmail, Signal } from '../types';

export interface MLFeatures {
  // Text features
  urgencyScore: number;
  threatLanguageScore: number;
  grammarScore: number;
  sentimentScore: number;

  // Structural features
  linkCount: number;
  externalLinkRatio: number;
  shortenerLinkCount: number;
  formActionCount: number;
  hiddenElementCount: number;

  // Sender features
  senderReputationScore: number;
  domainAge: number;
  isFreemailProvider: boolean;
  displayNameMismatch: boolean;

  // Content features
  attachmentRiskScore: number;
  hasPasswordProtectedAttachment: boolean;
  imageToTextRatio: number;

  // Behavioral features
  isReplyChain: boolean;
  hasUnsubscribeLink: boolean;
  requestsPersonalInfo: boolean;
  requestsFinancialAction: boolean;
}

export interface MLPrediction {
  score: number;
  confidence: number;
  category: 'legitimate' | 'spam' | 'phishing' | 'bec' | 'malware';
  features: Partial<MLFeatures>;
  signals: Signal[];
}

// Common phishing/urgency keywords
const URGENCY_KEYWORDS = [
  'urgent', 'immediately', 'asap', 'right away', 'act now',
  'expires', 'deadline', 'limited time', 'last chance', 'final notice',
  'suspended', 'locked', 'disabled', 'verify now', 'confirm now',
  '24 hours', '48 hours', 'within hours', 'today only',
];

const THREAT_KEYWORDS = [
  'account suspended', 'unusual activity', 'unauthorized access',
  'security alert', 'password expired', 'verify your identity',
  'confirm your account', 'update your information', 'click here to verify',
  'failure to comply', 'legal action', 'your account will be',
];

const BEC_KEYWORDS = [
  // Wire fraud
  'wire transfer', 'bank transfer', 'urgent payment', 'wire funds',
  'transfer funds', 'send payment', 'payment instruction', 'banking information',
  'routing number', 'swift code', 'iban', 'account number', 'beneficiary',
  // Gift card scams
  'gift cards', 'itunes card', 'google play card', 'amazon card',
  'steam card', 'prepaid card', 'scratch off', 'redemption code',
  // Invoice fraud
  'updated invoice', 'revised invoice', 'banking changed', 'payment redirect',
  'new bank details', 'vendor change',
  // Payroll diversion
  'direct deposit', 'update payroll', 'w-2', 'w2 form', 'payroll change',
  // Pressure tactics
  'keep this confidential', 'between us', 'do not discuss', 'private matter',
  'just between us', 'bypass', 'skip the usual',
  // Authority manipulation
  'i need you to', 'personal favor', 'trust you', 'count on you',
  'im in a meeting', 'traveling', 'out of office', 'cant call',
  // Executive impersonation
  'ceo', 'cfo', 'coo', 'cto', 'president', 'director', 'executive',
  'board meeting', 'confidential deal', 'acquisition',
  // Bitcoin/crypto
  'bitcoin', 'cryptocurrency', 'crypto wallet', 'btc address',
];

const PERSONAL_INFO_REQUESTS = [
  'social security', 'ssn', 'date of birth', 'dob', 'mother\'s maiden',
  'credit card', 'bank account', 'routing number', 'password',
  'pin', 'security question', 'username', 'login credentials',
];

const FREEMAIL_PROVIDERS = [
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
  'mail.com', 'protonmail.com', 'icloud.com', 'live.com', 'msn.com',
  'yandex.com', 'zoho.com', 'gmx.com', 'inbox.com',
];

const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
  'buff.ly', 'rebrand.ly', 'bl.ink', 'short.io', 'cutt.ly',
];

/**
 * Main ML classifier - extracts features and predicts threat category
 */
export async function classifyEmail(email: ParsedEmail): Promise<MLPrediction> {
  const features = extractFeatures(email);
  const signals: Signal[] = [];

  // Calculate component scores
  const textScore = calculateTextScore(features, signals);
  const structuralScore = calculateStructuralScore(features, signals);
  const senderScore = calculateSenderScore(features, signals);
  const contentScore = calculateContentScore(features, signals);
  const behavioralScore = calculateBehavioralScore(features, signals);

  // Weighted combination
  const weights = {
    text: 0.25,
    structural: 0.20,
    sender: 0.25,
    content: 0.15,
    behavioral: 0.15,
  };

  const rawScore =
    textScore * weights.text +
    structuralScore * weights.structural +
    senderScore * weights.sender +
    contentScore * weights.content +
    behavioralScore * weights.behavioral;

  // Normalize to 0-100
  const score = Math.min(100, Math.max(0, Math.round(rawScore)));

  // Determine category based on signals
  const category = determineCategory(signals, features);

  // Calculate confidence based on feature coverage
  const confidence = calculateConfidence(features, signals);

  return {
    score,
    confidence,
    category,
    features,
    signals,
  };
}

/**
 * Extract all features from email
 */
function extractFeatures(email: ParsedEmail): MLFeatures {
  const text = (email.body.text || '') + ' ' + (email.subject || '');
  const html = email.body.html || '';
  const lowerText = text.toLowerCase();

  // Extract URLs from text and HTML
  const urlRegex = /https?:\/\/[^\s<>"]+/gi;
  const urls = [...(text.match(urlRegex) || []), ...(html.match(urlRegex) || [])];
  const uniqueUrls = [...new Set(urls)];

  // Count URL shorteners
  const shortenerCount = uniqueUrls.filter(url =>
    URL_SHORTENERS.some(s => url.includes(s))
  ).length;

  // Extract forms from HTML
  const formActions = (html.match(/<form[^>]*action/gi) || []).length;
  const hiddenInputs = (html.match(/<input[^>]*type=["']hidden/gi) || []).length;

  // Check sender - handle both string and EmailAddress object formats
  const fromAddress = typeof email.from === 'string'
    ? email.from
    : (email.from?.address || '');
  const senderDomain = fromAddress.split('@')[1]?.toLowerCase() || '';
  const isFreemailProvider = FREEMAIL_PROVIDERS.includes(senderDomain);

  // Check display name vs email mismatch
  const displayNameMismatch = checkDisplayNameMismatch(email.from);

  // Calculate image to text ratio
  const imageCount = (html.match(/<img/gi) || []).length;
  const textLength = text.length;
  const imageToTextRatio = textLength > 0 ? imageCount / (textLength / 100) : 0;

  // Check for reply chain
  const isReplyChain = email.subject?.toLowerCase().startsWith('re:') ||
                       email.subject?.toLowerCase().startsWith('fw:') ||
                       email.headers?.['in-reply-to'] !== undefined;

  // Check for unsubscribe
  const hasUnsubscribeLink = lowerText.includes('unsubscribe') ||
                             html.toLowerCase().includes('list-unsubscribe');

  return {
    urgencyScore: calculateKeywordScore(lowerText, URGENCY_KEYWORDS),
    threatLanguageScore: calculateKeywordScore(lowerText, THREAT_KEYWORDS),
    grammarScore: calculateGrammarScore(text),
    sentimentScore: calculateSentimentScore(lowerText),

    linkCount: uniqueUrls.length,
    externalLinkRatio: calculateExternalLinkRatio(uniqueUrls, senderDomain),
    shortenerLinkCount: shortenerCount,
    formActionCount: formActions,
    hiddenElementCount: hiddenInputs,

    senderReputationScore: 50, // Default - would be set by reputation service
    domainAge: 365, // Default - would be looked up
    isFreemailProvider,
    displayNameMismatch,

    attachmentRiskScore: calculateAttachmentRisk(email.attachments),
    hasPasswordProtectedAttachment: checkPasswordProtectedAttachments(email.attachments),
    imageToTextRatio,

    isReplyChain,
    hasUnsubscribeLink,
    requestsPersonalInfo: PERSONAL_INFO_REQUESTS.some(k => lowerText.includes(k)),
    requestsFinancialAction: BEC_KEYWORDS.some(k => lowerText.includes(k)),
  };
}

/**
 * Calculate keyword presence score
 */
function calculateKeywordScore(text: string, keywords: string[]): number {
  let matches = 0;
  for (const keyword of keywords) {
    if (text.includes(keyword.toLowerCase())) {
      matches++;
    }
  }
  return Math.min(100, (matches / keywords.length) * 200);
}

/**
 * Simple grammar score based on common errors
 */
function calculateGrammarScore(text: string): number {
  const issues: string[] = [];

  // Check for excessive caps
  const capsRatio = (text.match(/[A-Z]/g) || []).length / Math.max(text.length, 1);
  if (capsRatio > 0.3) issues.push('excessive_caps');

  // Check for multiple exclamation/question marks
  if (/[!?]{2,}/.test(text)) issues.push('multiple_punctuation');

  // Check for common spam patterns
  if (/\$\d+/.test(text) && /free|win|won|prize/i.test(text)) {
    issues.push('money_spam_pattern');
  }

  // Check for ALL CAPS words (more than 3 in a row)
  if (/\b[A-Z]{4,}\b/.test(text)) issues.push('caps_words');

  return Math.min(100, issues.length * 25);
}

/**
 * Simple sentiment analysis
 */
function calculateSentimentScore(text: string): number {
  const negativeWords = [
    'threat', 'suspend', 'terminate', 'cancel', 'urgent', 'warning',
    'alert', 'problem', 'issue', 'error', 'failed', 'denied', 'blocked',
    'illegal', 'fraud', 'scam', 'hack', 'breach', 'compromised',
  ];

  let negativeCount = 0;
  for (const word of negativeWords) {
    const regex = new RegExp(`\\b${word}\\b`, 'gi');
    negativeCount += (text.match(regex) || []).length;
  }

  return Math.min(100, negativeCount * 10);
}

/**
 * Calculate ratio of external links
 */
function calculateExternalLinkRatio(urls: string[], senderDomain: string): number {
  if (urls.length === 0) return 0;

  const externalCount = urls.filter(url => {
    try {
      const urlDomain = new URL(url).hostname;
      return !urlDomain.includes(senderDomain);
    } catch {
      return true; // Malformed URLs count as external
    }
  }).length;

  return externalCount / urls.length;
}

/**
 * Check for display name spoofing
 */
function checkDisplayNameMismatch(from: string | { address?: string; displayName?: string }): boolean {
  // Handle string format - can't check mismatch without structured data
  if (typeof from === 'string') {
    // Try to parse "Name <email>" format
    const match = from.match(/^(.+?)\s*<([^>]+)>$/);
    if (match) {
      const name = match[1].trim().toLowerCase();
      const email = match[2].toLowerCase();
      if (/@/.test(name) && name !== email) return true;
    }
    return false;
  }

  // Handle object format
  if (!from.displayName) return false;

  const name = from.displayName.toLowerCase();
  const email = (from.address || '').toLowerCase();

  // Check if display name looks like an email
  if (/@/.test(name) && name !== email) return true;

  // Check if display name contains a different domain
  const emailDomain = email.split('@')[1];
  const domainPattern = /\b[\w-]+\.(com|org|net|io|co)\b/i;
  const nameMatch = name.match(domainPattern);
  if (nameMatch && !email.includes(nameMatch[0])) return true;

  return false;
}

/**
 * Calculate attachment risk score
 */
function calculateAttachmentRisk(attachments: ParsedEmail['attachments']): number {
  if (attachments.length === 0) return 0;

  let riskScore = 0;
  const highRiskExtensions = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.msi'];
  const mediumRiskExtensions = ['.docm', '.xlsm', '.pptm', '.zip', '.rar', '.7z', '.iso', '.img'];

  for (const att of attachments) {
    const ext = att.filename.toLowerCase().split('.').pop() || '';

    if (highRiskExtensions.some(e => att.filename.toLowerCase().endsWith(e))) {
      riskScore += 50;
    } else if (mediumRiskExtensions.some(e => att.filename.toLowerCase().endsWith(e))) {
      riskScore += 25;
    }

    // Double extension trick (e.g., document.pdf.exe)
    if ((att.filename.match(/\./g) || []).length > 1) {
      riskScore += 30;
    }
  }

  return Math.min(100, riskScore);
}

/**
 * Check for password-protected attachments
 */
function checkPasswordProtectedAttachments(attachments: ParsedEmail['attachments']): boolean {
  // Would need actual file analysis - this is a placeholder
  // Check for common password-protected indicators in filename
  return attachments.some(att =>
    /password|protected|encrypted/i.test(att.filename)
  );
}

/**
 * Calculate text-based threat score
 */
function calculateTextScore(features: MLFeatures, signals: Signal[]): number {
  let score = 0;

  if (features.urgencyScore > 30) {
    score += features.urgencyScore * 0.4;
    signals.push({
      type: 'ml_urgency',
      severity: features.urgencyScore > 60 ? 'warning' : 'info',
      score: Math.round(features.urgencyScore * 0.4),
      detail: 'High urgency language detected',
    });
  }

  if (features.threatLanguageScore > 30) {
    score += features.threatLanguageScore * 0.5;
    signals.push({
      type: 'ml_threat_language',
      severity: features.threatLanguageScore > 60 ? 'critical' : 'warning',
      score: Math.round(features.threatLanguageScore * 0.5),
      detail: 'Threat/phishing language patterns detected',
    });
  }

  if (features.grammarScore > 40) {
    score += features.grammarScore * 0.3;
    signals.push({
      type: 'ml_grammar',
      severity: 'info',
      score: Math.round(features.grammarScore * 0.3),
      detail: 'Poor grammar or spam-like formatting',
    });
  }

  return score;
}

/**
 * Calculate structural threat score
 */
function calculateStructuralScore(features: MLFeatures, signals: Signal[]): number {
  let score = 0;

  if (features.shortenerLinkCount > 0) {
    score += features.shortenerLinkCount * 15;
    signals.push({
      type: 'ml_shortener',
      severity: 'warning',
      score: features.shortenerLinkCount * 15,
      detail: `${features.shortenerLinkCount} URL shortener(s) detected`,
    });
  }

  if (features.formActionCount > 0) {
    score += features.formActionCount * 20;
    signals.push({
      type: 'ml_form',
      severity: 'warning',
      score: features.formActionCount * 20,
      detail: 'Email contains form elements',
    });
  }

  if (features.hiddenElementCount > 2) {
    score += 15;
    signals.push({
      type: 'ml_hidden',
      severity: 'info',
      score: 15,
      detail: 'Multiple hidden elements detected',
    });
  }

  if (features.externalLinkRatio > 0.8 && features.linkCount > 2) {
    score += 20;
    signals.push({
      type: 'ml_external_links',
      severity: 'info',
      score: 20,
      detail: 'High ratio of external links',
    });
  }

  return Math.min(100, score);
}

/**
 * Calculate sender-based threat score
 */
function calculateSenderScore(features: MLFeatures, signals: Signal[]): number {
  let score = 0;

  if (features.displayNameMismatch) {
    score += 35;
    signals.push({
      type: 'ml_display_mismatch',
      severity: 'critical',
      score: 35,
      detail: 'Display name does not match sender email',
    });
  }

  if (features.isFreemailProvider) {
    score += 10;
    // Only add signal if combined with other suspicious features
  }

  // Domain age (would be populated by reputation service)
  if (features.domainAge < 30) {
    score += 25;
    signals.push({
      type: 'ml_new_domain',
      severity: 'warning',
      score: 25,
      detail: 'Sender domain is less than 30 days old',
    });
  }

  return Math.min(100, score);
}

/**
 * Calculate content-based threat score
 */
function calculateContentScore(features: MLFeatures, signals: Signal[]): number {
  let score = 0;

  if (features.attachmentRiskScore > 0) {
    score += features.attachmentRiskScore;
    if (features.attachmentRiskScore >= 50) {
      signals.push({
        type: 'ml_dangerous_attachment',
        severity: 'critical',
        score: features.attachmentRiskScore,
        detail: 'High-risk attachment type detected',
      });
    } else if (features.attachmentRiskScore >= 25) {
      signals.push({
        type: 'ml_risky_attachment',
        severity: 'warning',
        score: features.attachmentRiskScore,
        detail: 'Potentially risky attachment type',
      });
    }
  }

  if (features.hasPasswordProtectedAttachment) {
    score += 20;
    signals.push({
      type: 'ml_password_attachment',
      severity: 'warning',
      score: 20,
      detail: 'Password-protected attachment detected',
    });
  }

  return Math.min(100, score);
}

/**
 * Calculate behavioral threat score
 */
function calculateBehavioralScore(features: MLFeatures, signals: Signal[]): number {
  let score = 0;

  if (features.requestsPersonalInfo) {
    score += 30;
    signals.push({
      type: 'ml_personal_info_request',
      severity: 'critical',
      score: 30,
      detail: 'Email requests personal/sensitive information',
    });
  }

  if (features.requestsFinancialAction) {
    score += 35;
    signals.push({
      type: 'ml_financial_request',
      severity: 'critical',
      score: 35,
      detail: 'Email requests financial action (possible BEC)',
    });
  }

  // Legitimate indicators (reduce score)
  if (features.hasUnsubscribeLink) {
    score -= 10;
  }

  if (features.isReplyChain) {
    score -= 15; // Reply chains are less likely to be phishing
  }

  return Math.max(0, Math.min(100, score));
}

/**
 * Determine threat category based on signals
 */
function determineCategory(
  signals: Signal[],
  features: MLFeatures
): MLPrediction['category'] {
  const hasFinancialRequest = signals.some(s => s.type === 'ml_financial_request');
  const hasPersonalInfoRequest = signals.some(s => s.type === 'ml_personal_info_request');
  const hasDangerousAttachment = signals.some(s => s.type === 'ml_dangerous_attachment');
  const hasThreatLanguage = signals.some(s => s.type === 'ml_threat_language');

  if (hasDangerousAttachment) {
    return 'malware';
  }

  if (hasFinancialRequest && features.displayNameMismatch) {
    return 'bec';
  }

  if (hasThreatLanguage || hasPersonalInfoRequest) {
    return 'phishing';
  }

  const totalScore = signals.reduce((sum, s) => sum + s.score, 0);
  if (totalScore > 40) {
    return 'spam';
  }

  return 'legitimate';
}

/**
 * Calculate prediction confidence
 */
function calculateConfidence(features: MLFeatures, signals: Signal[]): number {
  // More signals = higher confidence
  const signalConfidence = Math.min(0.9, 0.5 + signals.length * 0.1);

  // Strong indicators increase confidence
  let indicatorBoost = 0;
  if (features.displayNameMismatch) indicatorBoost += 0.1;
  if (features.threatLanguageScore > 50) indicatorBoost += 0.1;
  if (features.attachmentRiskScore > 40) indicatorBoost += 0.1;

  return Math.min(0.95, signalConfidence + indicatorBoost);
}
