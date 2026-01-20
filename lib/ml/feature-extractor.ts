/**
 * ML Feature Extractor
 *
 * Extracts comprehensive features from emails for ML-based phishing detection.
 * Integrates with existing email-auth, behavioral, threat-intel, and detection modules.
 *
 * Features extracted:
 * - HeaderFeatures: SPF/DKIM/DMARC results, reply-to mismatch, received chain anomalies
 * - ContentFeatures: Urgency score, threat keywords, credential patterns, link-to-text ratio
 * - SenderFeatures: Domain age, reputation, first-time sender, cousin domain detection
 * - UrlFeatures: URL count, shortener usage, suspicious TLDs, IP-based URLs, homograph detection
 * - AttachmentFeatures: File type risk, macro presence, double extensions, encrypted files
 * - BehavioralFeatures: Communication frequency, time anomaly, BEC patterns
 */

import type { Attachment, AuthenticationResults } from '@/lib/detection/types';
import { parseAuthenticationResults } from '@/lib/detection/parser';
import { LookalikeDetector } from '@/lib/behavioral/lookalike-detector';

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Raw email input for feature extraction
 */
export interface RawEmail {
  messageId: string;
  from: {
    address: string;
    displayName?: string;
  };
  replyTo?: {
    address: string;
    displayName?: string;
  };
  to: Array<{ address: string; displayName?: string }>;
  cc?: Array<{ address: string; displayName?: string }>;
  subject: string;
  date: Date;
  headers: Record<string, string>;
  body: {
    text?: string;
    html?: string;
  };
  attachments: Attachment[];
  rawHeaders?: string;
  /** Alias for date - when the email was received */
  receivedAt?: Date;
  /** Pre-extracted URLs from the email (optional) */
  urls?: string[];
}

/**
 * Attachment information for feature extraction
 */
export interface AttachmentInfo {
  filename: string;
  contentType: string;
  size: number;
  content?: Buffer;
  hash?: string;
}

/**
 * Context for feature extraction (optional optimization hints)
 */
export interface ExtractionContext {
  /** Tenant ID for tenant-specific features */
  tenantId: string;
  /** Skip expensive async operations */
  skipAsync?: boolean;
  /** Skip domain age lookup */
  skipDomainAge?: boolean;
  /** Skip threat intel lookup */
  skipThreatIntel?: boolean;
  /** Skip behavioral analysis */
  skipBehavioral?: boolean;
  /** Known VIPs for impersonation detection */
  vipList?: Array<{ email: string; name: string; title?: string }>;
  /** Known vendors for vendor impersonation detection */
  vendorDomains?: string[];
  /** Timeout for async operations in milliseconds */
  asyncTimeoutMs?: number;
}

/**
 * Email headers for authentication parsing
 */
export interface EmailHeaders {
  'authentication-results'?: string;
  'received'?: string | string[];
  'reply-to'?: string;
  'from'?: string;
  'x-originating-ip'?: string;
  'x-sender-ip'?: string;
  'x-mailer'?: string;
  'return-path'?: string;
  [key: string]: string | string[] | undefined;
}

/**
 * Complete extracted features for ML model
 */
export interface EmailFeatures {
  header: HeaderFeatures;
  content: ContentFeatures;
  sender: SenderFeatures;
  url: UrlFeatures;
  attachment: AttachmentFeatures;
  behavioral: BehavioralFeatures;
  metadata: {
    extractedAt: Date;
    extractionTimeMs: number;
    featureVersion: string;
  };
}

/**
 * Features extracted from email headers
 */
export interface HeaderFeatures {
  // Authentication results
  spfResult: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
  spfPassed: boolean;
  dkimResult: 'pass' | 'fail' | 'neutral' | 'none' | 'temperror' | 'permerror';
  dkimPassed: boolean;
  dmarcResult: 'pass' | 'fail' | 'none';
  dmarcPassed: boolean;
  authenticationScore: number; // 0-100 composite score

  // Received header analysis
  receivedHopCount: number;
  receivedChainValid: boolean;
  hasInternalHops: boolean;
  firstExternalHop?: string;

  // Mismatch detection
  replyToMismatch: boolean;
  replyToDomainMismatch: boolean;
  displayNameEmailMismatch: boolean;
  displayNameContainsBrand: boolean;
  envelopeMismatch: boolean;

  // X-Originating-IP
  hasOriginatingIP: boolean;
  originatingIP?: string;
  originatingIPCountry?: string;
  originatingIPIsProxy: boolean;
  originatingIPIsTor: boolean;

  // Additional header anomalies
  missingMessageId: boolean;
  missingDate: boolean;
  suspiciousMailer: boolean;
  mailerName?: string;
}

/**
 * Features extracted from email content
 */
export interface ContentFeatures {
  // Urgency indicators
  urgencyWordCount: number;
  urgencyWordDensity: number;
  urgencyPhrases: string[];
  hasUrgencyIndicator: boolean;

  // Financial terminology
  financialTermCount: number;
  financialTermDensity: number;
  hasFinancialRequest: boolean;
  financialPhrases: string[];

  // Credential requests
  credentialRequestCount: number;
  hasCredentialRequest: boolean;
  credentialPhrases: string[];

  // Sentiment analysis (simple implementation)
  sentimentScore: number; // -1 (negative) to 1 (positive)
  threatLanguageScore: number; // 0-1, higher = more threatening
  hasThreateningLanguage: boolean;

  // URL analysis within content
  urlCount: number;
  suspiciousUrlRatio: number;
  hasIPUrl: boolean;
  hasDataUrl: boolean;

  // HTML/Text analysis
  hasHtml: boolean;
  hasText: boolean;
  htmlTextRatio: number;
  htmlLength: number;
  textLength: number;

  // Hidden content detection
  hasHiddenText: boolean;
  hiddenTextLength: number;
  hasZeroSizeFont: boolean;
  hasInvisibleText: boolean;

  // Obfuscation patterns
  hasObfuscatedLinks: boolean;
  hasEncodedContent: boolean;
  hasBase64Images: boolean;
  obfuscationScore: number; // 0-1

  // Grammar and style
  grammarErrorEstimate: number; // 0-1
  excessivePunctuation: boolean;
  allCapsRatio: number;

  // Subject analysis
  subjectLength: number;
  subjectHasUrgency: boolean;
  subjectAllCaps: boolean;
  subjectExcessivePunctuation: boolean;
}

/**
 * Features related to sender analysis
 */
export interface SenderFeatures {
  // First contact
  isFirstContact: boolean;
  priorContactCount: number;
  daysSinceLastContact?: number;

  // Communication frequency
  communicationFrequency: number; // emails per month
  isFrequentSender: boolean;

  // Domain analysis
  senderDomain: string;
  domainAge?: number; // days
  domainAgeRisk: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  domainReputationScore: number; // 0-100

  // Lookalike detection
  isLookalikeDomain: boolean;
  lookalikeDistance?: number;
  lookalikeSimilarity?: number;
  targetedBrand?: string;

  // VIP impersonation
  isVIPImpersonation: boolean;
  impersonatedVIP?: string;
  impersonationType?: 'display_name' | 'email_lookalike' | 'domain_lookalike';

  // Free/disposable email
  isFreeEmailProvider: boolean;
  isDisposableEmail: boolean;
  freeEmailProvider?: string;
}

/**
 * Features extracted from URLs
 */
export interface UrlFeatures {
  // Counts
  totalUrlCount: number;
  uniqueDomainCount: number;

  // Suspicious indicators
  suspiciousTldCount: number;
  suspiciousTlds: string[];
  urlShortenerCount: number;
  shortenerDomains: string[];

  // Homoglyph detection
  homoglyphUrlCount: number;
  homoglyphUrls: string[];

  // Redirect analysis
  maxRedirectDepth: number;
  avgRedirectDepth: number;

  // Malicious URL matches
  knownMaliciousCount: number;
  maliciousUrls: string[];

  // URL characteristics
  hasIPAddressUrl: boolean;
  ipAddressUrls: string[];
  hasPortInUrl: boolean;
  hasEncodedUrl: boolean;
  avgUrlLength: number;
  maxUrlLength: number;

  // Protocol analysis
  httpCount: number;
  httpsCount: number;
  httpRatio: number;
}

/**
 * Features extracted from attachments
 */
export interface AttachmentFeatures {
  // Counts and types
  fileCount: number;
  fileTypes: string[];
  uniqueExtensions: string[];
  totalSize: number;
  avgSize: number;

  // Dangerous file detection
  executableCount: number;
  executableFiles: string[];
  hasExecutable: boolean;

  scriptCount: number;
  scriptFiles: string[];
  hasScript: boolean;

  // Macro detection
  macroEnabledCount: number;
  macroFiles: string[];
  hasMacros: boolean;

  // Password protection
  passwordProtectedCount: number;
  passwordProtectedFiles: string[];
  isPasswordProtected: boolean;

  // Archive analysis
  archiveCount: number;
  archiveFiles: string[];
  maxArchiveDepth: number;
  nestedArchiveCount: number;

  // Size anomalies
  hasSizeAnomaly: boolean;
  anomalousFiles: string[];

  // Extension mismatch
  extensionMismatchCount: number;
  mismatchedFiles: string[];
  hasDoubleExtension: boolean;

  // Risk assessment
  riskScore: number; // 0-100
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Behavioral features based on communication patterns
 */
export interface BehavioralFeatures {
  // Send time anomaly
  sendTimeAnomalyScore: number; // 0-1
  isUnusualSendTime: boolean;
  sendHour: number;
  isWeekend: boolean;
  hourProbability: number;

  // Recipient pattern anomaly
  recipientAnomalyScore: number; // 0-1
  hasNewRecipients: boolean;
  newRecipientCount: number;
  hasNewDomains: boolean;
  newDomainCount: number;

  // Volume anomaly
  volumeAnomalyScore: number; // 0-1
  volumeZScore: number;
  isVolumeSpike: boolean;

  // Subject pattern deviation
  subjectDeviationScore: number; // 0-1
  isUnusualSubjectPattern: boolean;

  // Composite behavioral score
  compositeBehavioralScore: number; // 0-100
}

/**
 * Feature schema definition for documentation and validation
 */
export interface FeatureSchemaField {
  name: string;
  type: 'number' | 'boolean' | 'string' | 'string[]' | 'enum';
  description: string;
  range?: { min: number; max: number };
  enumValues?: string[];
  importance: 'high' | 'medium' | 'low';
  category: 'header' | 'content' | 'sender' | 'url' | 'attachment' | 'behavioral';
}

export interface FeatureSchema {
  version: string;
  totalFeatures: number;
  categories: {
    header: FeatureSchemaField[];
    content: FeatureSchemaField[];
    sender: FeatureSchemaField[];
    url: FeatureSchemaField[];
    attachment: FeatureSchemaField[];
    behavioral: FeatureSchemaField[];
  };
}

// ============================================================================
// Constants
// ============================================================================

const FREE_EMAIL_PROVIDERS = new Set([
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
  'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com',
  'gmx.com', 'live.com', 'msn.com', 'fastmail.com', 'mail.ru',
]);

const DISPOSABLE_EMAIL_DOMAINS = new Set([
  'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
  'throwaway.email', 'temp-mail.org', 'fakeinbox.com', 'trashmail.com',
  'sharklasers.com', 'guerrillamailblock.com', 'pokemail.net',
]);

const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', // Free TLDs
  'xyz', 'top', 'club', 'online', 'site', 'work', 'click', 'link',
  'loan', 'win', 'racing', 'review', 'stream', 'download', 'bid',
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'j.mp', 'ht.ly', 'lnkd.in', 'rebrand.ly', 'cutt.ly', 'bl.ink',
]);

const URGENCY_WORDS = [
  'urgent', 'asap', 'immediately', 'now', 'critical', 'emergency',
  'deadline', 'expire', 'suspend', 'terminate', 'action required',
  'final warning', 'last chance', 'time sensitive', 'respond immediately',
  'account will be', 'verify immediately', 'act now', 'limited time',
  'expires today', 'within 24 hours', 'before it\'s too late',
];

const FINANCIAL_TERMS = [
  'wire transfer', 'bank transfer', 'payment request', 'invoice',
  'pay immediately', 'update payment', 'billing', 'bank account',
  'gift card', 'bitcoin', 'cryptocurrency', 'western union',
  'money gram', 'bank details', 'routing number', 'account number',
  'ach transfer', 'payroll', 'direct deposit',
];

const CREDENTIAL_PATTERNS = [
  'enter password', 'verify password', 'confirm password', 'reset password',
  'enter credentials', 'verify credentials', 'login required',
  'sign in required', 'verify account', 'confirm identity',
  'ssn', 'social security', 'credit card number', 'cvv',
];

const THREAT_WORDS = [
  'suspend', 'terminate', 'close', 'block', 'disable', 'unauthorized',
  'suspicious', 'fraud', 'illegal', 'violation', 'penalty', 'legal action',
  'law enforcement', 'arrest', 'prosecution', 'fine', 'consequence',
];

const BRAND_DOMAINS = [
  'paypal.com', 'amazon.com', 'microsoft.com', 'apple.com', 'google.com',
  'facebook.com', 'netflix.com', 'bankofamerica.com', 'chase.com', 'wellsfargo.com',
  'dropbox.com', 'linkedin.com', 'twitter.com', 'instagram.com', 'adobe.com',
];

const DANGEROUS_EXTENSIONS = new Set([
  '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe',
  '.js', '.jse', '.ws', '.wsf', '.wsc', '.wsh', '.ps1', '.psm1',
  '.msi', '.msp', '.dll', '.jar', '.hta', '.cpl', '.reg',
]);

const SCRIPT_EXTENSIONS = new Set([
  '.js', '.vbs', '.vbe', '.jse', '.ws', '.wsf', '.ps1', '.py', '.pl', '.sh',
]);

const MACRO_EXTENSIONS = new Set([
  '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm',
]);

const ARCHIVE_EXTENSIONS = new Set([
  '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz',
]);

// ============================================================================
// Feature Extractor Class
// ============================================================================

export class FeatureExtractor {
  private lookalikeDetector: LookalikeDetector;
  private static readonly FEATURE_VERSION = '1.0.0';

  constructor() {
    this.lookalikeDetector = new LookalikeDetector();
  }

  /**
   * Extract all features from a raw email
   * @param email - The raw email to extract features from
   * @param context - Optional extraction context with tenant ID and optimization hints
   */
  async extractFeatures(email: RawEmail, context?: ExtractionContext | string): Promise<EmailFeatures> {
    const startTime = Date.now();

    // Handle legacy signature where tenantId was passed directly
    const extractionContext: ExtractionContext = typeof context === 'string'
      ? { tenantId: context }
      : context || { tenantId: 'default' };

    const tenantId = extractionContext.tenantId;

    // Extract URLs from content if not pre-provided
    const urls = email.urls || this.extractUrlsFromContent(email.body.html || email.body.text || '');

    // Build array of extraction promises based on context
    const extractionPromises: Promise<unknown>[] = [
      Promise.resolve(this.extractHeaderFeatures(email.headers as EmailHeaders)),
      Promise.resolve(this.extractContentFeatures(email.body.text, email.body.html, email.subject)),
    ];

    // Sender features (may include async domain age lookup)
    if (extractionContext.skipAsync && extractionContext.skipDomainAge) {
      extractionPromises.push(Promise.resolve(this.extractSenderFeaturesSync(email.from.address, email.from.displayName)));
    } else {
      extractionPromises.push(this.extractSenderFeatures(email.from.address, email.from.displayName, tenantId));
    }

    // URL features (may include async threat intel lookup)
    if (extractionContext.skipAsync && extractionContext.skipThreatIntel) {
      extractionPromises.push(Promise.resolve(this.extractUrlFeaturesSync(urls)));
    } else {
      extractionPromises.push(this.extractUrlFeatures(urls));
    }

    // Attachment features (sync)
    extractionPromises.push(Promise.resolve(this.extractAttachmentFeatures(email.attachments)));

    // Behavioral features (may require async context)
    if (extractionContext.skipAsync || extractionContext.skipBehavioral) {
      extractionPromises.push(Promise.resolve(this.extractBehavioralFeaturesSync(email)));
    } else {
      extractionPromises.push(this.extractBehavioralFeatures(email, tenantId));
    }

    const [headerFeatures, contentFeatures, senderFeatures, urlFeatures, attachmentFeatures, behavioralFeatures] = await Promise.all(extractionPromises) as [
      HeaderFeatures,
      ContentFeatures,
      SenderFeatures,
      UrlFeatures,
      AttachmentFeatures,
      BehavioralFeatures
    ];

    return {
      header: headerFeatures,
      content: contentFeatures,
      sender: senderFeatures,
      url: urlFeatures,
      attachment: attachmentFeatures,
      behavioral: behavioralFeatures,
      metadata: {
        extractedAt: new Date(),
        extractionTimeMs: Date.now() - startTime,
        featureVersion: FeatureExtractor.FEATURE_VERSION,
      },
    };
  }

  /**
   * Batch extraction for efficiency
   * Processes multiple emails in parallel with optional concurrency limit
   */
  async batchExtract(emails: RawEmail[], context?: ExtractionContext): Promise<EmailFeatures[]> {
    const concurrencyLimit = 10; // Process 10 emails at a time
    const results: EmailFeatures[] = [];

    for (let i = 0; i < emails.length; i += concurrencyLimit) {
      const batch = emails.slice(i, i + concurrencyLimit);
      const batchResults = await Promise.all(
        batch.map(email => this.extractFeatures(email, context))
      );
      results.push(...batchResults);
    }

    return results;
  }

  /**
   * Get feature schema for documentation and validation
   */
  getFeatureSchema(): FeatureSchema {
    return {
      version: FeatureExtractor.FEATURE_VERSION,
      totalFeatures: 84, // Total number of numeric features in featuresToVector
      categories: {
        header: [
          { name: 'spfResult', type: 'enum', description: 'SPF authentication result', enumValues: ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'], importance: 'high', category: 'header' },
          { name: 'dkimResult', type: 'enum', description: 'DKIM authentication result', enumValues: ['pass', 'fail', 'neutral', 'none', 'temperror', 'permerror'], importance: 'high', category: 'header' },
          { name: 'dmarcResult', type: 'enum', description: 'DMARC authentication result', enumValues: ['pass', 'fail', 'none'], importance: 'high', category: 'header' },
          { name: 'authenticationScore', type: 'number', description: 'Composite authentication score', range: { min: 0, max: 100 }, importance: 'high', category: 'header' },
          { name: 'replyToMismatch', type: 'boolean', description: 'Reply-To differs from sender', importance: 'high', category: 'header' },
          { name: 'displayNameEmailMismatch', type: 'boolean', description: 'Display name contains brand but email does not match', importance: 'high', category: 'header' },
          { name: 'envelopeMismatch', type: 'boolean', description: 'Envelope sender differs from header sender', importance: 'medium', category: 'header' },
          { name: 'receivedHopCount', type: 'number', description: 'Number of mail server hops', range: { min: 0, max: 50 }, importance: 'low', category: 'header' },
          { name: 'suspiciousMailer', type: 'boolean', description: 'X-Mailer indicates suspicious mail client', importance: 'medium', category: 'header' },
        ],
        content: [
          { name: 'urgencyWordCount', type: 'number', description: 'Count of urgency words', range: { min: 0, max: 100 }, importance: 'high', category: 'content' },
          { name: 'urgencyWordDensity', type: 'number', description: 'Density of urgency words', range: { min: 0, max: 1 }, importance: 'high', category: 'content' },
          { name: 'financialTermCount', type: 'number', description: 'Count of financial terms', range: { min: 0, max: 100 }, importance: 'high', category: 'content' },
          { name: 'hasCredentialRequest', type: 'boolean', description: 'Contains credential/login requests', importance: 'high', category: 'content' },
          { name: 'threatLanguageScore', type: 'number', description: 'Threat language intensity', range: { min: 0, max: 1 }, importance: 'high', category: 'content' },
          { name: 'sentimentScore', type: 'number', description: 'Sentiment analysis score', range: { min: -1, max: 1 }, importance: 'medium', category: 'content' },
          { name: 'hasHiddenText', type: 'boolean', description: 'Contains hidden/invisible text', importance: 'medium', category: 'content' },
          { name: 'obfuscationScore', type: 'number', description: 'Content obfuscation level', range: { min: 0, max: 1 }, importance: 'medium', category: 'content' },
        ],
        sender: [
          { name: 'isFirstContact', type: 'boolean', description: 'First email from this sender', importance: 'high', category: 'sender' },
          { name: 'domainAge', type: 'number', description: 'Domain age in days', range: { min: 0, max: 36500 }, importance: 'high', category: 'sender' },
          { name: 'domainReputationScore', type: 'number', description: 'Domain reputation score', range: { min: 0, max: 100 }, importance: 'high', category: 'sender' },
          { name: 'isLookalikeDomain', type: 'boolean', description: 'Domain is a lookalike/cousin domain', importance: 'high', category: 'sender' },
          { name: 'isVIPImpersonation', type: 'boolean', description: 'Attempting VIP/executive impersonation', importance: 'high', category: 'sender' },
          { name: 'isFreeEmailProvider', type: 'boolean', description: 'From free email provider (gmail, yahoo, etc.)', importance: 'medium', category: 'sender' },
          { name: 'isDisposableEmail', type: 'boolean', description: 'From disposable email provider', importance: 'high', category: 'sender' },
        ],
        url: [
          { name: 'totalUrlCount', type: 'number', description: 'Total URLs in email', range: { min: 0, max: 100 }, importance: 'medium', category: 'url' },
          { name: 'suspiciousTldCount', type: 'number', description: 'Count of suspicious TLDs', range: { min: 0, max: 50 }, importance: 'high', category: 'url' },
          { name: 'urlShortenerCount', type: 'number', description: 'Count of URL shorteners', range: { min: 0, max: 20 }, importance: 'high', category: 'url' },
          { name: 'homoglyphUrlCount', type: 'number', description: 'Count of URLs with homoglyph characters', range: { min: 0, max: 20 }, importance: 'high', category: 'url' },
          { name: 'hasIPAddressUrl', type: 'boolean', description: 'Contains IP-address based URLs', importance: 'high', category: 'url' },
          { name: 'knownMaliciousCount', type: 'number', description: 'Count of known malicious URLs', range: { min: 0, max: 20 }, importance: 'high', category: 'url' },
        ],
        attachment: [
          { name: 'fileCount', type: 'number', description: 'Total attachment count', range: { min: 0, max: 50 }, importance: 'medium', category: 'attachment' },
          { name: 'hasExecutable', type: 'boolean', description: 'Contains executable files', importance: 'high', category: 'attachment' },
          { name: 'hasMacros', type: 'boolean', description: 'Contains macro-enabled documents', importance: 'high', category: 'attachment' },
          { name: 'hasDoubleExtension', type: 'boolean', description: 'Files with double extensions (e.g., .pdf.exe)', importance: 'high', category: 'attachment' },
          { name: 'isPasswordProtected', type: 'boolean', description: 'Password-protected attachments', importance: 'medium', category: 'attachment' },
          { name: 'riskScore', type: 'number', description: 'Overall attachment risk score', range: { min: 0, max: 100 }, importance: 'high', category: 'attachment' },
        ],
        behavioral: [
          { name: 'sendTimeAnomalyScore', type: 'number', description: 'Send time anomaly score', range: { min: 0, max: 1 }, importance: 'medium', category: 'behavioral' },
          { name: 'recipientAnomalyScore', type: 'number', description: 'Unusual recipient pattern score', range: { min: 0, max: 1 }, importance: 'medium', category: 'behavioral' },
          { name: 'volumeAnomalyScore', type: 'number', description: 'Email volume anomaly score', range: { min: 0, max: 1 }, importance: 'medium', category: 'behavioral' },
          { name: 'compositeBehavioralScore', type: 'number', description: 'Combined behavioral score', range: { min: 0, max: 100 }, importance: 'high', category: 'behavioral' },
        ],
      },
    };
  }

  /**
   * Synchronous sender feature extraction (without async lookups)
   */
  private extractSenderFeaturesSync(fromAddress: string, displayName?: string): SenderFeatures {
    const senderDomain = fromAddress.split('@')[1]?.toLowerCase() || '';
    const isFreeEmailProvider = FREE_EMAIL_PROVIDERS.has(senderDomain);
    const isDisposableEmail = DISPOSABLE_EMAIL_DOMAINS.has(senderDomain);

    return {
      isFirstContact: true, // Default to true without context
      priorContactCount: 0,
      daysSinceLastContact: undefined,
      communicationFrequency: 0,
      isFrequentSender: false,
      senderDomain,
      domainAge: undefined,
      domainAgeRisk: 'unknown',
      domainReputationScore: 50,
      isLookalikeDomain: false,
      lookalikeDistance: undefined,
      lookalikeSimilarity: undefined,
      targetedBrand: undefined,
      isVIPImpersonation: false,
      impersonatedVIP: undefined,
      impersonationType: undefined,
      isFreeEmailProvider,
      isDisposableEmail,
      freeEmailProvider: isFreeEmailProvider ? senderDomain : undefined,
    };
  }

  /**
   * Synchronous URL feature extraction (without threat intel lookup)
   */
  private extractUrlFeaturesSync(urls: string[]): UrlFeatures {
    const uniqueUrls = [...new Set(urls)];
    const domains = new Set<string>();
    const suspiciousTlds: string[] = [];
    const shortenerDomains: string[] = [];
    const homoglyphUrls: string[] = [];
    const ipAddressUrls: string[] = [];

    let httpCount = 0;
    let httpsCount = 0;
    let totalLength = 0;
    let maxLength = 0;
    let hasPortInUrl = false;
    let hasEncodedUrl = false;

    for (const url of uniqueUrls) {
      try {
        const parsed = new URL(url);
        const hostname = parsed.hostname.toLowerCase();
        domains.add(hostname);

        if (parsed.protocol === 'http:') httpCount++;
        if (parsed.protocol === 'https:') httpsCount++;

        const tld = hostname.split('.').pop() || '';
        if (SUSPICIOUS_TLDS.has(tld)) {
          suspiciousTlds.push(tld);
        }

        if (URL_SHORTENERS.has(hostname) || URL_SHORTENERS.has(hostname.replace('www.', ''))) {
          shortenerDomains.push(hostname);
        }

        if (this.isIPAddressUrl(url)) {
          ipAddressUrls.push(url);
        }

        if (parsed.port) {
          hasPortInUrl = true;
        }

        if (url.includes('%') || url.includes('&#')) {
          hasEncodedUrl = true;
        }

        if (this.checkUrlHomoglyph(hostname).hasHomoglyph) {
          homoglyphUrls.push(url);
        }

        totalLength += url.length;
        maxLength = Math.max(maxLength, url.length);
      } catch {
        // Invalid URL
      }
    }

    const avgUrlLength = uniqueUrls.length > 0 ? totalLength / uniqueUrls.length : 0;
    const totalUrlCount = uniqueUrls.length;
    const httpRatio = totalUrlCount > 0 ? httpCount / totalUrlCount : 0;

    return {
      totalUrlCount,
      uniqueDomainCount: domains.size,
      suspiciousTldCount: suspiciousTlds.length,
      suspiciousTlds: [...new Set(suspiciousTlds)],
      urlShortenerCount: shortenerDomains.length,
      shortenerDomains: [...new Set(shortenerDomains)],
      homoglyphUrlCount: homoglyphUrls.length,
      homoglyphUrls,
      maxRedirectDepth: 0,
      avgRedirectDepth: 0,
      knownMaliciousCount: 0, // Cannot determine without threat intel
      maliciousUrls: [],
      hasIPAddressUrl: ipAddressUrls.length > 0,
      ipAddressUrls,
      hasPortInUrl,
      hasEncodedUrl,
      avgUrlLength,
      maxUrlLength: maxLength,
      httpCount,
      httpsCount,
      httpRatio,
    };
  }

  /**
   * Synchronous behavioral feature extraction (without context lookup)
   */
  private extractBehavioralFeaturesSync(email: RawEmail): BehavioralFeatures {
    const sendTime = email.date || email.receivedAt || new Date();
    const sendHour = sendTime.getHours();
    const dayOfWeek = sendTime.getDay();
    const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;

    // Estimate time anomaly based on typical business hours
    const businessHours = [9, 10, 11, 12, 13, 14, 15, 16, 17];
    let sendTimeAnomalyScore = 0;
    let hourProbability = 0.0416; // 1/24 uniform distribution

    if (!businessHours.includes(sendHour) || isWeekend) {
      sendTimeAnomalyScore = 0.5;
      hourProbability = 0.01;
    }

    return {
      sendTimeAnomalyScore,
      isUnusualSendTime: sendTimeAnomalyScore > 0.5,
      sendHour,
      isWeekend,
      hourProbability,
      recipientAnomalyScore: 0,
      hasNewRecipients: false,
      newRecipientCount: 0,
      hasNewDomains: false,
      newDomainCount: 0,
      volumeAnomalyScore: 0,
      volumeZScore: 0,
      isVolumeSpike: false,
      subjectDeviationScore: 0,
      isUnusualSubjectPattern: false,
      compositeBehavioralScore: Math.round(sendTimeAnomalyScore * 15),
    };
  }

  /**
   * Extract features from email headers
   */
  extractHeaderFeatures(headers: EmailHeaders): HeaderFeatures {
    // Parse authentication results
    const authResults = parseAuthenticationResults(headers['authentication-results'] || '');

    const spfPassed = authResults.spf.result === 'pass';
    const dkimPassed = authResults.dkim.result === 'pass';
    const dmarcPassed = authResults.dmarc.result === 'pass';

    // Calculate authentication score
    let authScore = 0;
    if (spfPassed) authScore += 30;
    if (dkimPassed) authScore += 30;
    if (dmarcPassed) authScore += 40;

    // Parse received headers
    const receivedHeaders = this.parseReceivedHeaders(headers['received']);

    // Check for reply-to mismatch
    const fromAddress = this.parseEmailFromHeader(headers['from'] || '');
    const replyToAddress = this.parseEmailFromHeader(headers['reply-to'] || '');
    const fromDomain = fromAddress.split('@')[1]?.toLowerCase() || '';
    const replyToDomain = replyToAddress.split('@')[1]?.toLowerCase() || '';

    const replyToMismatch = !!(replyToAddress && replyToAddress !== fromAddress);
    const replyToDomainMismatch = !!(replyToAddress && replyToDomain !== fromDomain);

    // Check display name vs email mismatch
    const { displayNameEmailMismatch, displayNameContainsBrand } = this.analyzeDisplayName(
      headers['from'] || ''
    );

    // Parse X-Originating-IP
    const originatingIP = headers['x-originating-ip'] || headers['x-sender-ip'];
    const cleanIP = originatingIP ? this.cleanIPAddress(originatingIP) : undefined;

    // Check for suspicious mailer
    const mailerName = headers['x-mailer'];
    const suspiciousMailer = this.isSuspiciousMailer(mailerName);

    return {
      spfResult: authResults.spf.result as HeaderFeatures['spfResult'],
      spfPassed,
      dkimResult: authResults.dkim.result as HeaderFeatures['dkimResult'],
      dkimPassed,
      dmarcResult: authResults.dmarc.result as HeaderFeatures['dmarcResult'],
      dmarcPassed,
      authenticationScore: authScore,

      receivedHopCount: receivedHeaders.hopCount,
      receivedChainValid: receivedHeaders.isValid,
      hasInternalHops: receivedHeaders.hasInternalHops,
      firstExternalHop: receivedHeaders.firstExternalHop,

      replyToMismatch,
      replyToDomainMismatch,
      displayNameEmailMismatch,
      displayNameContainsBrand,
      envelopeMismatch: this.checkEnvelopeMismatch(headers),

      hasOriginatingIP: !!cleanIP,
      originatingIP: cleanIP,
      originatingIPCountry: undefined, // Would require GeoIP lookup
      originatingIPIsProxy: false, // Would require IP intelligence
      originatingIPIsTor: false, // Would require Tor exit node list

      missingMessageId: !headers['message-id'],
      missingDate: !headers['date'],
      suspiciousMailer,
      mailerName: typeof mailerName === 'string' ? mailerName : undefined,
    };
  }

  /**
   * Extract features from email content
   */
  extractContentFeatures(body?: string, html?: string, subject?: string): ContentFeatures {
    const text = body || this.stripHtml(html || '');
    const fullContent = `${subject || ''} ${text}`;
    const lowerContent = fullContent.toLowerCase();

    // Urgency analysis
    const urgencyMatches = this.findPatternMatches(lowerContent, URGENCY_WORDS);
    const urgencyWordCount = urgencyMatches.length;
    const wordCount = text.split(/\s+/).filter(w => w.length > 0).length || 1;
    const urgencyWordDensity = urgencyWordCount / wordCount;

    // Financial terminology
    const financialMatches = this.findPatternMatches(lowerContent, FINANCIAL_TERMS);
    const financialTermCount = financialMatches.length;
    const financialTermDensity = financialTermCount / wordCount;

    // Credential requests
    const credentialMatches = this.findPatternMatches(lowerContent, CREDENTIAL_PATTERNS);
    const credentialRequestCount = credentialMatches.length;

    // Threat language analysis
    const threatMatches = this.findPatternMatches(lowerContent, THREAT_WORDS);
    const threatLanguageScore = Math.min(threatMatches.length / 5, 1);

    // Simple sentiment score (negative words reduce score)
    const sentimentScore = this.calculateSentimentScore(lowerContent);

    // URL analysis within content
    const urls = this.extractUrlsFromContent(html || text);
    const suspiciousUrls = urls.filter(url => this.isUrlSuspicious(url));
    const hasIPUrl = urls.some(url => this.isIPAddressUrl(url));
    const hasDataUrl = urls.some(url => url.startsWith('data:'));

    // HTML/Text analysis
    const htmlLength = html?.length || 0;
    const textLength = text.length;
    const htmlTextRatio = textLength > 0 ? htmlLength / textLength : 0;

    // Hidden content detection
    const hiddenTextAnalysis = this.analyzeHiddenContent(html || '');

    // Obfuscation patterns
    const obfuscationAnalysis = this.analyzeObfuscation(html || '', text);

    // Grammar and style
    const excessivePunctuation = this.hasExcessivePunctuation(text);
    const allCapsRatio = this.calculateAllCapsRatio(text);
    const grammarErrorEstimate = this.estimateGrammarErrors(text);

    // Subject analysis
    const subjectAnalysis = this.analyzeSubject(subject || '');

    return {
      urgencyWordCount,
      urgencyWordDensity,
      urgencyPhrases: urgencyMatches.slice(0, 10),
      hasUrgencyIndicator: urgencyWordCount >= 2,

      financialTermCount,
      financialTermDensity,
      hasFinancialRequest: financialTermCount > 0,
      financialPhrases: financialMatches.slice(0, 10),

      credentialRequestCount,
      hasCredentialRequest: credentialRequestCount > 0,
      credentialPhrases: credentialMatches.slice(0, 10),

      sentimentScore,
      threatLanguageScore,
      hasThreateningLanguage: threatMatches.length >= 2,

      urlCount: urls.length,
      suspiciousUrlRatio: urls.length > 0 ? suspiciousUrls.length / urls.length : 0,
      hasIPUrl,
      hasDataUrl,

      hasHtml: !!html,
      hasText: !!body,
      htmlTextRatio,
      htmlLength,
      textLength,

      hasHiddenText: hiddenTextAnalysis.hasHidden,
      hiddenTextLength: hiddenTextAnalysis.hiddenLength,
      hasZeroSizeFont: hiddenTextAnalysis.hasZeroSizeFont,
      hasInvisibleText: hiddenTextAnalysis.hasInvisible,

      hasObfuscatedLinks: obfuscationAnalysis.hasObfuscatedLinks,
      hasEncodedContent: obfuscationAnalysis.hasEncoded,
      hasBase64Images: obfuscationAnalysis.hasBase64Images,
      obfuscationScore: obfuscationAnalysis.score,

      grammarErrorEstimate,
      excessivePunctuation,
      allCapsRatio,

      subjectLength: subject?.length || 0,
      subjectHasUrgency: subjectAnalysis.hasUrgency,
      subjectAllCaps: subjectAnalysis.isAllCaps,
      subjectExcessivePunctuation: subjectAnalysis.hasExcessivePunctuation,
    };
  }

  /**
   * Extract sender-related features
   */
  async extractSenderFeatures(
    fromAddress: string,
    displayName: string | undefined,
    tenantId: string
  ): Promise<SenderFeatures> {
    const senderDomain = fromAddress.split('@')[1]?.toLowerCase() || '';

    // Check for free/disposable email
    const isFreeEmailProvider = FREE_EMAIL_PROVIDERS.has(senderDomain);
    const isDisposableEmail = DISPOSABLE_EMAIL_DOMAINS.has(senderDomain);

    // Get domain age and reputation (async operations)
    let domainAge: number | undefined;
    let domainAgeRisk: SenderFeatures['domainAgeRisk'] = 'unknown';
    let domainReputationScore = 50;

    try {
      const { checkDomainAge } = await import('@/lib/threat-intel/domain/age');
      const ageResult = await checkDomainAge(senderDomain);
      domainAge = ageResult.ageInDays ?? undefined;
      domainAgeRisk = ageResult.riskLevel;
      domainReputationScore = Math.round((1 - ageResult.riskScore) * 100);
    } catch {
      // Domain age check unavailable
    }

    // Check for lookalike domains
    const lookalikeResult = await this.checkLookalikeDomain(senderDomain, displayName);

    // Check for VIP impersonation
    const vipResult = await this.checkVIPImpersonation(fromAddress, displayName, tenantId);

    // Check contact history (would integrate with FirstContactDetector)
    let isFirstContact = true;
    let priorContactCount = 0;
    let communicationFrequency = 0;

    try {
      const { FirstContactDetector } = await import('@/lib/behavioral/first-contact');
      const detector = new FirstContactDetector();
      // Would need actual tenant data to check contact history
      // For now, return conservative defaults
    } catch {
      // First contact detection unavailable
    }

    return {
      isFirstContact,
      priorContactCount,
      daysSinceLastContact: undefined,

      communicationFrequency,
      isFrequentSender: communicationFrequency > 10,

      senderDomain,
      domainAge,
      domainAgeRisk,
      domainReputationScore,

      isLookalikeDomain: lookalikeResult.isLookalike,
      lookalikeDistance: lookalikeResult.distance,
      lookalikeSimilarity: lookalikeResult.similarity,
      targetedBrand: lookalikeResult.targetedBrand,

      isVIPImpersonation: vipResult.isImpersonation,
      impersonatedVIP: vipResult.impersonatedVIP,
      impersonationType: vipResult.impersonationType,

      isFreeEmailProvider,
      isDisposableEmail,
      freeEmailProvider: isFreeEmailProvider ? senderDomain : undefined,
    };
  }

  /**
   * Extract URL-related features
   */
  async extractUrlFeatures(urls: string[]): Promise<UrlFeatures> {
    const uniqueUrls = [...new Set(urls)];
    const domains = new Set<string>();
    const suspiciousTlds: string[] = [];
    const shortenerDomains: string[] = [];
    const homoglyphUrls: string[] = [];
    const maliciousUrls: string[] = [];
    const ipAddressUrls: string[] = [];

    let httpCount = 0;
    let httpsCount = 0;
    let totalLength = 0;
    let maxLength = 0;
    let hasPortInUrl = false;
    let hasEncodedUrl = false;

    for (const url of uniqueUrls) {
      try {
        const parsed = new URL(url);
        const hostname = parsed.hostname.toLowerCase();
        domains.add(hostname);

        // Protocol analysis
        if (parsed.protocol === 'http:') httpCount++;
        if (parsed.protocol === 'https:') httpsCount++;

        // TLD analysis
        const tld = hostname.split('.').pop() || '';
        if (SUSPICIOUS_TLDS.has(tld)) {
          suspiciousTlds.push(tld);
        }

        // URL shortener detection
        if (URL_SHORTENERS.has(hostname) || URL_SHORTENERS.has(hostname.replace('www.', ''))) {
          shortenerDomains.push(hostname);
        }

        // IP address URL detection
        if (this.isIPAddressUrl(url)) {
          ipAddressUrls.push(url);
        }

        // Port detection
        if (parsed.port) {
          hasPortInUrl = true;
        }

        // Encoding detection
        if (url.includes('%') || url.includes('&#')) {
          hasEncodedUrl = true;
        }

        // Homoglyph detection
        const homoglyphResult = this.checkUrlHomoglyph(hostname);
        if (homoglyphResult.hasHomoglyph) {
          homoglyphUrls.push(url);
        }

        // URL length
        totalLength += url.length;
        maxLength = Math.max(maxLength, url.length);
      } catch {
        // Invalid URL
      }
    }

    // Check for known malicious URLs (would integrate with threat intel)
    try {
      const { checkUrlReputation } = await import('@/lib/threat-intel/feeds');
      for (const url of uniqueUrls.slice(0, 10)) { // Limit to first 10
        const result = await checkUrlReputation(url);
        if (result.isThreat) {
          maliciousUrls.push(url);
        }
      }
    } catch {
      // Threat intel unavailable
    }

    const avgUrlLength = uniqueUrls.length > 0 ? totalLength / uniqueUrls.length : 0;
    const totalUrlCount = uniqueUrls.length;
    const httpRatio = totalUrlCount > 0 ? httpCount / totalUrlCount : 0;

    return {
      totalUrlCount,
      uniqueDomainCount: domains.size,

      suspiciousTldCount: suspiciousTlds.length,
      suspiciousTlds: [...new Set(suspiciousTlds)],
      urlShortenerCount: shortenerDomains.length,
      shortenerDomains: [...new Set(shortenerDomains)],

      homoglyphUrlCount: homoglyphUrls.length,
      homoglyphUrls,

      maxRedirectDepth: 0, // Would require actual URL following
      avgRedirectDepth: 0,

      knownMaliciousCount: maliciousUrls.length,
      maliciousUrls,

      hasIPAddressUrl: ipAddressUrls.length > 0,
      ipAddressUrls,
      hasPortInUrl,
      hasEncodedUrl,
      avgUrlLength,
      maxUrlLength: maxLength,

      httpCount,
      httpsCount,
      httpRatio,
    };
  }

  /**
   * Extract attachment-related features
   */
  extractAttachmentFeatures(attachments: Attachment[]): AttachmentFeatures {
    const fileTypes: string[] = [];
    const uniqueExtensions = new Set<string>();
    const executableFiles: string[] = [];
    const scriptFiles: string[] = [];
    const macroFiles: string[] = [];
    const passwordProtectedFiles: string[] = [];
    const archiveFiles: string[] = [];
    const anomalousFiles: string[] = [];
    const mismatchedFiles: string[] = [];

    let totalSize = 0;
    let maxArchiveDepth = 0;
    let hasDoubleExtension = false;

    for (const attachment of attachments) {
      const filename = attachment.filename.toLowerCase();
      const extension = this.getExtension(filename);
      const contentType = attachment.contentType.toLowerCase();

      fileTypes.push(contentType);
      if (extension) uniqueExtensions.add(extension);
      totalSize += attachment.size;

      // Executable detection
      if (DANGEROUS_EXTENSIONS.has(extension)) {
        executableFiles.push(attachment.filename);
      }

      // Script detection
      if (SCRIPT_EXTENSIONS.has(extension)) {
        scriptFiles.push(attachment.filename);
      }

      // Macro detection
      if (MACRO_EXTENSIONS.has(extension)) {
        macroFiles.push(attachment.filename);
      }

      // Archive detection
      if (ARCHIVE_EXTENSIONS.has(extension)) {
        archiveFiles.push(attachment.filename);
      }

      // Double extension detection
      if (this.hasDoubleExtension(filename)) {
        hasDoubleExtension = true;
        mismatchedFiles.push(attachment.filename);
      }

      // Size anomaly detection
      if (this.hasSizeAnomaly(attachment.size, extension, contentType)) {
        anomalousFiles.push(attachment.filename);
      }

      // Extension/content-type mismatch
      if (this.hasExtensionMismatch(extension, contentType)) {
        mismatchedFiles.push(attachment.filename);
      }
    }

    // Calculate risk score
    let riskScore = 0;
    if (executableFiles.length > 0) riskScore += 50;
    if (scriptFiles.length > 0) riskScore += 40;
    if (macroFiles.length > 0) riskScore += 30;
    if (passwordProtectedFiles.length > 0) riskScore += 20;
    if (hasDoubleExtension) riskScore += 40;
    if (anomalousFiles.length > 0) riskScore += 15;
    if (mismatchedFiles.length > 0) riskScore += 25;
    riskScore = Math.min(100, riskScore);

    const riskLevel = this.getRiskLevel(riskScore);
    const avgSize = attachments.length > 0 ? totalSize / attachments.length : 0;

    return {
      fileCount: attachments.length,
      fileTypes,
      uniqueExtensions: [...uniqueExtensions],
      totalSize,
      avgSize,

      executableCount: executableFiles.length,
      executableFiles,
      hasExecutable: executableFiles.length > 0,

      scriptCount: scriptFiles.length,
      scriptFiles,
      hasScript: scriptFiles.length > 0,

      macroEnabledCount: macroFiles.length,
      macroFiles,
      hasMacros: macroFiles.length > 0,

      passwordProtectedCount: passwordProtectedFiles.length,
      passwordProtectedFiles,
      isPasswordProtected: passwordProtectedFiles.length > 0,

      archiveCount: archiveFiles.length,
      archiveFiles,
      maxArchiveDepth,
      nestedArchiveCount: 0, // Would require archive inspection

      hasSizeAnomaly: anomalousFiles.length > 0,
      anomalousFiles,

      extensionMismatchCount: mismatchedFiles.length,
      mismatchedFiles: [...new Set(mismatchedFiles)],
      hasDoubleExtension,

      riskScore,
      riskLevel,
    };
  }

  /**
   * Extract behavioral features based on communication patterns
   */
  async extractBehavioralFeatures(email: RawEmail, tenantId: string): Promise<BehavioralFeatures> {
    const sendTime = email.date;
    const sendHour = sendTime.getHours();
    const dayOfWeek = sendTime.getDay();
    const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;

    // Default values when behavioral data unavailable
    let sendTimeAnomalyScore = 0;
    let hourProbability = 0.0416; // 1/24 uniform distribution
    let recipientAnomalyScore = 0;
    let newRecipientCount = 0;
    let newDomainCount = 0;
    let volumeAnomalyScore = 0;
    let volumeZScore = 0;
    let subjectDeviationScore = 0;

    try {
      // Try to get behavioral analysis from AnomalyDetector
      const { AnomalyDetector } = await import('@/lib/behavioral/anomaly-engine');
      const detector = new AnomalyDetector({ tenantId });

      // Would need actual baseline data - for now return estimates
      // In production, this would query stored baselines
    } catch {
      // Behavioral analysis unavailable
    }

    // Estimate time anomaly based on typical business hours
    const businessHours = [9, 10, 11, 12, 13, 14, 15, 16, 17];
    if (!businessHours.includes(sendHour) || isWeekend) {
      sendTimeAnomalyScore = 0.5;
      hourProbability = 0.01;
    }

    // Calculate composite score
    const compositeBehavioralScore = Math.round(
      (sendTimeAnomalyScore * 15 +
       recipientAnomalyScore * 30 +
       volumeAnomalyScore * 35 +
       subjectDeviationScore * 20)
    );

    return {
      sendTimeAnomalyScore,
      isUnusualSendTime: sendTimeAnomalyScore > 0.5,
      sendHour,
      isWeekend,
      hourProbability,

      recipientAnomalyScore,
      hasNewRecipients: newRecipientCount > 0,
      newRecipientCount,
      hasNewDomains: newDomainCount > 0,
      newDomainCount,

      volumeAnomalyScore,
      volumeZScore,
      isVolumeSpike: volumeZScore > 3,

      subjectDeviationScore,
      isUnusualSubjectPattern: subjectDeviationScore > 0.5,

      compositeBehavioralScore,
    };
  }

  // ============================================================================
  // Helper Methods
  // ============================================================================

  private parseReceivedHeaders(received: string | string[] | undefined): {
    hopCount: number;
    isValid: boolean;
    hasInternalHops: boolean;
    firstExternalHop?: string;
  } {
    const headers = Array.isArray(received) ? received : received ? [received] : [];

    return {
      hopCount: headers.length,
      isValid: headers.length > 0,
      hasInternalHops: headers.some(h => h.includes('internal') || h.includes('localhost')),
      firstExternalHop: headers.length > 0 ? headers[headers.length - 1] : undefined,
    };
  }

  private parseEmailFromHeader(header: string): string {
    const match = header.match(/<([^>]+)>/);
    return match ? match[1].toLowerCase() : header.toLowerCase();
  }

  private analyzeDisplayName(fromHeader: string): {
    displayNameEmailMismatch: boolean;
    displayNameContainsBrand: boolean;
  } {
    const displayNameMatch = fromHeader.match(/^"?([^"<]+)"?\s*</);
    const displayName = displayNameMatch ? displayNameMatch[1].trim().toLowerCase() : '';
    const emailMatch = fromHeader.match(/<([^>]+)>/);
    const email = emailMatch ? emailMatch[1].toLowerCase() : '';
    const emailDomain = email.split('@')[1] || '';

    let displayNameEmailMismatch = false;
    let displayNameContainsBrand = false;

    // Check if display name contains a brand that doesn't match email domain
    for (const brand of BRAND_DOMAINS) {
      const brandName = brand.split('.')[0];
      if (displayName.includes(brandName) && !emailDomain.includes(brandName)) {
        displayNameEmailMismatch = true;
        displayNameContainsBrand = true;
        break;
      }
    }

    return { displayNameEmailMismatch, displayNameContainsBrand };
  }

  private checkEnvelopeMismatch(headers: EmailHeaders): boolean {
    const from = this.parseEmailFromHeader(headers['from'] || '');
    const returnPath = this.parseEmailFromHeader(headers['return-path'] || '');

    if (!returnPath || !from) return false;

    const fromDomain = from.split('@')[1];
    const returnPathDomain = returnPath.split('@')[1];

    return fromDomain !== returnPathDomain;
  }

  private cleanIPAddress(ip: string): string {
    // Remove brackets and whitespace
    return ip.replace(/[\[\]\s]/g, '');
  }

  private isSuspiciousMailer(mailer: string | string[] | undefined): boolean {
    if (!mailer || Array.isArray(mailer)) return false;
    const lowerMailer = mailer.toLowerCase();

    const suspiciousPatterns = [
      'php', 'phpmailer', 'mass mailer', 'bulk mailer',
      'python', 'script', 'anonymous',
    ];

    return suspiciousPatterns.some(p => lowerMailer.includes(p));
  }

  private stripHtml(html: string): string {
    return html
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/g, ' ')
      .replace(/&[a-z]+;/gi, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  private findPatternMatches(content: string, patterns: string[]): string[] {
    const matches: string[] = [];
    for (const pattern of patterns) {
      if (content.includes(pattern.toLowerCase())) {
        matches.push(pattern);
      }
    }
    return matches;
  }

  private calculateSentimentScore(content: string): number {
    const negativeWords = ['suspend', 'terminate', 'urgent', 'warning', 'expired', 'blocked'];
    const positiveWords = ['thank', 'appreciate', 'congratulations', 'welcome'];

    let score = 0;
    for (const word of negativeWords) {
      if (content.includes(word)) score -= 0.2;
    }
    for (const word of positiveWords) {
      if (content.includes(word)) score += 0.2;
    }

    return Math.max(-1, Math.min(1, score));
  }

  private extractUrlsFromContent(content: string): string[] {
    const urlRegex = /https?:\/\/[^\s<>"']+/gi;
    const matches = content.match(urlRegex) || [];
    return [...new Set(matches)];
  }

  private isUrlSuspicious(url: string): boolean {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();

      // Check for IP address
      if (this.isIPAddressUrl(url)) return true;

      // Check for suspicious TLD
      const tld = hostname.split('.').pop() || '';
      if (SUSPICIOUS_TLDS.has(tld)) return true;

      // Check for excessive subdomains
      if (hostname.split('.').length > 4) return true;

      // Check for URL shortener
      if (URL_SHORTENERS.has(hostname)) return true;

      return false;
    } catch {
      return true; // Invalid URL is suspicious
    }
  }

  private isIPAddressUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parsed.hostname);
    } catch {
      return false;
    }
  }

  private analyzeHiddenContent(html: string): {
    hasHidden: boolean;
    hiddenLength: number;
    hasZeroSizeFont: boolean;
    hasInvisible: boolean;
  } {
    const hasZeroSizeFont = /font-size:\s*0/i.test(html);
    const hasInvisible = /display:\s*none|visibility:\s*hidden|color:\s*#fff\s*;.*background:\s*#fff/i.test(html);
    const hasHidden = hasZeroSizeFont || hasInvisible;

    // Estimate hidden content length
    let hiddenLength = 0;
    const hiddenMatches = html.match(/<[^>]*style="[^"]*(?:display:\s*none|visibility:\s*hidden)[^"]*"[^>]*>([^<]*)</gi);
    if (hiddenMatches) {
      hiddenLength = hiddenMatches.reduce((sum, m) => sum + m.length, 0);
    }

    return { hasHidden, hiddenLength, hasZeroSizeFont, hasInvisible };
  }

  private analyzeObfuscation(html: string, text: string): {
    hasObfuscatedLinks: boolean;
    hasEncoded: boolean;
    hasBase64Images: boolean;
    score: number;
  } {
    const hasObfuscatedLinks = /<a[^>]+href="[^"]*javascript:/i.test(html) ||
                               /<a[^>]+href="[^"]*data:/i.test(html);
    const hasEncoded = /&#\d+;/.test(html) || /%[0-9A-F]{2}/i.test(html);
    const hasBase64Images = /src="data:image\/[^;]+;base64,/i.test(html);

    let score = 0;
    if (hasObfuscatedLinks) score += 0.4;
    if (hasEncoded) score += 0.2;
    if (hasBase64Images) score += 0.2;

    return { hasObfuscatedLinks, hasEncoded, hasBase64Images, score };
  }

  private hasExcessivePunctuation(text: string): boolean {
    const punctuationCount = (text.match(/[!?]{2,}/g) || []).length;
    return punctuationCount > 2;
  }

  private calculateAllCapsRatio(text: string): number {
    const alphaChars = text.replace(/[^a-zA-Z]/g, '');
    if (alphaChars.length === 0) return 0;

    const upperChars = alphaChars.replace(/[^A-Z]/g, '');
    return upperChars.length / alphaChars.length;
  }

  private estimateGrammarErrors(text: string): number {
    // Simple heuristics for grammar error estimation
    let score = 0;

    // Check for double spaces
    if (/\s{2,}/.test(text)) score += 0.1;

    // Check for missing capitalization after periods
    if (/\.\s+[a-z]/.test(text)) score += 0.2;

    // Check for common misspellings/errors
    const errorPatterns = [
      /\bi\b(?!\s+[A-Z])/, // lowercase "i"
      /\s,/, // space before comma
      /\s\./, // space before period
    ];

    for (const pattern of errorPatterns) {
      if (pattern.test(text)) score += 0.1;
    }

    return Math.min(1, score);
  }

  private analyzeSubject(subject: string): {
    hasUrgency: boolean;
    isAllCaps: boolean;
    hasExcessivePunctuation: boolean;
  } {
    const lowerSubject = subject.toLowerCase();
    const hasUrgency = URGENCY_WORDS.some(word => lowerSubject.includes(word));

    const alphaChars = subject.replace(/[^a-zA-Z]/g, '');
    const isAllCaps = alphaChars.length > 5 && alphaChars === alphaChars.toUpperCase();

    const hasExcessivePunctuation = /[!?]{2,}/.test(subject);

    return { hasUrgency, isAllCaps, hasExcessivePunctuation };
  }

  private async checkLookalikeDomain(domain: string, displayName?: string): Promise<{
    isLookalike: boolean;
    distance?: number;
    similarity?: number;
    targetedBrand?: string;
  }> {
    for (const brand of BRAND_DOMAINS) {
      const brandBase = brand.split('.')[0];

      // Check domain similarity
      const similarity = this.lookalikeDetector.calculateSimilarity(domain, brand);

      if (similarity > 0.8 && similarity < 1) {
        return {
          isLookalike: true,
          similarity,
          distance: this.lookalikeDetector.levenshteinDistance(domain, brand),
          targetedBrand: brand,
        };
      }

      // Check for homoglyphs
      if (this.lookalikeDetector.hasHomoglyphs(domain)) {
        const normalized = this.lookalikeDetector.normalizeHomoglyphs(domain);
        if (normalized.includes(brandBase)) {
          return {
            isLookalike: true,
            similarity: 0.95,
            targetedBrand: brand,
          };
        }
      }
    }

    return { isLookalike: false };
  }

  private async checkVIPImpersonation(
    email: string,
    displayName: string | undefined,
    tenantId: string
  ): Promise<{
    isImpersonation: boolean;
    impersonatedVIP?: string;
    impersonationType?: 'display_name' | 'email_lookalike' | 'domain_lookalike';
  }> {
    // Would integrate with VIP list from tenant configuration
    // For now, check common executive titles in display name
    if (!displayName) return { isImpersonation: false };

    const executiveTitles = ['ceo', 'cfo', 'cto', 'coo', 'president', 'director'];
    const lowerName = displayName.toLowerCase();

    for (const title of executiveTitles) {
      if (lowerName.includes(title)) {
        // If using free email with executive title, likely impersonation
        const domain = email.split('@')[1]?.toLowerCase() || '';
        if (FREE_EMAIL_PROVIDERS.has(domain)) {
          return {
            isImpersonation: true,
            impersonatedVIP: displayName,
            impersonationType: 'display_name',
          };
        }
      }
    }

    return { isImpersonation: false };
  }

  private checkUrlHomoglyph(hostname: string): { hasHomoglyph: boolean } {
    return { hasHomoglyph: this.lookalikeDetector.hasHomoglyphs(hostname) };
  }

  private getExtension(filename: string): string {
    const parts = filename.split('.');
    return parts.length > 1 ? `.${parts.pop()?.toLowerCase()}` : '';
  }

  private hasDoubleExtension(filename: string): boolean {
    const parts = filename.split('.');
    if (parts.length < 3) return false;

    const lastExt = `.${parts.pop()?.toLowerCase()}`;
    const secondLastExt = `.${parts.pop()?.toLowerCase()}`;

    return DANGEROUS_EXTENSIONS.has(secondLastExt) || SCRIPT_EXTENSIONS.has(secondLastExt);
  }

  private hasSizeAnomaly(size: number, extension: string, contentType: string): boolean {
    // Very small executable
    if (DANGEROUS_EXTENSIONS.has(extension) && size < 4096) return true;

    // Very large image
    if (contentType.startsWith('image/') && size > 50 * 1024 * 1024) return true;

    // Empty archive
    if (ARCHIVE_EXTENSIONS.has(extension) && size < 50) return true;

    return false;
  }

  private hasExtensionMismatch(extension: string, contentType: string): boolean {
    const expectedTypes: Record<string, string[]> = {
      '.pdf': ['application/pdf'],
      '.doc': ['application/msword'],
      '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
      '.xls': ['application/vnd.ms-excel'],
      '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
      '.zip': ['application/zip', 'application/x-zip-compressed'],
      '.exe': ['application/x-msdownload', 'application/x-executable'],
    };

    const expected = expectedTypes[extension];
    if (!expected) return false;

    return !expected.some(t => contentType.includes(t));
  }

  private getRiskLevel(score: number): 'safe' | 'low' | 'medium' | 'high' | 'critical' {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'safe';
  }
}

// ============================================================================
// Export singleton and convenience functions
// ============================================================================

export const featureExtractor = new FeatureExtractor();

export async function extractFeatures(email: RawEmail, tenantId: string): Promise<EmailFeatures> {
  return featureExtractor.extractFeatures(email, tenantId);
}

export function extractHeaderFeatures(headers: EmailHeaders): HeaderFeatures {
  return featureExtractor.extractHeaderFeatures(headers);
}

export function extractContentFeatures(body?: string, html?: string, subject?: string): ContentFeatures {
  return featureExtractor.extractContentFeatures(body, html, subject);
}

export async function extractSenderFeatures(
  fromAddress: string,
  displayName: string | undefined,
  tenantId: string
): Promise<SenderFeatures> {
  return featureExtractor.extractSenderFeatures(fromAddress, displayName, tenantId);
}

export async function extractUrlFeatures(urls: string[]): Promise<UrlFeatures> {
  return featureExtractor.extractUrlFeatures(urls);
}

export function extractAttachmentFeatures(attachments: Attachment[]): AttachmentFeatures {
  return featureExtractor.extractAttachmentFeatures(attachments);
}

export async function extractBehavioralFeatures(
  email: RawEmail,
  tenantId: string
): Promise<BehavioralFeatures> {
  return featureExtractor.extractBehavioralFeatures(email, tenantId);
}

/**
 * Convert extracted features to a flat numeric vector for ML models
 */
export function featuresToVector(features: EmailFeatures): number[] {
  return [
    // Header features (15 features)
    features.header.spfPassed ? 1 : 0,
    features.header.dkimPassed ? 1 : 0,
    features.header.dmarcPassed ? 1 : 0,
    features.header.authenticationScore / 100,
    features.header.receivedHopCount,
    features.header.replyToMismatch ? 1 : 0,
    features.header.replyToDomainMismatch ? 1 : 0,
    features.header.displayNameEmailMismatch ? 1 : 0,
    features.header.displayNameContainsBrand ? 1 : 0,
    features.header.envelopeMismatch ? 1 : 0,
    features.header.hasOriginatingIP ? 1 : 0,
    features.header.originatingIPIsProxy ? 1 : 0,
    features.header.originatingIPIsTor ? 1 : 0,
    features.header.missingMessageId ? 1 : 0,
    features.header.suspiciousMailer ? 1 : 0,

    // Content features (25 features)
    features.content.urgencyWordCount,
    features.content.urgencyWordDensity,
    features.content.hasUrgencyIndicator ? 1 : 0,
    features.content.financialTermCount,
    features.content.financialTermDensity,
    features.content.hasFinancialRequest ? 1 : 0,
    features.content.credentialRequestCount,
    features.content.hasCredentialRequest ? 1 : 0,
    features.content.sentimentScore,
    features.content.threatLanguageScore,
    features.content.hasThreateningLanguage ? 1 : 0,
    features.content.urlCount,
    features.content.suspiciousUrlRatio,
    features.content.hasIPUrl ? 1 : 0,
    features.content.htmlTextRatio,
    features.content.hasHiddenText ? 1 : 0,
    features.content.hasZeroSizeFont ? 1 : 0,
    features.content.hasObfuscatedLinks ? 1 : 0,
    features.content.obfuscationScore,
    features.content.grammarErrorEstimate,
    features.content.excessivePunctuation ? 1 : 0,
    features.content.allCapsRatio,
    features.content.subjectHasUrgency ? 1 : 0,
    features.content.subjectAllCaps ? 1 : 0,
    features.content.subjectExcessivePunctuation ? 1 : 0,

    // Sender features (12 features)
    features.sender.isFirstContact ? 1 : 0,
    features.sender.priorContactCount,
    features.sender.communicationFrequency,
    (features.sender.domainAge || 365) / 365, // Normalize to years
    features.sender.domainReputationScore / 100,
    features.sender.isLookalikeDomain ? 1 : 0,
    features.sender.lookalikeSimilarity || 0,
    features.sender.isVIPImpersonation ? 1 : 0,
    features.sender.isFreeEmailProvider ? 1 : 0,
    features.sender.isDisposableEmail ? 1 : 0,
    features.sender.domainAgeRisk === 'critical' ? 1 : features.sender.domainAgeRisk === 'high' ? 0.75 : features.sender.domainAgeRisk === 'medium' ? 0.5 : 0.25,
    features.sender.isFrequentSender ? 1 : 0,

    // URL features (12 features)
    features.url.totalUrlCount,
    features.url.uniqueDomainCount,
    features.url.suspiciousTldCount,
    features.url.urlShortenerCount,
    features.url.homoglyphUrlCount,
    features.url.knownMaliciousCount,
    features.url.hasIPAddressUrl ? 1 : 0,
    features.url.hasPortInUrl ? 1 : 0,
    features.url.hasEncodedUrl ? 1 : 0,
    features.url.httpRatio,
    features.url.avgUrlLength / 100, // Normalize
    features.url.maxRedirectDepth,

    // Attachment features (12 features)
    features.attachment.fileCount,
    features.attachment.hasExecutable ? 1 : 0,
    features.attachment.hasScript ? 1 : 0,
    features.attachment.hasMacros ? 1 : 0,
    features.attachment.isPasswordProtected ? 1 : 0,
    features.attachment.archiveCount,
    features.attachment.maxArchiveDepth,
    features.attachment.hasSizeAnomaly ? 1 : 0,
    features.attachment.extensionMismatchCount,
    features.attachment.hasDoubleExtension ? 1 : 0,
    features.attachment.riskScore / 100,
    features.attachment.totalSize / (1024 * 1024), // Normalize to MB

    // Behavioral features (8 features)
    features.behavioral.sendTimeAnomalyScore,
    features.behavioral.isUnusualSendTime ? 1 : 0,
    features.behavioral.hourProbability,
    features.behavioral.recipientAnomalyScore,
    features.behavioral.volumeAnomalyScore,
    features.behavioral.volumeZScore / 5, // Normalize z-score
    features.behavioral.subjectDeviationScore,
    features.behavioral.compositeBehavioralScore / 100,
  ];
}

/**
 * Get feature names for the vector (useful for model interpretation)
 */
export function getFeatureNames(): string[] {
  return [
    // Header features
    'header_spf_passed', 'header_dkim_passed', 'header_dmarc_passed',
    'header_auth_score', 'header_hop_count', 'header_reply_to_mismatch',
    'header_reply_domain_mismatch', 'header_display_email_mismatch',
    'header_display_brand', 'header_envelope_mismatch', 'header_has_origin_ip',
    'header_origin_proxy', 'header_origin_tor', 'header_missing_msgid',
    'header_suspicious_mailer',

    // Content features
    'content_urgency_count', 'content_urgency_density', 'content_has_urgency',
    'content_financial_count', 'content_financial_density', 'content_has_financial',
    'content_credential_count', 'content_has_credential', 'content_sentiment',
    'content_threat_score', 'content_has_threat', 'content_url_count',
    'content_suspicious_url_ratio', 'content_has_ip_url', 'content_html_text_ratio',
    'content_has_hidden', 'content_zero_font', 'content_obfuscated_links',
    'content_obfuscation_score', 'content_grammar_errors', 'content_excessive_punct',
    'content_caps_ratio', 'content_subject_urgency', 'content_subject_caps',
    'content_subject_punct',

    // Sender features
    'sender_first_contact', 'sender_prior_count', 'sender_frequency',
    'sender_domain_age', 'sender_reputation', 'sender_lookalike',
    'sender_lookalike_similarity', 'sender_vip_impersonation', 'sender_free_email',
    'sender_disposable', 'sender_domain_risk', 'sender_frequent',

    // URL features
    'url_total_count', 'url_unique_domains', 'url_suspicious_tld',
    'url_shortener_count', 'url_homoglyph_count', 'url_malicious_count',
    'url_has_ip', 'url_has_port', 'url_encoded', 'url_http_ratio',
    'url_avg_length', 'url_redirect_depth',

    // Attachment features
    'attach_file_count', 'attach_executable', 'attach_script', 'attach_macro',
    'attach_password', 'attach_archive_count', 'attach_archive_depth',
    'attach_size_anomaly', 'attach_ext_mismatch', 'attach_double_ext',
    'attach_risk_score', 'attach_total_size',

    // Behavioral features
    'behavior_time_anomaly', 'behavior_unusual_time', 'behavior_hour_prob',
    'behavior_recipient_anomaly', 'behavior_volume_anomaly', 'behavior_volume_zscore',
    'behavior_subject_deviation', 'behavior_composite_score',
  ];
}

/**
 * Convert extracted features to the format expected by ThreatPredictor
 * This bridges the feature extractor output to the predictor input format
 */
export function featuresToPredictorFormat(features: EmailFeatures): import('./predictor').EmailFeatures {
  return {
    headerFeatures: {
      spfScore: features.header.spfPassed ? 1 : 0,
      dkimScore: features.header.dkimPassed ? 1 : 0,
      dmarcScore: features.header.dmarcPassed ? 1 : 0,
      replyToMismatch: features.header.replyToMismatch,
      displayNameSpoof: features.header.displayNameEmailMismatch || features.header.displayNameContainsBrand,
      headerAnomalyCount: (features.header.missingMessageId ? 1 : 0) + (features.header.missingDate ? 1 : 0),
      envelopeMismatch: features.header.envelopeMismatch,
      suspiciousMailer: features.header.suspiciousMailer,
    },
    contentFeatures: {
      urgencyScore: Math.min(features.content.urgencyWordDensity * 5, 1),
      threatScore: features.content.threatLanguageScore,
      grammarScore: 1 - features.content.grammarErrorEstimate,
      sentimentScore: Math.max(0, -features.content.sentimentScore), // Convert to 0-1 negativity
      requestsPersonalInfo: features.content.hasCredentialRequest,
      requestsCredentials: features.content.hasCredentialRequest,
      hasFinancialRequest: features.content.hasFinancialRequest,
      imageToTextRatio: features.content.htmlTextRatio > 0 ? 1 / features.content.htmlTextRatio : 0,
      suspiciousKeywordCount: features.content.urgencyWordCount + features.content.financialTermCount + features.content.credentialRequestCount,
    },
    senderFeatures: {
      reputationScore: features.sender.domainReputationScore / 100,
      domainAgeDays: features.sender.domainAge ?? -1,
      isFreemailProvider: features.sender.isFreeEmailProvider,
      isDisposableEmail: features.sender.isDisposableEmail,
      domainSimilarityScore: features.sender.lookalikeSimilarity ?? 0,
      isFirstContact: features.sender.isFirstContact,
      isCousinDomain: features.sender.isLookalikeDomain,
      executiveImpersonationScore: features.sender.isVIPImpersonation ? 0.8 : 0,
    },
    urlFeatures: {
      urlCount: features.url.totalUrlCount,
      externalUrlCount: features.url.totalUrlCount, // Assume all URLs are external
      shortenerCount: features.url.urlShortenerCount,
      ipUrlCount: features.url.ipAddressUrls.length,
      maliciousUrlCount: features.url.knownMaliciousCount,
      maxUrlSuspicionScore: features.url.suspiciousTldCount > 0 || features.url.homoglyphUrlCount > 0 ? 0.7 : 0,
      hasRedirects: features.url.maxRedirectDepth > 0,
      newDomainUrlCount: 0, // Would need additional context
    },
    attachmentFeatures: {
      attachmentCount: features.attachment.fileCount,
      attachmentRiskScore: features.attachment.riskScore / 100,
      hasExecutable: features.attachment.hasExecutable,
      hasMacros: features.attachment.hasMacros,
      hasPasswordProtected: features.attachment.isPasswordProtected,
      hasDoubleExtension: features.attachment.hasDoubleExtension,
      totalSizeBytes: features.attachment.totalSize,
    },
    behavioralFeatures: {
      isReplyChain: false, // Would need email thread context
      hasUnsubscribeLink: false, // Would need content analysis
      sendHour: features.behavioral.sendHour,
      sentDuringBusinessHours: !features.behavioral.isUnusualSendTime,
      becPatternScore: features.behavioral.compositeBehavioralScore / 100,
      hasWireTransferRequest: features.content.hasFinancialRequest,
      hasGiftCardRequest: features.content.financialPhrases.some(p => p.includes('gift card')),
      hasInvoiceUpdate: features.content.financialPhrases.some(p => p.includes('invoice')),
    },
  };
}

/**
 * Batch extract and convert to predictor format
 */
export async function batchExtractForPredictor(
  emails: RawEmail[],
  context?: ExtractionContext
): Promise<import('./predictor').EmailFeatures[]> {
  const extracted = await featureExtractor.batchExtract(emails, context);
  return extracted.map(featuresToPredictorFormat);
}

/**
 * Get the feature schema for documentation
 */
export function getFeatureSchema(): FeatureSchema {
  return featureExtractor.getFeatureSchema();
}
