/**
 * Core types for the email detection engine
 */

// Email structure after parsing
export interface ParsedEmail {
  messageId: string;
  subject: string;
  from: EmailAddress;
  replyTo?: EmailAddress;
  to: EmailAddress[];
  cc?: EmailAddress[];
  bcc?: EmailAddress[];
  date: Date;
  headers: Record<string, string>;
  body: {
    text?: string;
    html?: string;
  };
  attachments: Attachment[];
  rawHeaders: string;
}

export interface EmailAddress {
  address: string;
  displayName?: string;
  domain: string;
}

export interface Attachment {
  filename: string;
  contentType: string;
  size: number;
  content?: Buffer;
  hash?: string; // SHA-256
}

// Authentication results from headers
export interface AuthenticationResults {
  spf: AuthResult;
  dkim: AuthResult;
  dmarc: AuthResult;
}

export interface AuthResult {
  result: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
  details?: string;
}

// Detection signals
export interface Signal {
  type: SignalType;
  severity: 'info' | 'warning' | 'critical';
  score: number; // 0-100 contribution to overall score
  detail: string;
  metadata?: Record<string, unknown>;
}

export type SignalType =
  // Policy
  | 'policy'
  // Authentication
  | 'spf'
  | 'dkim'
  | 'dmarc'
  // Domain analysis
  | 'domain_age'
  | 'homoglyph'
  | 'cousin_domain'
  | 'free_email_provider'
  | 'disposable_email'
  // Header anomalies
  | 'header_anomaly'
  | 'reply_to_mismatch'
  | 'display_name_spoof'
  | 'envelope_mismatch'
  // Content analysis
  | 'urgency_language'
  | 'credential_request'
  | 'financial_request'
  | 'threat_language'
  // URL analysis
  | 'suspicious_url'
  | 'url_redirect'
  | 'dangerous_url'
  | 'shortened_url'
  | 'ip_url'
  | 'tracking_url' // Phase 2: Legitimate tracking URLs
  | 'malicious_url' // Phase 2: Classified as malicious
  // Attachment analysis
  | 'dangerous_attachment'
  | 'password_protected_archive'
  | 'macro_enabled'
  | 'executable'
  // Reputation
  | 'known_bad_sender'
  | 'known_bad_domain'
  | 'known_bad_ip'
  | 'malicious_domain'
  | 'suspicious_domain'
  | 'malicious_url'
  | 'malicious_sender'
  | 'suspicious_sender'
  // ML/LLM
  | 'ml_phishing'
  | 'llm_suspicious'
  | 'llm_analysis'
  | 'llm_bec_detected'
  | 'llm_phishing_detected'
  | 'llm_bec_indicator'
  | 'llm_phishing_indicator'
  // BEC detection
  | 'bec_detected'
  | 'bec_impersonation'
  | 'bec_financial_risk'
  | 'bec_wire_transfer_request'
  | 'bec_gift_card_scam'
  | 'bec_invoice_fraud'
  | 'bec_payroll_diversion'
  | 'bec_urgency_pressure'
  | 'bec_secrecy_request'
  | 'bec_authority_manipulation'
  | 'bec_compound_attack'
  | 'bec_financial_amount'
  | 'bec_display_name_spoof'
  | 'bec_title_spoof'
  | 'bec_domain_lookalike'
  | 'bec_reply_to_mismatch'
  | 'bec_unicode_spoof'
  | 'bec_cousin_domain'
  | 'bec_free_email_executive'
  // ML classifier signals
  | 'ml_urgency'
  | 'ml_threat_language'
  | 'ml_grammar'
  | 'ml_shortener'
  | 'ml_form'
  | 'ml_hidden'
  | 'ml_external_links'
  | 'ml_display_mismatch'
  | 'ml_new_domain'
  | 'ml_dangerous_attachment'
  | 'ml_risky_attachment'
  | 'ml_password_attachment'
  | 'ml_personal_info_request'
  | 'ml_financial_request'
  | 'ml_phishing_detected'
  | 'ml_bec_detected'
  | 'ml_malware_detected'
  | 'ml_spam_detected'
  | 'ml_spf'
  | 'ml_dkim'
  | 'ml_dmarc'
  | 'ml_domain_age'
  | 'ml_homoglyph'
  | 'ml_cousin_domain'
  | 'ml_free_email_provider'
  | 'ml_disposable_email'
  | 'ml_header_anomaly'
  | 'ml_reply_to_mismatch'
  | 'ml_display_name_spoof'
  | 'ml_envelope_mismatch'
  | 'ml_urgency_language'
  | 'ml_credential_request'
  | 'ml_suspicious_url'
  | 'ml_url_redirect'
  | 'ml_dangerous_url'
  | 'ml_shortened_url'
  | 'ml_ip_url'
  | 'ml_password_protected_archive'
  | 'ml_macro_enabled'
  | 'ml_executable'
  | 'ml_known_bad_sender'
  | 'ml_known_bad_domain'
  | 'ml_known_bad_ip'
  | 'ml_llm_suspicious'
  // Behavioral analysis
  | 'first_contact'
  | 'first_contact_vip_impersonation'
  | 'vip_impersonation'
  | 'new_domain'
  | 'vendor_lookalike'
  | 'domain_age_risk'
  | 'behavioral_anomaly'
  | 'anomaly_detected'
  | 'lookalike_detected'
  // Email classification
  | 'classification'
  // Sender reputation (Phase 1 FP reduction)
  | 'sender_reputation'
  | 'sender_trust_applied'
  | 'url_reputation'
  | 'url_whitelisted';

// Analysis result from each layer
export interface LayerResult {
  layer: 'deterministic' | 'reputation' | 'ml' | 'bec' | 'llm' | 'sandbox';
  score: number; // 0-100
  confidence: number; // 0-1
  signals: Signal[];
  processingTimeMs: number;
  skipped?: boolean;
  skipReason?: string;
  metadata?: Record<string, unknown>;
}

// Email classification result (from classifier module)
export interface EmailClassificationResult {
  type: 'marketing' | 'transactional' | 'automated' | 'personal' | 'unknown';
  confidence: number;
  isKnownSender: boolean;
  senderName?: string;
  senderCategory?: string;
  threatScoreModifier: number;
  skipBECDetection: boolean;
  skipGiftCardDetection: boolean;
  signals: string[];
}

// Final verdict
export interface EmailVerdict {
  messageId: string;
  tenantId: string;
  verdict: 'pass' | 'suspicious' | 'quarantine' | 'block';
  overallScore: number; // 0-100 (higher = more suspicious)
  confidence: number; // 0-1
  signals: Signal[];
  layerResults: LayerResult[];
  explanation?: string; // Human-readable from LLM
  recommendation?: string;
  processingTimeMs: number;
  llmTokensUsed?: number;
  analyzedAt: Date;
  policyApplied?: {
    policyId?: string;
    policyName?: string;
    action?: string;
  };
  // Email classification (runs before threat detection)
  emailClassification?: EmailClassificationResult;
}

// Detection pipeline configuration
export interface DetectionConfig {
  // Score thresholds
  passThreshold: number; // Below this = pass (default: 30)
  suspiciousThreshold: number; // Above this = suspicious (default: 50)
  quarantineThreshold: number; // Above this = quarantine (default: 70)
  blockThreshold: number; // Above this = block (default: 85)

  // Layer gating
  skipMlIfDeterministicBelow: number; // Skip ML if deterministic score below this
  skipMlIfDeterministicAbove: number; // Skip ML if deterministic score above this
  invokeLlmConfidenceRange: [number, number]; // Invoke LLM if ML confidence in this range
  skipLLM?: boolean; // Skip LLM layer entirely (for background sync)

  // LLM settings
  llmModel: string;
  llmMaxTokens: number;
  llmDailyLimitPerTenant: number;

  // Timeouts
  urlAnalysisTimeoutMs: number;
  sandboxTimeoutMs: number;
}

export const DEFAULT_DETECTION_CONFIG: DetectionConfig = {
  passThreshold: 35,        // Phase 3: Raised from 30 (+16.7% margin)
  suspiciousThreshold: 55,  // Phase 3: Raised from 50 (+10.0% margin)
  quarantineThreshold: 73,  // Phase 3: Balanced from 75 - allow BEC/phishing to reach block threshold
  blockThreshold: 85,       // Unchanged - maintain security bar

  skipMlIfDeterministicBelow: 20,
  skipMlIfDeterministicAbove: 80,
  invokeLlmConfidenceRange: [0.4, 0.7],

  llmModel: 'claude-3-5-haiku-20241022',
  llmMaxTokens: 1024,
  llmDailyLimitPerTenant: 100,

  urlAnalysisTimeoutMs: 5000,
  sandboxTimeoutMs: 180000,
};

// URL analysis result
export interface UrlAnalysis {
  originalUrl: string;
  finalUrl: string;
  redirectChain: string[];
  verdict: 'safe' | 'suspicious' | 'malicious' | 'unknown';
  reputationScore?: number;
  signals: Signal[];
}

// File analysis result
export interface FileAnalysis {
  hash: string;
  filename: string;
  fileType: string;
  size: number;
  verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  staticAnalysis?: {
    isExecutable: boolean;
    hasMacros: boolean;
    isEncrypted: boolean;
    suspiciousStrings: string[];
  };
  sandboxResult?: {
    score: number;
    behaviors: string[];
    networkActivity: string[];
    droppedFiles: string[];
  };
  reputationSources?: Record<string, unknown>;
  signals: Signal[];
}
