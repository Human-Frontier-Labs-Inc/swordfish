/**
 * Phase 4 Scoring Enhancements + Phase 1 FP Reduction
 *
 * Implements:
 * - First-Contact Risk Amplification (FP-001: reduced 1.5x → 1.2x with domain age exemption)
 * - Scoring Synergy Bonus (FP-007: capped at 8 points)
 * - Enhanced Score Calculation for Pipeline Integration
 * - FP-002: Government/Institutional Domain Whitelist
 * - FP-003: Thread Context Awareness
 * - FP-004: Attachment Analysis Refinement
 * - FP-007: Score Aggregation Formula Improvements
 * - FP-008: Feedback Loop Integration
 *
 * Target: ~2% FP rate → <0.1% FP rate
 */

import type { Signal, LayerResult, SignalType } from './types';

// ============================================================================
// Types
// ============================================================================

export interface AmplificationOptions {
  hasExecutiveTitle?: boolean;
  hasFinancialRequest?: boolean;
  targetingVIP?: boolean;
  /** FP-001: Domain age in days for sender domain */
  senderDomainAgeDays?: number;
}

export interface ThreadContext {
  isReply: boolean;
  threadDepth: number;
  previousSenderAddresses?: string[];
  currentSender?: string;
}

export interface AttachmentContext {
  fileTypes: string[];
  hasPasswordProtected: boolean;
  hasMacros: boolean;
}

export interface FeedbackContext {
  senderMarkedSafe?: boolean;
  feedbackCount?: number;
  lastFeedbackAt?: Date;
  similarPatternFpRate?: number;
  similarPatternCount?: number;
}

export interface EnhancedScoreOptions {
  enableFirstContactAmplification?: boolean;
  enableSynergyBonus?: boolean;
  enableBehavioralAnalysis?: boolean;
  enableImprovedAggregation?: boolean;
  enableReducedCriticalBoost?: boolean;
  emailClassification?: {
    type: string;
    isKnownSender?: boolean;
  };
  /** FP-001: Domain age in days */
  senderDomainAgeDays?: number;
  /** FP-002: Sender domain for institutional dampening */
  senderDomain?: string;
  /** FP-003: Thread context for reply awareness */
  threadContext?: ThreadContext;
  /** FP-004: Attachment context for refined analysis */
  attachmentContext?: AttachmentContext;
  /** FP-008: User feedback context */
  feedbackContext?: FeedbackContext;
}

export interface EnhancedScoreResult {
  overallScore: number;
  confidence: number;
  signals: Signal[];
  synergyBonus: number;
  compoundPatterns: string[];
  amplificationApplied: boolean;
  /** FP-002: Whether institutional dampening was applied */
  institutionalDampening?: boolean;
  /** FP-003: Whether thread dampening was applied */
  threadDampening?: boolean;
  /** FP-008: Whether feedback dampening was applied */
  feedbackDampening?: boolean;
  /** FP-008: Whether pattern FP dampening was applied */
  patternFpDampening?: boolean;
  /** FP-007: Critical signal boost amount */
  criticalBoost?: number;
}

// ============================================================================
// Constants
// ============================================================================

/**
 * FP-002: Institutional TLDs that get score dampening
 */
const INSTITUTIONAL_TLDS = ['.gov', '.edu', '.mil'];

/**
 * FP-002: Known nonprofit domains that get dampening
 */
const KNOWN_NONPROFIT_DOMAINS = [
  'redcross.org',
  'unicef.org',
  'who.int',
  'un.org',
  'unesco.org',
  'worldbank.org',
  'imf.org',
  'nih.gov',
  'cdc.gov',
  'fda.gov',
  'fbi.gov',
  'cia.gov',
  'nasa.gov',
  'noaa.gov',
];

/**
 * Signal types that count as attack patterns for synergy bonus
 */
const ATTACK_PATTERN_SIGNALS: SignalType[] = [
  'bec_detected',
  'bec_impersonation',
  'bec_financial_risk',
  'bec_wire_transfer_request',
  'bec_gift_card_scam',
  'bec_invoice_fraud',
  'bec_payroll_diversion',
  'bec_urgency_pressure',
  'bec_secrecy_request',
  'bec_authority_manipulation',
  'display_name_spoof',
  'free_email_provider',
  'homoglyph',
  'cousin_domain',
  'reply_to_mismatch',
  'first_contact',
  'first_contact_vip_impersonation',
  'credential_request',
  'financial_request',
  'malicious_url',
  'dangerous_url',
  'phishing_link' as SignalType,
];

/**
 * Signals that can be amplified by first-contact
 */
const AMPLIFIABLE_SIGNALS: SignalType[] = [
  'bec_detected',
  'bec_impersonation',
  'bec_financial_risk',
  'bec_wire_transfer_request',
  'bec_gift_card_scam',
  'bec_invoice_fraud',
  'bec_payroll_diversion',
  'credential_request',
  'financial_request',
  'malicious_url',
  'first_contact_vip_impersonation',
];

/**
 * Critical BEC signals that override dampening
 */
const CRITICAL_BEC_SIGNALS: SignalType[] = [
  'bec_wire_transfer_request',
  'bec_impersonation',
  'bec_gift_card_scam',
  'bec_invoice_fraud',
  'bec_payroll_diversion',
];

/**
 * Compound attack pattern definitions
 */
const COMPOUND_PATTERNS = {
  ceo_fraud: {
    required: ['bec_impersonation'],
    optional: ['bec_wire_transfer_request', 'bec_secrecy_request', 'bec_urgency_pressure', 'bec_financial_risk'],
    minRequired: 1,
    minOptional: 1,
  },
  executive_impersonation: {
    required: ['bec_impersonation', 'bec_financial_risk'],
    optional: ['first_contact', 'bec_urgency_pressure', 'free_email_provider'],
    minRequired: 2,
    minOptional: 0,
  },
  vendor_fraud: {
    required: ['bec_invoice_fraud'],
    optional: ['first_contact', 'cousin_domain', 'free_email_provider'],
    minRequired: 1,
    minOptional: 1,
  },
  gift_card_scam: {
    required: ['bec_gift_card_scam'],
    optional: ['bec_urgency_pressure', 'display_name_spoof', 'free_email_provider'],
    minRequired: 1,
    minOptional: 1,
  },
  credential_phishing: {
    required: ['credential_request'],
    optional: ['malicious_url', 'dangerous_url', 'homoglyph', 'cousin_domain'],
    minRequired: 1,
    minOptional: 1,
  },
  bec_pressure_campaign: {
    required: ['bec_urgency_pressure'],
    optional: ['bec_financial_risk', 'bec_impersonation', 'first_contact', 'free_email_provider'],
    minRequired: 1,
    minOptional: 2,
  },
};

// ============================================================================
// First-Contact Risk Amplification (FP-001)
// ============================================================================

/**
 * Amplifies BEC and attack signals when combined with first-contact
 *
 * FP-001 Changes:
 * - Base: 1.2x amplification (reduced from 1.5x)
 * - Domain age exemption:
 *   - >365 days: NO amplification (established domain)
 *   - 30-365 days: 1.1x amplification (medium-age domain)
 *   - <30 days: 1.2x amplification (new domain)
 * - +0.2x for executive title targeting (reduced from +0.3x)
 * - +0.1x for financial request (reduced from +0.2x)
 * - +0.2x for VIP targeting (reduced from +0.3x)
 * - Signal scores capped at 55 to prevent over-flagging
 *
 * @param signals Original signals from detection
 * @param options Additional context for amplification
 * @returns Amplified signals
 */
export function amplifyFirstContactRisk(
  signals: Signal[],
  options: AmplificationOptions = {}
): Signal[] {
  if (signals.length === 0) return [];

  // Check for first-contact presence
  const hasFirstContact = signals.some(
    s => s.type === 'first_contact' || s.type === 'first_contact_vip_impersonation'
  );

  if (!hasFirstContact) {
    // No amplification needed, return original signals
    return signals;
  }

  // FP-001: Domain age exemption
  const domainAgeDays = options.senderDomainAgeDays;

  // Skip amplification entirely for established domains (>365 days)
  if (domainAgeDays !== undefined && domainAgeDays > 365) {
    // Established domain - no amplification, no boost signal
    return signals;
  }

  // Calculate amplification multiplier based on domain age
  let multiplier: number;
  if (domainAgeDays !== undefined && domainAgeDays >= 30) {
    // Medium-age domain (30-365 days): reduced amplification
    multiplier = 1.1;
  } else {
    // New domain (<30 days) or unknown: base amplification (reduced from 1.5x)
    multiplier = 1.2;
  }

  // Additional multipliers (reduced from original)
  if (options.hasExecutiveTitle) multiplier += 0.2;
  if (options.hasFinancialRequest) multiplier += 0.1;
  if (options.targetingVIP) multiplier += 0.2;

  const amplifiedSignals: Signal[] = [];

  for (const signal of signals) {
    if (AMPLIFIABLE_SIGNALS.includes(signal.type)) {
      // Amplify the signal score
      const amplifiedScore = Math.min(55, Math.round(signal.score * multiplier));
      amplifiedSignals.push({
        ...signal,
        score: amplifiedScore,
        metadata: {
          ...signal.metadata,
          amplified: true,
          originalScore: signal.score,
          multiplier,
        },
      });
    } else {
      // Keep original signal
      amplifiedSignals.push(signal);
    }
  }

  // Add amplification summary signal if executive + financial + first-contact
  // BUT only for new domains (<30 days)
  if (options.hasExecutiveTitle && options.hasFinancialRequest && (domainAgeDays === undefined || domainAgeDays < 30)) {
    amplifiedSignals.push({
      type: 'first_contact_amplified' as SignalType,
      severity: 'critical',
      score: 15,
      detail: 'First-contact amplification triggered: executive title + financial request',
      metadata: {
        hasExecutiveTitle: options.hasExecutiveTitle,
        hasFinancialRequest: options.hasFinancialRequest,
        targetingVIP: options.targetingVIP,
        multiplier,
        domainAgeDays,
      },
    });
  }

  return amplifiedSignals;
}

// ============================================================================
// Synergy Bonus Calculation (FP-007)
// ============================================================================

/**
 * Calculates synergy bonus for multiple attack patterns
 *
 * FP-007 Changes:
 * - Bonus tiers (REDUCED):
 *   - 2 patterns: +4 points (reduced from +5)
 *   - 3 patterns: +6 points (reduced from +8)
 *   - 4+ patterns: +8 points (reduced from +12, hard cap)
 *
 * @param signals Signals to analyze
 * @returns Synergy bonus points (0-8)
 */
export function calculateSynergyBonus(signals: Signal[], capAtEight = true): number {
  if (signals.length === 0) return 0;

  // Count unique attack patterns
  const attackPatterns = new Set<SignalType>();

  for (const signal of signals) {
    if (ATTACK_PATTERN_SIGNALS.includes(signal.type)) {
      attackPatterns.add(signal.type);
    } else if (signal.severity === 'warning' || signal.severity === 'critical') {
      attackPatterns.add(signal.type);
    }
  }

  const patternCount = attackPatterns.size;

  // Calculate bonus based on pattern count (FP-007: reduced values, capped at 8)
  let bonus = 0;
  if (patternCount >= 4) {
    bonus = capAtEight ? 8 : 12; // FP-007: Cap at 8
  } else if (patternCount >= 3) {
    bonus = capAtEight ? 6 : 8;
  } else if (patternCount >= 2) {
    bonus = capAtEight ? 4 : 5;
  }

  return bonus;
}

/**
 * Identifies specific compound attack patterns
 */
export function identifyCompoundPatterns(signals: Signal[]): string[] {
  const signalTypes = new Set(signals.map(s => s.type));
  const identifiedPatterns: string[] = [];

  for (const [patternName, pattern] of Object.entries(COMPOUND_PATTERNS)) {
    const requiredMatches = pattern.required.filter(type =>
      signalTypes.has(type as SignalType)
    ).length;

    const optionalMatches = pattern.optional.filter(type =>
      signalTypes.has(type as SignalType)
    ).length;

    if (
      requiredMatches >= pattern.minRequired &&
      optionalMatches >= pattern.minOptional
    ) {
      identifiedPatterns.push(patternName);
    }
  }

  return identifiedPatterns;
}

// ============================================================================
// FP-002: Institutional Domain Detection
// ============================================================================

/**
 * Checks if a domain is institutional (government, education, etc.)
 */
function isInstitutionalDomain(domain: string | undefined): boolean {
  if (!domain) return false;

  const lowerDomain = domain.toLowerCase();

  // Check TLDs
  for (const tld of INSTITUTIONAL_TLDS) {
    if (lowerDomain.endsWith(tld)) {
      return true;
    }
  }

  // Check known nonprofit domains
  return KNOWN_NONPROFIT_DOMAINS.some(d => lowerDomain === d || lowerDomain.endsWith('.' + d));
}

/**
 * Checks if domain appears to be spoofed (homoglyph attack on institutional domain)
 */
function isSpoogedInstitutionalDomain(domain: string | undefined, signals: Signal[]): boolean {
  if (!domain) return false;

  // Check for homoglyph signals
  const hasHomoglyph = signals.some(s =>
    s.type === 'homoglyph' ||
    s.type === 'lookalike_homoglyph' ||
    s.type === 'cousin_domain'
  );

  return hasHomoglyph;
}

// ============================================================================
// FP-003: Thread Context Helpers
// ============================================================================

/**
 * Checks if thread context allows for dampening
 */
function canApplyThreadDampening(
  threadContext: ThreadContext | undefined,
  signals: Signal[]
): boolean {
  if (!threadContext) return false;
  if (!threadContext.isReply || threadContext.threadDepth < 1) return false;

  // Check for thread hijacking (new sender in existing thread)
  if (threadContext.currentSender && threadContext.previousSenderAddresses) {
    const senderInThread = threadContext.previousSenderAddresses.includes(
      threadContext.currentSender
    );
    if (!senderInThread) {
      // New sender in thread - could be hijacking, don't dampen
      return false;
    }
  }

  // Check for critical BEC signals - don't dampen if present
  const hasCriticalBec = signals.some(s =>
    CRITICAL_BEC_SIGNALS.includes(s.type) && s.severity === 'critical'
  );
  if (hasCriticalBec) return false;

  return true;
}

// ============================================================================
// FP-008: Feedback Context Helpers
// ============================================================================

const FEEDBACK_EXPIRY_DAYS = 90;

/**
 * Checks if feedback context allows for dampening
 */
function canApplyFeedbackDampening(
  feedbackContext: FeedbackContext | undefined,
  signals: Signal[]
): boolean {
  if (!feedbackContext) return false;
  if (!feedbackContext.senderMarkedSafe) return false;

  // Check for feedback expiry
  if (feedbackContext.lastFeedbackAt) {
    const daysSinceFeedback = Math.floor(
      (Date.now() - feedbackContext.lastFeedbackAt.getTime()) / (1000 * 60 * 60 * 24)
    );
    if (daysSinceFeedback > FEEDBACK_EXPIRY_DAYS) {
      return false;
    }
  }

  // Critical BEC signals override feedback
  const hasCriticalBec = signals.some(s =>
    CRITICAL_BEC_SIGNALS.includes(s.type) && s.severity === 'critical'
  );
  if (hasCriticalBec) return false;

  return true;
}

/**
 * Checks if pattern FP rate warrants dampening
 */
function shouldApplyPatternFpDampening(feedbackContext: FeedbackContext | undefined): boolean {
  if (!feedbackContext) return false;
  if (!feedbackContext.similarPatternFpRate) return false;
  if (!feedbackContext.similarPatternCount || feedbackContext.similarPatternCount < 20) return false;

  // Apply dampening if FP rate > 10%
  return feedbackContext.similarPatternFpRate > 0.1;
}

// ============================================================================
// Enhanced Score Calculation
// ============================================================================

/**
 * Layer weights for enhanced score calculation
 */
const ENHANCED_LAYER_WEIGHTS: Record<string, number> = {
  deterministic: 0.25,
  reputation: 0.15,
  ml: 0.15,
  bec: 0.20,
  llm: 0.10,
  sandbox: 0.05,
  behavioral: 0.10,
};

/**
 * Calculates enhanced score with all Phase 4 improvements + Phase 1 FP reductions
 *
 * Applies:
 * - First-contact risk amplification (FP-001: reduced with domain age exemption)
 * - Synergy bonus for compound attacks (FP-007: capped at 8)
 * - Institutional domain dampening (FP-002)
 * - Thread context awareness (FP-003)
 * - Attachment analysis refinement (FP-004)
 * - Score aggregation improvements (FP-007)
 * - Feedback loop integration (FP-008)
 */
export function calculateEnhancedScore(
  layerResults: LayerResult[],
  options: EnhancedScoreOptions = {}
): EnhancedScoreResult {
  // Collect all signals from all layers
  let allSignals: Signal[] = [];
  for (const layer of layerResults) {
    allSignals.push(...layer.signals);
  }

  // Deduplicate signals by type (keep highest score)
  const signalMap = new Map<SignalType, Signal>();
  for (const signal of allSignals) {
    const existing = signalMap.get(signal.type);
    if (!existing || signal.score > existing.score) {
      signalMap.set(signal.type, signal);
    }
  }
  allSignals = Array.from(signalMap.values());

  // Check if this is a marketing/known sender email
  const isMarketingEmail =
    options.emailClassification?.type === 'marketing' ||
    options.emailClassification?.isKnownSender === true;

  // Apply first-contact amplification if enabled
  let amplificationApplied = false;
  if (options.enableFirstContactAmplification !== false) {
    const hasFirstContact = allSignals.some(
      s => s.type === 'first_contact' || s.type === 'first_contact_vip_impersonation'
    );

    if (hasFirstContact) {
      const hasExecutiveTitle = allSignals.some(
        s => s.detail?.toLowerCase().includes('executive') ||
             s.detail?.toLowerCase().includes('ceo') ||
             s.detail?.toLowerCase().includes('cfo') ||
             s.detail?.toLowerCase().includes('president')
      );
      const hasFinancialRequest = allSignals.some(
        s => s.type === 'bec_financial_risk' ||
             s.type === 'bec_wire_transfer_request' ||
             s.type === 'financial_request'
      );
      const targetingVIP = allSignals.some(
        s => s.type === 'first_contact_vip_impersonation' ||
             s.type === 'vip_impersonation'
      );

      // FP-001: Include domain age in amplification
      allSignals = amplifyFirstContactRisk(allSignals, {
        hasExecutiveTitle,
        hasFinancialRequest,
        targetingVIP,
        senderDomainAgeDays: options.senderDomainAgeDays,
      });
      amplificationApplied = true;
    }
  }

  // Calculate synergy bonus if enabled (FP-007: capped at 8)
  let synergyBonus = 0;
  let compoundPatterns: string[] = [];

  if (options.enableSynergyBonus !== false && !isMarketingEmail) {
    // FP-007: Always cap synergy bonus at 8
    synergyBonus = calculateSynergyBonus(allSignals, true);
    compoundPatterns = identifyCompoundPatterns(allSignals);
  }

  // Calculate weighted layer score
  let weightedScore = 0;
  let totalWeight = 0;

  for (const layer of layerResults) {
    const weight = ENHANCED_LAYER_WEIGHTS[layer.layer] || 0.05;
    weightedScore += layer.score * weight;
    totalWeight += weight;
  }

  const normalizedScore = totalWeight > 0 ? weightedScore / totalWeight : 0;

  // FP-007: Calculate signal boost with reduced critical boost option
  const criticalSignals = allSignals.filter(s => s.severity === 'critical');
  const warningSignals = allSignals.filter(s => s.severity === 'warning');

  // FP-007: Reduce critical boost from +7 to +5 per signal
  const criticalBoostPerSignal = options.enableReducedCriticalBoost !== false ? 5 : 7;
  const maxCriticalBoost = options.enableReducedCriticalBoost !== false ? 20 : 28;
  const criticalBoost = Math.min(maxCriticalBoost, criticalSignals.length * criticalBoostPerSignal);
  const warningBoost = Math.min(10, warningSignals.length * 2);

  // Calculate signal score contribution
  const totalSignalScore = allSignals.reduce((sum, s) => sum + s.score, 0);
  const signalScoreContribution = Math.min(30, totalSignalScore * 0.25);

  // Calculate amplification bonus
  const amplificationBonus = amplificationApplied ? 8 : 0; // Reduced from 10

  // Behavioral anomaly bonus
  const hasBehavioralAnomaly = allSignals.some(
    s => s.type === 'anomaly_detected' || s.type === 'behavioral_anomaly'
  );
  const behavioralBonus = hasBehavioralAnomaly ? 3 : 0;

  // Calculate base score
  let overallScore = Math.round(
    normalizedScore * 0.4 +
    criticalBoost +
    warningBoost +
    signalScoreContribution +
    synergyBonus +
    amplificationBonus +
    behavioralBonus
  );

  // Apply marketing email dampening
  if (isMarketingEmail) {
    overallScore = Math.round(overallScore * 0.7);
  }

  // FP-002: Apply institutional domain dampening
  let institutionalDampening = false;
  if (options.senderDomain) {
    const isInstitutional = isInstitutionalDomain(options.senderDomain);
    const isSpoofed = isSpoogedInstitutionalDomain(options.senderDomain, allSignals);
    const hasCriticalBec = allSignals.some(s =>
      CRITICAL_BEC_SIGNALS.includes(s.type) && s.severity === 'critical'
    );

    if (isInstitutional && !isSpoofed && !hasCriticalBec) {
      overallScore = Math.round(overallScore * 0.5); // 50% dampening for institutional
      institutionalDampening = true;
    }
  }

  // FP-003: Apply thread context dampening
  let threadDampening = false;
  if (canApplyThreadDampening(options.threadContext, allSignals)) {
    overallScore = Math.round(overallScore * 0.6); // 40% dampening for thread replies
    threadDampening = true;
  }

  // FP-004: Attachment analysis refinement
  if (options.attachmentContext) {
    const { hasPasswordProtected, hasMacros, fileTypes } = options.attachmentContext;

    // Safe document types without macros/password get score reduction
    const isSafeDocType = fileTypes.some(t =>
      t.includes('pdf') ||
      t.includes('word') ||
      t.includes('document')
    );

    if (isSafeDocType && !hasPasswordProtected && !hasMacros && options.emailClassification?.isKnownSender) {
      overallScore = Math.round(overallScore * 0.8); // Slight dampening for safe docs from known senders
    }
  }

  // FP-008: Apply feedback dampening
  let feedbackDampening = false;
  if (canApplyFeedbackDampening(options.feedbackContext, allSignals)) {
    overallScore = Math.round(overallScore * 0.7); // 30% dampening for user-verified senders
    feedbackDampening = true;
  }

  // FP-008: Apply pattern FP dampening
  let patternFpDampening = false;
  if (shouldApplyPatternFpDampening(options.feedbackContext)) {
    overallScore = Math.round(overallScore * 0.85); // 15% dampening for high-FP patterns
    patternFpDampening = true;
  }

  // Cap at 100
  overallScore = Math.min(100, Math.max(0, overallScore));

  // Calculate confidence
  const expectedLayers = ['deterministic', 'reputation', 'ml', 'bec'];
  const presentLayers = new Set(layerResults.map(l => l.layer));
  const layerCoverage = expectedLayers.filter(l => presentLayers.has(l as any)).length / expectedLayers.length;

  const avgConfidence = layerResults.length > 0
    ? layerResults.reduce((sum, l) => sum + l.confidence, 0) / layerResults.length
    : 0.5;

  const confidence = Math.min(1, avgConfidence * 0.7 + layerCoverage * 0.3);

  return {
    overallScore,
    confidence,
    signals: allSignals,
    synergyBonus,
    compoundPatterns,
    amplificationApplied,
    institutionalDampening,
    threadDampening,
    feedbackDampening,
    patternFpDampening,
    criticalBoost,
  };
}
