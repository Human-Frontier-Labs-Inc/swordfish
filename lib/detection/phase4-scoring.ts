/**
 * Phase 4 Scoring Enhancements
 *
 * Implements:
 * - First-Contact Risk Amplification (+2.5 points)
 * - Scoring Synergy Bonus (+0.5 points)
 * - Enhanced Score Calculation for Pipeline Integration
 *
 * Target: 80/100 → 86/100 with scoring improvements
 */

import type { Signal, LayerResult, SignalType } from './types';

// ============================================================================
// Types
// ============================================================================

export interface AmplificationOptions {
  hasExecutiveTitle?: boolean;
  hasFinancialRequest?: boolean;
  targetingVIP?: boolean;
}

export interface EnhancedScoreOptions {
  enableFirstContactAmplification?: boolean;
  enableSynergyBonus?: boolean;
  enableBehavioralAnalysis?: boolean;
  emailClassification?: {
    type: string;
    isKnownSender?: boolean;
  };
}

export interface EnhancedScoreResult {
  overallScore: number;
  confidence: number;
  signals: Signal[];
  synergyBonus: number;
  compoundPatterns: string[];
  amplificationApplied: boolean;
}

// ============================================================================
// Attack Pattern Constants
// ============================================================================

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
// First-Contact Risk Amplification
// ============================================================================

/**
 * Amplifies BEC and attack signals when combined with first-contact
 *
 * Amplification rules:
 * - Base: 1.5x amplification for BEC + first-contact
 * - +0.3x for executive title targeting
 * - +0.2x for financial request
 * - +0.3x for VIP targeting
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

  // Calculate amplification multiplier
  let multiplier = 1.5; // Base amplification for first-contact + BEC
  if (options.hasExecutiveTitle) multiplier += 0.3;
  if (options.hasFinancialRequest) multiplier += 0.2;
  if (options.targetingVIP) multiplier += 0.3;

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
  if (options.hasExecutiveTitle && options.hasFinancialRequest) {
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
      },
    });
  }

  return amplifiedSignals;
}

// ============================================================================
// Synergy Bonus Calculation
// ============================================================================

/**
 * Calculates synergy bonus for multiple attack patterns
 *
 * Bonus tiers:
 * - 2 patterns: +5 points
 * - 3 patterns: +8 points
 * - 4+ patterns: +12 points (compound attack)
 *
 * @param signals Signals to analyze
 * @returns Synergy bonus points (0-12)
 */
export function calculateSynergyBonus(signals: Signal[]): number {
  if (signals.length === 0) return 0;

  // Count unique attack patterns
  // Attack patterns are counted if they're in the known attack patterns list
  // OR if they have warning/critical severity (indicates a threat)
  const attackPatterns = new Set<SignalType>();

  for (const signal of signals) {
    // Count if it's a known attack pattern type (regardless of severity)
    // or if it's a warning/critical signal that indicates an attack
    if (ATTACK_PATTERN_SIGNALS.includes(signal.type)) {
      attackPatterns.add(signal.type);
    } else if (signal.severity === 'warning' || signal.severity === 'critical') {
      // Also count non-listed warning/critical signals as they indicate threats
      attackPatterns.add(signal.type);
    }
  }

  const patternCount = attackPatterns.size;

  // Calculate bonus based on pattern count
  if (patternCount >= 4) {
    return 12; // Compound attack
  } else if (patternCount >= 3) {
    return 8;
  } else if (patternCount >= 2) {
    return 5;
  }

  return 0;
}

/**
 * Identifies specific compound attack patterns
 *
 * @param signals Signals to analyze
 * @returns Array of identified compound pattern names
 */
export function identifyCompoundPatterns(signals: Signal[]): string[] {
  const signalTypes = new Set(signals.map(s => s.type));
  const identifiedPatterns: string[] = [];

  for (const [patternName, pattern] of Object.entries(COMPOUND_PATTERNS)) {
    // Check required signals
    const requiredMatches = pattern.required.filter(type =>
      signalTypes.has(type as SignalType)
    ).length;

    // Check optional signals
    const optionalMatches = pattern.optional.filter(type =>
      signalTypes.has(type as SignalType)
    ).length;

    // Pattern matches if minimum requirements are met
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
// Enhanced Score Calculation
// ============================================================================

/**
 * Layer weights for enhanced score calculation
 * Includes new behavioral layer
 */
const ENHANCED_LAYER_WEIGHTS: Record<string, number> = {
  deterministic: 0.25,
  reputation: 0.15,
  ml: 0.15,
  bec: 0.20,
  llm: 0.10,
  sandbox: 0.05,
  behavioral: 0.10, // New behavioral layer (Phase 4)
};

/**
 * Calculates enhanced score with all Phase 4 improvements
 *
 * Applies:
 * - First-contact risk amplification
 * - Synergy bonus for compound attacks
 * - Behavioral layer integration
 * - Signal deduplication
 *
 * @param layerResults Results from all detection layers
 * @param options Configuration options
 * @returns Enhanced score result
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

  // Check if this is a marketing/known sender email (skip synergy bonus)
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
      // Detect context for amplification
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

      allSignals = amplifyFirstContactRisk(allSignals, {
        hasExecutiveTitle,
        hasFinancialRequest,
        targetingVIP,
      });
      amplificationApplied = true;
    }
  }

  // Calculate synergy bonus if enabled
  let synergyBonus = 0;
  let compoundPatterns: string[] = [];

  if (options.enableSynergyBonus !== false && !isMarketingEmail) {
    synergyBonus = calculateSynergyBonus(allSignals);
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

  // Normalize weighted score
  const normalizedScore = totalWeight > 0 ? weightedScore / totalWeight : 0;

  // Calculate signal boost
  const criticalSignals = allSignals.filter(s => s.severity === 'critical');
  const warningSignals = allSignals.filter(s => s.severity === 'warning');

  const criticalBoost = Math.min(28, criticalSignals.length * 7);
  const warningBoost = Math.min(10, warningSignals.length * 2);

  // Calculate signal score contribution (amplified signals contribute more)
  const totalSignalScore = allSignals.reduce((sum, s) => sum + s.score, 0);
  const signalScoreContribution = Math.min(30, totalSignalScore * 0.25);

  // Calculate amplification bonus (when amplification was applied)
  const amplificationBonus = amplificationApplied ? 10 : 0;

  // Calculate behavioral anomaly bonus (behavioral signals indicate risk)
  const hasBehavioralAnomaly = allSignals.some(
    s => s.type === 'anomaly_detected' || s.type === 'behavioral_anomaly'
  );
  const behavioralBonus = hasBehavioralAnomaly ? 3 : 0;

  // Calculate final score
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

  // Cap at 100
  overallScore = Math.min(100, Math.max(0, overallScore));

  // Calculate confidence based on layer coverage
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
  };
}
