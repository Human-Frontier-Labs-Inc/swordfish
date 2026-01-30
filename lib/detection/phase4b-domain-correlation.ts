/**
 * Phase 4b: Domain Age Temporal Correlation
 *
 * Correlates domain age with attack signals for amplified detection:
 * - New domain + BEC = critical risk
 * - New domain + first-contact = elevated risk
 * - Lookalike + new domain = critical risk
 *
 * Expected Impact: +1 detection point
 */

import type { Signal } from './types';

// ============================================================================
// Types & Interfaces
// ============================================================================

export interface DomainAgeInfo {
  domain: string;
  ageDays: number;
  riskLevel: 'critical' | 'high' | 'moderate' | 'safe';
  lookalikeTarget?: string;
  inEmailLinks?: boolean;
  registrar?: string;
  privacyProtected?: boolean;
}

export interface DomainCorrelationResult {
  amplificationApplied: boolean;
  amplificationMultiplier: number;
  correlatedSignals: Signal[];
  originalSignalCount: number;
  reason?: string;
}

export interface RegistrationTimingInput {
  domain: string;
  registrationDate: Date;
  targetOrganization?: string;
}

export interface RegistrationTimingResult {
  isSuspicious: boolean;
  suspicionReason?: string;
  riskScore: number;
}

export interface CompoundDomainRiskResult {
  isCompoundThreat: boolean;
  riskMultiplier: number;
  threatPattern?: string;
  signals: Signal[];
}

// ============================================================================
// Constants
// ============================================================================

/**
 * Domain age thresholds (in days)
 */
const AGE_THRESHOLDS = {
  CRITICAL: 7,      // Less than 7 days
  HIGH: 30,         // Less than 30 days
  MODERATE: 90,     // Less than 90 days
  SAFE: 365,        // More than 1 year
};

/**
 * Signal types that get amplified by domain age
 */
const AMPLIFIABLE_SIGNAL_TYPES = [
  'bec_impersonation',
  'bec_financial_risk',
  'bec_urgency_pressure',
  'first_contact',
  'credential_request',
  'wire_transfer_request',
  'executive_impersonation',
];

/**
 * Amplification multipliers by domain age risk level
 */
const AMPLIFICATION_MULTIPLIERS: Record<DomainAgeInfo['riskLevel'], number> = {
  critical: 2.0,
  high: 1.5,
  moderate: 1.2,
  safe: 1.0,
};

// ============================================================================
// Core Correlation Functions
// ============================================================================

/**
 * Correlate domain age with existing signals for amplified detection
 */
export function correlateDomainAgeWithSignals(
  signals: Signal[],
  domainAge: DomainAgeInfo
): DomainCorrelationResult {
  const correlatedSignals: Signal[] = [...signals];
  let amplificationApplied = false;
  let amplificationMultiplier = 1.0;

  // Skip amplification for safe/established domains
  if (domainAge.riskLevel === 'safe') {
    return {
      amplificationApplied: false,
      amplificationMultiplier: 1.0,
      correlatedSignals,
      originalSignalCount: signals.length,
    };
  }

  // Get the base multiplier
  amplificationMultiplier = AMPLIFICATION_MULTIPLIERS[domainAge.riskLevel];

  // Check for signals that should be amplified
  const hasAmplifiableSignals = signals.some(s =>
    AMPLIFIABLE_SIGNAL_TYPES.some(type => s.type.includes(type) || s.type === type)
  );

  if (hasAmplifiableSignals) {
    amplificationApplied = true;

    // Check for BEC + new domain correlation
    const hasBEC = signals.some(s => s.type.includes('bec_'));
    if (hasBEC && domainAge.ageDays <= AGE_THRESHOLDS.HIGH) {
      correlatedSignals.push({
        type: 'domain_age_bec_correlation',
        severity: domainAge.ageDays <= AGE_THRESHOLDS.CRITICAL ? 'critical' : 'warning',
        score: Math.round(25 * amplificationMultiplier),
        detail: `BEC attack from domain registered ${domainAge.ageDays} days ago`,
        metadata: {
          domainAgeDays: domainAge.ageDays,
          riskLevel: domainAge.riskLevel,
          correlationType: 'bec_new_domain',
        },
      });
    }

    // Check for credential phishing + lookalike domain
    const hasCredentialPhishing = signals.some(s =>
      s.type.includes('credential') || s.type.includes('password')
    );
    if (hasCredentialPhishing && domainAge.lookalikeTarget) {
      correlatedSignals.push({
        type: 'domain_age_lookalike_correlation',
        severity: 'critical',
        score: 35,
        detail: `Credential phishing from lookalike domain mimicking ${domainAge.lookalikeTarget}`,
        metadata: {
          lookalikeTarget: domainAge.lookalikeTarget,
          domainAgeDays: domainAge.ageDays,
        },
      });
    }

    // Check for new domain in email links (not sender)
    if (domainAge.inEmailLinks && domainAge.ageDays <= AGE_THRESHOLDS.HIGH) {
      const hasFreeEmail = signals.some(s => s.type === 'free_email_provider');
      if (hasFreeEmail) {
        correlatedSignals.push({
          type: 'new_domain_in_links',
          severity: 'warning',
          score: 20,
          detail: `Email contains links to newly registered domain (${domainAge.ageDays} days old)`,
          metadata: {
            domain: domainAge.domain,
            ageDays: domainAge.ageDays,
            senderType: 'free_email',
          },
        });
      }
    }
  }

  return {
    amplificationApplied,
    amplificationMultiplier,
    correlatedSignals,
    originalSignalCount: signals.length,
    reason: amplificationApplied
      ? `Domain age (${domainAge.ageDays} days) amplifies risk signals`
      : undefined,
  };
}

/**
 * Analyze registration timing for suspicious patterns
 */
export function analyzeRegistrationTiming(
  input: RegistrationTimingInput
): RegistrationTimingResult {
  const daysSinceRegistration = Math.floor(
    (Date.now() - input.registrationDate.getTime()) / (1000 * 60 * 60 * 24)
  );

  let isSuspicious = false;
  let suspicionReason: string | undefined;
  let riskScore = 0;

  // Very recent registration (less than 7 days)
  if (daysSinceRegistration < AGE_THRESHOLDS.CRITICAL) {
    isSuspicious = true;
    riskScore = 9;

    if (input.targetOrganization) {
      // Domain appears to target specific organization
      suspicionReason = 'recent_registration_targeting';
    } else {
      suspicionReason = 'very_recent_registration';
    }
  }
  // Recent registration (less than 30 days)
  else if (daysSinceRegistration < AGE_THRESHOLDS.HIGH) {
    isSuspicious = true;
    riskScore = 7;
    suspicionReason = 'recent_registration';
  }
  // Moderately new (less than 90 days)
  else if (daysSinceRegistration < AGE_THRESHOLDS.MODERATE) {
    isSuspicious = false;
    riskScore = 4;
    suspicionReason = undefined;
  }

  // Check for domain name patterns suggesting targeted attack
  if (input.targetOrganization) {
    const normalizedDomain = input.domain.toLowerCase();
    const normalizedTarget = input.targetOrganization.toLowerCase().replace(/\.[^.]+$/, '');

    if (normalizedDomain.includes(normalizedTarget) ||
        normalizedDomain.includes(normalizedTarget.replace('.', '-'))) {
      isSuspicious = true;
      riskScore = Math.max(riskScore, 8);
      suspicionReason = suspicionReason
        ? `${suspicionReason},targeted_domain_name`
        : 'targeted_domain_name';
    }
  }

  return {
    isSuspicious,
    suspicionReason,
    riskScore,
  };
}

/**
 * Calculate compound risk for first-contact combined with new domain
 */
export function calculateCompoundDomainRisk(
  signals: Signal[],
  domainAge: DomainAgeInfo
): CompoundDomainRiskResult {
  const resultSignals: Signal[] = [];

  // Check for first-contact signal
  const hasFirstContact = signals.some(s =>
    s.type === 'first_contact' || s.type.includes('first_contact')
  );

  // Check for financial risk signals
  const hasFinancialRisk = signals.some(s =>
    s.type.includes('financial') || s.type.includes('wire_transfer') ||
    s.type.includes('invoice') || s.type.includes('payment')
  );

  // Compound threat: First contact + new domain + financial request
  if (hasFirstContact && domainAge.ageDays <= AGE_THRESHOLDS.HIGH && hasFinancialRisk) {
    const multiplier = domainAge.ageDays <= AGE_THRESHOLDS.CRITICAL ? 2.5 : 2.0;

    resultSignals.push({
      type: 'compound_domain_risk',
      severity: 'critical',
      score: 40,
      detail: `New vendor fraud pattern: First contact from ${domainAge.ageDays}-day-old domain with financial request`,
      metadata: {
        pattern: 'new_vendor_fraud',
        domainAgeDays: domainAge.ageDays,
        riskMultiplier: multiplier,
      },
    });

    return {
      isCompoundThreat: true,
      riskMultiplier: multiplier,
      threatPattern: 'new_vendor_fraud',
      signals: resultSignals,
    };
  }

  // Compound threat: First contact + new domain (without financial)
  if (hasFirstContact && domainAge.ageDays <= AGE_THRESHOLDS.HIGH) {
    const multiplier = 1.5;

    resultSignals.push({
      type: 'compound_domain_risk',
      severity: 'warning',
      score: 20,
      detail: `First contact from recently registered domain (${domainAge.ageDays} days)`,
      metadata: {
        pattern: 'first_contact_new_domain',
        domainAgeDays: domainAge.ageDays,
        riskMultiplier: multiplier,
      },
    });

    return {
      isCompoundThreat: true,
      riskMultiplier: multiplier,
      threatPattern: 'first_contact_new_domain',
      signals: resultSignals,
    };
  }

  return {
    isCompoundThreat: false,
    riskMultiplier: 1.0,
    signals: [],
  };
}

/**
 * Helper function to determine domain age risk level
 */
export function getDomainAgeRiskLevel(ageDays: number): DomainAgeInfo['riskLevel'] {
  if (ageDays < 0) return 'moderate'; // Unknown age
  if (ageDays <= AGE_THRESHOLDS.CRITICAL) return 'critical';
  if (ageDays <= AGE_THRESHOLDS.HIGH) return 'high';
  if (ageDays <= AGE_THRESHOLDS.MODERATE) return 'moderate';
  return 'safe';
}
