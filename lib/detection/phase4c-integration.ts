/**
 * Phase 4c: Lookalike Domain Learning Integration
 *
 * Integrates adaptive lookalike domain detection into the detection pipeline:
 * - Tenant-specific brand protection
 * - Learning from confirmed threats
 * - Pattern generalization from attacks
 * - Adaptive confidence scoring
 *
 * Expected Impact: +1 detection point
 */

import type { Signal, ParsedEmail } from './types';
import {
  LookalikeLearningService,
  detectWithLearning,
  recordLookalikeDetection,
  type LookalikeDetectionResult,
  type LookalikeDetection,
} from './phase4c-lookalike-learning';

// ============================================================================
// Types & Interfaces
// ============================================================================

export interface LookalikeAnalysisResult {
  hasLookalike: boolean;
  detections: LookalikeDetectionResult[];
  signals: Signal[];
  riskScore: number;
  confidence: number;
}

export interface Phase4cEnhancements {
  lookalikeResult?: {
    hasLookalike: boolean;
    targetBrands: string[];
    attackTypes: string[];
    maxConfidence: number;
  };
}

// ============================================================================
// Singleton Service Instance
// ============================================================================

// Global service instance for pattern learning persistence
let globalLearningService: LookalikeLearningService | null = null;

/**
 * Get or create the global learning service instance
 */
export function getLearningService(): LookalikeLearningService {
  if (!globalLearningService) {
    globalLearningService = new LookalikeLearningService();
  }
  return globalLearningService;
}

/**
 * Reset the learning service (for testing)
 */
export function resetLearningService(): void {
  globalLearningService = new LookalikeLearningService();
}

// ============================================================================
// Core Analysis Functions
// ============================================================================

/**
 * Extract sender domain from email
 */
function extractSenderDomain(email: ParsedEmail): string | null {
  const address = email.from?.address;
  if (!address) return null;

  const parts = address.split('@');
  return parts.length > 1 ? parts[1].toLowerCase() : null;
}

/**
 * Extract domains from URLs in email body
 */
function extractUrlDomains(body: string): string[] {
  const urlPattern = /https?:\/\/([a-z0-9.-]+)/gi;
  const domains: string[] = [];
  let match;

  while ((match = urlPattern.exec(body)) !== null) {
    const domain = match[1].toLowerCase();
    if (!domains.includes(domain)) {
      domains.push(domain);
    }
  }

  return domains;
}

/**
 * Run lookalike domain analysis on an email
 */
export function runLookalikeAnalysis(
  email: ParsedEmail,
  tenantId: string
): LookalikeAnalysisResult {
  const service = getLearningService();
  const signals: Signal[] = [];
  const detections: LookalikeDetectionResult[] = [];
  let hasLookalike = false;
  let maxConfidence = 0;

  // Check sender domain
  const senderDomain = extractSenderDomain(email);
  if (senderDomain) {
    const result = detectWithLearning(service, tenantId, senderDomain);
    if (result.isLookalike) {
      hasLookalike = true;
      detections.push(result);
      maxConfidence = Math.max(maxConfidence, result.finalConfidence);

      // Create signal for sender lookalike
      signals.push(createLookalikeSignal(result, 'sender', senderDomain));
    }
  }

  // Check URL domains in body
  const bodyText = (email.body.text || '') + (email.body.html || '');
  const urlDomains = extractUrlDomains(bodyText);

  for (const domain of urlDomains.slice(0, 10)) { // Limit to 10 URLs
    const result = detectWithLearning(service, tenantId, domain);
    if (result.isLookalike) {
      hasLookalike = true;
      detections.push(result);
      maxConfidence = Math.max(maxConfidence, result.finalConfidence);

      // Create signal for URL lookalike
      signals.push(createLookalikeSignal(result, 'url', domain));
    }
  }

  // Calculate overall risk score
  const riskScore = calculateLookalikeRiskScore(detections);

  return {
    hasLookalike,
    detections,
    signals,
    riskScore,
    confidence: maxConfidence,
  };
}

/**
 * Create a signal from a lookalike detection result
 */
function createLookalikeSignal(
  result: LookalikeDetectionResult,
  context: 'sender' | 'url',
  domain: string
): Signal {
  const severityMap: Record<string, Signal['severity']> = {
    homoglyph: 'critical',
    typosquat: 'warning',
    cousin: 'warning',
  };

  const scoreMap: Record<string, number> = {
    homoglyph: 35,
    typosquat: 25,
    cousin: 20,
  };

  const attackType = result.attackType || 'unknown';
  const severity = severityMap[attackType] || 'warning';
  const baseScore = scoreMap[attackType] || 20;

  // Boost score based on confidence and learning
  const confidenceBoost = Math.round(result.finalConfidence * 10);
  const learningBoost = Math.round(result.learningBoost * 20);
  const finalScore = Math.min(50, baseScore + confidenceBoost + learningBoost);

  const contextLabel = context === 'sender' ? 'Sender domain' : 'URL domain';

  return {
    type: `lookalike_${attackType}` as Signal['type'],
    severity,
    score: finalScore,
    detail: `${contextLabel} "${domain}" is a ${attackType} lookalike of ${result.targetBrand} (${result.targetDomain})`,
    metadata: {
      attackType,
      targetBrand: result.targetBrand,
      targetDomain: result.targetDomain,
      confidence: result.finalConfidence,
      learningBoost: result.learningBoost,
      context,
    },
  };
}

/**
 * Calculate overall risk score from lookalike detections
 */
function calculateLookalikeRiskScore(detections: LookalikeDetectionResult[]): number {
  if (detections.length === 0) return 0;

  let score = 0;

  for (const detection of detections) {
    const attackType = detection.attackType || 'unknown';

    // Base scores by attack type
    const baseScore = attackType === 'homoglyph' ? 30 :
                     attackType === 'typosquat' ? 20 :
                     attackType === 'cousin' ? 15 : 10;

    // Apply confidence multiplier
    const confidenceMultiplier = detection.finalConfidence;

    // Add learning boost
    const learningBonus = detection.learningBoost * 10;

    score += (baseScore * confidenceMultiplier) + learningBonus;
  }

  // Cap at 100
  return Math.min(100, Math.round(score));
}

/**
 * Convert lookalike analysis to pipeline signals
 */
export function convertLookalikeAnalysisToSignals(
  result: LookalikeAnalysisResult
): Signal[] {
  return result.signals;
}

/**
 * Record a confirmed lookalike detection for learning
 */
export function recordConfirmedLookalike(
  domain: string,
  targetBrand: string,
  targetDomain: string,
  attackType: 'homoglyph' | 'typosquat' | 'cousin',
  confidence: number
): void {
  const service = getLearningService();

  const detection: LookalikeDetection = {
    attackerDomain: domain,
    targetBrand,
    targetDomain,
    attackType,
    confidence,
    timestamp: new Date(),
  };

  recordLookalikeDetection(service, detection);
}

/**
 * Calculate Phase 4c score contribution
 */
export function calculatePhase4cScore(
  lookalikeResult: LookalikeAnalysisResult
): number {
  if (!lookalikeResult.hasLookalike) return 0;

  // Scale risk score to Phase 4c contribution (max 1 point scaled to 10)
  const contribution = (lookalikeResult.riskScore / 100) * 10;

  return Math.min(10, Math.round(contribution * 10) / 10);
}

/**
 * Build Phase 4c enhancements summary
 */
export function buildPhase4cEnhancements(
  lookalikeResult: LookalikeAnalysisResult
): Phase4cEnhancements {
  if (!lookalikeResult.hasLookalike) {
    return {};
  }

  const targetBrands = lookalikeResult.detections
    .filter(d => d.targetBrand)
    .map(d => d.targetBrand!)
    .filter((v, i, a) => a.indexOf(v) === i); // Deduplicate

  const attackTypes = lookalikeResult.detections
    .filter(d => d.attackType)
    .map(d => d.attackType!)
    .filter((v, i, a) => a.indexOf(v) === i);

  return {
    lookalikeResult: {
      hasLookalike: lookalikeResult.hasLookalike,
      targetBrands,
      attackTypes,
      maxConfidence: lookalikeResult.confidence,
    },
  };
}

// Re-export types and functions from core module for convenience
export {
  LookalikeLearningService,
  type LookalikeDetectionResult,
  type LookalikeDetection,
} from './phase4c-lookalike-learning';
