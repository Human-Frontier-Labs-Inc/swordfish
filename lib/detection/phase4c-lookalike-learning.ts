/**
 * Phase 4c: Lookalike Domain Learning
 *
 * Adaptive lookalike domain detection with machine learning capabilities:
 * - Tenant-specific brand protection
 * - Learning from confirmed threats
 * - Pattern generalization from attacks
 * - Adaptive confidence scoring
 *
 * Expected Impact: +1 detection point
 */

import {
  PROTECTED_BRANDS,
  HOMOGLYPHS,
  type BrandMatch,
} from './brand-protection';

// ============================================================================
// Types & Interfaces
// ============================================================================

export interface TenantBrand {
  domain: string;
  brandName: string;
  aliases?: string[];
  priority: 'critical' | 'high' | 'medium' | 'low';
}

export interface LookalikeDetection {
  attackerDomain: string;
  targetBrand: string;
  targetDomain: string;
  attackType: 'homoglyph' | 'typosquat' | 'cousin' | 'exact';
  confidence: number;
  timestamp: Date;
}

export interface DetectionFeedback {
  attackerDomain: string;
  wasCorrect: boolean;
  confirmedThreat: boolean;
  feedbackSource: 'user' | 'analyst' | 'automated';
}

export interface LearnedPattern {
  pattern: string;
  targetBrand: string;
  targetDomain: string;
  attackType: 'homoglyph' | 'typosquat' | 'cousin';
  occurrences: number;
  averageConfidence: number;
  isGeneralized: boolean;
  lastSeen: Date;
  feedbackScore: number; // -1 to 1, negative means false positive prone
}

export interface LookalikeDetectionResult {
  isLookalike: boolean;
  targetBrand?: string;
  targetDomain?: string;
  attackType?: 'homoglyph' | 'typosquat' | 'cousin';
  baseConfidence: number;
  learningBoost: number;
  finalConfidence: number;
  confidence?: number; // Alias for finalConfidence (test compatibility)
  matchedPattern?: LearnedPattern;
}

// ============================================================================
// LookalikeLearningService Class
// ============================================================================

export class LookalikeLearningService {
  private tenantBrands: Map<string, TenantBrand[]> = new Map();
  private detections: LookalikeDetection[] = [];
  private learnedPatterns: LearnedPattern[] = [];
  private feedbackHistory: Map<string, DetectionFeedback[]> = new Map();

  constructor() {
    // Initialize with empty state
  }

  getTenantBrands(tenantId: string): TenantBrand[] {
    return this.tenantBrands.get(tenantId) || [];
  }

  addTenantBrand(tenantId: string, brand: TenantBrand): void {
    const brands = this.tenantBrands.get(tenantId) || [];
    brands.push(brand);
    this.tenantBrands.set(tenantId, brands);
  }

  recordDetection(detection: LookalikeDetection): void {
    this.detections.push(detection);
    this.updateLearnedPatterns(detection);
  }

  recordFeedback(feedback: DetectionFeedback): void {
    const existing = this.feedbackHistory.get(feedback.attackerDomain) || [];
    existing.push(feedback);
    this.feedbackHistory.set(feedback.attackerDomain, existing);
    this.applyFeedbackToPatterns(feedback);
  }

  getLearnedPatterns(): LearnedPattern[] {
    return [...this.learnedPatterns];
  }

  private updateLearnedPatterns(detection: LookalikeDetection): void {
    // Extract pattern from domain
    const pattern = this.extractPattern(detection.attackerDomain, detection.targetDomain);

    // For all attack types, group by brand+attackType for pattern aggregation
    // This allows proper time-weighted averaging across similar attacks
    const findKey = (p: LearnedPattern) =>
      p.targetBrand === detection.targetBrand && p.attackType === detection.attackType;

    const existing = this.learnedPatterns.find(findKey);

    if (existing) {
      // Update existing pattern with time-weighted average
      const weight = this.calculateTimeWeight(existing.lastSeen);
      const weightedOccurrences = existing.occurrences * weight;
      existing.averageConfidence = (existing.averageConfidence * weightedOccurrences + detection.confidence) /
                                   (weightedOccurrences + 1);
      existing.occurrences++;
      existing.lastSeen = detection.timestamp;
    } else {
      // Create new pattern
      this.learnedPatterns.push({
        pattern,
        targetBrand: detection.targetBrand,
        targetDomain: detection.targetDomain,
        attackType: detection.attackType,
        occurrences: 1,
        averageConfidence: detection.confidence,
        isGeneralized: false,
        lastSeen: detection.timestamp,
        feedbackScore: 0,
      });
    }

    // Check for generalized patterns
    this.checkForGeneralizedPatterns();
  }

  private extractPattern(attackerDomain: string, targetDomain: string): string {
    const attackerBase = attackerDomain.split('.')[0].toLowerCase();
    const targetBase = targetDomain.split('.')[0].toLowerCase();

    // Check for prefix patterns (e.g., "secure-brand")
    if (attackerBase.includes('-')) {
      const parts = attackerBase.split('-');
      if (parts.some(p => this.isSimilar(p, targetBase))) {
        return parts.filter(p => !this.isSimilar(p, targetBase)).join('-') + '-';
      }
    }

    // Check for suffix patterns (e.g., "brand-login")
    if (attackerBase.includes('-')) {
      const parts = attackerBase.split('-');
      if (parts.some(p => this.isSimilar(p, targetBase))) {
        return '-' + parts.filter(p => !this.isSimilar(p, targetBase)).join('-');
      }
    }

    // Return the attacker domain as the pattern
    return attackerBase;
  }

  private isSimilar(a: string, b: string): boolean {
    if (a === b) return true;
    if (a.length < 2 || b.length < 2) return false;

    // Levenshtein distance check
    const distance = this.levenshteinDistance(a, b);
    return distance <= Math.max(1, Math.floor(b.length / 4));
  }

  private levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }

    return matrix[b.length][a.length];
  }

  private calculateTimeWeight(lastSeen: Date): number {
    const daysSince = (Date.now() - lastSeen.getTime()) / (1000 * 60 * 60 * 24);
    // Exponential decay with half-life of 7 days
    return Math.exp(-daysSince / 7);
  }

  private checkForGeneralizedPatterns(): void {
    // Group patterns by prefix/suffix
    const prefixPatterns = new Map<string, LearnedPattern[]>();
    const suffixPatterns = new Map<string, LearnedPattern[]>();

    for (const pattern of this.learnedPatterns) {
      if (pattern.pattern.endsWith('-')) {
        const prefix = pattern.pattern;
        const existing = prefixPatterns.get(prefix) || [];
        existing.push(pattern);
        prefixPatterns.set(prefix, existing);
      } else if (pattern.pattern.startsWith('-')) {
        const suffix = pattern.pattern;
        const existing = suffixPatterns.get(suffix) || [];
        existing.push(pattern);
        suffixPatterns.set(suffix, existing);
      }
    }

    // Create generalized patterns for common prefixes/suffixes
    for (const [prefix, patterns] of prefixPatterns) {
      if (patterns.length >= 3) {
        // Check if generalized pattern already exists
        const generalized = this.learnedPatterns.find(
          p => p.pattern === prefix && p.isGeneralized
        );
        if (!generalized) {
          const avgConfidence = patterns.reduce((sum, p) => sum + p.averageConfidence, 0) / patterns.length;
          this.learnedPatterns.push({
            pattern: prefix,
            targetBrand: '*', // Matches any brand
            targetDomain: '*',
            attackType: 'cousin',
            occurrences: patterns.reduce((sum, p) => sum + p.occurrences, 0),
            averageConfidence: avgConfidence,
            isGeneralized: true,
            lastSeen: new Date(),
            feedbackScore: 0,
          });
        }
      }
    }

    for (const [suffix, patterns] of suffixPatterns) {
      if (patterns.length >= 3) {
        const generalized = this.learnedPatterns.find(
          p => p.pattern === suffix && p.isGeneralized
        );
        if (!generalized) {
          const avgConfidence = patterns.reduce((sum, p) => sum + p.averageConfidence, 0) / patterns.length;
          this.learnedPatterns.push({
            pattern: suffix,
            targetBrand: '*',
            targetDomain: '*',
            attackType: 'cousin',
            occurrences: patterns.reduce((sum, p) => sum + p.occurrences, 0),
            averageConfidence: avgConfidence,
            isGeneralized: true,
            lastSeen: new Date(),
            feedbackScore: 0,
          });
        }
      }
    }
  }

  private applyFeedbackToPatterns(feedback: DetectionFeedback): void {
    // Find related patterns - match by domain directly for more accurate feedback application
    for (const pattern of this.learnedPatterns) {
      const domainMatches = this.matchesPattern(feedback.attackerDomain, pattern);
      // Also match directly to the domain for precise feedback
      const directMatch = feedback.attackerDomain.split('.')[0].toLowerCase().includes(
        pattern.pattern.replace(/-/g, '').toLowerCase()
      ) || pattern.pattern.includes(feedback.attackerDomain.split('.')[0].toLowerCase().substring(0, 4));

      if (domainMatches || directMatch) {
        // Adjust feedback score
        const adjustment = feedback.wasCorrect && feedback.confirmedThreat ? 0.15 : -0.2;
        const sourceWeight = feedback.feedbackSource === 'analyst' ? 1.5 :
                            feedback.feedbackSource === 'automated' ? 0.8 : 1.0;
        pattern.feedbackScore = Math.max(-1, Math.min(1,
          pattern.feedbackScore + adjustment * sourceWeight
        ));

        // Adjust confidence based on feedback with stronger effect
        if (feedback.wasCorrect && feedback.confirmedThreat) {
          pattern.averageConfidence = Math.min(1, pattern.averageConfidence + 0.03);
        } else if (!feedback.wasCorrect) {
          // Stronger penalty for false positives
          pattern.averageConfidence = Math.max(0, pattern.averageConfidence - 0.1);
        }
      }
    }
  }

  private matchesPattern(domain: string, pattern: LearnedPattern): boolean {
    const domainBase = domain.split('.')[0].toLowerCase();

    if (pattern.isGeneralized) {
      if (pattern.pattern.endsWith('-')) {
        return domainBase.startsWith(pattern.pattern.slice(0, -1));
      } else if (pattern.pattern.startsWith('-')) {
        return domainBase.endsWith(pattern.pattern.slice(1));
      }
    }

    return domainBase.includes(pattern.pattern.replace(/-/g, ''));
  }

  calculateAdaptiveConfidence(
    domain: string,
    targetBrand: string,
    baseConfidence: number
  ): number {
    let boost = 0;
    let penalty = 0;
    const domainBase = domain.split('.')[0].toLowerCase();

    // Find matching patterns
    for (const pattern of this.learnedPatterns) {
      // Check if domain matches this pattern's target brand
      const brandMatches = pattern.targetBrand === targetBrand || pattern.targetBrand === '*';
      // Also check cousin-style pattern matching
      const patternMatches = this.matchesPattern(domain, pattern) ||
        (pattern.attackType === 'cousin' && domainBase.includes(targetBrand.toLowerCase().substring(0, 4)));

      if (brandMatches && patternMatches) {
        // Apply confidence adjustment based on pattern history
        const occurrenceWeight = Math.min(10, pattern.occurrences) / 10; // Max 1.0 for 10+ occurrences
        const recency = this.calculateTimeWeight(pattern.lastSeen);

        if (pattern.feedbackScore > 0) {
          // Positive feedback boosts confidence
          boost += pattern.feedbackScore * 0.08 * (1 + occurrenceWeight) * recency;
        } else if (pattern.feedbackScore < 0) {
          // Negative feedback (false positives) reduces confidence
          penalty += Math.abs(pattern.feedbackScore) * 0.1 * (1 + occurrenceWeight);
        }
      }
    }

    const adjusted = baseConfidence + boost - penalty;
    return Math.max(0, Math.min(1, adjusted));
  }

  detect(tenantId: string | null, domain: string): LookalikeDetectionResult {
    if (!domain || domain.length < 3 || !domain.includes('.')) {
      return {
        isLookalike: false,
        baseConfidence: 0,
        learningBoost: 0,
        finalConfidence: 0,
        confidence: 0,
      };
    }

    const domainLower = domain.toLowerCase();
    const domainBase = domainLower.split('.')[0];

    // Check against tenant-specific brands first
    if (tenantId) {
      const tenantBrands = this.getTenantBrands(tenantId);
      for (const brand of tenantBrands) {
        const result = this.checkAgainstBrand(domainLower, domainBase, brand.domain, brand.brandName);
        if (result.isLookalike) {
          return this.applyLearningBoost(result, brand.brandName);
        }
      }
    }

    // Check against global protected brands
    for (const brand of PROTECTED_BRANDS) {
      const result = this.checkAgainstBrand(domainLower, domainBase, brand.domain, brand.brand);
      if (result.isLookalike) {
        return this.applyLearningBoost(result, brand.brand);
      }
    }

    // Check for learned patterns that might match (e.g., paypa1-new.com should match PayPal)
    const learnedResult = this.checkLearnedPatternMatch(domainLower, domainBase);
    if (learnedResult.isLookalike) {
      return learnedResult;
    }

    // Check for generalized patterns even without brand match
    const generalizedResult = this.checkGeneralizedPatterns(domainLower, domainBase);
    if (generalizedResult.isLookalike) {
      return generalizedResult;
    }

    return {
      isLookalike: false,
      baseConfidence: 0,
      learningBoost: 0,
      finalConfidence: 0,
      confidence: 0,
    };
  }

  private checkLearnedPatternMatch(
    fullDomain: string,
    domainBase: string
  ): LookalikeDetectionResult {
    // Check if domain matches any learned patterns with positive feedback
    for (const pattern of this.learnedPatterns) {
      if (pattern.feedbackScore > 0 && pattern.occurrences >= 2) {
        // Check for patterns in the domain (like paypa1 in paypa1-new)
        const patternBase = pattern.pattern.replace(/-/g, '').toLowerCase();
        const targetBase = pattern.targetDomain?.split('.')[0].toLowerCase() || '';

        // Check if domain contains a homoglyph/typosquat variant of a learned brand
        if (targetBase && this.containsLearnedVariant(domainBase, targetBase, pattern.attackType)) {
          const boost = pattern.feedbackScore * 0.1 * Math.min(pattern.occurrences, 10);
          const baseConf = pattern.averageConfidence * 0.9;
          return {
            isLookalike: true,
            targetBrand: pattern.targetBrand,
            targetDomain: pattern.targetDomain,
            attackType: pattern.attackType,
            baseConfidence: baseConf,
            learningBoost: boost,
            finalConfidence: Math.min(1, baseConf + boost),
            confidence: Math.min(1, baseConf + boost),
            matchedPattern: pattern,
          };
        }
      }
    }

    return {
      isLookalike: false,
      baseConfidence: 0,
      learningBoost: 0,
      finalConfidence: 0,
      confidence: 0,
    };
  }

  private containsLearnedVariant(
    testDomain: string,
    brandBase: string,
    attackType: 'homoglyph' | 'typosquat' | 'cousin'
  ): boolean {
    // Extract core part from test domain (handle prefixes/suffixes like paypa1-new -> paypa1)
    const parts = testDomain.split('-');
    for (const part of parts) {
      if (part.length >= brandBase.length - 1) {
        // Check for homoglyph pattern
        if (attackType === 'homoglyph' && part.length === brandBase.length) {
          let homoglyphCount = 0;
          let mismatchCount = 0;
          for (let i = 0; i < part.length; i++) {
            if (part[i] !== brandBase[i]) {
              if (this.isHomoglyph(part[i], brandBase[i])) {
                homoglyphCount++;
              } else {
                mismatchCount++;
              }
            }
          }
          if (homoglyphCount > 0 && mismatchCount === 0) {
            return true;
          }
        }

        // Check for typosquat pattern
        if (attackType === 'typosquat') {
          const dist = this.levenshteinDistance(part, brandBase);
          if (dist === 1 || dist === 2) {
            return true;
          }
        }
      }
    }

    return false;
  }

  private checkAgainstBrand(
    fullDomain: string,
    domainBase: string,
    brandDomain: string,
    brandName: string
  ): LookalikeDetectionResult {
    const brandBase = brandDomain.split('.')[0].toLowerCase();

    // Skip exact matches and subdomains
    if (fullDomain === brandDomain.toLowerCase() ||
        fullDomain.endsWith('.' + brandDomain.toLowerCase())) {
      return {
        isLookalike: false,
        baseConfidence: 0,
        learningBoost: 0,
        finalConfidence: 0,
      };
    }

    // Check for homoglyph attack
    const homoglyphResult = this.detectHomoglyph(domainBase, brandBase, brandName, brandDomain);
    if (homoglyphResult.isLookalike) {
      return homoglyphResult;
    }

    // Check for typosquat attack
    const typosquatResult = this.detectTyposquat(domainBase, brandBase, brandName, brandDomain);
    if (typosquatResult.isLookalike) {
      return typosquatResult;
    }

    // Check for cousin domain attack
    const cousinResult = this.detectCousin(domainBase, brandBase, brandName, brandDomain);
    if (cousinResult.isLookalike) {
      return cousinResult;
    }

    return {
      isLookalike: false,
      baseConfidence: 0,
      learningBoost: 0,
      finalConfidence: 0,
    };
  }

  private detectHomoglyph(
    testBase: string,
    brandBase: string,
    brandName: string,
    brandDomain: string
  ): LookalikeDetectionResult {
    if (testBase.length !== brandBase.length) {
      return { isLookalike: false, baseConfidence: 0, learningBoost: 0, finalConfidence: 0 };
    }

    let homoglyphCount = 0;
    for (let i = 0; i < testBase.length; i++) {
      const testChar = testBase[i];
      const brandChar = brandBase[i];

      if (testChar !== brandChar) {
        // Check if it's a homoglyph
        const isHomo = this.isHomoglyph(testChar, brandChar);
        if (isHomo) {
          homoglyphCount++;
        } else {
          // Not a homoglyph, might be typosquat
          return { isLookalike: false, baseConfidence: 0, learningBoost: 0, finalConfidence: 0 };
        }
      }
    }

    if (homoglyphCount > 0) {
      const confidence = 0.9 - (homoglyphCount - 1) * 0.05;
      return {
        isLookalike: true,
        targetBrand: brandName,
        targetDomain: brandDomain,
        attackType: 'homoglyph',
        baseConfidence: confidence,
        learningBoost: 0,
        finalConfidence: confidence,
      };
    }

    return { isLookalike: false, baseConfidence: 0, learningBoost: 0, finalConfidence: 0 };
  }

  private isHomoglyph(testChar: string, targetChar: string): boolean {
    const normalizedTarget = targetChar.toLowerCase();
    const normalizedTest = testChar.toLowerCase();

    if (normalizedTest === normalizedTarget) return false;

    const homoglyphsForTarget = HOMOGLYPHS[normalizedTarget] || [];
    return homoglyphsForTarget.includes(testChar) || homoglyphsForTarget.includes(normalizedTest);
  }

  private detectTyposquat(
    testBase: string,
    brandBase: string,
    brandName: string,
    brandDomain: string
  ): LookalikeDetectionResult {
    const distance = this.levenshteinDistance(testBase, brandBase);

    // Allow 1-2 character difference for typosquat
    if (distance >= 1 && distance <= 2 && brandBase.length >= 4) {
      const confidence = distance === 1 ? 0.85 : 0.7;
      return {
        isLookalike: true,
        targetBrand: brandName,
        targetDomain: brandDomain,
        attackType: 'typosquat',
        baseConfidence: confidence,
        learningBoost: 0,
        finalConfidence: confidence,
      };
    }

    return { isLookalike: false, baseConfidence: 0, learningBoost: 0, finalConfidence: 0 };
  }

  private detectCousin(
    testBase: string,
    brandBase: string,
    brandName: string,
    brandDomain: string
  ): LookalikeDetectionResult {
    // Common cousin patterns
    const cousinPatterns = [
      'secure-', 'login-', 'my-', 'account-', 'support-', 'help-',
      'service-', 'online-', 'portal-', 'mail-', 'web-', 'app-',
      '-secure', '-login', '-verify', '-account', '-support', '-help',
      '-service', '-online', '-portal', '-access', '-update', '-alert',
    ];

    for (const pattern of cousinPatterns) {
      let candidate: string;
      if (pattern.startsWith('-')) {
        candidate = brandBase + pattern;
      } else {
        candidate = pattern + brandBase;
      }

      // Check for exact match or close match
      if (testBase === candidate || this.levenshteinDistance(testBase, candidate) <= 1) {
        return {
          isLookalike: true,
          targetBrand: brandName,
          targetDomain: brandDomain,
          attackType: 'cousin',
          baseConfidence: 0.75,
          learningBoost: 0,
          finalConfidence: 0.75,
        };
      }
    }

    // Also check if test domain contains brand name with other text
    if (testBase.includes(brandBase) && testBase !== brandBase && testBase.length > brandBase.length + 2) {
      return {
        isLookalike: true,
        targetBrand: brandName,
        targetDomain: brandDomain,
        attackType: 'cousin',
        baseConfidence: 0.65,
        learningBoost: 0,
        finalConfidence: 0.65,
      };
    }

    return { isLookalike: false, baseConfidence: 0, learningBoost: 0, finalConfidence: 0 };
  }

  private checkGeneralizedPatterns(
    fullDomain: string,
    domainBase: string
  ): LookalikeDetectionResult {
    for (const pattern of this.learnedPatterns) {
      if (pattern.isGeneralized && pattern.feedbackScore > 0) {
        if (this.matchesPattern(fullDomain, pattern)) {
          const baseConf = pattern.averageConfidence * 0.8;
          const boost = pattern.feedbackScore * 0.1;
          const finalConf = Math.min(1, baseConf + boost);
          return {
            isLookalike: true,
            attackType: pattern.attackType,
            baseConfidence: baseConf,
            learningBoost: boost,
            finalConfidence: finalConf,
            confidence: finalConf, // Add for test compatibility
            matchedPattern: pattern,
          };
        }
      }
    }

    return { isLookalike: false, baseConfidence: 0, learningBoost: 0, finalConfidence: 0, confidence: 0 };
  }

  private applyLearningBoost(
    result: LookalikeDetectionResult,
    brandName: string
  ): LookalikeDetectionResult {
    let boost = 0;

    // Find relevant learned patterns
    for (const pattern of this.learnedPatterns) {
      if (pattern.targetBrand === brandName && pattern.feedbackScore > 0) {
        boost += pattern.feedbackScore * 0.05 * Math.min(pattern.occurrences, 10);
      }
    }

    // Also check for generalized patterns that match this detection
    for (const pattern of this.learnedPatterns) {
      if (pattern.isGeneralized && pattern.feedbackScore > 0) {
        boost += pattern.feedbackScore * 0.05;
      }
    }

    result.learningBoost = boost;
    result.finalConfidence = Math.min(1, result.baseConfidence + boost);
    result.confidence = result.finalConfidence; // Set for test compatibility

    return result;
  }
}

// ============================================================================
// Module-level Functions (Convenience API)
// ============================================================================

export function addTenantBrand(
  service: LookalikeLearningService,
  tenantId: string,
  brand: TenantBrand
): void {
  service.addTenantBrand(tenantId, brand);
}

export function getTenantBrands(
  service: LookalikeLearningService,
  tenantId: string
): TenantBrand[] {
  return service.getTenantBrands(tenantId);
}

export function recordLookalikeDetection(
  service: LookalikeLearningService,
  detection: LookalikeDetection
): void {
  service.recordDetection(detection);
}

export function recordFeedback(
  service: LookalikeLearningService,
  feedback: DetectionFeedback
): void {
  service.recordFeedback(feedback);
}

export function getLearnedPatterns(
  service: LookalikeLearningService
): LearnedPattern[] {
  return service.getLearnedPatterns();
}

export function calculateAdaptiveConfidence(
  service: LookalikeLearningService,
  domain: string,
  targetBrand: string,
  baseConfidence: number
): number {
  return service.calculateAdaptiveConfidence(domain, targetBrand, baseConfidence);
}

export function detectWithLearning(
  service: LookalikeLearningService,
  tenantId: string | null,
  domain: string
): LookalikeDetectionResult {
  return service.detect(tenantId, domain);
}
