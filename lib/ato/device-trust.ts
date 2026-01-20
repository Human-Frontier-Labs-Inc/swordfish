/**
 * Device Trust Scoring
 *
 * Calculates trust scores for devices based on various factors
 * including age, usage patterns, approval status, and consistency.
 */

// ============================================================================
// Types
// ============================================================================

export interface TrustFactors {
  /** Number of days since device was first seen */
  ageInDays: number;
  /** Total number of successful logins from this device */
  loginCount: number;
  /** Days since last login */
  lastLoginDaysAgo: number;
  /** Whether the device has been manually approved */
  isApproved: boolean;
  /** Whether login locations are consistent */
  consistentLocation: boolean;
  /** Whether usage patterns (time of day, frequency) are consistent */
  consistentUsagePattern: boolean;
}

export interface TrustScoreBreakdown {
  /** Final trust score (0-100) */
  score: number;
  /** Score contribution from device age */
  ageScore: number;
  /** Score contribution from login frequency */
  frequencyScore: number;
  /** Score contribution from recency of use */
  recencyScore: number;
  /** Score contribution from approval status */
  approvalScore: number;
  /** Score contribution from location consistency */
  locationScore: number;
  /** Score contribution from usage pattern consistency */
  patternScore: number;
}

// ============================================================================
// Score Calculation
// ============================================================================

/**
 * Calculate device trust score based on various factors
 * Returns a score from 0-100
 */
export function calculateDeviceTrustScore(factors: TrustFactors): number {
  const breakdown = calculateTrustScoreBreakdown(factors);
  return breakdown.score;
}

/**
 * Calculate trust score with full breakdown of contributing factors
 */
export function calculateTrustScoreBreakdown(
  factors: TrustFactors
): TrustScoreBreakdown {
  // Weights for each factor (total = 100)
  const weights = {
    age: 15,
    frequency: 15,
    recency: 15,
    approval: 25,
    location: 15,
    pattern: 15,
  };

  // Age score (max 15 points)
  // Devices older than 90 days get full score
  const ageScore = Math.min(factors.ageInDays / 90, 1) * weights.age;

  // Frequency score (max 15 points)
  // Devices with 50+ logins get full score
  const frequencyScore = Math.min(factors.loginCount / 50, 1) * weights.frequency;

  // Recency score (max 15 points)
  // Devices used recently get higher scores
  // Score decreases as lastLoginDaysAgo increases
  let recencyMultiplier = 1;
  if (factors.lastLoginDaysAgo > 90) {
    recencyMultiplier = 0;
  } else if (factors.lastLoginDaysAgo > 60) {
    recencyMultiplier = 0.25;
  } else if (factors.lastLoginDaysAgo > 30) {
    recencyMultiplier = 0.5;
  } else if (factors.lastLoginDaysAgo > 14) {
    recencyMultiplier = 0.75;
  }
  const recencyScore = recencyMultiplier * weights.recency;

  // Approval score (max 25 points)
  // Approved devices get a significant boost
  const approvalScore = factors.isApproved ? weights.approval : 0;

  // Location consistency score (max 15 points)
  const locationScore = factors.consistentLocation ? weights.location : 0;

  // Usage pattern score (max 15 points)
  const patternScore = factors.consistentUsagePattern ? weights.pattern : 0;

  // Calculate total
  const totalScore =
    ageScore +
    frequencyScore +
    recencyScore +
    approvalScore +
    locationScore +
    patternScore;

  // Round to nearest integer
  const score = Math.round(totalScore);

  return {
    score,
    ageScore: Math.round(ageScore * 10) / 10,
    frequencyScore: Math.round(frequencyScore * 10) / 10,
    recencyScore: Math.round(recencyScore * 10) / 10,
    approvalScore: Math.round(approvalScore * 10) / 10,
    locationScore: Math.round(locationScore * 10) / 10,
    patternScore: Math.round(patternScore * 10) / 10,
  };
}

/**
 * Determine if a device should be considered trusted based on score
 */
export function isDeviceTrusted(
  score: number,
  threshold: number = 50
): boolean {
  return score >= threshold;
}

/**
 * Get trust level category based on score
 */
export function getTrustLevel(
  score: number
): 'untrusted' | 'low' | 'medium' | 'high' | 'verified' {
  if (score < 20) return 'untrusted';
  if (score < 40) return 'low';
  if (score < 60) return 'medium';
  if (score < 80) return 'high';
  return 'verified';
}

/**
 * Calculate the minimum trust factors needed for a given score threshold
 */
export function getRequiredFactorsForScore(
  targetScore: number
): Partial<TrustFactors> {
  // This is a helper for understanding what's needed to reach a trust level
  if (targetScore >= 80) {
    return {
      ageInDays: 90,
      loginCount: 50,
      lastLoginDaysAgo: 0,
      isApproved: true,
      consistentLocation: true,
      consistentUsagePattern: true,
    };
  }

  if (targetScore >= 50) {
    return {
      ageInDays: 30,
      loginCount: 20,
      isApproved: true,
      consistentLocation: true,
    };
  }

  return {
    ageInDays: 7,
    loginCount: 5,
  };
}

// Default export
export default calculateDeviceTrustScore;
