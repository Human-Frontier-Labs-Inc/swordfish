/**
 * Threshold sweep — for a set of detection scores + ground truth, compute
 * binary safe-vs-threat P/R/F1/ham-FPR at each candidate score threshold.
 *
 * Used to pick the operating point (docs/audit/plans/stream-b.md Days 12-13):
 * "lowered quarantine to 68 to lift BEC recall +8pts at cost of +0.3% FP".
 * Pure logic; reuses computeBinaryMetrics so the counting has one home.
 */

import { computeBinaryMetrics } from './predict';

/** 25..95 step 5 — spans the pass/suspicious/quarantine/block thresholds (35/55/73/85). */
export const DEFAULT_THRESHOLDS: readonly number[] = Array.from(
  { length: (95 - 25) / 5 + 1 },
  (_, i) => 25 + i * 5
);

export interface ThresholdPoint {
  threshold: number;
  precision: number;
  recall: number;
  f1: number;
  falsePositiveRate: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
}

/**
 * @param scores        Per-sample detection score (overallScore, 0-100).
 * @param actualIsThreat Ground truth per sample.
 * @param thresholds    Candidate thresholds (predict threat when score >= threshold).
 */
export function sweepThresholds(
  scores: readonly number[],
  actualIsThreat: readonly boolean[],
  thresholds: readonly number[] = DEFAULT_THRESHOLDS
): ThresholdPoint[] {
  if (scores.length !== actualIsThreat.length) {
    throw new Error(
      `sweepThresholds: scores length (${scores.length}) must equal actual length (${actualIsThreat.length})`
    );
  }

  return thresholds.map((threshold) => {
    const predicted = scores.map((s) => s >= threshold);
    const m = computeBinaryMetrics(actualIsThreat, predicted);
    return {
      threshold,
      precision: m.precision,
      recall: m.recall,
      f1: m.f1,
      falsePositiveRate: m.falsePositiveRate,
      truePositives: m.truePositives,
      falsePositives: m.falsePositives,
      falseNegatives: m.falseNegatives,
      trueNegatives: m.trueNegatives,
    };
  });
}
