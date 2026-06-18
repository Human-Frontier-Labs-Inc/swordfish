/**
 * Unit tests for scripts/eval/threshold-sweep.ts. Hand-computed.
 */

import { describe, it, expect } from 'vitest';
import {
  sweepThresholds,
  DEFAULT_THRESHOLDS,
} from '../../scripts/eval/threshold-sweep';

describe('DEFAULT_THRESHOLDS', () => {
  it('spans 25..95 step 5', () => {
    expect(DEFAULT_THRESHOLDS[0]).toBe(25);
    expect(DEFAULT_THRESHOLDS[DEFAULT_THRESHOLDS.length - 1]).toBe(95);
    expect(DEFAULT_THRESHOLDS).toHaveLength(15);
  });
});

describe('sweepThresholds', () => {
  // scores:  10, 40, 60, 90
  // actual:  F,  F,  T,  T
  const scores = [10, 40, 60, 90];
  const actual = [false, false, true, true];

  it('at threshold 50 → predicts [F,F,T,T] → perfect', () => {
    const points = sweepThresholds(scores, actual, [50]);
    const p = points[0];
    expect(p.truePositives).toBe(2);
    expect(p.falsePositives).toBe(0);
    expect(p.falseNegatives).toBe(0);
    expect(p.trueNegatives).toBe(2);
    expect(p.precision).toBe(1);
    expect(p.recall).toBe(1);
    expect(p.falsePositiveRate).toBe(0);
  });

  it('higher threshold lowers recall, precision stays 1 here', () => {
    const points = sweepThresholds(scores, actual, [70]);
    const p = points[0];
    // >=70 → [F,F,F,T]: TP=1 (idx3), FN=1 (idx2), FP=0, TN=2
    expect(p.truePositives).toBe(1);
    expect(p.falseNegatives).toBe(1);
    expect(p.falsePositives).toBe(0);
    expect(p.recall).toBeCloseTo(0.5);
    expect(p.precision).toBe(1);
  });

  it('low threshold flags everything → high FPR, full recall', () => {
    const points = sweepThresholds(scores, actual, [5]);
    const p = points[0];
    // >=5 → all threat: TP=2, FP=2, FN=0, TN=0
    expect(p.truePositives).toBe(2);
    expect(p.falsePositives).toBe(2);
    expect(p.recall).toBe(1);
    expect(p.precision).toBeCloseTo(0.5);
    expect(p.falsePositiveRate).toBe(1);
  });

  it('returns one point per threshold, ascending threshold', () => {
    const points = sweepThresholds(scores, actual, [60, 40, 50]);
    expect(points).toHaveLength(3);
    expect(points.map((p) => p.threshold)).toEqual([60, 40, 50]);
  });

  it('throws on length mismatch', () => {
    expect(() => sweepThresholds([10], [false, true])).toThrow();
  });
});
