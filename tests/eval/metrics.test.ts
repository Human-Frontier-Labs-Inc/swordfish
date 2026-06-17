/**
 * Unit tests for scripts/eval/metrics.ts.
 *
 * Every expected value below is hand-computed (not derived from the function
 * under test) so this is a real check on the math, not a tautology.
 */

import { describe, it, expect } from 'vitest';
import {
  computeMetrics,
  type EvalLabel,
} from '../../scripts/eval/metrics';

const L = (
  actual: EvalLabel[],
  predicted: EvalLabel[]
) => computeMetrics(actual, predicted);

describe('computeMetrics', () => {
  it('perfect prediction → P=R=F1=1, accuracy=1, safe FP rate=0', () => {
    const m = L(
      ['safe', 'spam', 'phishing', 'bec'],
      ['safe', 'spam', 'phishing', 'bec']
    );
    expect(m.total).toBe(4);
    expect(m.accuracy).toBe(1);
    expect(m.macroPrecision).toBe(1);
    expect(m.macroRecall).toBe(1);
    expect(m.macroF1).toBe(1);
    expect(m.microF1).toBe(1);
    expect(m.safeFalsePositiveRate).toBe(0);
    for (const c of m.perClass) {
      expect(c.precision).toBe(1);
      expect(c.recall).toBe(1);
      expect(c.f1).toBe(1);
      expect(c.support).toBe(1);
    }
  });

  it('mixed case — hand-computed P/R/F1, macro/micro, accuracy, safe FP rate', () => {
    // actual:    safe, safe, phishing, phishing, bec
    // predicted: safe, phishing, phishing, safe, bec
    const m = L(
      ['safe', 'safe', 'phishing', 'phishing', 'bec'],
      ['safe', 'phishing', 'phishing', 'safe', 'bec']
    );

    const byLabel = Object.fromEntries(m.perClass.map((c) => [c.label, c]));

    // safe: tp=1, fp=1 (idx3), fn=1 (idx1), support=2
    expect(byLabel.safe.truePositives).toBe(1);
    expect(byLabel.safe.falsePositives).toBe(1);
    expect(byLabel.safe.falseNegatives).toBe(1);
    expect(byLabel.safe.support).toBe(2);
    expect(byLabel.safe.precision).toBe(0.5);
    expect(byLabel.safe.recall).toBe(0.5);
    expect(byLabel.safe.f1).toBe(0.5);

    // phishing: tp=1, fp=1 (idx1), fn=1 (idx3), support=2
    expect(byLabel.phishing.precision).toBe(0.5);
    expect(byLabel.phishing.recall).toBe(0.5);
    expect(byLabel.phishing.f1).toBe(0.5);

    // bec: tp=1, fp=0, fn=0, support=1 → perfect
    expect(byLabel.bec.precision).toBe(1);
    expect(byLabel.bec.recall).toBe(1);
    expect(byLabel.bec.f1).toBe(1);

    // macro over {safe, phishing, bec}: (0.5 + 0.5 + 1) / 3
    expect(m.macroPrecision).toBeCloseTo(2 / 3);
    expect(m.macroRecall).toBeCloseTo(2 / 3);
    expect(m.macroF1).toBeCloseTo(2 / 3);

    // micro: pooled tp=3, fp=2, fn=2
    expect(m.microPrecision).toBeCloseTo(0.6);
    expect(m.microRecall).toBeCloseTo(0.6);
    expect(m.microF1).toBeCloseTo(0.6);

    // accuracy: 3 correct of 5
    expect(m.accuracy).toBeCloseTo(0.6);

    // safe FP rate: 1 of 2 safe mispredicted
    expect(m.safeFalsePositiveRate).toBeCloseTo(0.5);
  });

  it('all predicted as one class — hand-computed, exercises zero-precision path', () => {
    // actual:    safe, safe, phishing
    // predicted: phishing, phishing, phishing
    const m = L(
      ['safe', 'safe', 'phishing'],
      ['phishing', 'phishing', 'phishing']
    );
    const byLabel = Object.fromEntries(m.perClass.map((c) => [c.label, c]));

    // safe: never predicted → tp=0, fp=0, fn=2, support=2 → all zeros
    expect(byLabel.safe.truePositives).toBe(0);
    expect(byLabel.safe.falsePositives).toBe(0);
    expect(byLabel.safe.falseNegatives).toBe(2);
    expect(byLabel.safe.precision).toBe(0);
    expect(byLabel.safe.recall).toBe(0);
    expect(byLabel.safe.f1).toBe(0);

    // phishing: tp=1, fp=2, fn=0, support=1
    expect(byLabel.phishing.truePositives).toBe(1);
    expect(byLabel.phishing.falsePositives).toBe(2);
    expect(byLabel.phishing.recall).toBe(1);
    expect(byLabel.phishing.precision).toBeCloseTo(1 / 3);
    expect(byLabel.phishing.f1).toBeCloseTo(0.5); // 2*(1/3*1)/(1/3+1)

    // macro over {safe, phishing}: (0 + 1/3)/2 , (0 + 1)/2 , (0 + 0.5)/2
    expect(m.macroPrecision).toBeCloseTo(1 / 6);
    expect(m.macroRecall).toBeCloseTo(0.5);
    expect(m.macroF1).toBeCloseTo(0.25);

    // micro: tp=1, fp=2, fn=2 → 1/3
    expect(m.microF1).toBeCloseTo(1 / 3);
    expect(m.accuracy).toBeCloseTo(1 / 3);

    // both safe samples mispredicted → FP rate 1.0
    expect(m.safeFalsePositiveRate).toBe(1);
  });

  it('empty input does not throw and returns zeros', () => {
    const m = L([], []);
    expect(m.total).toBe(0);
    expect(m.accuracy).toBe(0);
    expect(m.perClass).toEqual([]);
    expect(m.macroF1).toBe(0);
    expect(m.microF1).toBe(0);
    expect(m.safeFalsePositiveRate).toBe(0);
    expect(m.confusion.matrix).toEqual([]);
  });

  it('throws on length mismatch', () => {
    expect(() => L(['safe'], ['safe', 'phishing'])).toThrow();
  });

  it('confusion matrix has correct shape and counts', () => {
    const m = L(
      ['safe', 'phishing'],
      ['phishing', 'phishing']
    );
    // labels present = {safe, phishing} → 2x2
    expect(m.confusion.labels).toEqual(['safe', 'phishing']);
    expect(m.confusion.matrix).toHaveLength(2);
    // matrix[actual][predicted]: actual safe→pred phishing (1), actual phishing→pred phishing (1)
    expect(m.confusion.matrix[0]).toEqual([0, 1]); // actual 'safe'
    expect(m.confusion.matrix[1]).toEqual([0, 1]); // actual 'phishing'
  });
});
