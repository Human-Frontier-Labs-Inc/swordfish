/**
 * Unit tests for scripts/eval/predict.ts. Expected values are hand-computed.
 */

import { describe, it, expect } from 'vitest';
import {
  verdictIsThreat,
  isThreatLabel,
  computeBinaryMetrics,
  catchRateByClass,
} from '../../scripts/eval/predict';

describe('verdictIsThreat / isThreatLabel', () => {
  it('treats only "pass" as safe', () => {
    expect(verdictIsThreat('pass')).toBe(false);
    expect(verdictIsThreat('suspicious')).toBe(true);
    expect(verdictIsThreat('quarantine')).toBe(true);
    expect(verdictIsThreat('block')).toBe(true);
  });

  it('treats only "safe" as non-threat', () => {
    expect(isThreatLabel('safe')).toBe(false);
    expect(isThreatLabel('spam')).toBe(true);
    expect(isThreatLabel('phishing')).toBe(true);
    expect(isThreatLabel('bec')).toBe(true);
  });
});

describe('computeBinaryMetrics', () => {
  it('mixed case — hand-computed TP/FP/FN/TN, P/R/F1, accuracy, FPR', () => {
    // actual:    T, T, F, F
    // predicted: T, F, T, F
    const m = computeBinaryMetrics(
      [true, true, false, false],
      [true, false, true, false]
    );
    expect(m.truePositives).toBe(1);
    expect(m.falseNegatives).toBe(1);
    expect(m.falsePositives).toBe(1);
    expect(m.trueNegatives).toBe(1);
    expect(m.precision).toBeCloseTo(0.5);
    expect(m.recall).toBeCloseTo(0.5);
    expect(m.f1).toBeCloseTo(0.5);
    expect(m.accuracy).toBeCloseTo(0.5);
    expect(m.falsePositiveRate).toBeCloseTo(0.5);
  });

  it('perfect prediction', () => {
    const m = computeBinaryMetrics(
      [true, true, false, false],
      [true, true, false, false]
    );
    expect(m.truePositives).toBe(2);
    expect(m.trueNegatives).toBe(2);
    expect(m.falsePositives).toBe(0);
    expect(m.falseNegatives).toBe(0);
    expect(m.precision).toBe(1);
    expect(m.recall).toBe(1);
    expect(m.f1).toBe(1);
    expect(m.accuracy).toBe(1);
    expect(m.falsePositiveRate).toBe(0);
  });

  it('flags nothing (all pass) → zero precision/recall, FPR 0', () => {
    // actual: T, F ; predicted: F, F (pipeline passes everything)
    const m = computeBinaryMetrics([true, false], [false, false]);
    expect(m.truePositives).toBe(0);
    expect(m.falseNegatives).toBe(1);
    expect(m.falsePositives).toBe(0);
    expect(m.trueNegatives).toBe(1);
    expect(m.precision).toBe(0);
    expect(m.recall).toBe(0);
    expect(m.f1).toBe(0);
    expect(m.accuracy).toBeCloseTo(0.5);
    expect(m.falsePositiveRate).toBe(0);
  });

  it('throws on length mismatch', () => {
    expect(() => computeBinaryMetrics([true], [true, false])).toThrow();
  });
});

describe('catchRateByClass', () => {
  it('per-class catch rate without needing a predicted class', () => {
    // actual: safe, safe, phishing, phishing, bec
    // caught: F,    T,    T,         T,         F
    const rates = catchRateByClass(
      ['safe', 'safe', 'phishing', 'phishing', 'bec'],
      [false, true, true, true, false]
    );
    expect(rates.safe.support).toBe(2);
    expect(rates.safe.caught).toBe(1);
    expect(rates.safe.rate).toBeCloseTo(0.5);
    expect(rates.phishing.support).toBe(2);
    expect(rates.phishing.caught).toBe(2);
    expect(rates.phishing.rate).toBe(1);
    expect(rates.bec.support).toBe(1);
    expect(rates.bec.caught).toBe(0);
    expect(rates.bec.rate).toBe(0);
    expect(rates.spam.support).toBe(0);
    expect(rates.spam.rate).toBe(0);
  });

  it('throws on length mismatch', () => {
    expect(() =>
      catchRateByClass(['safe', 'phishing'], [true])
    ).toThrow();
  });
});
