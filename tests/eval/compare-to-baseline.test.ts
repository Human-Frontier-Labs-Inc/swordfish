/**
 * Unit tests for scripts/eval/compare-to-baseline.ts. Hand-computed.
 */

import { describe, it, expect } from 'vitest';
import {
  compareAgainstBaseline,
  metricsFromSummary,
  DEFAULT_THRESHOLDS,
  type BaselineMetrics,
  type EvalSummary,
} from '../../scripts/eval/compare-to-baseline';

const base: BaselineMetrics = {
  binaryF1: 0.9,
  binaryPrecision: 0.92,
  binaryRecall: 0.88,
  hamFalsePositiveRate: 0.005,
};

describe('compareAgainstBaseline', () => {
  it('passes when current equals baseline (zero deltas)', () => {
    const r = compareAgainstBaseline(base, base);
    expect(r.pass).toBe(true);
    expect(r.failures).toEqual([]);
    expect(r.deltas.binaryF1).toBe(0);
    expect(r.deltas.hamFpr).toBe(0);
  });

  it('fails when binary F1 drops more than 2 pts', () => {
    const current: BaselineMetrics = { ...base, binaryF1: 0.87 }; // -3 pts
    const r = compareAgainstBaseline(current, base);
    expect(r.pass).toBe(false);
    expect(r.deltas.binaryF1).toBeCloseTo(-0.03);
    expect(r.failures.some((f) => f.includes('binary F1 dropped'))).toBe(true);
  });

  it('passes when binary F1 drops at most 2 pts', () => {
    const current: BaselineMetrics = { ...base, binaryF1: 0.89 }; // -1 pt
    const r = compareAgainstBaseline(current, base);
    expect(r.pass).toBe(true);
  });

  it('fails when ham FP rate rises more than 1 pt', () => {
    const current: BaselineMetrics = { ...base, hamFalsePositiveRate: 0.025 }; // +2 pts
    const r = compareAgainstBaseline(current, base);
    expect(r.pass).toBe(false);
    expect(r.deltas.hamFpr).toBeCloseTo(0.02);
    expect(r.failures.some((f) => f.includes('ham false-positive rate rose'))).toBe(true);
  });

  it('passes when both metrics improve', () => {
    const current: BaselineMetrics = {
      ...base,
      binaryF1: 0.95,
      hamFalsePositiveRate: 0.001,
    };
    const r = compareAgainstBaseline(current, base);
    expect(r.pass).toBe(true);
    expect(r.deltas.binaryF1).toBeGreaterThan(0);
    expect(r.deltas.hamFpr).toBeLessThan(0);
  });

  it('respects custom thresholds', () => {
    // A 1pt F1 drop passes the default (2pt) gate but fails a strict 0.5pt gate.
    const current: BaselineMetrics = { ...base, binaryF1: 0.89 };
    expect(compareAgainstBaseline(current, base).pass).toBe(true);
    expect(
      compareAgainstBaseline(current, base, { ...DEFAULT_THRESHOLDS, maxBinaryF1Drop: 0.005 }).pass
    ).toBe(false);
  });

  it('reports multiple failures together', () => {
    const current: BaselineMetrics = { ...base, binaryF1: 0.8, hamFalsePositiveRate: 0.05 };
    const r = compareAgainstBaseline(current, base);
    expect(r.pass).toBe(false);
    expect(r.failures.length).toBe(2);
  });
});

describe('metricsFromSummary', () => {
  it('projects binary + catch-rate metrics out of a run summary', () => {
    const summary: EvalSummary = {
      counts: { total: 100, skipped: 0, analyzed: 100, errors: 0, llmInvocations: 0 },
      binary: {
        total: 100,
        truePositives: 80,
        falsePositives: 5,
        falseNegatives: 15,
        trueNegatives: 0,
        precision: 0.94,
        recall: 0.84,
        f1: 0.88,
        accuracy: 0.8,
        falsePositiveRate: 0.01,
      },
      catchRates: {
        safe: { support: 50, caught: 1, rate: 0.02 },
        spam: { support: 20, caught: 18, rate: 0.9 },
        phishing: { support: 20, caught: 19, rate: 0.95 },
        bec: { support: 10, caught: 9, rate: 0.9 },
      },
      latency: { count: 100, mean: 50, p50: 45, p95: 120 },
    };
    const m = metricsFromSummary(summary);
    expect(m.binaryF1).toBe(0.88);
    expect(m.binaryPrecision).toBe(0.94);
    expect(m.binaryRecall).toBe(0.84);
    expect(m.hamFalsePositiveRate).toBe(0.01);
    expect(m.catchRates?.bec).toBe(0.9);
    expect(m.catchRates?.phishing).toBe(0.95);
  });
});
