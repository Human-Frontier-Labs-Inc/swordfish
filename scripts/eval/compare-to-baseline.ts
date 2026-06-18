#!/usr/bin/env tsx
/**
 * Detection-eval accuracy gate — compare a run against the committed baseline
 * and fail (exit 1) on regression.
 *
 * Pure logic (compareAgainstBaseline / metricsFromSummary) is unit-tested in
 * tests/eval/compare-to-baseline.test.ts; the CLI main() reads two JSON files,
 * prints the deltas, and exits non-zero on failure so CI can gate on it.
 *
 * Gate (defaults, overridable via thresholds):
 *   - binary F1 drops more than 2 points vs baseline  → FAIL
 *   - ham false-positive rate rises more than 1 point  → FAIL
 * Binary F1 is the primary safe-vs-threat accuracy number; ham-FPR is the
 * "don't quarantine real mail" guarantee. Both are load-bearing for the pitch.
 */

import { readFile } from 'node:fs/promises';
import type { EvalSummary } from './reporter';
export type { EvalSummary } from './reporter';

export interface BaselineMetrics {
  binaryF1: number;
  binaryPrecision: number;
  binaryRecall: number;
  hamFalsePositiveRate: number;
  catchRates?: {
    bec?: number;
    phishing?: number;
    spam?: number;
    safe?: number;
  };
}

export interface GateThresholds {
  /** Fail if (baseline.binaryF1 - current.binaryF1) exceeds this. Default 0.02 (2 pts). */
  maxBinaryF1Drop: number;
  /** Fail if (current.hamFpr - baseline.hamFpr) exceeds this. Default 0.01 (1 pt). */
  maxHamFprIncrease: number;
}

export const DEFAULT_THRESHOLDS: GateThresholds = {
  maxBinaryF1Drop: 0.02,
  maxHamFprIncrease: 0.01,
};

export interface MetricDelta {
  binaryF1: number; // current - baseline (positive = improved)
  binaryPrecision: number;
  binaryRecall: number;
  hamFpr: number; // current - baseline (positive = WORSE)
}

export interface ComparisonResult {
  pass: boolean;
  deltas: MetricDelta;
  failures: string[];
}

function pct(x: number): string {
  return `${(x * 100).toFixed(2)}%`;
}

export function compareAgainstBaseline(
  current: BaselineMetrics,
  baseline: BaselineMetrics,
  thresholds: GateThresholds = DEFAULT_THRESHOLDS
): ComparisonResult {
  const deltas: MetricDelta = {
    binaryF1: current.binaryF1 - baseline.binaryF1,
    binaryPrecision: current.binaryPrecision - baseline.binaryPrecision,
    binaryRecall: current.binaryRecall - baseline.binaryRecall,
    hamFpr: current.hamFalsePositiveRate - baseline.hamFalsePositiveRate,
  };

  const failures: string[] = [];

  const f1Drop = baseline.binaryF1 - current.binaryF1;
  if (f1Drop > thresholds.maxBinaryF1Drop) {
    failures.push(
      `binary F1 dropped ${pct(f1Drop)} (baseline ${pct(baseline.binaryF1)} → current ${pct(current.binaryF1)}); max allowed drop is ${pct(thresholds.maxBinaryF1Drop)}`
    );
  }

  if (deltas.hamFpr > thresholds.maxHamFprIncrease) {
    failures.push(
      `ham false-positive rate rose ${pct(deltas.hamFpr)} (baseline ${pct(baseline.hamFalsePositiveRate)} → current ${pct(current.hamFalsePositiveRate)}); max allowed rise is ${pct(thresholds.maxHamFprIncrease)}`
    );
  }

  return { pass: failures.length === 0, deltas, failures };
}

/** Project the comparable metrics out of an eval run summary. */
export function metricsFromSummary(summary: EvalSummary): BaselineMetrics {
  return {
    binaryF1: summary.binary.f1,
    binaryPrecision: summary.binary.precision,
    binaryRecall: summary.binary.recall,
    hamFalsePositiveRate: summary.binary.falsePositiveRate,
    catchRates: {
      bec: summary.catchRates.bec.rate,
      phishing: summary.catchRates.phishing.rate,
      spam: summary.catchRates.spam.rate,
      safe: summary.catchRates.safe.rate,
    },
  };
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const get = (key: string): string | undefined => {
    const i = argv.indexOf(`--${key}`);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  };
  const summaryPath = get('summary');
  const baselinePath = get('baseline');
  if (!summaryPath || !baselinePath) {
    process.stderr.write(
      'usage: compare-to-baseline --summary <run summary.json> --baseline <docs/eval/baseline.json>\n'
    );
    process.exit(2);
  }

  const [summary, baseline] = await Promise.all([
    readJson<EvalSummary>(summaryPath),
    readJson<BaselineMetrics>(baselinePath),
  ]);
  const result = compareAgainstBaseline(metricsFromSummary(summary), baseline);

  const d = result.deltas;
  process.stdout.write(
    `binary F1: ${d.binaryF1 >= 0 ? '+' : ''}${pct(Math.abs(d.binaryF1))}  ·  ` +
      `precision: ${d.binaryPrecision >= 0 ? '+' : ''}${pct(Math.abs(d.binaryPrecision))}  ·  ` +
      `recall: ${d.binaryRecall >= 0 ? '+' : ''}${pct(Math.abs(d.binaryRecall))}  ·  ` +
      `ham-FPR: ${d.hamFpr >= 0 ? '+' : ''}${pct(Math.abs(d.hamFpr))}\n`
  );

  if (result.pass) {
    process.stdout.write('accuracy gate: PASS\n');
    process.exit(0);
  }
  process.stderr.write(`accuracy gate: FAIL\n${result.failures.map((f) => `  - ${f}`).join('\n')}\n`);
  process.exit(1);
}

// Run the CLI only when invoked directly (not when imported by tests).
const invokedDirectly = process.argv[1]?.endsWith('compare-to-baseline.ts');
if (invokedDirectly) {
  main().catch((err) => {
    process.stderr.write(`compare-to-baseline failed: ${err}\n`);
    process.exit(1);
  });
}
