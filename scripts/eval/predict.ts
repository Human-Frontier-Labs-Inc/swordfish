/**
 * Prediction helpers for the detection eval harness.
 *
 * Why this module exists: the pipeline's `analyzeEmail` returns an
 * `EmailVerdict` with a SEVERITY verdict (`pass | suspicious | quarantine |
 * block`) + score + signals, but NO native threat-class label (its
 * `emailClassification` only categorizes legitimate email type —
 * marketing/transactional/automated/personal). So we can't ask "did the
 * pipeline predict phishing vs bec" without deriving it from signals
 * (a heuristic). Instead we evaluate two defensible things:
 *
 *   1. Binary safe-vs-threat — verdict non-pass == predicted threat. Gives
 *      precision/recall/F1/accuracy and the ham false-positive rate (launch
 *      target ≤ 1%).
 *   2. Per-class catch rate — of actual-<class> samples, the fraction the
 *      pipeline flagged (verdict non-pass). This is real recall-by-class
 *      ("we catch X% of BEC") and needs NO predicted class.
 *
 * Full per-class precision (requires a signal-derived predicted class) is a
 * documented follow-up, not silently invented here.
 *
 * Pure logic, no deps. Unit-tested in tests/eval/predict.test.ts.
 */

import { EVAL_LABELS, type EvalLabel } from './metrics';

export type Verdict = 'pass' | 'suspicious' | 'quarantine' | 'block';

/** Corpus labels that represent threats (everything except ham). */
export const THREAT_LABELS: readonly EvalLabel[] = ['spam', 'phishing', 'bec'];

export function isThreatLabel(label: EvalLabel): boolean {
  return label !== 'safe';
}

/** A non-pass verdict means the pipeline flagged the email as a threat. */
export function verdictIsThreat(verdict: Verdict): boolean {
  return verdict !== 'pass';
}

export interface BinaryMetrics {
  total: number;
  truePositives: number; // actual threat, predicted threat (caught)
  falsePositives: number; // actual safe, predicted threat (ham flagged)
  falseNegatives: number; // actual threat, predicted safe (missed)
  trueNegatives: number; // actual safe, predicted safe
  precision: number; // TP / (TP + FP)
  recall: number; // TP / (TP + FN) — overall threat catch rate
  f1: number;
  accuracy: number;
  /** Fraction of actual-safe (ham) flagged as a threat. Launch target ≤ 1%. */
  falsePositiveRate: number;
}

function safeDiv(numerator: number, denominator: number): number {
  return denominator > 0 ? numerator / denominator : 0;
}

/**
 * Binary safe-vs-threat metrics.
 *
 * @param actualIsThreat    Ground truth per sample (corpus label != safe).
 * @param predictedIsThreat Pipeline prediction per sample (verdict non-pass).
 */
export function computeBinaryMetrics(
  actualIsThreat: readonly boolean[],
  predictedIsThreat: readonly boolean[]
): BinaryMetrics {
  if (actualIsThreat.length !== predictedIsThreat.length) {
    throw new Error(
      `computeBinaryMetrics: actual length (${actualIsThreat.length}) must equal predicted length (${predictedIsThreat.length})`
    );
  }

  let tp = 0;
  let fp = 0;
  let fn = 0;
  let tn = 0;
  for (let i = 0; i < actualIsThreat.length; i++) {
    const a = actualIsThreat[i];
    const p = predictedIsThreat[i];
    if (a && p) tp++;
    else if (!a && p) fp++;
    else if (a && !p) fn++;
    else tn++;
  }

  const precision = safeDiv(tp, tp + fp);
  const recall = safeDiv(tp, tp + fn);
  const f1 = safeDiv(2 * precision * recall, precision + recall);
  const accuracy = safeDiv(tp + tn, actualIsThreat.length);
  const falsePositiveRate = safeDiv(fp, fp + tn);

  return {
    total: actualIsThreat.length,
    truePositives: tp,
    falsePositives: fp,
    falseNegatives: fn,
    trueNegatives: tn,
    precision,
    recall,
    f1,
    accuracy,
    falsePositiveRate,
  };
}

export interface ClassCatchRate {
  /** Actual count for this class in the corpus. */
  support: number;
  /** Count flagged by the pipeline (verdict non-pass). */
  caught: number;
  /** caught / support; 0 when support is 0. */
  rate: number;
}

/**
 * Per-class catch rate: of actual-<class> samples, the fraction the pipeline
 * flagged. The key "do we catch BEC / phishing / spam" figure. Needs no
 * predicted class — only whether each sample was caught.
 *
 * @param actual Ground-truth corpus label per sample.
 * @param caught Whether the pipeline flagged the sample (verdict non-pass).
 */
export function catchRateByClass(
  actual: readonly EvalLabel[],
  caught: readonly boolean[]
): Record<EvalLabel, ClassCatchRate> {
  if (actual.length !== caught.length) {
    throw new Error(
      `catchRateByClass: actual length (${actual.length}) must equal caught length (${caught.length})`
    );
  }

  const result = {} as Record<EvalLabel, ClassCatchRate>;
  for (const label of EVAL_LABELS) {
    result[label] = { support: 0, caught: 0, rate: 0 };
  }
  for (let i = 0; i < actual.length; i++) {
    const bucket = result[actual[i]];
    bucket.support++;
    if (caught[i]) bucket.caught++;
  }
  for (const label of EVAL_LABELS) {
    result[label].rate = safeDiv(result[label].caught, result[label].support);
  }
  return result;
}
