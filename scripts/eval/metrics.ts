/**
 * Detection-eval metrics — per-class precision/recall/F1, confusion matrix,
 * macro/micro averages, accuracy, and the safe-ham false-positive rate.
 *
 * Pure logic: no I/O, no deps. Unit-tested in tests/eval/metrics.test.ts.
 *
 * This is the analytical core of the eval harness (scripts/eval/run.ts). The
 * launch accuracy claim ("X% precision / Y% recall on a published benchmark")
 * is generated FROM these numbers, so the math has to be boring and correct.
 *
 * Label taxonomy matches the labeled-corpus schema in tests/fixtures/corpus/
 * (see docs/audit/plans/stream-b.md): safe | spam | phishing | bec.
 */

export type EvalLabel = 'safe' | 'spam' | 'phishing' | 'bec';

/** Canonical label ordering. macro/micro are computed over the labels that
 * actually appear in `actual` ∪ `predicted` (matching common ML tooling). */
export const EVAL_LABELS: readonly EvalLabel[] = [
  'safe',
  'spam',
  'phishing',
  'bec',
] as const;

export interface ConfusionMatrix {
  /** labels[i] is the label for row/column i */
  labels: EvalLabel[];
  /** matrix[actualIndex][predictedIndex] = count */
  matrix: number[][];
}

export interface PerClassMetrics {
  label: EvalLabel;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  /** actual count for this label (row sum) */
  support: number;
  /** tp / (tp + fp); 0 when the class was never predicted */
  precision: number;
  /** tp / (tp + fn); 0 when the class has no support */
  recall: number;
  /** harmonic mean of precision & recall; 0 when precision + recall == 0 */
  f1: number;
}

export interface EvalMetrics {
  total: number;
  accuracy: number;
  perClass: PerClassMetrics[];
  confusion: ConfusionMatrix;
  macroPrecision: number;
  macroRecall: number;
  macroF1: number;
  microPrecision: number;
  microRecall: number;
  microF1: number;
  /** Fraction of actual-'safe' samples predicted as non-safe.
   * The launch target is FP ≤ 1% on the ham corpus. 0 when no safe samples. */
  safeFalsePositiveRate: number;
}

function safeDiv(numerator: number, denominator: number): number {
  return denominator > 0 ? numerator / denominator : 0;
}

function indexOf(
  map: Map<EvalLabel, number>,
  label: EvalLabel,
  context: string
): number {
  const i = map.get(label);
  if (i === undefined) {
    throw new Error(`${context}: label "${label}" missing from index`);
  }
  return i;
}

/**
 * Compute classification metrics for a single-label multi-class evaluation.
 *
 * @param actual    Ground-truth labels, one per sample.
 * @param predicted Predicted labels, one per sample (same length).
 */
export function computeMetrics(
  actual: readonly EvalLabel[],
  predicted: readonly EvalLabel[]
): EvalMetrics {
  if (actual.length !== predicted.length) {
    throw new Error(
      `computeMetrics: actual length (${actual.length}) must equal predicted length (${predicted.length})`
    );
  }

  // Label universe = canonical labels that appear in either array.
  const present = new Set<EvalLabel>([...actual, ...predicted]);
  const labels = EVAL_LABELS.filter((l) => present.has(l));
  const index = new Map<EvalLabel, number>();
  labels.forEach((l, i) => index.set(l, i));
  const n = labels.length;

  // Confusion matrix[actual][predicted].
  const matrix: number[][] = Array.from({ length: n }, () =>
    new Array<number>(n).fill(0)
  );
  for (let i = 0; i < actual.length; i++) {
    const a = indexOf(index, actual[i], 'computeMetrics');
    const p = indexOf(index, predicted[i], 'computeMetrics');
    matrix[a][p]++;
  }

  // Per-class one-vs-rest + pooled totals for micro averaging.
  let totalTP = 0;
  let totalFP = 0;
  let totalFN = 0;
  const perClass: PerClassMetrics[] = labels.map((label, i) => {
    let truePositives = matrix[i][i];
    let falsePositives = 0;
    let falseNegatives = 0;
    let support = 0;
    for (let j = 0; j < n; j++) {
      support += matrix[i][j]; // row = actual count for label i
      if (j !== i) {
        falsePositives += matrix[j][i]; // predicted i but actually not
        falseNegatives += matrix[i][j]; // actually i but predicted not
      }
    }
    const precision = safeDiv(truePositives, truePositives + falsePositives);
    const recall = safeDiv(truePositives, truePositives + falseNegatives);
    const f1 = safeDiv(2 * precision * recall, precision + recall);
    totalTP += truePositives;
    totalFP += falsePositives;
    totalFN += falseNegatives;
    return {
      label,
      truePositives,
      falsePositives,
      falseNegatives,
      support,
      precision,
      recall,
      f1,
    };
  });

  const total = actual.length;
  let correct = 0;
  for (let i = 0; i < n; i++) correct += matrix[i][i];
  const accuracy = safeDiv(correct, total);

  const meanOf = (select: (m: PerClassMetrics) => number): number =>
    safeDiv(
      perClass.reduce((sum, m) => sum + select(m), 0),
      perClass.length
    );

  const macroPrecision = meanOf((m) => m.precision);
  const macroRecall = meanOf((m) => m.recall);
  const macroF1 = meanOf((m) => m.f1);

  const microPrecision = safeDiv(totalTP, totalTP + totalFP);
  const microRecall = safeDiv(totalTP, totalTP + totalFN);
  const microF1 = safeDiv(
    2 * microPrecision * microRecall,
    microPrecision + microRecall
  );

  // Safe-ham FP rate: of actual 'safe', the fraction predicted non-safe.
  let safeFalsePositiveRate = 0;
  if (present.has('safe')) {
    const si = indexOf(index, 'safe', 'computeMetrics');
    const safeSupport = matrix[si].reduce((s, v) => s + v, 0);
    const safeCorrect = matrix[si][si];
    safeFalsePositiveRate = safeDiv(safeSupport - safeCorrect, safeSupport);
  }

  return {
    total,
    accuracy,
    perClass,
    confusion: { labels: [...labels], matrix },
    macroPrecision,
    macroRecall,
    macroF1,
    microPrecision,
    microRecall,
    microF1,
    safeFalsePositiveRate,
  };
}
