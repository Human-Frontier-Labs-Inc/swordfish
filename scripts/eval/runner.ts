/**
 * Detection eval runner — orchestrates corpus → analyze → aggregated metrics.
 *
 * The analyze step is INJECTABLE (AnalyzeFn) so the orchestration, metrics
 * aggregation, latency stats, and error handling are unit-testable without
 * the real detection pipeline, a database, or LLM API calls. The CLI entry
 * (scripts/eval/run.ts) wires the real parseEmail + analyzeEmail in; tests
 * pass a mock.
 *
 * Failure semantics: a sample whose analysis throws or returns
 * analysisStatus 'analysis_failed' is counted as NOT caught (predicted safe).
 * That's the security-conservative read — if we couldn't analyze it, we didn't
 * catch it — and the error count is reported separately so it can't hide.
 */

import { loadCorpus, type CorpusSample, type LoadCorpusResult } from './load-corpus';
import {
  computeBinaryMetrics,
  catchRateByClass,
  verdictIsThreat,
  isThreatLabel,
  type Verdict,
  type BinaryMetrics,
  type ClassCatchRate,
} from './predict';
import type { EvalLabel } from './metrics';

export interface AnalyzeOutcome {
  verdict?: Verdict;
  score?: number;
  llmTokensUsed?: number;
  latencyMs?: number;
  analysisStatus?: string;
  analysisError?: string;
}

/** Analyze a single raw email. Implementations wire the real pipeline. */
export type AnalyzeFn = (
  rawEmail: string,
  sample: CorpusSample
) => Promise<AnalyzeOutcome>;

export interface AnalyzedSample {
  id: string;
  label: EvalLabel;
  source: string;
  actualIsThreat: boolean;
  predictedIsThreat: boolean;
  verdict?: Verdict;
  score?: number;
  latencyMs?: number;
  llmInvoked: boolean;
  status?: string;
  error?: string;
}

export interface LatencyStats {
  count: number;
  mean?: number;
  p50?: number;
  p95?: number;
}

export interface EvalRunResult {
  samples: AnalyzedSample[];
  total: number;
  skipped: number;
  analyzed: number;
  errors: number;
  llmInvocations: number;
  binary: BinaryMetrics;
  catchRates: Record<EvalLabel, ClassCatchRate>;
  latency: LatencyStats;
}

export interface RunOptions {
  rootDir: string;
  analyze: AnalyzeFn;
  onProgress?: (done: number, total: number) => void;
}

export async function runEval(opts: RunOptions): Promise<EvalRunResult> {
  const corpus = await loadCorpus({ rootDir: opts.rootDir });
  return runEvalOnCorpus(corpus, opts.analyze, opts.onProgress);
}

/** Run the eval over an already-loaded corpus (testable without the filesystem). */
export async function runEvalOnCorpus(
  corpus: LoadCorpusResult,
  analyze: AnalyzeFn,
  onProgress?: (done: number, total: number) => void
): Promise<EvalRunResult> {
  const total = corpus.samples.length;
  const analyzed: AnalyzedSample[] = [];
  let errors = 0;
  let llmInvocations = 0;

  for (let i = 0; i < corpus.samples.length; i++) {
    const sample = corpus.samples[i];
    onProgress?.(i, total);

    let outcome: AnalyzeOutcome;
    try {
      outcome = await analyze(sample.rawEmail, sample);
    } catch (err) {
      outcome = {
        analysisStatus: 'analysis_failed',
        analysisError: err instanceof Error ? err.message : String(err),
      };
    }

    const predictedIsThreat = outcome.verdict
      ? verdictIsThreat(outcome.verdict)
      : false;
    const llmInvoked = (outcome.llmTokensUsed ?? 0) > 0;
    if (outcome.analysisStatus === 'analysis_failed') errors++;
    if (llmInvoked) llmInvocations++;

    analyzed.push({
      id: sample.id,
      label: sample.label,
      source: sample.source,
      actualIsThreat: isThreatLabel(sample.label),
      predictedIsThreat,
      verdict: outcome.verdict,
      score: outcome.score,
      latencyMs: outcome.latencyMs,
      llmInvoked,
      status: outcome.analysisStatus,
      error: outcome.analysisError,
    });
  }
  onProgress?.(total, total);

  const binary = computeBinaryMetrics(
    analyzed.map((s) => s.actualIsThreat),
    analyzed.map((s) => s.predictedIsThreat)
  );
  const catchRates = catchRateByClass(
    analyzed.map((s) => s.label),
    analyzed.map((s) => s.predictedIsThreat)
  );
  const latency = computeLatencyStats(analyzed.map((s) => s.latencyMs));

  return {
    samples: analyzed,
    total,
    skipped: corpus.skipped.length,
    analyzed: analyzed.length,
    errors,
    llmInvocations,
    binary,
    catchRates,
    latency,
  };
}

function computeLatencyStats(latencies: ReadonlyArray<number | undefined>): LatencyStats {
  const vals = latencies
    .filter((l): l is number => typeof l === 'number' && Number.isFinite(l))
    .sort((a, b) => a - b);
  const count = vals.length;
  if (count === 0) return { count: 0 };
  const mean = vals.reduce((sum, v) => sum + v, 0) / count;
  return { count, mean, p50: percentile(vals, 0.5), p95: percentile(vals, 0.95) };
}

/** Nearest-rank percentile over a sorted-ascending array. */
export function percentile(sortedAsc: readonly number[], p: number): number {
  if (sortedAsc.length === 0) return 0;
  const rank = Math.ceil(p * sortedAsc.length);
  const idx = Math.min(Math.max(rank - 1, 0), sortedAsc.length - 1);
  return sortedAsc[idx];
}
