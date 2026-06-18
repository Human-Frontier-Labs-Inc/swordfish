/**
 * Unit tests for scripts/eval/runner.ts.
 *
 * Uses runEvalOnCorpus with mock AnalyzeFn implementations so the
 * orchestration/metrics/latency/error handling is checked without the real
 * detection pipeline. Expected numbers are hand-computed.
 */

import { describe, it, expect } from 'vitest';
import {
  runEvalOnCorpus,
  percentile,
  type AnalyzeFn,
} from '../../scripts/eval/runner';
import type { LoadCorpusResult, CorpusSample } from '../../scripts/eval/load-corpus';
import { isThreatLabel } from '../../scripts/eval/predict';
import type { EvalLabel } from '../../scripts/eval/metrics';

function sample(id: string, label: EvalLabel, source = 'test'): CorpusSample {
  return { id, path: `/corpus/${id}.eml`, rawEmail: `raw-${id}`, label, source };
}

function corpusOf(samples: CorpusSample[]): LoadCorpusResult {
  return { samples, skipped: [], manifest: null };
}

const PERFECT: AnalyzeFn = async (_raw, s) => ({
  verdict: isThreatLabel(s.label) ? 'quarantine' : 'pass',
  score: isThreatLabel(s.label) ? 80 : 10,
  latencyMs: 5,
  llmTokensUsed: 0,
});

const FOUR = [
  sample('safe/1', 'safe'),
  sample('spam/1', 'spam'),
  sample('phishing/1', 'phishing'),
  sample('bec/1', 'bec'),
];

describe('runEvalOnCorpus', () => {
  it('perfect detector → perfect binary metrics, full threat catch, zero ham FPs', async () => {
    const r = await runEvalOnCorpus(corpusOf(FOUR), PERFECT);
    expect(r.analyzed).toBe(4);
    expect(r.errors).toBe(0);
    expect(r.binary.truePositives).toBe(3);
    expect(r.binary.trueNegatives).toBe(1);
    expect(r.binary.falsePositives).toBe(0);
    expect(r.binary.falseNegatives).toBe(0);
    expect(r.binary.precision).toBe(1);
    expect(r.binary.recall).toBe(1);
    expect(r.binary.f1).toBe(1);
    expect(r.binary.falsePositiveRate).toBe(0);
    expect(r.catchRates.bec.rate).toBe(1);
    expect(r.catchRates.phishing.rate).toBe(1);
    expect(r.catchRates.spam.rate).toBe(1);
    expect(r.catchRates.safe.rate).toBe(0); // safe correctly not flagged
  });

  it('missing all BEC → bec catch rate 0, recall drops', async () => {
    const missBec: AnalyzeFn = async (_raw, s) => ({
      verdict: s.label === 'bec' ? 'pass' : isThreatLabel(s.label) ? 'quarantine' : 'pass',
      score: 50,
      latencyMs: 5,
    });
    const r = await runEvalOnCorpus(corpusOf(FOUR), missBec);
    // threats = spam, phishing, bec (3). caught = spam, phishing (2). bec missed.
    expect(r.binary.truePositives).toBe(2);
    expect(r.binary.falseNegatives).toBe(1);
    expect(r.binary.falsePositives).toBe(0);
    expect(r.binary.recall).toBeCloseTo(2 / 3);
    expect(r.binary.precision).toBe(1);
    expect(r.catchRates.bec.rate).toBe(0);
    expect(r.catchRates.phishing.rate).toBe(1);
    expect(r.binary.accuracy).toBeCloseTo(0.75);
  });

  it('flags everything → high ham FP rate, recall 1, precision < 1', async () => {
    const flagAll: AnalyzeFn = async () => ({ verdict: 'block', score: 90, latencyMs: 5 });
    const r = await runEvalOnCorpus(corpusOf(FOUR), flagAll);
    expect(r.binary.truePositives).toBe(3);
    expect(r.binary.falsePositives).toBe(1); // safe flagged
    expect(r.binary.falseNegatives).toBe(0);
    expect(r.binary.trueNegatives).toBe(0);
    expect(r.binary.recall).toBe(1);
    expect(r.binary.precision).toBeCloseTo(0.75);
    expect(r.binary.falsePositiveRate).toBe(1);
    expect(r.catchRates.safe.rate).toBe(1); // ham wrongly flagged
  });

  it('counts LLM invocations from llmTokensUsed', async () => {
    const withLlm: AnalyzeFn = async (_raw, s) => ({
      verdict: isThreatLabel(s.label) ? 'quarantine' : 'pass',
      llmTokensUsed: s.label === 'phishing' ? 500 : 0,
    });
    const r = await runEvalOnCorpus(corpusOf(FOUR), withLlm);
    expect(r.llmInvocations).toBe(1);
    const phish = r.samples.find((s) => s.label === 'phishing')!;
    expect(phish.llmInvoked).toBe(true);
  });

  it('a thrown analysis is recorded as a failure and counted as not-caught', async () => {
    let called = 0;
    const throwing: AnalyzeFn = async (_raw, s) => {
      called++;
      if (s.label === 'phishing') throw new Error('boom');
      return { verdict: isThreatLabel(s.label) ? 'quarantine' : 'pass' };
    };
    const r = await runEvalOnCorpus(corpusOf(FOUR), throwing);
    expect(called).toBe(4); // thrown sample still invoked the fn
    expect(r.errors).toBe(1);
    const phish = r.samples.find((s) => s.label === 'phishing')!;
    expect(phish.status).toBe('analysis_failed');
    expect(phish.error).toBe('boom');
    expect(phish.predictedIsThreat).toBe(false); // failure → not caught → miss
    // phishing was an actual threat, missed → fn
    expect(r.binary.falseNegatives).toBe(1);
    expect(r.binary.truePositives).toBe(2);
  });

  it('aggregates latency p50/p95/mean', async () => {
    const latencies: Record<string, number> = {
      'safe/1': 10,
      'spam/1': 20,
      'phishing/1': 30,
      'bec/1': 40,
    };
    const withLatency: AnalyzeFn = async (_raw, s) => ({
      verdict: 'pass',
      latencyMs: latencies[s.id],
    });
    const r = await runEvalOnCorpus(corpusOf(FOUR), withLatency);
    expect(r.latency.count).toBe(4);
    expect(r.latency.mean).toBe(25);
    expect(r.latency.p50).toBe(20); // ceil(0.5*4)=2 → idx1
    expect(r.latency.p95).toBe(40); // ceil(0.95*4)=4 → idx3
  });
});

describe('percentile', () => {
  it('nearest-rank on a sorted array', () => {
    expect(percentile([10, 20, 30, 40], 0.5)).toBe(20);
    expect(percentile([10, 20, 30, 40], 0.95)).toBe(40);
    expect(percentile([10, 20, 30, 40], 0)).toBe(10);
    expect(percentile([], 0.5)).toBe(0);
  });
});
