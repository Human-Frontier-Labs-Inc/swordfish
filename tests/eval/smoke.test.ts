/**
 * End-to-end smoke for the eval harness.
 *
 * Runs the WHOLE chain — real on-disk loadCorpus (over the committed
 * tests/fixtures/corpus seeded by scripts/corpus/seed-corpus.ts) → runner →
 * metrics → reporter — with two hand-computable mock detectors (flag-all and
 * pass-all). This proves the harness plumbing works as a system on real files;
 * it is NOT a detector-accuracy test (that's what the real pipeline + a full
 * corpus produce).
 *
 * Corpus counts: safe=4, spam=2, phishing=4, bec=9 → 15 threats, 4 ham, 19 total.
 */

import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { runEval, type AnalyzeFn } from '../../scripts/eval/runner';
import { buildSummary, renderReportMarkdown } from '../../scripts/eval/reporter';

const CORPUS_DIR = fileURLToPath(new URL('../fixtures/corpus', import.meta.url));

const TOTAL = 19;
const THREATS = 15; // spam(2) + phishing(4) + bec(9)
const HAM = 4;

const flagAll: AnalyzeFn = async () => ({ verdict: 'block', score: 95, latencyMs: 7 });
const passAll: AnalyzeFn = async () => ({ verdict: 'pass', score: 5, latencyMs: 3 });

describe('eval harness end-to-end smoke (real on-disk corpus)', () => {
  it('loads all 19 seeded samples with zero skips', async () => {
    const r = await runEval({ rootDir: CORPUS_DIR, analyze: passAll });
    expect(r.total).toBe(TOTAL);
    expect(r.analyzed).toBe(TOTAL);
    expect(r.skipped).toBe(0);
    expect(r.errors).toBe(0);
  });

  it('flag-all detector → full recall, precision = threats/total, ham FPR = 1', async () => {
    const r = await runEval({ rootDir: CORPUS_DIR, analyze: flagAll });
    expect(r.binary.truePositives).toBe(THREATS);
    expect(r.binary.falsePositives).toBe(HAM);
    expect(r.binary.falseNegatives).toBe(0);
    expect(r.binary.trueNegatives).toBe(0);
    expect(r.binary.recall).toBe(1);
    expect(r.binary.precision).toBeCloseTo(THREATS / TOTAL);
    expect(r.binary.falsePositiveRate).toBe(1);
    expect(r.catchRates.bec.rate).toBe(1);
    expect(r.catchRates.phishing.rate).toBe(1);
    expect(r.catchRates.safe.rate).toBe(1); // ham wrongly flagged
    expect(r.latency.count).toBe(TOTAL);
  });

  it('pass-all detector → zero recall, zero FP, all classes uncaught', async () => {
    const r = await runEval({ rootDir: CORPUS_DIR, analyze: passAll });
    expect(r.binary.truePositives).toBe(0);
    expect(r.binary.falsePositives).toBe(0);
    expect(r.binary.falseNegatives).toBe(THREATS);
    expect(r.binary.trueNegatives).toBe(HAM);
    expect(r.binary.recall).toBe(0);
    expect(r.binary.falsePositiveRate).toBe(0);
    expect(r.catchRates.bec.rate).toBe(0);
    expect(r.catchRates.phishing.rate).toBe(0);
  });

  it('reporter renders a headline report over the real run', async () => {
    const r = await runEval({ rootDir: CORPUS_DIR, analyze: flagAll });
    const report = renderReportMarkdown(r, { corpusDir: CORPUS_DIR, skipLlm: true });
    expect(report).toContain('# Detection Eval Report');
    expect(report).toContain('## Headline');
    expect(report.indexOf('## Headline')).toBeLessThan(report.indexOf('## Counts'));
    expect(report).toContain('Ham false-positive rate');
    // flag-all: 15 threats caught of 19
    expect(report).toContain(`| bec | 9 | 9 |`);
    const summary = buildSummary(r, { skipLlm: true });
    expect(summary.counts.analyzed).toBe(TOTAL);
    expect(summary.binary.truePositives).toBe(THREATS);
  });
});
