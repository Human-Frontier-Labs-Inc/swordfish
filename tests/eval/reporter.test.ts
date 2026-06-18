/**
 * Unit tests for scripts/eval/reporter.ts.
 */

import { describe, it, expect } from 'vitest';
import { buildSummary, renderReportMarkdown } from '../../scripts/eval/reporter';
import type { EvalRunResult } from '../../scripts/eval/runner';

const RESULT: EvalRunResult = {
  samples: [],
  total: 4,
  skipped: 1,
  analyzed: 4,
  errors: 1,
  llmInvocations: 2,
  binary: {
    total: 4,
    truePositives: 3,
    falsePositives: 1,
    falseNegatives: 0,
    trueNegatives: 0,
    precision: 0.75,
    recall: 1,
    f1: 0.857142857,
    accuracy: 0.75,
    falsePositiveRate: 1,
  },
  catchRates: {
    safe: { support: 1, caught: 1, rate: 1 },
    spam: { support: 1, caught: 1, rate: 1 },
    phishing: { support: 1, caught: 1, rate: 1 },
    bec: { support: 1, caught: 0, rate: 0 },
  },
  latency: { count: 3, mean: 20, p50: 20, p95: 30 },
};

describe('buildSummary', () => {
  it('projects counts, binary, catch rates, latency, and meta', () => {
    const s = buildSummary(RESULT, { generatedAt: '2026-06-17', corpusDir: '/c' });
    expect(s.generatedAt).toBe('2026-06-17');
    expect(s.counts.analyzed).toBe(4);
    expect(s.counts.errors).toBe(1);
    expect(s.counts.llmInvocations).toBe(2);
    expect(s.binary.precision).toBe(0.75);
    expect(s.catchRates.bec.rate).toBe(0);
    expect(s.latency.p95).toBe(30);
    expect(s.meta?.corpusDir).toBe('/c');
  });
});

describe('renderReportMarkdown', () => {
  const md = renderReportMarkdown(RESULT, {
    generatedAt: '2026-06-17',
    corpusDir: '/corpus',
    skipLlm: true,
    notes: ['predicted-class derivation deferred (pipeline has no native category)'],
  });

  it('renders the title and metadata', () => {
    expect(md).toContain('# Detection Eval Report');
    expect(md).toContain('2026-06-17');
    expect(md).toContain('/corpus');
    expect(md).toContain('disabled (--no-llm)');
  });

  it('surfaces catch / precision / ham-FP as a top-line headline (load-bearing)', () => {
    expect(md).toContain('## Headline');
    expect(md).toContain('Threat catch rate (recall)');
    expect(md).toContain('Safe-vs-threat precision');
    expect(md).toContain('Ham false-positive rate');
    expect(md).toContain("we don't quarantine your real mail");
    // headline leads the report, before the counts table
    expect(md.indexOf('## Headline')).toBeLessThan(md.indexOf('## Counts'));
  });

  it('renders the key binary metrics as percentages', () => {
    expect(md).toContain('75.00%'); // precision + accuracy
    expect(md).toContain('100.00%'); // recall + FPR
    expect(md).toContain('Ham false-positive rate');
    expect(md).toContain('TP / FP / FN / TN');
    expect(md).toContain('3 / 1 / 0 / 0');
  });

  it('renders a per-class catch-rate table with all four labels', () => {
    expect(md).toContain('Per-class catch rate');
    for (const label of ['safe', 'spam', 'phishing', 'bec']) {
      expect(md).toContain(`| ${label} |`);
    }
  });

  it('renders latency and notes', () => {
    expect(md).toContain('Latency (ms)');
    expect(md).toContain('20.00'); // p50 + mean
    expect(md).toContain('30.00'); // p95
    expect(md).toContain('predicted-class derivation deferred');
  });
});
