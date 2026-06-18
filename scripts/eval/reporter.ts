/**
 * Eval reporter — renders an EvalRunResult as a JSON summary + a human-readable
 * markdown report. Pure functions (no I/O); the CLI writes the files.
 *
 * The markdown report is what a human reads to judge accuracy; summary.json is
 * what the CI gate and launch-numbers doc are generated from. Neither is
 * hand-edited — both derive from the run result so the published numbers can
 * always be traced back to a run.
 */

import type { EvalRunResult } from './runner';
import type { EvalLabel } from './metrics';

export interface ReportMeta {
  generatedAt?: string;
  corpusDir?: string;
  skipLlm?: boolean;
  llmBudget?: number;
  notes?: string[];
}

export interface EvalSummary {
  generatedAt?: string;
  counts: {
    total: number;
    skipped: number;
    analyzed: number;
    errors: number;
    llmInvocations: number;
  };
  binary: EvalRunResult['binary'];
  catchRates: EvalRunResult['catchRates'];
  latency: EvalRunResult['latency'];
  meta?: ReportMeta;
}

export function buildSummary(
  result: EvalRunResult,
  meta?: ReportMeta
): EvalSummary {
  return {
    generatedAt: meta?.generatedAt,
    counts: {
      total: result.total,
      skipped: result.skipped,
      analyzed: result.analyzed,
      errors: result.errors,
      llmInvocations: result.llmInvocations,
    },
    binary: result.binary,
    catchRates: result.catchRates,
    latency: result.latency,
    meta,
  };
}

function pct(x: number | undefined): string {
  return x === undefined ? 'n/a' : `${(x * 100).toFixed(2)}%`;
}

function num(x: number | undefined): string {
  return x === undefined ? 'n/a' : x.toFixed(2);
}

export function renderReportMarkdown(
  result: EvalRunResult,
  meta?: ReportMeta
): string {
  const b = result.binary;
  const lines: string[] = [];

  lines.push('# Detection Eval Report');
  if (meta?.generatedAt) lines.push(``, `_Generated: ${meta.generatedAt}_`);
  if (meta?.corpusDir) lines.push(``, `_Corpus: \`${meta.corpusDir}\`_`);
  if (meta?.skipLlm !== undefined) {
    lines.push(``, `_LLM layer: ${meta.skipLlm ? 'disabled (--no-llm)' : 'enabled'}_`);
  }

  // Headline numbers first — for a Proofpoint/Mimecast-replacement pitch,
  // "we don't quarantine your real mail" (ham FP rate) is as load-bearing as
  // catch rate, so it leads the report instead of sitting inside the table.
  lines.push('', '## Headline');
  lines.push(`- **Threat catch rate (recall):** ${pct(b.recall)}`);
  lines.push(`- **Safe-vs-threat precision:** ${pct(b.precision)}`);
  lines.push(
    `- **Ham false-positive rate:** ${pct(b.falsePositiveRate)} _(launch target <= 1% — "we don't quarantine your real mail")_`
  );

  lines.push('', '## Counts');
  lines.push(
    `- Samples analyzed: **${result.analyzed}** / ${result.total} loaded (${result.skipped} skipped by loader)`
  );
  lines.push(`- Analysis failures: **${result.errors}**`);
  lines.push(`- LLM invocations: **${result.llmInvocations}**`);

  lines.push('', '## Binary safe-vs-threat');
  lines.push('| Metric | Value |', '|---|---|');
  lines.push(`| Precision | ${pct(b.precision)} |`);
  lines.push(`| Recall (threat catch) | ${pct(b.recall)} |`);
  lines.push(`| F1 | ${pct(b.f1)} |`);
  lines.push(`| Accuracy | ${pct(b.accuracy)} |`);
  lines.push(
    `| **Ham false-positive rate** | **${pct(b.falsePositiveRate)}** _(launch target <= 1%)_ |`
  );
  lines.push(
    `| TP / FP / FN / TN | ${b.truePositives} / ${b.falsePositives} / ${b.falseNegatives} / ${b.trueNegatives} |`
  );

  lines.push('', '## Per-class catch rate');
  lines.push('| Class | Support | Caught | Rate |', '|---|---|---|---|');
  const entries = Object.entries(result.catchRates) as Array<
    [EvalLabel, { support: number; caught: number; rate: number }]
  >;
  for (const [label, c] of entries) {
    lines.push(`| ${label} | ${c.support} | ${c.caught} | ${pct(c.rate)} |`);
  }

  lines.push(
    '',
    `## Latency (ms)`,
    `- p50: ${num(result.latency.p50)} · p95: ${num(result.latency.p95)} · mean: ${num(result.latency.mean)} (n=${result.latency.count})`
  );

  if (meta?.notes?.length) {
    lines.push('', '## Notes');
    for (const note of meta.notes) lines.push(`- ${note}`);
  }

  lines.push(''); // trailing newline
  return lines.join('\n');
}
