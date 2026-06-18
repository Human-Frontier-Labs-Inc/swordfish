#!/usr/bin/env tsx
/**
 * Detection eval CLI — wires the real detection pipeline into the eval harness
 * and writes a run to disk.
 *
 * Usage:
 *   npx tsx scripts/eval/run.ts --corpus tests/fixtures/corpus \
 *       --out docs/eval/runs [--no-llm] [--llm-budget N] [--tenant eval-tenant]
 *
 * (The `npm run eval` alias is deliberately NOT added here — Stream A owns
 * package.json right now. Add the alias after A lands, or invoke via tsx.)
 *
 * Outputs (under <out>/<ISO timestamp>/):
 *   results.json   - per-sample verdicts/scores/labels
 *   summary.json   - aggregated metrics (consumed by the CI gate + launch doc)
 *   report.md      - human-readable summary
 *
 * Verified by typecheck; the orchestration (runEval) + every helper it calls
 * are unit-tested. A live run needs a populated corpus + runtime env (DB/LLM).
 */

import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { parseEmail } from '../../lib/detection/parser';
import { analyzeEmail } from '../../lib/detection/pipeline';
import type { DetectionConfig } from '../../lib/detection/types';
import { runEval, type AnalyzeFn } from './runner';
import { buildSummary, renderReportMarkdown } from './reporter';

interface ParsedArgs {
  corpus: string;
  out: string;
  tenant: string;
  noLlm: boolean;
  llmBudget?: number;
}

function parseArgs(argv: string[]): ParsedArgs {
  const get = (key: string): string | undefined => {
    const i = argv.indexOf(`--${key}`);
    return i >= 0 && i + 1 < argv.length && !argv[i + 1].startsWith('--')
      ? argv[i + 1]
      : undefined;
  };
  const flag = (key: string): boolean => argv.includes(`--${key}`);
  const llmBudget = get('llm-budget');
  return {
    corpus: get('corpus') ?? 'tests/fixtures/corpus',
    out: get('out') ?? 'docs/eval/runs',
    tenant: get('tenant') ?? 'eval-tenant',
    noLlm: flag('no-llm'),
    llmBudget: llmBudget !== undefined ? Number.parseInt(llmBudget, 10) : undefined,
  };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const baseConfig: Partial<DetectionConfig> = args.noLlm
    ? { skipLLM: true }
    : {};

  let llmUsed = 0;

  // Real-pipeline analyze step. --llm-budget is enforced by flipping skipLLM
  // once the budget is reached (analyzed samples still run, just LLM-free).
  const analyze: AnalyzeFn = async (rawEmail) => {
    const overrides: Partial<DetectionConfig> = { ...baseConfig };
    if (args.llmBudget !== undefined && llmUsed >= args.llmBudget) {
      overrides.skipLLM = true;
    }
    const start = Date.now();
    const parsed = parseEmail(rawEmail);
    const verdict = await analyzeEmail(parsed, args.tenant, overrides);
    if ((verdict.llmTokensUsed ?? 0) > 0) llmUsed++;
    return {
      verdict: verdict.verdict,
      score: verdict.overallScore,
      llmTokensUsed: verdict.llmTokensUsed,
      latencyMs: Date.now() - start,
      analysisStatus: verdict.analysisStatus,
      analysisError: verdict.analysisError,
    };
  };

  const result = await runEval({ rootDir: args.corpus, analyze });
  const generatedAt = new Date().toISOString();
  const meta = {
    generatedAt,
    corpusDir: args.corpus,
    skipLlm: args.noLlm,
    llmBudget: args.llmBudget,
    notes: [
      'predicted-class derivation deferred — pipeline has no native threat category; primary metrics are binary safe-vs-threat + per-class catch rate',
    ],
  };
  const summary = buildSummary(result, meta);
  const report = renderReportMarkdown(result, meta);

  const stamp = generatedAt.replace(/[:.]/g, '-');
  const runDir = join(args.out, stamp);
  await mkdir(runDir, { recursive: true });
  await writeFile(
    join(runDir, 'results.json'),
    JSON.stringify({ samples: result.samples }, null, 2),
    'utf8'
  );
  await writeFile(join(runDir, 'summary.json'), JSON.stringify(summary, null, 2), 'utf8');
  await writeFile(join(runDir, 'report.md'), report, 'utf8');

  const b = result.binary;
  const pct = (x: number) => `${(x * 100).toFixed(x < 1 ? 2 : 0)}%`;
  process.stdout.write(`\nEval run written to ${runDir}\n`);
  process.stdout.write(
    `Binary: precision=${pct(b.precision)} recall=${pct(b.recall)} f1=${pct(b.f1)} ham-FPR=${pct(b.falsePositiveRate)}\n`
  );
  process.stdout.write(
    `Catch: bec=${pct(result.catchRates.bec.rate)} phishing=${pct(result.catchRates.phishing.rate)} spam=${pct(result.catchRates.spam.rate)}\n`
  );
  process.stdout.write(
    `(${result.analyzed} analyzed, ${result.errors} failures, ${result.llmInvocations} LLM calls)\n\n`
  );
}

main().catch((err) => {
  console.error('eval run failed:', err);
  process.exit(1);
});
