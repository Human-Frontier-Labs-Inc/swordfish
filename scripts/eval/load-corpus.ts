/**
 * Labeled-corpus loader for the detection eval harness.
 *
 * On-disk schema (see docs/audit/plans/stream-b.md):
 *   <root>/
 *     index.json                      # optional manifest (counts + attribution)
 *     safe/<source>/*.eml             # ham
 *     spam/<source>/*.eml
 *     phishing/<source>/*.eml
 *     bec/curated/*.eml
 *   <sample>.eml                      # RFC822 raw, parseable by lib/detection/parser.ts
 *   <sample>.eml.label.json           # sidecar: { label, source, notes? }
 *
 * One labeled sample = one .eml + one sidecar. The loader:
 *   - walks the root recursively for *.eml
 *   - pairs each with its sidecar, validates the label
 *   - yields raw .eml text + label + source (parsing into ParsedEmail is the
 *     eval runner's job — keeps this module free of the detection dependency)
 *   - skips (and reports) any sample with a missing/invalid sidecar instead of
 *     throwing, so one bad file can't poison a 5k-sample run
 *
 * Pure I/O over the filesystem; no detection or DB deps. Unit-tested in
 * tests/eval/load-corpus.test.ts against a temp corpus.
 */

import { promises as fs } from 'node:fs';
import { join, relative, dirname, basename } from 'node:path';
import { EVAL_LABELS, type EvalLabel } from './metrics';

const LABEL_SET: ReadonlySet<EvalLabel> = new Set(EVAL_LABELS);

export interface CorpusSample {
  /** Stable id = path relative to root, without the .eml suffix. */
  id: string;
  /** Absolute path to the .eml file. */
  path: string;
  /** Raw RFC822 .eml contents (call parseEmail on this in the runner). */
  rawEmail: string;
  label: EvalLabel;
  source: string;
}

export interface CorpusSourceSummary {
  name: string;
  label: EvalLabel;
  count: number;
  license?: string;
  attribution?: string;
}

export interface CorpusManifest {
  version: number;
  sampleCount: number;
  labelCounts: Record<EvalLabel, number>;
  sources: CorpusSourceSummary[];
}

export interface SkippedSample {
  path: string;
  reason: string;
}

export interface LoadCorpusOptions {
  rootDir: string;
  /** Called for each skipped sample (logging hook). */
  onSkipped?: (skipped: SkippedSample) => void;
}

export interface LoadCorpusResult {
  samples: CorpusSample[];
  skipped: SkippedSample[];
  /** The manifest read from <root>/index.json, if present. */
  manifest: CorpusManifest | null;
}

interface Sidecar {
  label?: unknown;
  source?: unknown;
  notes?: unknown;
}

async function walkEmlFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  let entries: import('node:fs').Dirent[];
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    // Skip noise that shouldn't be treated as samples.
    if (entry.name.startsWith('.')) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await walkEmlFiles(full)));
    } else if (entry.isFile() && entry.name.endsWith('.eml')) {
      out.push(full);
    }
  }
  return out;
}

function isEvalLabel(value: unknown): value is EvalLabel {
  return typeof value === 'string' && LABEL_SET.has(value as EvalLabel);
}

function stemWithoutEml(filename: string): string {
  return filename.endsWith('.eml') ? filename.slice(0, -4) : filename;
}

export async function loadCorpus(
  options: LoadCorpusOptions
): Promise<LoadCorpusResult> {
  const { rootDir, onSkipped } = options;
  const samples: CorpusSample[] = [];
  const skipped: SkippedSample[] = [];

  const skip = (path: string, reason: string): void => {
    skipped.push({ path, reason });
    onSkipped?.({ path, reason });
  };

  const emlFiles = await walkEmlFiles(rootDir);

  for (const emlPath of emlFiles) {
    const sidecarPath = `${emlPath}.label.json`;

    // Read + validate the sidecar first — cheap reject before reading the body.
    let sidecar: Sidecar;
    try {
      const raw = await fs.readFile(sidecarPath, 'utf8');
      sidecar = JSON.parse(raw) as Sidecar;
    } catch {
      skip(emlPath, `missing or unparseable sidecar at ${basename(sidecarPath)}`);
      continue;
    }

    if (!isEvalLabel(sidecar.label)) {
      skip(emlPath, `invalid label ${JSON.stringify(sidecar.label)}`);
      continue;
    }

    // Read the .eml body.
    let rawEmail: string;
    try {
      rawEmail = await fs.readFile(emlPath, 'utf8');
    } catch {
      skip(emlPath, 'could not read .eml body');
      continue;
    }

    const rel = relative(rootDir, emlPath);
    const id = stemWithoutEml(rel);
    const source =
      typeof sidecar.source === 'string' && sidecar.source.length > 0
        ? sidecar.source
        : basename(dirname(rel)) || 'unknown';

    samples.push({ id, path: emlPath, rawEmail, label: sidecar.label, source });
  }

  // Stable order for deterministic eval runs.
  samples.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  const manifest = await readManifest(join(rootDir, 'index.json'));

  return { samples, skipped, manifest };
}

async function readManifest(path: string): Promise<CorpusManifest | null> {
  let raw: string;
  try {
    raw = await fs.readFile(path, 'utf8');
  } catch {
    return null;
  }
  try {
    return parseManifest(JSON.parse(raw));
  } catch {
    return null;
  }
}

/** Validate + normalize a parsed manifest object (tolerant of missing fields). */
export function parseManifest(value: unknown): CorpusManifest {
  const obj = (value ?? {}) as Record<string, unknown>;
  const labelCounts = { safe: 0, spam: 0, phishing: 0, bec: 0 } as Record<EvalLabel, number>;
  const rawCounts = (obj.labelCounts ?? {}) as Record<string, unknown>;
  for (const label of EVAL_LABELS) {
    const n = rawCounts[label];
    if (typeof n === 'number' && Number.isFinite(n)) {
      labelCounts[label] = n;
    }
  }
  const sources: CorpusSourceSummary[] = Array.isArray(obj.sources)
    ? (obj.sources as unknown[])
        .map((s) => toSourceSummary(s))
        .filter((s): s is CorpusSourceSummary => s !== null)
    : [];
  const sampleCount =
    typeof obj.sampleCount === 'number' && Number.isFinite(obj.sampleCount)
      ? obj.sampleCount
      : Object.values(labelCounts).reduce((a, b) => a + b, 0);

  return {
    version: typeof obj.version === 'number' ? obj.version : 1,
    sampleCount,
    labelCounts,
    sources,
  };
}

function toSourceSummary(value: unknown): CorpusSourceSummary | null {
  if (!value || typeof value !== 'object') return null;
  const obj = value as Record<string, unknown>;
  if (!isEvalLabel(obj.label)) return null;
  const count =
    typeof obj.count === 'number' && Number.isFinite(obj.count) ? obj.count : 0;
  const summary: CorpusSourceSummary = {
    name: typeof obj.name === 'string' ? obj.name : 'unknown',
    label: obj.label,
    count,
  };
  if (typeof obj.license === 'string') summary.license = obj.license;
  if (typeof obj.attribution === 'string') summary.attribution = obj.attribution;
  return summary;
}

/** Derive a manifest from already-loaded samples (used after fetch/normalize). */
export function buildManifest(samples: readonly CorpusSample[]): CorpusManifest {
  const labelCounts = { safe: 0, spam: 0, phishing: 0, bec: 0 } as Record<
    EvalLabel,
    number
  >;
  const byKey = new Map<string, CorpusSourceSummary>();
  for (const s of samples) {
    labelCounts[s.label]++;
    const key = `${s.source}|${s.label}`;
    const existing = byKey.get(key);
    if (existing) {
      existing.count++;
    } else {
      byKey.set(key, { name: s.source, label: s.label, count: 1 });
    }
  }
  return {
    version: 1,
    sampleCount: samples.length,
    labelCounts,
    sources: [...byKey.values()].sort((a, b) =>
      a.label === b.label
        ? a.name < b.name
          ? -1
          : 1
        : a.label < b.label
          ? -1
          : 1
    ),
  };
}
