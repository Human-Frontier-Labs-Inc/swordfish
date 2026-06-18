/**
 * Unit tests for scripts/eval/load-corpus.ts.
 *
 * Builds a throwaway corpus in the OS temp dir for each test — no committed
 * fixture data required.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import {
  loadCorpus,
  buildManifest,
  parseManifest,
} from '../../scripts/eval/load-corpus';

let root: string;

beforeEach(async () => {
  root = await fs.mkdtemp(join(tmpdir(), 'corpus-'));
});

afterEach(async () => {
  await fs.rm(root, { recursive: true, force: true });
});

async function writeFile(rel: string, content: string): Promise<void> {
  const full = join(root, rel);
  await fs.mkdir(dirname(full), { recursive: true });
  await fs.writeFile(full, content, 'utf8');
}

function sidecar(label: string, source?: string): string {
  return JSON.stringify(source ? { label, source } : { label });
}

describe('loadCorpus', () => {
  it('loads valid samples, skips missing-sidecar and invalid-label entries', async () => {
    await writeFile('safe/sa/s1.eml', 'From: a@b.com\n\nbody-safe');
    await writeFile('safe/sa/s1.eml.label.json', sidecar('safe', 'sa'));
    await writeFile('phishing/nazario/p1.eml', 'From: phish@x.io\n\nbody-phish');
    await writeFile('phishing/nazario/p1.eml.label.json', sidecar('phishing', 'nazario'));
    await writeFile('bec/curated/b1.eml', 'From: ceo@fake.com\n\nwire please');
    await writeFile('bec/curated/b1.eml.label.json', sidecar('bec', 'curated'));
    // no sidecar → skip
    await writeFile('spam/sa/missing.eml', 'From: c@d.com\n\nno label file');
    // invalid label → skip
    await writeFile('safe/sa/bad.eml', 'From: e@f.com\n\nbad label');
    await writeFile('safe/sa/bad.eml.label.json', sidecar('malware'));

    const result = await loadCorpus({ rootDir: root });

    expect(result.samples).toHaveLength(3);
    expect(result.skipped).toHaveLength(2);

    const labels = result.samples.map((s) => s.label).sort();
    expect(labels).toEqual(['bec', 'phishing', 'safe']);

    const reasons = result.skipped.map((s) => s.reason).join(' ');
    expect(reasons).toMatch(/missing/i);
    expect(reasons).toMatch(/invalid label/i);

    const safe = result.samples.find((s) => s.label === 'safe')!;
    expect(safe.rawEmail).toContain('body-safe');
    expect(safe.source).toBe('sa');
    expect(safe.id).toBe('safe/sa/s1');
  });

  it('falls back to the parent directory name when the sidecar omits source', async () => {
    await writeFile('safe/hamhost/fb.eml', 'From: a@b.com\n\nbody');
    await writeFile('safe/hamhost/fb.eml.label.json', sidecar('safe')); // no source

    const result = await loadCorpus({ rootDir: root });
    expect(result.samples).toHaveLength(1);
    expect(result.samples[0].source).toBe('hamhost');
  });

  it('emits onSkipped for each skipped sample', async () => {
    await writeFile('safe/sa/orphan.eml', 'body');
    const skipped: string[] = [];
    await loadCorpus({ rootDir: root, onSkipped: (s) => skipped.push(s.reason) });
    expect(skipped).toHaveLength(1);
    expect(skipped[0]).toMatch(/missing/i);
  });

  it('reads index.json manifest when present, null when absent', async () => {
    await writeFile(
      'index.json',
      JSON.stringify({
        version: 2,
        sampleCount: 99,
        labelCounts: { safe: 50, spam: 10, phishing: 30, bec: 9 },
      })
    );
    const withManifest = await loadCorpus({ rootDir: root });
    expect(withManifest.manifest).not.toBeNull();
    expect(withManifest.manifest?.sampleCount).toBe(99);
    expect(withManifest.manifest?.labelCounts.phishing).toBe(30);

    // Fresh dir with no index.json
    const empty = await fs.mkdtemp(join(tmpdir(), 'corpus-empty-'));
    try {
      const noManifest = await loadCorpus({ rootDir: empty });
      expect(noManifest.manifest).toBeNull();
    } finally {
      await fs.rm(empty, { recursive: true, force: true });
    }
  });
});

describe('buildManifest', () => {
  it('derives sample count, label counts, and per-source breakdown', async () => {
    await writeFile('safe/sa/a.eml', 'b');
    await writeFile('safe/sa/a.eml.label.json', sidecar('safe', 'sa'));
    await writeFile('safe/sa/c.eml', 'b');
    await writeFile('safe/sa/c.eml.label.json', sidecar('safe', 'sa'));
    await writeFile('phishing/nazario/d.eml', 'b');
    await writeFile('phishing/nazario/d.eml.label.json', sidecar('phishing', 'nazario'));

    const { samples } = await loadCorpus({ rootDir: root });
    const manifest = buildManifest(samples);

    expect(manifest.sampleCount).toBe(3);
    expect(manifest.labelCounts.safe).toBe(2);
    expect(manifest.labelCounts.phishing).toBe(1);
    expect(manifest.labelCounts.bec).toBe(0);
    const sa = manifest.sources.find((s) => s.name === 'sa');
    expect(sa?.label).toBe('safe');
    expect(sa?.count).toBe(2);
  });
});

describe('parseManifest', () => {
  it('tolerates missing fields and ignores junk', () => {
    const empty = parseManifest({});
    expect(empty.version).toBe(1);
    expect(empty.sampleCount).toBe(0);
    expect(empty.sources).toEqual([]);

    const partial = parseManifest({
      labelCounts: { safe: 5, junk: 'x' },
      sampleCount: 7,
    });
    expect(partial.labelCounts.safe).toBe(5);
    expect(partial.sampleCount).toBe(7);

    const withSources = parseManifest({
      sources: [
        { label: 'phishing', name: 'nazario', count: 10 },
        { label: 'not-a-label', name: 'bad' },
        null,
      ],
    });
    expect(withSources.sources).toHaveLength(1);
    expect(withSources.sources[0].name).toBe('nazario');
  });
});
