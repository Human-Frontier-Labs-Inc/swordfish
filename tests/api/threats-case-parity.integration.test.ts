/**
 * DB-gated CASE-parity test for the repointed threats read paths.
 *
 * The mock-based route tests (threats-reads.test.ts) prove the routes BUILD the
 * status/threat_type CASE expressions and shape responses correctly, but the
 * CASE never executes under a mock (canned rows come back regardless). This file
 * runs ONLY when a real database is present (hasRealDatabase), seeds
 * email_verdicts rows spanning every branch of deriveThreatStatus /
 * deriveThreatType, and asserts the route's ACTUAL SQL CASE output equals the JS
 * derivation for the same rows. That is the only honest parity proof. It skips
 * cleanly in mock-only CI so the 9/3278 baseline is unaffected.
 *
 * Parity is checked WITHOUT duplicating the CASE: the JS oracle is
 * getThreatsForManagement (derives via mapVerdictRowToThreat), and the SQL-CASE
 * side is exercised through the real route/readers — search with status /
 * threatTypes filters (CASE in the WHERE) and getThreatFeedStats (status counts
 * via CASE). If the route's CASE ever drifts from the JS derivation, these sets
 * diverge.
 */

import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import { sql } from '@/lib/db';
import { getThreatsForManagement, getThreatFeedStats } from '@/lib/detection/storage';
import { GET as searchGet } from '@/app/api/threats/search/route';

// Mirror tests/helpers/vitest-setup.ts: a real DB only when DATABASE_URL is set
// to something other than the localhost fallback.
const hasRealDatabase =
  !!process.env.DATABASE_URL &&
  !process.env.DATABASE_URL.includes('localhost:5432/test');

// Hoisted so the auth mock factory (also hoisted) can reference it safely.
const { TENANT } = vi.hoisted(() => ({ TENANT: 'glm_case_parity' }));

vi.mock('@clerk/nextjs/server', () => ({
  // Force the routes onto our isolated seed tenant.
  auth: vi.fn().mockResolvedValue({ userId: 'glm_case_parity_user', orgId: TENANT }),
}));

// Seeded rows spanning every branch of deriveThreatStatus + deriveThreatType.
// All use threatening verdicts so they fall inside the search/feed scope
// (verdict IN suspicious/quarantine/block).
const SEED: Array<{
  message_id: string;
  verdict: string;
  action_taken: string | null;
  user_feedback: string | null;
  signals: Array<{ type: string }>;
}> = [
  // --- status branches (deriveThreatStatus) ---
  { message_id: '<p-released@x.com>', verdict: 'quarantine', action_taken: 'released', user_feedback: null, signals: [{ type: 'credential_request' }] }, // -> released
  { message_id: '<p-delivered@x.com>', verdict: 'block', action_taken: 'delivered', user_feedback: null, signals: [{ type: 'credential_request' }] }, // -> released
  { message_id: '<p-deleted@x.com>', verdict: 'quarantine', action_taken: 'deleted', user_feedback: null, signals: [{ type: 'credential_request' }] }, // -> deleted
  { message_id: '<p-fp@x.com>', verdict: 'quarantine', action_taken: null, user_feedback: 'false_positive', signals: [{ type: 'credential_request' }] }, // -> released
  { message_id: '<p-quar@x.com>', verdict: 'quarantine', action_taken: null, user_feedback: null, signals: [{ type: 'credential_request' }] }, // -> quarantined
  { message_id: '<p-block@x.com>', verdict: 'block', action_taken: null, user_feedback: null, signals: [{ type: 'credential_request' }] }, // -> quarantined
  // --- threat_type branches (deriveThreatType) ---
  { message_id: '<p-bec@x.com>', verdict: 'quarantine', action_taken: null, user_feedback: null, signals: [{ type: 'financial_request' }] }, // -> bec
  { message_id: '<p-malware@x.com>', verdict: 'quarantine', action_taken: null, user_feedback: null, signals: [{ type: 'executable' }] }, // -> malware
  { message_id: '<p-spam@x.com>', verdict: 'quarantine', action_taken: null, user_feedback: null, signals: [{ type: 'spam' }] }, // -> spam
  { message_id: '<p-none@x.com>', verdict: 'quarantine', action_taken: null, user_feedback: null, signals: [] }, // -> phishing (default)
];

type Derived = { status: string; threat_type: string };

describe.skipIf(!hasRealDatabase)('threats CASE-parity (DB-gated)', () => {
  let oracle: Map<string, Derived>;

  beforeAll(async () => {
    // Seed (idempotent in case a prior run was interrupted before cleanup).
    for (const r of SEED) {
      await sql`
        INSERT INTO email_verdicts (
          tenant_id, message_id, verdict, score, signals,
          action_taken, user_feedback, subject, from_address, created_at
        ) VALUES (
          ${TENANT}, ${r.message_id}, ${r.verdict}, 80, ${JSON.stringify(r.signals)}::jsonb,
          ${r.action_taken}, ${r.user_feedback}, 'parity', 'p@x.com', NOW()
        )
        ON CONFLICT (tenant_id, message_id) DO UPDATE SET
          verdict = EXCLUDED.verdict,
          signals = EXCLUDED.signals,
          action_taken = EXCLUDED.action_taken,
          user_feedback = EXCLUDED.user_feedback
      `;
    }

    // JS oracle: getThreatsForManagement derives status/threat_type in JS.
    const managed = await getThreatsForManagement(TENANT, { status: 'all', limit: 100 });
    oracle = new Map(managed.map((t) => [t.message_id, { status: t.status, threat_type: t.threat_type }]));
    // Sanity: every seeded row made it into the oracle.
    for (const r of SEED) {
      expect(oracle.has(r.message_id)).toBe(true);
    }
  });

  afterAll(async () => {
    await sql`DELETE FROM email_verdicts WHERE tenant_id = ${TENANT}`;
  });

  function oracleIdsFor(pred: (v: Derived) => boolean): Set<string> {
    return new Set([...oracle.entries()].filter(([, v]) => pred(v)).map(([k]) => k));
  }

  async function searchIds(query: string): Promise<Set<string>> {
    const res = await searchGet(
      new NextRequest(`http://localhost/api/threats/search?${query}&limit=100`)
    );
    const data = await res.json();
    return new Set((data.threats as Array<{ message_id: string }>).map((t) => t.message_id));
  }

  it('search STATUS_EXPR matches JS deriveThreatStatus for every status', async () => {
    for (const s of ['quarantined', 'released', 'deleted']) {
      const sqlIds = await searchIds(`status=${s}`);
      const jsIds = oracleIdsFor((v) => v.status === s);
      expect([...sqlIds].sort(), `status=${s}`).toEqual([...jsIds].sort());
    }
  });

  it('search THREAT_TYPE_EXPR matches JS deriveThreatType for every type', async () => {
    for (const t of ['phishing', 'bec', 'malware', 'spam']) {
      const sqlIds = await searchIds(`types=${t}`);
      const jsIds = oracleIdsFor((v) => v.threat_type === t);
      expect([...sqlIds].sort(), `threat_type=${t}`).toEqual([...jsIds].sort());
    }
  });

  it('getThreatFeedStats status counts match the JS derivation', async () => {
    const stats = await getThreatFeedStats(TENANT);
    for (const s of ['quarantined', 'released', 'deleted'] as const) {
      const jsCount = oracleIdsFor((v) => v.status === s).size;
      expect(stats[s], `status=${s}`).toBe(jsCount);
    }
  });
});
