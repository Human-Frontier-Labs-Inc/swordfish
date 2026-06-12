# Stream B — Detection Accuracy Proof (Day-by-Day Plan)

**Scope:** Turn Swordfish's existing 9-layer detection plumbing into a launchable accuracy claim. Decision #2 locked: public corpora + 50-100 hand-curated BEC. No commercial license until +30 unless the launch number forces it.

**Owner stream:** Single engineer + one Sonnet/Haiku coder fork for grunt work. Stay off Opus for routine file moves and CSV transforms.

**Hard rule:** at launch, "X% precision / Y% recall on a published benchmark + N curated BEC scenarios" must be a sentence we can defend on a sales call. Today, the answer is "we have unit tests" and that does not survive contact with a security buyer.

---

## Phase 1 — Verification of engine state (Day 0)

Findings from Audit 2 verified by direct read on 2026-05-28:

| Claim | Verified at | Status |
|---|---|---|
| 9-layer pipeline real, ~1427 LOC | `lib/detection/pipeline.ts` (`wc -l` = 1427) | ✓ |
| "ML classifier" is hand-written weighted sum, not trained | `lib/detection/ml/classifier.ts:126-134` — literal `text*0.30 + structural*0.25 + sender*0.15 + content*0.15 + behavioral*0.15` | ✓ |
| URL shortener escalation wired | `lib/detection/ml/classifier.ts:136-154` — escalates to `critical` + 20 when ≥2 other warning/critical signals present | ✓ |
| Thresholds | `lib/detection/types.ts:323-339` — pass=35 / suspicious=55 / quarantine=73 / block=85 | ✓ |
| `llmDailyLimitPerTenant: 100` (dangerously low at $3–8/mailbox pricing) | `lib/detection/types.ts:335` | ✓ |
| `llmModel: 'claude-3-5-haiku-20241022'` hardcoded | `lib/detection/types.ts:333` | ✓ |
| PhishTank feed dead — registration closed | `lib/threat-intel/feeds/phishtank.ts:45` — comment "registration closed as of 2024" + 25 hardcoded `SAMPLE_PHISHING_URLS` | ✓ (note: actual path is `lib/threat-intel/feeds/`, NOT `lib/detection/feeds/` as the original directive said) |
| No labeled corpus | `tests/fixtures/` contains `emails.ts` (9 synthetic) + `index.ts`. No `corpus/`. | ✓ |
| No eval harness | `scripts/test-detection.ts` is a 2-email console demo (header confirmed). No P/R/F1 anywhere. | ✓ |
| `node_modules` missing in working tree | `test -d node_modules` returns missing | ✓ — must `npm install` before any eval run |

Path correction noted: the directive said `lib/detection/feeds/phishtank.ts` — the actual file is `lib/threat-intel/feeds/phishtank.ts`. Plan below uses the correct path.

---

## Days 1-3 — Public corpora acquisition + on-disk schema

**Goal:** Get 3,000-5,000 labeled emails from public sources on disk, normalized to a single schema.

### Sources

| Source | Type | Approx count | License | Notes |
|---|---|---|---|---|
| **SpamAssassin Public Corpus** | ham + spam | ~6,000 ham, ~2,000 spam | Apache 2.0 | https://spamassassin.apache.org/old/publiccorpus/ — RFC822 mbox files |
| **Nazario Phishing Corpus** | phishing | ~4,000 | Public, attribution required | https://monkey.org/~jose/phishing/ — RFC822 |
| **APWG eCrime samples** | phishing + BEC | ~200-500 | Free for research with agreement | https://apwg.org/ecx — slower; only if Nazario doesn't cover BEC well |
| **(Stretch) Enron** | ham (corporate baseline) | thousands | Public | https://www.cs.cmu.edu/~enron/ — useful for BEC baseline (real corporate language) |

**Out of scope for Phase 1:** anything that requires a commercial license. Per locked decision #2, that's a +30 question.

### On-disk schema

Land at `tests/fixtures/corpus/`:

```
tests/fixtures/corpus/
├── index.json                    # manifest: source, license attribution, count per label
├── README.md                     # corpus description, attribution, how to add samples
├── safe/
│   ├── spamassassin-ham/         # *.eml files (RFC822)
│   └── enron-baseline/           # (Phase 1 stretch)
├── spam/
│   └── spamassassin-spam/
├── phishing/
│   ├── nazario/
│   └── apwg/
└── bec/
    └── curated/                  # populated in Days 4-5
```

**One labeled sample = one `.eml` file** (RFC822 raw, parseable by `lib/detection/parser.ts`). Filename: `{source}-{hash8}.eml`. Sidecar `{filename}.label.json` with `{ label: 'safe'|'spam'|'phishing'|'bec', source: '...', notes?: '...' }`.

### Tasks

- D1.1: Add `scripts/corpus/fetch-spamassassin.ts` — downloads + unpacks the published `.tar.bz2`, normalizes to `tests/fixtures/corpus/safe/spamassassin-ham/` + `tests/fixtures/corpus/spam/spamassassin-spam/`, writes sidecar labels.
- D1.2: Add `scripts/corpus/fetch-nazario.ts` — same shape for Nazario, into `phishing/nazario/`.
- D1.3: Define `tests/fixtures/corpus/index.json` — generated, not hand-edited. Includes per-source counts + SHA256 of the manifest for CI determinism.
- D2.1: Land `scripts/corpus/normalize.ts` (shared helpers): strip CRLF, validate parseability by `parseEmail`, drop unparseable samples to `tests/fixtures/corpus/.rejected/`.
- D2.2: Run normalizer end-to-end, verify counts within 10% of source claims.
- D3.1: Document attribution in `tests/fixtures/corpus/README.md` (required by some source licenses).
- D3.2: Add `.gitattributes` rule for `tests/fixtures/corpus/**/*.eml` → `linguist-generated` (don't bloat blame/diff stats).

### `.gitignore` decision (sign-off candidate)

A 3-5k email corpus is 50-200 MB. Two options:
1. **Commit it.** Pro: deterministic, CI-reachable. Con: bloats repo.
2. **Gitignore + fetch script in CI.** Pro: clean repo. Con: external dependency on the source URL staying up (and SpamAssassin's old URL is mostly stable but not guaranteed).

**Recommend:** commit a *subset* (~500 samples, balanced) for CI determinism, fetch the full corpus on demand. Need Corn sign-off before checking in large binary content. Default to committing the subset.

---

## Days 4-5 — Hand-curated BEC pack (50-100 scenarios)

**Goal:** 50-100 BEC samples covering the 5 classic scenarios. These are the differentiator vs. generic phishing detection.

### Categories (target ~10-20 each)

| Category | What it looks like | Source |
|---|---|---|
| **CEO impersonation** | Spoofed display-name, urgent ask from "CEO" | Construct from public BEC reports (FBI IC3, anti-phishing.org case studies) |
| **Wire fraud** | "Change wire account before tomorrow's transfer" | Same |
| **Payroll diversion** | "Update my direct deposit before payday" | Same |
| **Vendor change** | "We've changed bank accounts — new invoice attached" | Same |
| **Gift card scam** | "I'm in a meeting — buy me $500 in iTunes cards" | Same |

### Curation criteria (write to `tests/fixtures/corpus/bec/curated/CRITERIA.md`)

1. Real-style language (no obvious typos unless the scenario calls for it).
2. Realistic headers — Reply-To mismatch, free-mail domain spoof, or display-name spoof at minimum.
3. Each sample tags which signals it SHOULD trigger (header_mismatch, display_name_spoof, urgency, financial_request, vip_spoof).
4. **No PII / no copy from real victim correspondence.** Synthetic only, modeled on public reports.

### Tasks

- D4.1: Write 10 each of CEO impersonation, wire fraud, payroll, vendor change, gift card. Total = 50 first pass.
- D4.2: For each, attach `{filename}.label.json` with `label: 'bec'` + expected-signals list.
- D5.1: Second pass: 30-50 more covering edge cases (multi-stage replies, lookalike domains, late-signal cases).
- D5.2: Validate every sample parses + every sample's tagged signals are actually computable (i.e., the deterministic+lookalike layer extracts them).

**Sign-off needed:** none if synthetic. If we want to seed any redacted real samples from a pilot, that's a customer-data question.

---

## Days 6-10 — Eval harness (`scripts/eval/`)

**Goal:** Repeatable `npm run eval` produces a JSON + markdown report with per-class P/R/F1, confusion matrix, threshold sweep, per-layer attribution, and latency p50/p95.

### Output shape

`scripts/eval/run.ts` produces:

```
docs/eval/runs/{ISO_TIMESTAMP}/
├── results.json     # full per-sample verdict + scores
├── summary.json     # aggregated P/R/F1 + confusion + latency
├── threshold-sweep.json  # P/R at 5-point increments across each threshold
└── report.md        # human-readable summary
```

### Tasks

- D6.1: `scripts/eval/load-corpus.ts` — reads `tests/fixtures/corpus/index.json`, yields `{ email: ParsedEmail, label: ExpectedLabel, source: string }`. Handles malformed sidecar gracefully (logs + skips).
- D6.2: `scripts/eval/run.ts` — loads corpus, runs `analyzeEmail` from `lib/detection/pipeline.ts`, captures `{ score, verdict, signals[], category, latencyMs, llmInvoked }` per sample.
- D7.1: `scripts/eval/metrics.ts` — per-class P/R/F1 + confusion matrix + macro-/micro-averages.
- D7.2: `scripts/eval/threshold-sweep.ts` — re-applies `verdict` for {pass, suspicious, quarantine, block} ∈ [25..95 step 5]. Outputs F1-curve per category.
- D8.1: `scripts/eval/per-layer.ts` — attributes verdict to which layer's signals dominated (deterministic/ML/BEC/sandbox/LLM). Useful for "is LLM actually carrying weight?"
- D8.2: `scripts/eval/latency.ts` — p50/p95 per sample + LLM-invoked vs non-LLM.
- D9.1: Reporter that emits `report.md` (markdown table summarizing summary.json).
- D9.2: Wire `npm run eval` script in `package.json`.
- D10.1: Smoke-test on the 9 synthetic fixtures + 100 SpamAssassin samples to verify the harness runs end-to-end before the full corpus arrives.
- D10.2: Document `scripts/eval/README.md` (how to run, where reports land, how to interpret).

### Out of scope here

- Live LLM calls during eval. The eval harness must support a `--no-llm` flag (run with LLM disabled to baseline non-LLM layers) and a `--llm-budget N` flag (cap LLM calls per run for cost control). **Both flags ship in Days 6-10.**

---

## Days 11-15 — Baseline + threshold tuning

**Goal:** Pick an operating point that hits **target FP ≤ 1%** on the ham corpus while maximizing BEC + phishing recall.

### Tasks

- D11.1: Full-corpus baseline run with current thresholds (35/55/73/85) and `--no-llm`. Capture: macro-F1 per category, confusion matrix, FP rate on `safe/`.
- D11.2: Baseline run *with* LLM enabled (capped). Compare delta.
- D11.3: Sanity check — if BEC recall <60% on hand-curated set, audit signal extraction on the misses BEFORE touching thresholds (signals are the issue, not gating).
- D12: Threshold sweep, full corpus, no LLM. Plot per-category F1 vs each threshold.
- D13: Pick candidate operating point. Document tradeoff (e.g., "lowered quarantine to 68 to lift BEC recall +8pts at cost of +0.3% FP").
- D14: Verify operating point on a holdout (last 20% of corpus held out from tuning).
- D15: Lock thresholds into `DEFAULT_DETECTION_CONFIG` (migration to `lib/detection/types.ts:323`) and add a `LOCKED_AT` comment with the eval-run hash. Tenant-config overrides still allowed.

### Sign-off candidate

If baseline recall on BEC is below 50%, the right answer is probably to add detection logic (signals/heuristics), not to lower thresholds. That's a scope question for Corn — accept the lower launch number, extend Stream B, or both.

---

## Days 16-20 — PhishTank repair, LLM budget, CI gate

### PhishTank

The free PhishTank registration is closed (verified in `lib/threat-intel/feeds/phishtank.ts:45`). Three options:

1. **Migrate to OpenPhish primary.** `lib/threat-intel/feeds/openphish.ts` already exists. OpenPhish has a free community feed (lower volume) + paid feed. Use community feed; fall back to URLhaus + Sample list. ~2 days.
2. **Pay for PhishTank Plus** ($) — cleanest but adds vendor cost. Deferred.
3. **Drop PhishTank entirely** — rely on URLhaus + OpenPhish + reputation lookups. Simplest.

**Recommend option 1** (OpenPhish primary, PhishTank deprecated, hardcoded sample list deleted because it ages worse than not having it).

- D16: Migrate `lib/threat-intel/intel-service.ts` (the orchestrator) to read OpenPhish first; PhishTank becomes opt-in via env var.
- D16.5: Delete `SAMPLE_PHISHING_URLS` (lines 46-82 of `feeds/phishtank.ts`). Stale sample data is worse than a missing feed because it gives false confidence.

### LLM budget

`llmDailyLimitPerTenant: 100` (verified at `types.ts:335`) is broken at $3-8/mailbox pricing. A 50-mailbox tenant scanning ~5000 emails/day exhausts the layer in minutes.

Options:
- **Raise to 5000/tenant** — most flexible, but exposes us to LLM cost runaway.
- **Per-mailbox limit (e.g., 50/mailbox/day)** — scales with revenue. Best mapped to pricing.
- **Confidence-gated** — only LLM-call when ML confidence ∈ [0.4, 0.7] AND `current_daily_count < per_tenant_cap`.

**Recommend:** per-mailbox limit of 50/mailbox/day, hard cap of 50,000/tenant/day. Requires schema for `tenants.llm_daily_call_count` reset (or Redis counter — Upstash is already in stack). Sign-off candidate because it has cost implications.

- D17: Refactor `llmDailyLimitPerTenant` → `llmDailyLimitPerMailbox` in `types.ts`. Add `llmHardCapPerTenant`.
- D17.5: Wire the per-mailbox counter to Redis (`@upstash/redis` already a direct dep). TTL = end-of-day-UTC.
- D18: Update `lib/detection/llm.ts` to gate on per-mailbox counter + hard cap.

### CI accuracy regression gate

- D19: `.github/workflows/detection-eval.yml` — on PR touching `lib/detection/**` or `lib/threat-intel/**`, run the eval harness on a CI-pinned 500-sample subset. Fail if macro-F1 drops >2 points on any category vs. the `main` branch baseline.
- D19.5: Store `main` branch baseline at `docs/eval/baseline.json`. Comparison is fail-on-regress, not fail-on-absolute.
- D20: Add the same job to nightly: full corpus eval against `main`, post results to a Slack webhook (or whatever channel ops uses).

### Sign-off candidates here

1. LLM per-mailbox limit number (50/day default — Corn signs off on cost model).
2. Deleting `SAMPLE_PHISHING_URLS` hardcoded list — recommend yes, but flagging because the audit found removing this could surface "I thought we had threat intel" surprise.
3. PhishTank migration strategy.

---

## Days 21-25 — Publish, document, ship

### Tasks

- D21: Final full-corpus eval run on the locked thresholds + locked OpenPhish wiring + LLM gating.
- D22: Write `docs/eval/launch-numbers.md` — the launch claim, broken down: P/R/F1 per category, methodology (corpus sources, attribution, holdout), known limitations.
- D23: Update `app/(marketing)/security/page.tsx` (or wherever the marketing accuracy claim lives) with the published number. Hyperlink to `docs/eval/launch-numbers.md`. **Do not hand-write a number — generate from `summary.json`.**
- D24: Internal review pass — Corn reads the number + methodology, can he defend it on a sales call?
- D25: Cut the v0 detection baseline. Tag the repo with `detection-baseline-v0` so future runs can `git diff` against it.

---

## Items requiring Corn sign-off (consolidated)

1. **Commit vs. fetch the corpus** — recommend commit balanced 500-sample subset, fetch full on demand. (D3.1)
2. **Commercial corpus license** — per decision #2, **deferred to +30**. Do **not** procure without explicit go. Flag only if baseline F1 forces the conversation.
3. **Threshold lock value** — Day 15, present operating point + FP/recall tradeoff for sign-off.
4. **LLM per-mailbox limit + hard cap** — Day 17, present cost model with number + hard cap.
5. **Delete `SAMPLE_PHISHING_URLS` hardcoded list** — recommend yes, but worth a one-line confirmation. (D16.5)
6. **PhishTank vs OpenPhish primary** — recommend OpenPhish, PhishTank deprecated. (D16)
7. **CI accuracy gate threshold** — recommend "fail PR if macro-F1 drops >2pts on any category." (D19)
8. **`npm install`** — node_modules is missing in the working tree. Eval harness cannot run until installed. Operational dependency.

---

## Out of scope for Stream B

These are real but belong to other streams or +30:

- Refactoring `lib/detection/pipeline.ts` (1427 LOC), `ml/classifier.ts` (640), `deterministic.ts` (650) to <500 LOC each. Per CLAUDE.md but a Stream A concern.
- `response-learner.ts` — frozen per decision #6.
- M365 ingestion → detection wiring — Stream C.
- LLM call cost dashboards — observability is Stream C.
- Auto-remediation triggering off detection verdict — Stream D.
- Replacing the hand-written "ML classifier" with a trained model — explicitly +30 or later. The hand-written scoring + LLM-gating combo is enough for launch if accuracy proves out.

---

## Risk register

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| RB-1 | Public corpora are too generic to lift BEC recall | High | Hand-curated BEC pack (D4-5) is the antidote. If still bad, defer launch claim on BEC and stick to "phishing" only. |
| RB-2 | LLM cost explosion at launch with open self-serve (decision #4) | High | Per-mailbox cap + hard tenant cap (D17). Default conservative; revisit when usage data lands. |
| RB-3 | Stale `SAMPLE_PHISHING_URLS` continues to be used somewhere we didn't grep | Medium | Day 16.5 delete + grep for `SAMPLE_PHISHING_URLS` across `app/`, `lib/`, `scripts/`. |
| RB-4 | CI eval gate flakes on slow LLM calls | Medium | CI run uses `--no-llm` + a fixed-pinned subset. LLM-on full runs are nightly only. |
| RB-5 | Threshold tuning overfits to corpus, doesn't generalize | Medium | 20% holdout (D14). Plan a 30-day-post-launch retune from real customer traffic. |
| RB-6 | Source URL for SpamAssassin or Nazario goes down mid-stream | Low | Mirror to a private bucket on first successful fetch. |

---

## 300-word summary (for parent agent)

**Engine state confirmed by direct read:** 9-layer pipeline at `lib/detection/pipeline.ts` (1427 LOC), ML classifier at `ml/classifier.ts` is a hand-written weighted sum (verified at lines 126-134, not a trained model), thresholds locked in `types.ts:323-339` (pass=35/suspicious=55/quarantine=73/block=85), `llmDailyLimitPerTenant: 100` is broken at $3-8/mailbox pricing (verified `types.ts:335`), PhishTank registration is closed with a 2024-era hardcoded `SAMPLE_PHISHING_URLS` fallback (verified `lib/threat-intel/feeds/phishtank.ts:45-82` — note: actual path is `lib/threat-intel/feeds/`, not `lib/detection/feeds/` as the original directive said). `node_modules` is missing — `npm install` is a prerequisite before any eval run.

**Plan headline:** 25-day, six-phase plan landed at `docs/audit/plans/stream-b.md`. Days 1-3 acquire SpamAssassin + Nazario into `tests/fixtures/corpus/` with a normalized `.eml` + sidecar-label schema. Days 4-5 hand-curate 50-100 BEC samples across 5 classic scenarios (CEO, wire, payroll, vendor, gift card). Days 6-10 build the eval harness at `scripts/eval/` emitting per-class P/R/F1 + threshold sweep + per-layer attribution + latency to `docs/eval/runs/{ts}/`. Days 11-15 baseline + tune (target FP ≤1% on ham). Days 16-20 migrate to OpenPhish primary, refactor LLM budget to per-mailbox limit + Redis counter, ship CI accuracy regression gate. Days 21-25 publish launch numbers + tag baseline.

**Sign-off items for Corn:** (1) commit a 500-sample corpus subset to git vs. fetch-on-CI, (2) defer commercial corpus license to +30 unless baseline F1 forces conversation, (3) Day-15 operating-point tradeoff, (4) LLM per-mailbox limit number + hard cap with cost model, (5) deleting `SAMPLE_PHISHING_URLS` hardcoded sample list, (6) PhishTank → OpenPhish primary, (7) CI gate "fail PR if macro-F1 drops >2pts," and (8) operational `npm install` to unblock eval. Risk register includes 6 items, highest being public-corpora-too-generic-for-BEC and LLM-cost-explosion at open self-serve.
