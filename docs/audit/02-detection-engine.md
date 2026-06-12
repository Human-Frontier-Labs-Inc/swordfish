# Audit 02 — Detection Engine

**Scope:** What actually catches BEC/phishing today, can we prove it works, and is "measurable detection accuracy at launch in 30 days" credible?
**Method:** Read-only static audit of `lib/detection/`, `lib/threat-intel/`, `tests/detection/`, `tests/fixtures/`, `scripts/test-detection.ts`. Tests could not be executed because `node_modules` is not installed.

---

## 1. What detects threats today

`lib/detection/pipeline.ts:116` (`analyzeEmail`) is a 1,427-line orchestrator that runs ~9 layers in three phases. There is real, multi-layer logic here — this is not a single LLM call wrapper.

### Layers (in order of contribution)

| # | Layer | File | Type |
|---|---|---|---|
| 0 | Email type classification | `lib/detection/classifier/email-type.ts` | Heuristic (marketing/transactional/personal) |
| 1 | Policy (allow/block lists) | `lib/policies/engine.ts` (called at `pipeline.ts:147`) | Tenant-config rules |
| 2 | Sender reputation lookup | `lib/detection/reputation/sender-lookup.ts` | DB-backed registry + trust score |
| 3 | Deterministic | `lib/detection/deterministic.ts:99` (650 lines) | Heuristics — SPF/DKIM/DMARC, homoglyph, cousin, urgency/credential/financial regex, URL extraction |
| 3.5 | Lookalike (Phase 4c) | `lib/detection/phase4c-integration.ts` | Homoglyph + typosquat + cousin domain detector |
| 4 | ML classifier | `lib/detection/ml/classifier.ts:1` (640 lines) | Hand-written feature extraction → weighted score (NOT a trained model — see §6) |
| 5 | BEC detector | `lib/detection/bec/detector.ts` | Pattern + VIP-list-based BEC scoring |
| 6 | Sandbox | `lib/detection/sandbox-layer.ts` | Attachment dynamic analysis |
| 7 | LLM | `lib/detection/llm.ts:241` + `llm-provider.ts` | **Anthropic Claude Haiku 3.5** (`claude-3-5-haiku-20241022`); gated to uncertain or trusted-high-score cases |
| 8 | Feedback learning | `lib/feedback/feedback-learning.ts` (called at `pipeline.ts:429`) | Tenant rule adjustments |
| 9 | Trust modifier + safety floor | `pipeline.ts:461-545` | Caps trusted-sender scores; re-applies floor for ≥2-3 critical signals |

### Third-party reputation/threat intel
`lib/threat-intel/`:
- **PhishTank** (`feeds/phishtank.ts:21`) — public-data URL fetch; **API registration is closed**, falls back to pattern-based hardcoded sample list (`SAMPLE_PHISHING_URLS`).
- **OpenPhish, URLhaus** — feed pullers exist (`feeds/openphish.ts`, `feeds/urlhaus.ts`).
- **urlscan.io, VirusTotal** — `urlscan.ts`, `virustotal.ts` (require API keys via env).
- **Domain age / WHOIS** — `domain/age.ts`, `domain/whois.ts`.
- **IP blocklists** — `ip/blocklists.ts`.

Verdict: real threat-intel surface area exists, but PhishTank fallback is a list of 2024-era hardcoded samples — not a live feed.

---

## 2. Labeled test corpus

**There is no labeled production corpus.** What exists:

- `tests/fixtures/emails.ts` (303 lines, 9 synthetic email fixtures — `legitimateBusinessEmail`, `obviousPhishingEmail`, `becEmail`, `urgencyOnlyEmail`, `marketingEmail`, etc.). Hand-crafted, not from the wild.
- `scripts/test-detection.ts` (109 lines) — one-off demo with **2 hardcoded emails** that prints signal output. Not an eval, no metrics.
- `tests/detection/*.test.ts` — 18 spec files, ~572 `it/test` blocks. These are unit tests asserting things like `score < 40` or `score > 10` against the 9 synthetic fixtures. Not precision/recall measurement.

External corpus references searched (`phishtank|labeled|corpus|golden`): only PhishTank fetch code, no committed labeled dataset. No `tests/fixtures/corpus/`, no `data/`, no `eval/`.

---

## 3. Eval harness measuring precision/recall

**There is no precision/recall eval harness.**

- No script computes confusion matrix, per-category P/R/F1, or threshold sweep.
- Tests use boolean assertions (`expect(result.score).toBeGreaterThan(N)`) against single fixtures.
- `scripts/test-detection.ts` is a console demo of two emails, not measurement.
- I attempted `vitest run tests/detection/edge-cases.test.ts`: **failed — `node_modules` is not installed** in the working tree (`vitest/config` cannot be resolved). Tests have not been executed in this audit.

Verdict: today's "accuracy" claims would be vibes, not measurement.

---

## 4. Signals extracted

Comprehensive — the surface area is wide. From `lib/detection/types.ts:60-243` (`SignalType` union) and code:

- **Headers**: SPF, DKIM, DMARC, Authentication-Results, Reply-To mismatch, Message-ID presence, envelope mismatch.
- **Sender domain**: free-email provider, disposable, homoglyph (Cyrillic/Greek substitution table at `deterministic.ts:38-66`), cousin domain, display-name spoof, domain age, lookalike (typosquat/homoglyph/cousin), unicode spoof.
- **Content**: urgency regex (`deterministic.ts:69-76`), financial-request regex, credential-request regex, BEC keyword bank (~60 phrases at `ml/classifier.ts`), grammar/sentiment scoring.
- **URLs**: extraction, classification (tracking/redirect/malicious/safe), lookalike target detection, obfuscation, redirect-chain analysis (Phase 4b), shortener detection, IP-as-host detection, QR-code-encoded URL detection (`qr-detector.ts`).
- **Attachments**: file-type magic-byte detection, dangerous/script/executable/archive extensions, macro extraction (Phase 4b `macro-analysis`), password-protected archives, RTL-override filename trick.
- **Behavioral** (`lib/behavioral/`): first-contact, contact graph, anomaly engine, baselines, lookalike detector — all DB-backed per-tenant.
- **Reputation**: sender trust score (0-100), known-good categorization (newsletter/government/business).
- **Threat intel**: domain/URL hits across PhishTank, URLhaus, OpenPhish, urlscan, VirusTotal (when keys present).

Compared to "Proofpoint/Mimecast modern alternative" framing: signal coverage is competitive on paper. The gap is not breadth — it's measurement.

---

## 5. URL shortener escalation (commit 25d90e3)

**Wiring** — `lib/detection/ml/classifier.ts:136-154`:
- After ML scoring, finds any `ml_shortener` signal.
- Counts **other** signals with severity `warning` or `critical`.
- If ≥2 such signals exist, escalates the shortener signal to `severity: 'critical'` and adds **+20 score**.
- Detail string is appended with `— escalated: combined with N other suspicious signals`.

**Companion logic** — `lib/detection/deterministic.ts:131-150`:
- If SPF + DKIM + DMARC are all `'none'` AND any URL is present, adds a `no_authentication` signal (`score: 20`, severity `warning`).

**Tests** — `tests/detection/edge-cases.test.ts:40-105` (3 tests):
1. Shortener alone stays `warning`, detail does not contain "escalated".
2. Shortener + 2+ other warning/critical signals becomes `critical` with "escalated" in detail.
3. Escalated shortener score ≥ 35 (15 base × 1 + 20 boost).

**Test execution status:** could not run — `node_modules` missing. Logic by inspection looks correct, but unverified.

---

## 6. Thresholds and where they're set

**Verdict thresholds** — `lib/detection/types.ts:323-340` (`DEFAULT_DETECTION_CONFIG`):

| Setting | Value | Notes |
|---|---|---|
| `passThreshold` | 35 | Phase 3 raised from 30 |
| `suspiciousThreshold` | 55 | Phase 3 raised from 50 |
| `quarantineThreshold` | 73 | Phase 3 lowered from 75 |
| `blockThreshold` | 85 | Unchanged |
| `skipMlIfDeterministicBelow` | 20 | ML gating |
| `skipMlIfDeterministicAbove` | 80 | ML gating |
| `invokeLlmConfidenceRange` | `[0.4, 0.7]` | LLM only on uncertain ML confidence |
| `llmModel` | `claude-3-5-haiku-20241022` | Hardcoded (could be promoted to env) |
| `llmMaxTokens` | 1024 | |
| `llmDailyLimitPerTenant` | **100** | **Very low — see risk note** |
| `urlAnalysisTimeoutMs` | 5000 | |
| `sandboxTimeoutMs` | 180000 | 3 minutes |

LLM-verdict-to-score mapping is hardcoded in `llm.ts:498-515` (`verdictToScore`): `phishing→50`, `bec→55`, `likely_phishing→35`, `likely_bec→40`, `suspicious→20`, `safe→0`.

Per-tenant overrides exist via `lib/detection/tenant-config.ts` (`getCategoryThreshold`, `isModuleEnabled`). MSP multi-tenant tuning is wired.

**Critical hidden gate** — the "ML classifier" (`ml/classifier.ts:1-640`) is **NOT a trained model**. It's hand-written feature extraction (`extractFeatures`) and a weighted-sum scorer (`text*0.30 + structural*0.25 + sender*0.15 + content*0.15 + behavioral*0.15`). The `lib/ml/predictor.ts`, `training-pipeline.ts`, and `feature-extractor.ts` files exist but the pipeline path uses the hand-written classifier, not a learned model. Calling this layer "ML" is generous; it is heuristic feature scoring.

---

## Critical question — credible "measurable detection accuracy" at launch in 30 days?

**Honest answer: No, not credibly, with the current corpus situation.** It is achievable in 30 days but requires deliberate work that is not in flight today.

### What's missing
1. **No labeled real-world corpus.** 9 synthetic fixtures cannot prove accuracy on production traffic. A modern email-security buyer (anyone replacing Proofpoint/Mimecast) will ask "what's your false-positive rate" and "what's your catch rate vs. industry benchmark." Today there is no way to answer.
2. **No eval harness.** No script feeds a corpus through `analyzeEmail` and emits P/R/F1 per category (BEC/phishing/spam/safe).
3. **No CI gate.** Detection regressions cannot be caught — there is nothing failing the build when accuracy drops.
4. **`llmDailyLimitPerTenant: 100`** at GA pricing of $3-8/mailbox would mean a 50-mailbox tenant starves the LLM layer almost immediately. Either the limit needs to be raised by 10-100x or the gating logic needs to ensure non-LLM layers carry weight without it.
5. **PhishTank is dead-letter.** The fallback is hardcoded sample URLs from 2024. URLhaus + OpenPhish are real — confirm those are actually being polled.

### What it would take in 30 days (one engineer, focused)
1. **Days 1-3 — corpus acquisition.** Combine: SpamAssassin Public Corpus (~7k ham, ~2k spam) + Nazario phishing corpus + APWG samples + 200-500 hand-curated BEC examples (synthetic + redacted real ones from any willing pilot). Target 3,000-5,000 labeled emails across `safe/spam/phishing/bec`.
2. **Days 4-6 — eval harness.** Script: `scripts/eval-detection.ts` that loads corpus → runs `analyzeEmail` on each → emits `eval-results.json` with per-class P/R/F1 + confusion matrix + threshold sweep + latency p50/p95.
3. **Days 7-10 — threshold tuning.** Run sweep across (passThreshold, quarantineThreshold, blockThreshold) and the `verdictToScore` map; pick the operating point that hits a target FP rate (e.g. <0.5% on ham) while maximizing BEC/phishing recall.
4. **Days 11-14 — LLM gating + budget.** Either raise daily limit to a defensible number, or rework `shouldInvokeLLM` so non-LLM layers can hit ≥85% recall on the corpus without LLM, keeping LLM as upgrade signal.
5. **Days 15-21 — CI gate + dashboards.** Eval runs in CI; PR fails if F1 drops >2% on any category; nightly run against threat-intel feeds; results piped to a dashboard customers can see.
6. **Days 22-30 — closed-loop pilot.** Onboard 1-2 friendly pilots, ingest their real (anonymized) flagged emails into corpus weekly, retune.

This is roughly 21-25 engineer-days of focused work — feasible in 30 if it starts now and isn't competing with M365 + Slack/Teams + SIEM webhook builds running in parallel. **If detection-accuracy proof is non-negotiable for launch, it should consume one of the 30-day work-streams entirely**, not be a "we'll get to it" item.

### Bottom line
The detection *plumbing* is real and competitive. The *proof* is not. Saying "we catch what Gmail misses" without a labeled corpus and a measured number is the kind of claim that gets challenged on the first sales call — and the answer "we have unit tests" will not survive contact with a security buyer.
