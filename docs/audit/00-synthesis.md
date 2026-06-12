# Swordfish — State-of-Project Audit & 30-Day Launch Plan

**Date:** 2026-05-08
**Audit scope:** 8 parallel deep-dives, ~97KB of evidence in `/docs/audit/01-08`.
**Synthesis goal:** Honest assessment of where the project is vs. where it needs to be for a credible production launch as a modern AI-first replacement for Proofpoint/Mimecast.

---

## TL;DR

| Dimension | Brief target | Reality | Gap |
|---|---|---|---|
| Buyers | SMB + Mid-market + MSP at launch | MSP tier has cross-tenant **defect**, not just a gap | Cut MSP from launch or invest 21.5d |
| Wedge | Catch BEC Gmail misses | 9-layer pipeline real, but no labeled corpus, no P/R/F1 eval, PhishTank feed dead | 21-25d to make accuracy claim defensible |
| Famous-for | AI auto-remediates, no human | Pipeline real, immutable audit log, but 3 gaps before claim is honest | 10-17d |
| Integrations | Gmail + M365 + Slack + Teams + SIEM | Gmail prod-grade. M365 80% **broken** (token tables mismatched, unencrypted writes). Slack alerting-only. Teams zero. Splunk prod, others stubs. | 17-20d for Gmail+M365+Splunk+Sentinel; Slack+Teams slip |
| Billing | Per-mailbox $3-8, plan limits enforced | **No Stripe webhook handler exists.** Plan never persists. Zero callers of plan-limit code. Hardcoded test price IDs. | 7-10d |
| Onboarding | <10 min self-serve | **`gmail.readonly` scope commented out.** OAuth redirects to settings not wizard. No first-scan job enqueued. Dashboard shows hardcoded demo threats. | 5-7d |
| Observability | On-call ready | 3,500 LOC scaffolding, **no Sentry/Datadog installed**, no `instrumentation.ts`, alert rules without cron, 440 `console.*` vs 8 logger uses | 10-14d |
| Compliance | SOC 2 Type II controls (no pentest), "more secure than standard" | Strong primitives (AES-256-GCM, immutable audit log, Svix webhooks). 5 enforcement gaps exploitable day 1: public `/api/debug/*` IDOR, RLS not actually enforced, CI lint/typecheck `continue-on-error: true`, encryption key bug, Stripe webhook missing. | 22d |

**Total honest dev cost across all streams: ~135-170 person-days.** Even with 4 parallel Claude swarms, that's 35-45 calendar days of serial-equivalent execution. **30 days for everything is not feasible.** 30 days for a *truly production-grade core* is.

---

## Brutal verdict

The codebase has more substance than expected — 9-layer detection pipeline, real Gmail integration, actual quarantine/claw-back via both Gmail and Graph API, immutable audit log via Postgres rules, encrypted token storage, structured logger framework. Bones are there.

But what shipped and what's *wired* keep diverging. The pattern across 8 audits is the same: **scaffolding without runtime.**

- "Stripe wired up" (commit message) = front half only. No webhook, plan never persists.
- "Observability" = 3,500 lines of monitoring code, but Sentry isn't installed and `instrumentation.ts` doesn't exist.
- "MSP support" = `msp_organizations` table with `branding` JSONB — and zero code referencing branding.
- "Auto-quarantine policy toggle" = UI control with no `/lib` enforcement.
- "M365 integration" = clean `lib/integrations/o365.ts`, but the route writes unencrypted tokens to a different table than the webhook reads.
- "Onboarding wizard" = 6 steps where step 3 has the value and 1/4/5 are friction; OAuth callback skips back to settings; first scan never runs; dashboard shows hardcoded demo threats.
- "Detection accuracy" = real signals + LLM gating, but no labeled corpus, eval is `score > 10` boolean assertions, PhishTank feed dead with 2024 hardcoded fallback.

**This is not a project that needs more features. It needs the existing features to actually work end-to-end before any new ones are added.**

---

## Critical findings — consolidated priority matrix

### P0 — Pre-launch blockers (cannot ship to a paying customer with these unresolved)

| # | Finding | Audit | Effort | Source |
|---|---|---|---|---|
| P0-1 | No Stripe webhook handler exists; `STRIPE_WEBHOOK_SECRET` unused | 4, 6 | 1d | `app/api/webhooks/stripe/` missing |
| P0-2 | `/api/debug/db-state` and `/api/debug/register-push` are public — IDOR across all tenants | 4 | 0.5d | C2 |
| P0-3 | `gmail.readonly` scope **commented out** | 8 | 0.5d | `app/api/auth/google/route.ts:25` |
| P0-4 | OAuth callback redirects to `/dashboard/settings`, not back to wizard | 8 | 0.5d | `route.ts:154-156` |
| P0-5 | No first-scan job enqueued on OAuth success | 8 | 1d | OAuth callbacks |
| P0-6 | Dashboard shows hardcoded demo threats | 8 | 0.5d | `app/dashboard/page.tsx:10-44` |
| P0-7 | M365 token table mismatch + unencrypted writes | 5 | 5-7d | `app/api/auth/microsoft/route.ts` vs webhook |
| P0-8 | MSP `is_msp_user` god-mode flag bypasses tenant isolation | 7 | 2d | `app/api/msp/tenants/route.ts:40` |
| P0-9 | `ENCRYPTION_KEY` length checked in chars not bytes; no rotation, no version prefix | 4 | 1.5d | `lib/security/encryption.ts:25` |
| P0-10 | `lib/billing/stripe.ts:9` boots silently with `'sk_test_placeholder'` if env missing | 1 | 0.25d | direct |
| P0-11 | RLS defined but not enforced — `withTenant()` called 5/119 times; Neon HTTP doesn't preserve session | 4 | 4d | C3 |
| P0-12 | CI uses `continue-on-error: true` for lint + typecheck | 4 | 0.5d | `.github/workflows/ci.yml:32,54,55` |
| P0-13 | `URL_SIGNATURE_SECRET \|\| ''` empty fallback — forgeable signed URLs | 4 | 0.25d | `lib/protection/url-rewriter.ts:126` |
| P0-14 | `ALLOW_UNSIGNED_WEBHOOKS` keyed off `NODE_ENV` — preview-deploy risk | 4 | 0.5d | webhook handlers |
| P0-15 | `/api/analyze` TODOs at lines 109/112 — doesn't store verdicts or take action | 1 | 1d | direct |

**P0 total: ~18-20 dev-days.** These are non-negotiable.

### P1 — Required for credible launch (not blockers, but launching without them = embarrassing)

| Theme | Effort |
|---|---|
| Stripe webhook + plan persistence + plan-limit enforcement + per-mailbox pricing alignment + cross-org collision fix + tax/address/dunning | 7-10d |
| Auto-remediation: end-recipient notification, enforce `autoQuarantine` policy gate, consolidate two parallel quarantine implementations | 5-9d |
| Detection: build/license 3-5k labeled corpus, build eval harness emitting P/R/F1 + threshold sweep, raise LLM daily limit, CI gate | 21-25d |
| Onboarding: rework wizard to stay in flow, real first-scan trigger, remove demo threats, domain-wide consent path | 5-7d |
| Observability: install Sentry, write `instrumentation.ts`, add `global-error.tsx`, alert-rule cron evaluator, replace `console.*` in critical paths, CI gate, automated migrations | 10-14d |
| Tests for the 11 zero-coverage `/lib` modules (quarantine, auth, logging, policies, notifications, feedback, reports) | 10-15d |
| Architecture cleanup: 30/36 pages incorrectly client-side, 17 client-side fetches that should be server, top 9 oversized files (>1k LOC) carved up | 10-15d |
| SOC 2 controls beyond P0: branch protection + CODEOWNERS + signed commits, RBAC `requireAdmin()` helper, documented backup/recovery runbook, audit log hash chain, envelope encryption with key versioning | 8-12d |
| Two cron stubs (`cleanup-exports`, `scheduled-reports`) made real | 1-2d |
| Gmail watch-renewal cron (watches expire 7d) | 0.5d |

**P1 total: ~78-110 dev-days.**

### P2 — Defer to +30 / +60

- MSP tier credible: bulk onboard, white-label, billing rollup, distinct MSP RBAC — **21.5d**
- Slack message scanning (not just alerting) — **7-10d**
- Microsoft Teams — **10-14d**
- Sentinel direct connector + Tines/Torq - **3-5d**
- Beyond-standard SOC2: blind-index field encryption, full CSP, edge-rate-limit, formal pentest — **10-15d**

---

## Recommended 30-day launchable-core scope

The brief's "everything in 30 days" is rejected. Here's what's actually shippable in 30 days *and* legitimately defensible as a modern Proofpoint/Mimecast alternative:

### Launch positioning at +30
- **Buyers:** SMB + mid-market on **Gmail and M365**. MSPs land at "early access — onboarding via your AE."
- **Differentiation claim:** "AI auto-remediation with end-recipient notification + immutable audit trail" — defensible because the pipeline + audit log are real.
- **Detection claim:** "X% precision / Y% recall on a public phishing benchmark + N curated BEC scenarios" — measured, published, not vibes.
- **Compliance claim:** "Built to SOC 2 Type II controls; audit in progress" — true after P0 + P1 SOC2 work.

### Workstreams (30 calendar days, 4 parallel Claude swarms)

**Stream A — Pre-launch security & wiring fixes (P0 closure)**
- Days 1-5: All P0 items closed in priority order. Public debug routes deleted. Stripe webhook + plan persistence. Encryption key + RLS enforcement. `gmail.readonly` restored. OAuth redirects fixed. Demo threats deleted. M365 token wiring repaired. CI gates restored.
- Owner: Single coder agent + reviewer agent per change.
- Exit: All P0s checked off, with proof-of-work logs.

**Stream B — Detection accuracy proof**
- Days 1-15: Acquire labeled corpus (SpamAssassin public + Nazario phish corpus + APWG samples + 50-100 hand-curated BEC). Build eval harness emitting P/R/F1 + threshold sweep + ROC. Run baseline. Tune thresholds. Repair PhishTank feed (or migrate to OpenPhish primary). Raise LLM daily limit. Add CI accuracy regression gate.
- Days 16-25: Iterate on findings. Publish accuracy numbers. Document corpus.
- Owner: Detection-focused coder swarm.

**Stream C — Onboarding-to-value & observability**
- Days 1-10: Rework signup → OAuth → wizard → first scan → real threats path. Remove all hardcoded demo data. Add domain-wide consent path for admin installs. Install Sentry + write `instrumentation.ts` + `global-error.tsx`. Wire alert-rule evaluator cron.
- Days 11-20: Replace `console.*` in critical request paths with structured logger. Health endpoint depth (Redis + Clerk reachability). Migration automation. Document runbook + on-call.
- Owner: UX/full-stack swarm + SRE swarm.

**Stream D — Auto-remediation gaps + plan-limit enforcement**
- Days 1-12: End-recipient notification (`lib/notifications/`). Enforce `autoQuarantine` policy gate (one place to read, one place to write). Consolidate `lib/quarantine/service.ts` and `lib/workers/remediation.ts` into one path. MSP-aware audit rollup view (read-only, no MSP writes yet).
- Days 13-20: Plan-limit enforcement at boundaries (mailbox count, scan volume, feature gates). Pricing schema aligned to per-mailbox $3-8. Stripe checkout `quantity: mailbox_count`. Tax + address + dunning.
- Owner: Backend swarm.

**Convergence days 26-30:** End-to-end smoke tests with real Gmail account. Real M365 account. Stripe test charge end-to-end. Quarantine real phishing email and verify recipient notification + audit trail. Document everything. Cut release branch.

### What gets cut from the original brief
1. **MSP launch tier** → "early access via AE" until +60. Schema + god-mode flag fix happens at P0 (security), but bulk onboard / white-label / billing rollup slip.
2. **Slack message scanning** → +30. Slack alerting works today; that ships.
3. **Microsoft Teams** → +60.
4. **Tines/Torq + Sentinel direct** → +60. Splunk HEC + signed generic webhook ship.
5. **Architecture-wide cleanup** (RSC drift, file size violations) → continuous after launch, not a launch blocker.

---

## Risk register

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R1 | "Wired-but-not-running" pattern repeats during 30-day push | High | Every PR merge requires a reviewer-agent verifying end-to-end with a tool-call receipt (per Corn's verification protocol). No "should work" merges. |
| R2 | Detection accuracy lands below acceptable threshold (e.g., precision <90%) | High | Stream B starts day 1 in parallel. If baseline at day 10 is bad, scope down to a narrower threat class (BEC only) for launch claim. |
| R3 | M365 wiring fix uncovers deeper Graph API gotchas (subscription TTL, throttling) | Medium | Stream A budgets 7d not 5d. Fall back to "M365 early access" if blocked at day 14. |
| R4 | SOC 2 control work expands when an external auditor reviews | Medium | Defer formal audit; "built to controls" is the launch posture. Add formal audit prep at +60. |
| R5 | A real customer hits a tenant-isolation edge case in launch week | Critical | RLS enforcement (P0-11) is non-negotiable. Add per-tenant pen test before first paying customer (internal, not external). |
| R6 | Hardcoded demo threats reappear in some other view we missed | Medium | Day-25 audit pass: grep entire codebase for `mockThreats`, `demoData`, hardcoded objects in `page.tsx`. |
| R7 | Stripe price IDs hardcoded as test fallbacks creep into prod | High | P0 includes deleting test fallbacks; CI check that env vars are set in prod build. |
| R8 | LLM daily limit (100/tenant) bites first paying customer | Medium | Raise to 1k+ during Stream B; add per-tenant rate-limit override. |
| R9 | First customer triggers Sentry storm because adoption gap is huge | Low | Stream C replaces `console.*` only in critical paths; rest stays as console for launch, with sampled Sentry on errors. |

---

## Open decisions for Corn

1. **MSP-at-launch vs MSP-at-+60.** Recommendation: +60. Doing it right is 21.5d alone, and the god-mode-flag defect must be fixed at P0 regardless. Confirm.
2. **Detection corpus license.** Recommendation: bootstrap with public (SpamAssassin + Nazario + APWG samples) + 50-100 hand-curated BEC. Confirm willingness to license a commercial corpus at +30 if numbers need a bump.
3. **Pricing tiers vs pure per-mailbox.** Recommendation: per-mailbox with volume discounts at 100/500/1000 seats. Tier names go away. Confirm.
4. **Beta gate.** Recommendation: signup-with-promo-code for first 30 days post-launch (control inflow while we watch the system). Confirm.
5. **External SOC 2 auditor engagement.** Recommendation: start outreach at +30 even if formal cert lands later. Audit firms have 8-12 week wait lists.
6. **`response-learner.ts` (2,341 LOC) — keep building or freeze?** It's the differentiation moat per its name, but it's massive and untested. Recommendation: freeze at launch (use it but don't extend), refactor at +30. Confirm.

---

## What you do with this report

1. Read this synthesis.
2. Skim the 8 underlying audits in `docs/audit/01-08` for any specific finding you want to verify in code.
3. Make the 6 decisions above.
4. Greenlight the 4-stream 30-day execution. I'll spawn the swarm.

The audits answered "where are we." This synthesis answers "what does done look like." Execution is the next call.

---

## Decisions locked (2026-05-27)

Corn made all six calls from the "open decisions" section above:

| # | Decision | Note |
|---|---|---|
| 1 | MSP slips to **+60** | God-mode flag fix stays at P0 (security defect, not feature gap) |
| 2 | Detection corpus = **public sets + 50-100 hand-curated BEC** | Commercial license deferred to +30 if numbers need a bump |
| 3 | Pricing = **pure per-mailbox $3-8, volume discounts at 100/500/1k** | Kill the Starter/Pro/Business tier names in code |
| 4 | Beta gate = **open self-serve day 1** | *Against my recommendation.* Observability must be on-call-ready as a tighter blocker, not "10-14d post-launch" |
| 5 | SOC 2 auditor outreach = **wait until +90** | *Against my recommendation.* No "SOC 2 cert" claim in launch marketing — only "built to controls" |
| 6 | `response-learner.ts` (2,341 LOC) = **freeze + refactor at +30** | Touch only if P0 requires it |

### Implications for the 30-day plan

- Stream A (P0 security/wiring) scope unchanged except: MSP god-mode flag fix moves earlier in the stream; SOC 2 control work stays at "controls only" depth (no audit-prep work).
- Stream C (onboarding + observability) is now **tighter** — open self-serve makes Sentry + instrumentation + alert cron a blocker, not a stretch goal.
- Stream B (detection) explicitly targets public corpus + curated BEC pack at days 1-15.
- Stream D (auto-remediation + billing) replaces the `tenants.plan` enum with `tenants.seat_count` + per-seat pricing schema. Drops the tier-name UI in `app/dashboard/billing/page.tsx`. This is a **schema migration** — needs plan-then-ask before execution.

Full rationale and alternatives considered: `/Users/corn/.claude/projects/-Users-corn-swordfish/memory/project_swordfish_launch_decisions.md`.
