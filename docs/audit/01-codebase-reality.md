# Audit 01 — Codebase Reality Check

Date: 2026-05-08
Branch: `main` @ `daaa01e`
Scope: `/app`, `/lib`, `/components`, `/tests`
Mode: read-only

## TL;DR

Swordfish has **531 source files** organized into a sprawling but coherent module layout (`/lib` has 38 sub-modules; `/app/api` exposes 125 route handlers). The frontend is **client-component-heavy**: 30 of 36 `page.tsx` files are `'use client'` and there are **17 client-side `fetch()` call sites in dashboard pages** — the opposite of the CLAUDE.md "RSC by default" rule. **64 files exceed the 500-LOC budget** (CLAUDE.md hard limit), led by `lib/ml/response-learner.ts` at **2,341 lines**, with 8 files over 1,000 LOC. Test density is highly uneven: 11 lib modules have **zero tests** (notably `quarantine`, `feedback`, `notifications`, `policies`, `analytics`, `reports`, `auth`, `reputation`, `logging`). API/route layer is largely *not* bypassing `/lib` for the DB — only **1 of 36 page routes** imports `@/lib/db` directly (`app/admin/tenants/page.tsx`), but **84 of 125 API route handlers** import the DB module directly, which is technically allowed by CLAUDE.md ("routes call lib functions") only if those handlers don't also write SQL — needs deeper review per route. Recent churn is concentrated in **detection pipeline**, **billing**, **onboarding**, and **dashboard pages** — the right places. TODOs are sparse (12 total) but flag real gaps in `analyze`, `cron`, `quarantine`, and a parked Gemini integration.

---

## (a) Top 10 hot spots needing attention

| # | File | Issue | Why it matters |
|---|---|---|---|
| 1 | `lib/ml/response-learner.ts:1-2341` | **2,341 LOC** — 4.7× the limit | "Learn from admin decisions" is the moat. Untested in `/tests/ml` (only 5 ML tests for 5 ML files); high-leverage logic locked in one file. |
| 2 | `lib/ml/feature-extractor.ts:1-2025` | **2,025 LOC** | Feature extraction is the input to detection accuracy — needs to be split + property-tested per feature family. |
| 3 | `lib/protection/click-scanner.ts:1-1931` & `lib/protection/url-rewriter.ts:1-1366` | Two giant URL-protection files | 0 dedicated test files in `/tests/protection`; `/tests/protection` has 4 entries vs 4 source files but coverage unclear. URL rewriting is a silent-failure risk surface. |
| 4 | `lib/detection/pipeline.ts:1-1427` (8 commits in last 100 — hottest file) | High churn, large file | Recent commits show repeated severity/scoring fixes (`8a7417c`, `ef2887c`, `9fddec8`). Indicates instability — needs decomposition + regression tests for every fix. |
| 5 | `lib/quarantine/service.ts:1-763` | **763 LOC, ZERO tests** | Quarantine is the user-visible action surface. Zero unit/integration coverage in `/tests/quarantine` (dir doesn't exist). Risk: silent regressions in release/restore flow. |
| 6 | `lib/feedback/feedback-learning.ts:1-800` | **800 LOC, ZERO tests** in `/tests/feedback-learning.test.ts` exists but tests subset only | Feedback is what trains the system. Untested = unverified. |
| 7 | `lib/billing/stripe.ts:9` | `STRIPE_SECRET_KEY \|\| 'sk_test_placeholder'` fallback | **Silently lets prod boot without a real key.** Should throw at module load if env missing in production. Recent file (5 churns in 100 commits). |
| 8 | `lib/detection/llm-provider.ts:6-84` | **Whole Gemini provider is a TODO** — 5 TODO markers, `@google/genai` not installed | Multi-provider LLM detection is half-built; current production path is Anthropic-only. Either delete or finish. |
| 9 | `app/onboarding/page.tsx:1-782` & `app/dashboard/settings/page.tsx:1-737` | Massive client-component pages | Onboarding is the <10-min-to-value gate. 782 LOC client-rendered, 6 churns recently — high regression surface for the most important UX path. |
| 10 | `lib/integrations/o365.ts:1-417` + `o365/sync-worker.ts:1-432` | M365 path exists but **no tests in `/tests/integrations`** for it (only 2 test files for 14 source files) | If M365 is launch scope, this is the biggest detection blind spot. Code shape is real (Graph API calls present), but unverified. |

**Honorable mentions / hot-file list (>500 LOC):** 64 files total. Selection: `lib/ml/explainer.ts` (1,895), `lib/reporting/phish-button.ts` (1,730), `lib/ml/predictor.ts` (1,546), `lib/protection/rewritten-urls.ts` (998), `lib/detection/attachment-analyzer.ts` (968), `lib/workers/remediation.ts` (960), `lib/detection/url-intelligence.ts` (930).

---

## (b) Modules in good shape

| Module | Source files | Tests | Notes |
|---|---|---|---|
| `lib/api` | 9 | 13 | More tests than source — healthy. `lib/api/auth.ts` and `lib/api/health.ts` are well-scoped. |
| `lib/security` | 7 | 10 | Good coverage ratio. `security-suite.ts` (879 LOC) is large but accompanied by tests. |
| `lib/threat-intel` | 14 | 8 | Decent ratio. Multi-provider stubs (`virustotal`, `blocklists`) but real shape. |
| `lib/monitoring` | 8 | 7 | `observability.ts` (693 LOC) is the only oversize concern. |
| `lib/db` | 2 | 1 | Small, focused. Type safety enforced (no `any` violations). |
| `lib/oauth/token-manager.ts` | — | — | Clean interface — `getAccessToken(tenantId, provider)` is correctly used by `o365.ts:22` and `gmail.ts`; centralization done right. |
| Type discipline | — | — | **Only 3 `any`-as-type violations** across all of `/lib` (`reputation/sender-reputation.ts:313`, `performance/connection-pool.ts:208`, `detection/phase4-scoring.ts:725`). CLAUDE.md "no `any`" rule is mostly honored — fix these 3 individually. |
| TypeScript strictness | — | — | Strict mode, no widespread escape hatches. |
| Conventional commits | — | — | Last 30 commits all follow `feat:`/`fix:`/`docs:` — disciplined. |

---

## (c) Modules to rewrite vs evolve

### Rewrite / decompose

- **`lib/ml/response-learner.ts` (2,341 LOC)** — Split into: `feedback-ingest`, `pattern-detector`, `drift-monitor`, `threshold-suggester`, `retraining-dataset`. Each ≤500 LOC, each independently testable.
- **`lib/ml/feature-extractor.ts` (2,025 LOC)** — Split per feature family: `headers`, `content`, `sender`, `urls`, `attachments`, `behavioral`. Property-test each.
- **`lib/protection/click-scanner.ts` (1,931 LOC) + `url-rewriter.ts` (1,366 LOC)** — Decompose into `rewrite-policy`, `redirect-handler`, `scan-pipeline`, `verdict-cache`.
- **`lib/detection/pipeline.ts` (1,427 LOC, 8 churns)** — High instability + size = top decomposition candidate. Extract `scoring`, `signals-aggregation`, `severity-floor`, `verdict-shaping`. Add regression test per recent severity fix (`9fddec8`, `ef2887c`, `8a7417c`).
- **`app/onboarding/page.tsx` (782 LOC, client component)** — Convert to RSC shell + small `'use client'` islands for the interactive steps. Per CLAUDE.md "RSC by default."
- **`lib/billing/stripe.ts:9`** — Replace placeholder fallback with hard fail in `NODE_ENV=production`.

### Evolve in place

- **`lib/integrations/o365.ts` + `o365/sync-worker.ts`** — Real shape, just under-tested. Add Graph API integration tests + delta-sync property tests; don't rewrite.
- **`lib/integrations/gmail.ts` (649 LOC)** — Working, hot-fixed recently (`1bed5f1` UUID cast fixes). Add tests for OAuth refresh + push-webhook idempotency.
- **`lib/quarantine/service.ts`** — Code is fine; **the gap is zero tests**. Add unit + integration coverage for release/restore/notify flows.
- **`lib/ato/*`** — 7 files, 4 test files, decent shape. Mid-priority.
- **`lib/email-auth/dkim.ts:517`** — One placeholder for testability is fine; document and move on.

### Delete or finish (don't leave half)

- **`lib/detection/llm-provider.ts` Gemini block (5 TODOs, lines 6-84)** — Either install `@google/genai` and ship multi-provider, or delete the dead branch. Half-state misleads.
- **`app/api/cron/cleanup-exports/route.ts:32`** — `// TODO: Delete file from R2/S3 storage` means cron "works" but doesn't actually clean up. Either implement or remove the cron.
- **`app/api/cron/scheduled-reports/route.ts:55`** — `// TODO: Generate actual report and send to recipients` — cron exists but doesn't do its job.
- **`app/api/dashboard/quarantine/route.ts:94`** — DELETE handler is a TODO. Quarantine deletion is user-visible.
- **`app/api/analyze/route.ts:109,112`** — `// TODO: Store verdict` and `// TODO: If quarantine/block, take action` — the analyze endpoint is **observation-only**; the action loop is unimplemented.

---

## (d) Architecture violations found

### CLAUDE.md "No direct database access in routes or pages"

- **PASS (mostly):** Only `app/admin/tenants/page.tsx` imports `@/lib/db` directly out of 36 page files.
- **AMBIGUOUS:** **84 of 125 API route handlers** import `@/lib/db`. CLAUDE.md says *"Routes call lib functions, lib functions call the database"* — importing `db` from a route handler is a violation if the handler writes SQL inline; it's fine if `db` is being passed through to a lib helper. This requires per-route review (out of scope for codebase audit; flagging for Audit 04 / Audit 06).
- **Low-hanging fix:** Move `app/admin/tenants/page.tsx` DB query into `lib/actions/tenants.ts` (or similar). Single-file violation.

### CLAUDE.md "Files under 500 lines"

- **64 violations** (12% of source files). Nine over 1,000 LOC. Top decomposition list is in section (c).

### CLAUDE.md "RSC by default. Only add `'use client'` when needed"

- **30 of 36 `page.tsx` files (83%) are `'use client'`.** Many of these (e.g., `dashboard/billing/page.tsx`, `dashboard/integrations/page.tsx`) likely render mostly static content with isolated interactive widgets — convertible to RSC + small islands.
- 17 client-side `fetch()` call sites in `/app/dashboard` — every one of these is an opportunity to move data fetching to the server.

### CLAUDE.md "No `any` types"

- **3 violations** total in `/lib`. Trivially fixable individually:
  - `lib/reputation/sender-reputation.ts:313` — type the `categoryResult` row.
  - `lib/performance/connection-pool.ts:208` — type the `conn` interface to include `isActive`.
  - `lib/detection/phase4-scoring.ts:725` — type `presentLayers` properly so the `as any` becomes unnecessary.

### CLAUDE.md "Never hardcode secrets or API keys"

- **PASS (mostly):** Quick scan of `lib` showed no hardcoded secrets, but `lib/billing/stripe.ts:9,17,18,19,20` use `'sk_test_placeholder'` and pinned test-mode `price_*` IDs as fallbacks. Better: hard-fail in production, accept env-only.

### CLAUDE.md "Tests in `/tests`, not root"

- **PASS:** No stray test files at repo root. `/tests` mirrors `/lib` structure correctly.

### Console-logging in production code paths

- **199 `console.log`/`console.error` calls in `/lib`.** A `lib/logging/logger.ts` exists and is the unified structured logger — these direct console calls bypass it. Top offenders: `lib/integrations/gmail.ts` (12+), `lib/feedback/feedback-learning.ts`, `lib/reputation/sender-reputation.ts`. Migration to the structured logger is a SOC 2 control prerequisite (audit-trail completeness).

### Duplicate module surfaces (worth verifying not redundant)

Both files in each pair *appear* to serve distinct purposes per their headers; flagging for verification:
- `lib/db/audit.ts` vs `lib/monitoring/audit.ts` — DB-write helper vs higher-level "audit logging module."
- `lib/actions/logger.ts` vs `lib/logging/logger.ts` — "Action audit trail" vs "Unified structured logger."
- `lib/behavioral/explainer.ts` vs `lib/ml/explainer.ts` — Anomaly explainer vs ML/XAI explainer.
- `lib/api/health.ts` vs `lib/deployment/health.ts` — endpoint vs deploy-time?
- `lib/integrations/gmail.ts` vs `lib/queue/gmail.ts` vs `lib/webhooks/handlers/gmail.ts` — appears layered (API client / queue worker / webhook), but worth confirming responsibilities don't overlap.

---

## Test coverage matrix (lib modules)

```
src tests  module
40   18    detection            (good)
14    8    threat-intel         (decent)
14    2    integrations         (POOR — M365/Gmail/Slack are the launch scope)
 9    4    behavioral
 9   13    api                  (excellent)
 8    7    monitoring
 8    2    actions              (POOR — actions = user-visible CRUD)
 7    4    ato
 7   10    security             (excellent)
 6    4    webhooks
 6    3    email-auth
 5    5    performance
 5    5    ml                   (POOR ratio given file sizes)
 4    3    protection           (POOR given file sizes)
 4    0    analytics            (ZERO)
 3    3    workers
 3    1    oauth
 3    0    reports              (ZERO)
 3    0    policies             (ZERO)
 2    2    resilience
 2    0    reputation           (ZERO)
 2    0    auth                 (ZERO)
 2    1    config
 2    1    billing              (POOR — billing just shipped)
 2    1    db
 2    1    deployment
 2    1    onboarding
 1    3    msp                  (more tests than src — needs source review)
 1    0    queue                (ZERO)
 1    0    quarantine           (ZERO — and 763 LOC of logic)
 1    0    notifications        (ZERO)
 1    0    logging              (ZERO — the logger itself is untested)
 1    0    hooks                (ZERO)
 1    0    feedback             (ZERO src/tests; one root test exists at tests/feedback-learning.test.ts)
 1    0    reporting            (ZERO — phish-button.ts is 1,730 LOC)
 1    0    utils                (ZERO)
 1    0    testing              (ZERO)
```

**11 modules with zero tests** are the biggest verification gap.

---

## Churn concentration (last 100 commits)

```
8  lib/detection/pipeline.ts          ← unstable + 1,427 LOC
7  lib/quarantine/service.ts          ← 0 tests + 763 LOC
7  app/api/webhooks/stripe/route.ts   ← billing critical path
6  components/layout/dashboard-layout.tsx
6  app/onboarding/page.tsx            ← <10-min onboarding gate
6  app/dashboard/emails/page.tsx
6  app/api/onboarding/route.ts
5  lib/billing/stripe.ts              ← placeholder fallback
5  components/layout/sidebar.tsx
```

Churn maps to the right priorities (detection accuracy, billing, onboarding) — but **3 of the top 5 hot files have <500 LOC of test coverage or none**.

---

## Quick-fix backlog (under 1 hour each)

1. Remove `'sk_test_placeholder'` fallback in `lib/billing/stripe.ts:9` — hard-fail in prod.
2. Type the 3 `any` violations: `reputation/sender-reputation.ts:313`, `performance/connection-pool.ts:208`, `detection/phase4-scoring.ts:725`.
3. Move `app/admin/tenants/page.tsx` DB query into a lib action.
4. Decide on `lib/detection/llm-provider.ts` Gemini path: install `@google/genai` or delete.
5. Decide on `cron/cleanup-exports` and `cron/scheduled-reports`: implement or remove.
6. Implement DELETE handler in `app/api/dashboard/quarantine/route.ts:94` or remove the route.

---

## Out of scope for this audit (handed off)

- **Per-route DB-import deep review** → Audit 04 (security) + Audit 06 (billing).
- **Detection accuracy claims / eval harness** → Audit 02.
- **Auto-remediation end-to-end coverage** → Audit 03.
- **MSP multi-tenancy data model fitness** → Audit 07.
- **Onboarding <10-min realism** → Audit 08.
