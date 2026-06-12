# Audit 08 — Onboarding Flow & Observability

**Audit scope:** Is `<10 min` self-serve realistic? Is the system on-call ready for paying customers?
**Verdict:** Onboarding **NOT** <10-min ready. Observability **partial** — substantial internal infra exists but is not wired to ship anywhere external, and adoption inside the codebase is ~2%.

---

## (A) Onboarding Flow — sign-up → OAuth → first threats surfaced

**Verdict: < 10 min self-serve is NOT achievable as currently wired.** Several breaks plus ~30% of the flow is friction with no value.

### Walked files
- `app/sign-up/[[...sign-up]]/page.tsx` — Clerk SignUp, redirects to `/onboarding`
- `app/onboarding/page.tsx` — 6-step wizard (welcome → account type → email connect → thresholds → notifications → done)
- `app/api/auth/google/route.ts` — Google OAuth init + callback
- `app/api/auth/microsoft/route.ts` — Microsoft OAuth init + callback
- `app/api/onboarding/setup-account/route.ts` — account-type write
- `app/dashboard/page.tsx` — landing after onboarding (demo threats hardcoded)

### Findings (with file:line)

| # | Issue | Severity | Where |
|---|---|---|---|
| 1 | **Gmail `gmail.readonly` scope is commented out.** Connection succeeds but Swordfish gets zero mail access. Restricted scope needs Google verification first — that gate has not been crossed. | **Blocker — present** | `app/api/auth/google/route.ts:25` |
| 2 | **OAuth callback breaks the onboarding wizard.** Successful Google/Microsoft callback redirects to `/dashboard/settings?success=...` instead of back into `/onboarding`. The user is yanked out of the wizard mid-flight; steps 4–6 (thresholds, notifications, done) never happen. | **Blocker — present** | `app/api/auth/google/route.ts:154-156`, `app/api/auth/microsoft/route.ts:156-158` |
| 3 | **Microsoft scopes are read-only** (`Mail.Read`, `Mail.ReadBasic`). No `Mail.ReadWrite` / `Mail.ReadWrite.Shared` → cannot quarantine, claw-back, label, or move messages. The "AI auto-remediates" promise is **architecturally impossible** at current consent. | **Blocker — present** | `app/api/auth/microsoft/route.ts:19-26` |
| 4 | **No first-scan trigger.** OAuth callback stores tokens, updates `tenant_settings.integrations.{google,microsoft}Connected = true`, and redirects. **No ingestion job is enqueued.** The user has no way to see real threats without an admin manually firing a sync. | **Blocker — present** | `app/api/auth/google/route.ts:94-138`, `app/api/auth/microsoft/route.ts:96-140` |
| 5 | **Dashboard shows hardcoded demo threats**, not the user's real data — `mockIntegrations` and `demoThreats` arrays. Even on the happy path, time-to-first-real-threat ≠ time-to-something-on-screen. | **High — present** | `app/dashboard/page.tsx:10-44` |
| 6 | **Personal-tenant fallback poisons org isolation.** `tenantId = orgId \|\| 'personal_' + userId`. If user OAuths before joining/creating an org, tokens land on the personal tenant and are never migrated. | **High — present** | `app/api/auth/google/route.ts:38`, `app/api/auth/microsoft/route.ts:38` |
| 7 | **2/6 wizard steps are pure friction.** Step 1 (decorative welcome), Step 4 (threshold sliders — premature; user has no data to calibrate against), Step 5 (notification toggles — could be in settings). Each is one extra click + roundtrip to `/api/onboarding`. | **Medium — present** | `app/onboarding/page.tsx:16-47, 470-613` |
| 8 | **OAuth state storage is single-row-per-tenant.** Two concurrent flows (e.g. user opens both Google and Microsoft) clobber each other's CSRF state. | **Medium — present** | `app/api/auth/google/route.ts:261-267` (`ON CONFLICT (tenant_id) DO UPDATE`) |
| 9 | **No org-wide / domain-wide install path.** Per-mailbox OAuth is the only option visible — Microsoft admin-consent / Google Workspace domain-wide-delegation flows are absent. Mid-market and MSP buyers expect this. | **High — missing** | n/a (whole flow missing) |
| 10 | **MSP path goes to `/admin` with no client-add primitive in onboarding.** MSPs sign up but have no first-client-onboard step inside the wizard — they hit empty `/admin` and have to figure it out. | **High — partial** | `app/onboarding/page.tsx:91, 228-229, 616-648` |

### Time-to-value reality check

Best case golden path (Microsoft, user already in org, no Google verification needed):
- Sign-up via Clerk: ~1 min
- Step 1 welcome + click Continue: ~10 sec
- Step 2 account type + org name + setup: ~30 sec
- Step 3 click Connect Microsoft → MS consent → callback → **redirect to `/dashboard/settings`** (wizard breaks here): ~2 min
- User now has to navigate back to `/dashboard`, see hardcoded demo threats, and figure out how to trigger a real scan (no UI for it found in scope): **time-to-real-threat = unbounded**.

Realistic outcome: **15+ minutes, then user sees demo data, not their mail.** Self-serve <10-min target is not currently achievable.

---

## (B) Observability — production-readiness for on-call

**Verdict: Partial. Heavy internal scaffolding (~3,500 lines in `lib/monitoring`) but the code is largely unwired — not registered at app start, almost no adoption in real code paths, no external sink configured.**

### Walked files
- `app/api/health/route.ts` (43 lines) — DB ping + HEAD liveness
- `app/api/metrics/route.ts` (69 lines) — JSON + Prometheus, token auth via `METRICS_AUTH_TOKEN`
- `app/api/webhooks/health/route.ts` — webhook-channel health (separate)
- `lib/monitoring/observability.ts` (693 lines) — config + types
- `lib/monitoring/metrics.ts` (548 lines) — Counter/Histogram/Gauge primitives, Prometheus formatter
- `lib/monitoring/error-tracking.ts` (456 lines) — `ErrorTracker`, `ConsoleReporter`, `WebhookReporter` (line 322)
- `lib/monitoring/tracing.ts` (387 lines) — span/tracer
- `lib/monitoring/alerts.ts` (354 lines) — alert rules + conditions
- `lib/monitoring/alert-notification-bridge.ts` (560 lines) — DB-backed notifications
- `lib/logging/logger.ts` — structured JSON logger w/ correlation IDs + sensitive-field masking
- `docs/DISASTER_RECOVERY.md` — real runbook, "Version 1.0.0", dated 2026-01-30
- `package.json` — **no Sentry, no Datadog, no Axiom, no Logtail, no OTel SDK**

### Component-by-component

| Component | Status | Evidence |
|---|---|---|
| Structured logs | **partial** | `lib/logging/logger.ts` exists, masks secrets, includes correlation IDs. Adoption: **8 files** use `loggers.*`; **440 `console.*` calls** remain across lib/ + app/. Vercel default capture only — no external aggregator. |
| Latency metrics | **partial** | Histograms defined in `lib/monitoring/observability.ts:64-78` (`emailProcessingDuration`, `httpRequestDuration`, `remediationDuration`). No middleware seen instrumenting routes — metrics primitives exist but call sites unverified within scope. |
| Error rate metrics | **partial** | `httpRequestsTotal` Counter declared (`observability.ts:74`); same instrumentation gap. |
| Queue depth | **present (definition)** | `emailsInQueue: Gauge` declared (`observability.ts:60`). Wiring to actual queue not verified within scope. |
| Detection volume | **present (definition)** | `threatsDetected: Counter`, `verdictDistribution: Counter` declared (`observability.ts:63-65`). |
| Error tracking — server | **partial / unwired** | `ErrorTracker` + `WebhookReporter` exist (`error-tracking.ts:322`). **No Sentry SDK installed.** No `instrumentation.ts` in repo root → no app-startup hook to register the tracker. Errors are not captured automatically; only manual `errorTracker.capture()` calls would land. |
| Error tracking — client | **missing** | No browser SDK, no `app/global-error.tsx`-based capture wiring confirmed. Client-side React errors only hit the console. |
| Alerting evaluator | **partial** | Rules + conditions defined (`alerts.ts`). No `app/api/cron/evaluate-alerts` route found within scope — rules are not being evaluated on a schedule, so they cannot fire. |
| Pager / Slack / PagerDuty | **missing (wired off)** | `.env.example` shows `# Sentry`, `# Datadog`, `# PagerDuty` lines all commented. `ObservabilityConfig` accepts `pagerDutyKey` / `slackWebhookUrl` but nothing initializes it. |
| Health endpoint | **present** | `app/api/health/route.ts:18` — `SELECT 1`, returns 200/503. Liveness HEAD at `:40`. |
| Readiness probe | **partial** | Same endpoint serves both — no separate "ready to accept traffic" check (queue/Redis/Clerk reachability). |
| Deploy / rollback | **missing (formal)** | Vercel default rollback (instant via dashboard) is implicit. No documented rollback procedure in repo. |
| Migration safety | **partial — risky** | `package.json` shows `migrate:009`, `migrate:014` etc. — manual one-off migration scripts. `scripts/run-migration-NNN.ts` files. No automated migration-on-deploy, no migration locking, no test of forward-compat between code and schema versions. |
| Runbook / incident docs | **present** | `docs/DISASTER_RECOVERY.md` (real, dated, versioned). Specific incident classifications and recovery steps would need verification beyond scope. |

### Bottom line

The monitoring code is not vaporware — it's substantial and the design (correlation IDs, masking, severity/category enums) is sane. **But it doesn't run.** No `instrumentation.ts`, no Sentry SDK, no scheduled alert evaluation, no external sink, and 98% of error paths in real code go to `console.error`. The DR doc and the metrics surface area on `/api/metrics` are the only externally usable observability today.

---

## What's needed to be on-call-ready at launch

Concrete punch list, ordered by leverage:

### Onboarding (must-fix for self-serve <10 min)
1. **Get Google verification** for `gmail.readonly` (and `gmail.modify` for remediation) — multi-week process, start now. In the meantime, soft-launch on Microsoft only.
2. **Promote Microsoft scopes to `Mail.ReadWrite` + `Mail.ReadWrite.Shared`** (admin-consent flow) — required for the auto-remediation positioning.
3. **Fix the OAuth callback redirect:** route Google/Microsoft callbacks back to `/onboarding?step=4&connected=microsoft` (or wherever wizard left off) instead of `/dashboard/settings`.
4. **Auto-trigger first ingestion** in the OAuth callback success path — enqueue a "scan last 7 days" job, return a job-id, and show the user a progress UI on the next wizard step.
5. **Replace the demo data on `/dashboard/page.tsx`** with empty-state UI + live "scan running" if the first ingestion hasn't completed.
6. **Cut Steps 1, 4, 5** from the wizard. Move thresholds + notifications to dashboard settings as later prompts. Net wizard: account-type → connect → done (3 steps).
7. **Add domain-wide install path** for Microsoft (admin consent) and Google Workspace (domain-wide delegation) — this is what mid-market / MSP buyers actually need.
8. **Fix tenant binding race**: require Clerk org membership before OAuth, or migrate `personal_*` tokens on org creation.
9. **Per-flow OAuth state**: store state keyed by `(tenant_id, provider, nonce)` so concurrent flows don't clobber.
10. **MSP path:** add a "Add your first client" wizard step instead of dropping at empty `/admin`.

### Observability (must-fix for on-call)
1. **Pick one external sink and wire it.** Recommend Sentry (cheapest, proven) for errors + breadcrumbs; Axiom or Datadog for logs/metrics. The `WebhookReporter` interface already exists — point it at Sentry's webhook or use the SDK.
2. **Add `instrumentation.ts`** at repo root — register Next.js instrumentation hook (`process.env.NEXT_RUNTIME` branch) that initializes the error tracker, metrics, and tracer at server start.
3. **Add `app/global-error.tsx`** + Sentry browser SDK to capture client errors.
4. **Wire Vercel cron to evaluate alerts.** Add `app/api/cron/evaluate-alerts/route.ts` calling `AlertManager.evaluate()` every 60 seconds. Without this, alert rules are decorative.
5. **Migrate the 440 `console.*` calls** to `loggers.*` — at minimum in detection, ingestion, OAuth, webhooks, billing. Spawn an agent on this; pattern is mechanical.
6. **Hook PagerDuty (or Slack-as-pager)** to critical alerts. Set service-level SLOs (detection latency, ingestion lag, error rate) and wire alerts to them.
7. **Split readiness probe from liveness:** add `app/api/ready/route.ts` checking DB + Redis + Clerk reachability before saying "OK".
8. **Migration safety:** consolidate `migrate:NNN` scripts into a single `npm run migrate` that runs all pending in order, with a `migration_locks` row to prevent concurrent runs. Run in Vercel build step.
9. **Document rollback** in `docs/DISASTER_RECOVERY.md` — explicit "Vercel dashboard → Deployments → Promote previous" plus DB rollback policy (forward-only with feature flags vs. reversible migrations).
10. **Set up an uptime probe** (e.g. Better Stack / Checkly) hitting `/api/health` from outside Vercel — Vercel can't tell you when Vercel itself is down.

### One-line summary
**Onboarding has the *components* but not the *wiring* — three blockers (commented Gmail scope, callback redirect, no first-scan trigger) make <10-min self-serve currently impossible.** Observability has the *scaffolding* but not the *runtime* — primitives are there, nothing ships externally, alerts don't evaluate, 98% of paths still `console.error`. Both are roughly two weeks of focused work to bring to "minimally on-call-ready."
