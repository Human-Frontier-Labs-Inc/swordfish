# Stream C — Onboarding + Observability (30-day plan)

**Owner:** Stream C planner (this doc)
**Scope:** Self-serve signup → real first scan in <10 min + on-call-ready observability for an open-from-day-1 launch (Decision #4).
**Cross-stream dependencies:**
- Stream A owns: P0-3 uncomment `gmail.readonly`, P0-4 fix OAuth callback redirect target, P0-6 delete hardcoded demo data, P0-15 `/api/analyze` implementation.
- Stream C owns: wizard re-routing, first-scan enqueue, empty-state UI, M365 admin-consent path, observability install + adoption.

**Pre-flight (verified by direct reads, 2026-05-28):**
- `app/api/auth/google/route.ts:25` — `gmail.readonly` commented; redirect at 154-156 hits `/dashboard/settings?success=google_connected`.
- `app/api/auth/microsoft/route.ts:19-26` — scopes are `Mail.Read` + `Mail.ReadBasic` (read-only); redirect at 156-158.
- `app/dashboard/page.tsx:10-46` — `mockIntegrations` + `demoThreats` arrays; lines 60-110 already have an `isDemo` flag + "Demo Mode" banner but render `demoThreats` as content.
- `oauth_states ON CONFLICT (tenant_id)` clobbering at routes line 265-266.
- `lib/monitoring/*` — 3,446 LOC across 8 files. No `@sentry/nextjs`, no `instrumentation.ts`, no `app/global-error.tsx`, no `/api/cron/evaluate-alerts`.

---

## Sub-stream C1 — Onboarding (days 1-7)

### Day 1 — Wizard re-route + state per-flow OAuth

**Goal:** OAuth callback returns user to wizard mid-flow; concurrent Google/Microsoft don't clobber CSRF state.

**Changes:**
- New: `lib/onboarding/wizard-state.ts` — server-action functions `setWizardStep(tenantId, step, payload)` / `getWizardStep(tenantId)`. Stored in `tenant_settings.settings.onboarding = { step, completedSteps[], lastProvider }`.
- Edit: `app/api/auth/google/route.ts:175-186` (init flow) — append `wizard=1` flag to state cookie/URL; redirect target after success becomes `/onboarding?step=connected&provider=google`.
- Edit: `app/api/auth/microsoft/route.ts:179-187` (init flow) — same.
- Edit: callback handlers (lines 154-156 / 156-158) — redirect `wizard=1` paths back into the wizard, non-wizard paths keep settings target.
- Schema migration: `migrations/0NNN_oauth_states_per_flow.sql` — drop unique `(tenant_id)`, add unique `(tenant_id, provider, nonce)`; oauth_states is gitignore-safe to migrate (no PII).

**Files touched:** 2 routes + 1 new lib + 1 migration.
**Sign-off:** Schema migration (per global CLAUDE.md plan-then-ask).

**Tests (TDD per project CLAUDE.md):** `tests/onboarding/wizard-state.test.ts`, `tests/api/auth/oauth-state-collision.test.ts` (two concurrent flows from same tenant land on different rows).

### Day 2 — First-scan enqueue on OAuth success

**Goal:** Token store → enqueue ingestion → user sees "Scanning your last 7 days" within seconds.

**Changes:**
- New: `lib/workers/first-scan.ts` — `enqueueFirstScan({ tenantId, provider, scope: 'last_7d' })` → push to Upstash queue, return `jobId`.
- Edit: `app/api/auth/google/route.ts` after audit-log block at 149 (before redirect 154) — call `enqueueFirstScan`, attach `jobId` to redirect URL.
- Edit: `app/api/auth/microsoft/route.ts` same surface (after 151, before 156).
- New: `app/api/onboarding/scan-progress/[jobId]/route.ts` — GET endpoint reads queue + `email_ingestion_jobs` table, returns `{ status, scanned, found, eta }`.
- New: `components/onboarding/scan-progress.tsx` — polls every 2s until `status=complete` or 60s timeout (then "we're still scanning — head to dashboard, threats will appear").
- Edit: `app/onboarding/page.tsx` add new step `scan-running` after provider connect.

**Files touched:** 2 routes (edit) + 2 new routes + 2 new lib/component + 1 wizard edit.
**Sign-off:** None — queue + table already exist per Audit 5.

**Tests:** `tests/workers/first-scan.test.ts`, `tests/api/onboarding/scan-progress.test.ts` (mock job in queue), Playwright e2e: signup → connect → progress UI appears.

### Day 3 — Dashboard empty-state (real, not demo)

**Goal:** New users land on `/dashboard` to see actual state — empty if no scan complete, real threats once they exist.

**Coordination:** Stream A's P0-6 removes the `mockIntegrations` + `demoThreats` arrays. Stream C replaces with empty-state UI.

**Changes:**
- Edit: `app/dashboard/page.tsx` — delete lines 10-46 (`mockIntegrations`, `demoThreats`). Replace `isDemo` branch (lines 93-110) with `<EmptyState />` component.
- New: `components/dashboard/empty-state.tsx` — three branches:
  - `no_integration`: "Connect your inbox" + button → `/onboarding?step=connect`
  - `scan_running`: "Scanning your last 7 days, threats will appear here" + progress
  - `no_threats_yet`: "All clear — Swordfish is watching" + last-scan timestamp
- Edit: `lib/hooks/use-dashboard-data.ts` — return `scanState: 'no_integration' | 'scan_running' | 'no_threats_yet' | 'active'` derived from `provider_connections` + most recent `email_ingestion_jobs` row.
- Edit: `app/dashboard/page.tsx` — move `'use client'` only to interactive subcomponents; make the page itself an RSC per project CLAUDE.md ("RSC by default").

**Files touched:** 1 page edit (also RSC migration) + 1 new component + 1 hook edit.
**Sign-off:** None — pure UI.

**Tests:** `tests/dashboard/empty-state.test.tsx` for each scanState; Playwright e2e: new account → onboarding → dashboard shows `scan_running` then `no_threats_yet`.

### Day 4 — Tenant binding race fix

**Goal:** No more `personal_${userId}` tokens stranded outside the org.

**Changes:**
- Edit: `app/api/auth/google/route.ts:38` and `microsoft/route.ts:38` — replace `const tenantId = orgId || \`personal_${userId}\`;` with: if `!orgId`, redirect to `/onboarding?step=account-type` with error "Set up your organization before connecting email."
- Edit: `app/onboarding/page.tsx` — enforce step ordering: account-type step (org creation/select) MUST complete before provider-connect step is reachable.
- Edit: `app/api/onboarding/setup-account/route.ts` — return error if user is already in personal tenant with orphaned `provider_connections` rows; offer migration path.
- New: `lib/onboarding/migrate-personal-tenant.ts` — `migratePersonalToOrg(userId, orgId)` — UPDATE provider_connections, tenant_settings, audit_log where tenant_id LIKE 'personal_%' AND user matches.

**Files touched:** 3 routes + 1 wizard + 1 new lib.
**Sign-off:** Schema-touching (UPDATE across multiple tables) — plan-then-ask.

**Tests:** `tests/onboarding/migrate-personal-tenant.test.ts`, `tests/api/auth/no-org-rejection.test.ts`.

### Day 5 — M365 admin-consent install path

**Goal:** Mid-market buyers can install Swordfish for the whole org with one consent (vs. per-user) AND get `Mail.ReadWrite` scopes needed for auto-remediation (the differentiation moat).

**Changes:**
- Edit: `app/api/auth/microsoft/route.ts:19-26` — split scopes into two arrays: `USER_SCOPES` (current Mail.Read) and `ADMIN_SCOPES` (`Mail.ReadWrite`, `Mail.ReadWrite.Shared`, `MailboxSettings.ReadWrite`, `User.Read.All`).
- Edit: init flow at line 179-187 — detect `?install_mode=admin` param, switch AUTH_URL to `https://login.microsoftonline.com/{tenant}/adminconsent` and scope set.
- New: `app/api/auth/microsoft/admin-consent/route.ts` — admin-consent callback handler; stores `installType: 'admin' | 'user'` in `provider_connections.metadata`.
- New: `components/onboarding/install-mode-picker.tsx` — "Install for me" vs. "Install for my whole org (admin)" toggle in step `connect-microsoft`.
- New: docs/integrations/m365-admin-consent.md — admin-consent flow doc for support.

**Files touched:** 1 route edit + 1 new route + 1 new component + 1 doc.
**Sign-off:** Microsoft Azure AD app-registration must allow admin-consent (one-time portal change, not code) — flag for Corn.

**Tests:** `tests/api/auth/microsoft-admin-consent.test.ts` (mock token + verify scopes stored correctly).

### Day 6 — Cut wizard friction (steps 1, 4, 5)

**Goal:** 6 steps → 3 steps. Net wizard: account-type → connect → done. Move thresholds + notifications to dashboard settings.

**Changes:**
- Edit: `app/onboarding/page.tsx` — delete steps 1 (welcome), 4 (thresholds), 5 (notifications). Re-number remaining: account-type → connect → scan-running → done.
- Move: thresholds + notifications UI to `app/dashboard/settings/thresholds/page.tsx` and `app/dashboard/settings/notifications/page.tsx`.
- New: dashboard nudge — empty-state component shows "Set up alert thresholds" CTA once first scan completes.
- MSP branch (per Decision #1 — MSP at +60): MSP signup hits a "MSP Early Access" page with `Book a call` CTA instead of the regular wizard. Don't build MSP first-client wizard step now.

**Files touched:** 1 wizard rewrite + 2 new settings pages + MSP gate.
**Sign-off:** None.

**Tests:** Playwright e2e: full signup → dashboard in <3 wizard steps.

### Day 7 — Time-to-value budget verification

**Goal:** Verify <10-min self-serve target via real Playwright timer.

**Changes:**
- New: `tests/e2e/onboarding-budget.spec.ts` — Playwright test using a real test Clerk user + a Mailtrap-backed Gmail OAuth flow (or M365 test tenant). Asserts: signup → first real threat visible in `<600s` wall clock. Fails the build if budget exceeded.
- Wire: CI gate on this test in `.github/workflows/ci.yml` (Stream A is restoring CI gates from `continue-on-error: true` to false).

**Sign-off:** Test Clerk org + test M365 tenant credentials in CI secrets — Corn provisions.

---

## Sub-stream C2 — Observability (days 1-12 in parallel)

### Day 1-2 — Sentry install + instrumentation.ts + sign-off

**Sign-off blocker:** Per project CLAUDE.md ("Do not introduce new external services without discussion"), Sentry is a new external service. **Flag for Corn before installing.**

If green: `npm i @sentry/nextjs@latest`. Create `sentry.client.config.ts`, `sentry.server.config.ts`, `sentry.edge.config.ts`. Create `instrumentation.ts` at repo root with `register()` exporting Sentry init (Next.js 16 contract) + initialize `ErrorTracker` from `lib/monitoring/error-tracking.ts` as a sink wrapped over Sentry.

DSN + auth token go in env: `SENTRY_DSN`, `SENTRY_AUTH_TOKEN`, `NEXT_PUBLIC_SENTRY_DSN`.

PII guard: Sentry `beforeSend` strips email bodies + headers via existing `lib/logging/logger.ts` masking helpers.

**Files touched:** 4 new config files + 1 `package.json` edit + env scaffolding in `.env.example`.

### Day 3 — Global error handler + client capture

**Changes:**
- New: `app/global-error.tsx` — minimal HTML doc with "Something went wrong" + `Sentry.captureException` call + reset button.
- New: `app/error.tsx` if not present (route-level boundary).
- Wire `WebhookReporter` in `lib/monitoring/error-tracking.ts:322` to a no-op when Sentry is the sink (avoid double-reporting).

**Tests:** Unit on the global error component + Playwright assertion that a thrown error in a server action shows the error page AND lands in Sentry (mocked).

### Day 4 — Alert-rule evaluator cron

**Goal:** Alert rules defined in `lib/monitoring/alerts.ts` actually evaluate and fire.

**Changes:**
- New: `app/api/cron/evaluate-alerts/route.ts` — Vercel cron handler, runs every 60s. Calls `AlertManager.evaluate()` (existing in `alerts.ts`). On firing alert, dispatches via `alert-notification-bridge.ts:*` to the configured sink.
- Edit: `vercel.json` cron config — add `{ path: "/api/cron/evaluate-alerts", schedule: "* * * * *" }`. Auth via `CRON_SECRET` header (already-flagged secret-leak finding — Corn needs to rotate that if real).
- Wire `alert-notification-bridge.ts:*` to Sentry-as-sink for "high severity" by default; Slack webhook as opt-in via `SLACK_ALERT_WEBHOOK_URL` env.

**Sign-off:** Slack webhook URL (Corn-owned Slack workspace) — flag for Corn.

**Tests:** `tests/monitoring/alert-cron.test.ts` (trigger condition → assert dispatch called); k6 or vitest that the cron handler returns <500ms.

### Day 5-7 — `console.*` → structured logger in critical paths

**Goal:** Get the 8-vs-440 ratio to where critical paths are 100% structured. Audit 8 estimates 440 calls total; my target for launch is "critical paths zero `console.*`, rest tolerated."

**Critical paths in scope:**
- `app/api/webhooks/**/*.ts`
- `app/api/auth/**/*.ts`
- `lib/billing/**/*.ts`
- `lib/workers/**/*.ts`
- `lib/quarantine/**/*.ts`
- `lib/detection/pipeline.ts` (hottest churn file per Audit 1)

**Changes:**
- Use `Edit` with `replace_all` per file: `console.error(...)` → `loggers.error(...)` with correlation-ID hookup. `console.log` → `loggers.info`. `console.warn` → `loggers.warn`. Tests stay on `console`.
- New ESLint rule: `no-console` enabled with `--rule no-console: error` overrides for `app/api/webhooks/**`, `app/api/auth/**`, `lib/billing/**`, `lib/workers/**`, `lib/quarantine/**`. Tests excluded.
- CI gate: ESLint runs in workflow, fails if any new `console.*` lands in those paths.

**Files touched:** ~40 files in critical paths (estimate, will measure on day 5). 1 ESLint config edit. 1 CI workflow edit (Stream A also touching CI — coordinate).

**Sign-off:** None.

**Tests:** Existing tests stay green; logger output verified by integration tests already in `tests/logging/`.

### Day 8 — Depth-check health + readiness split

**Changes:**
- Edit: `app/api/health/route.ts` — keep DB `SELECT 1` for liveness (HEAD); GET returns aggregate.
- New: `app/api/ready/route.ts` — checks DB + Upstash Redis (`redis.ping()`) + Clerk (`clerkClient.users.getCount()` with 1s timeout). Returns 503 if any unreachable.
- New: `app/api/health/deep/route.ts` — same as `/api/ready` + Stripe + Anthropic reachability, behind `METRICS_AUTH_TOKEN` for ops use only.

**Tests:** `tests/api/health-depth.test.ts` (mock outages, assert correct 200/503).

### Day 9 — Migration runner consolidation

**Changes:**
- Audit `package.json` for `migrate:NNN` scripts (estimate 14+ per Audit 8 — actual count on day 9).
- New: `scripts/migrate.ts` — reads `migrations/*.sql` in order, applies via Drizzle, tracks state in `schema_migrations` table with row-lock for concurrency. `--dry-run` flag prints intended SQL only.
- New: `package.json` script `migrate` and `migrate:dry`. Wire into `vercel-build` so each deploy applies pending.
- Delete: individual `migrate:NNN` entries once migration consolidates.
- New: `migrations/0NNN_create_schema_migrations.sql` — bootstrap the tracking table itself.

**Files touched:** 1 new script + 1 new migration + `package.json` edit.

**Sign-off:** Auto-running migrations in `vercel-build` is a deploy-pipeline behavior change — plan-then-ask. Corn approves the cutover commit.

**Tests:** `tests/scripts/migrate.test.ts` — dry-run produces expected SQL set; live run idempotent.

### Day 10 — Runbook + uptime probe + SLO definitions

**Changes:**
- New: `docs/runbook/on-call.md` — pager triage flow, escalation contacts, incident severity matrix, common-failure playbooks (DB outage, Redis outage, Clerk outage, Stripe webhook backlog, queue backup, OAuth provider error spikes, Sentry quota exhaustion).
- New: `docs/runbook/slo.md` — initial SLOs: 99.9% `/api/health` uptime, P95 `/api/webhooks/stripe` <500ms, ingestion lag <5min, detection P95 latency <2s, error rate <1%.
- New: External uptime probe — set up Better Stack or Checkly hitting `/api/health` every 60s from 3 regions, paging into the same Slack channel as alert-rule cron.
- Edit: `docs/DISASTER_RECOVERY.md` — append "Vercel rollback" + "DB rollback policy: forward-only with feature flags by default; reversible migrations annotated `-- REVERSIBLE` in migration header."

**Sign-off:** New external service (uptime probe) — flag for Corn alongside Sentry.

### Day 11-12 — Convergence + on-call dry run

**Day 11:** Cross-check all C1 + C2 deliverables in a staging env. Run the day-7 time-to-value Playwright on staging. Force a synthetic error in staging to verify Sentry receives it AND alert evaluator fires.

**Day 12:** On-call dry run — Corn or designated on-call walks through runbook with a simulated incident (e.g. "Stripe webhook backlog detected — what do I do?"). Update runbook with gaps surfaced.

---

## On-call-ready bar at day 12

Required for "open self-serve day 1" (Decision #4):

- [ ] Sentry receives errors from server + edge + client; PII stripped.
- [ ] `instrumentation.ts` registers at app start (`NEXT_RUNTIME` branch).
- [ ] Alert-rule cron runs every 60s; firing alerts hit Sentry OR Slack (whichever is sink).
- [ ] Critical-path code paths have zero `console.*` (CI-enforced).
- [ ] `/api/ready` and `/api/health/deep` check DB + Redis + Clerk reachability.
- [ ] Migrations run automatically on Vercel deploy with lock + dry-run.
- [ ] External uptime probe pages on `/api/health` 503.
- [ ] Runbook + SLO docs published; on-call dry-run completed.
- [ ] Self-serve signup → real first threat in <10 min (Playwright budget test green).
- [ ] Dashboard shows real state, never demo data.

If any item is red on day 12, do NOT launch open self-serve — gate to promo-code as my original Decision #4 recommendation.

---

## Items requiring Corn sign-off

1. **Sentry signup + DSN + auth token** (new external service per project CLAUDE.md).
2. **External uptime probe** (Better Stack or Checkly) — also a new external service.
3. **Slack webhook URL** for alert sink (or PagerDuty if preferred).
4. **Microsoft Azure AD app-registration** must allow admin-consent — one-time Azure portal change.
5. **Test Clerk org + test M365 tenant** credentials in CI secrets for the time-to-value Playwright.
6. **Schema migrations** (3 total): `oauth_states_per_flow`, personal-tenant migration helper, `schema_migrations` table bootstrap.
7. **Vercel auto-migration cutover** — deploy-pipeline behavior change.
8. **CRON_SECRET rotation** if the value at `scripts/enable-sync-and-register.mjs:10` (also flagged by sentinel) is real — needed because the new alert-evaluator cron uses the same secret.

---

## Risks I'm carrying

- **Google verification gate for `gmail.readonly`** is multi-week and outside Stream C control. Corn needs to start the verification submission in week 1 even though we soft-launch on M365.
- **`response-learner.ts` freeze** (Decision #6) — don't touch it from Stream C. If Stream B's eval harness needs telemetry I would have added there, route through `lib/monitoring/metrics.ts` instead.
- **MSP `is_msp_user` god-mode** (Decision #1) — Stream A territory. Stream C's MSP-branch wizard gate (Day 6) trusts Stream A's fix lands first.
- **Open self-serve from day 1** (Decision #4) is the tightest constraint here. Every day not green on the day-12 bar is a customer-facing-bug risk in launch week.
