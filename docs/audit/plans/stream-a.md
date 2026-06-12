# Stream A — Security & Wiring Closure (30-day plan)

**Owner:** Stream A fork (Phase 1 done 2026-05-28). Phase 2 = substantial P0 items + dep bumps.
**Status of Phase 1 mechanical fixes:** 9/9 done. Verifications below.
**Current blocker for downstream PRs:** flipping CI `continue-on-error: false` now exposes 25 pre-existing lint errors + 6 pre-existing typecheck errors (all in non-edited files). Day 1 below cleans those.

---

## Phase 1 receipts (already shipped)

| # | Fix | Verification |
|---|---|---|
| 1 | Deleted `/api/debug/db-state` + `/api/debug/register-push` | `ls app/api/debug` → "No such file" |
| 2 | Uncommented `gmail.readonly` scope at `app/api/auth/google/route.ts:25` | grep confirms scope present | **⚠️ requires Google app verification approval before OAuth will succeed in prod with new scope** |
| 3 | OAuth redirects (5 total) changed `/dashboard/settings` → `/onboarding?provider=google&...` | grep `dashboard/settings` in google/route.ts → 0 matches |
| 4 | Deleted `demoThreats` array + simplified `displayThreats` in `app/dashboard/page.tsx` | array removed; empty-state banner preserved via `isDemo` flag |
| 5 | Removed `'sk_test_placeholder'` fallback in `lib/billing/stripe.ts:9`; throws on missing env | grep returns 0 matches |
| 6 | Removed `URL_SIGNATURE_SECRET \|\| ''` fallback in `lib/protection/url-rewriter.ts:126`; throws on missing env | grep returns 0 matches |
| 7 | CI lint + typecheck `continue-on-error: false` at `.github/workflows/ci.yml:31,51` | grep confirms both at `false` |
| 8 | `lib/webhooks/validation.ts:50` bypass now requires `!process.env.VERCEL_ENV && NODE_ENV === 'development' && ALLOW_UNSIGNED_WEBHOOKS === 'true'` — preview deploys can't trigger | diff shows triple-gate |
| 9 | `scripts/enable-sync-and-register.mjs:10` literal CRON_SECRET → `process.env.CRON_SECRET` with required-check | diff confirms |

**Sign-off needed from Corn:**
- (a) Confirm Google app verification for `gmail.readonly` is submitted/approved before this hits prod, else OAuth flow returns `invalid_scope`.
- (b) Rotate the leaked `8d6d9eb9b50…` CRON_SECRET in Vercel (manual; the value is in git history forever).

**Typecheck result:** 6 errors, all in `app/_template/components/landing-hero.tsx` (missing image imports — pre-existing template noise). Zero new errors from Phase 1 edits.
**Lint result:** 25 errors + 209 warnings, all in pre-existing files. None in files I touched.

---

## Phase 2 day-by-day

Each day = ~6 productive hours. Adjust for parallelism with Streams B/C/D where noted.

### Day 1 — Unblock CI

- [ ] Fix the 25 lint errors + 6 typecheck errors so `main` builds clean now that CI is strict.
  - Most are `no-unused-vars` in `lib/threat-intel/*` and `lib/workers/*`. Either delete dead code or prefix with `_`.
  - The 6 typecheck errors in `app/_template/` are missing webp/png imports. Either commit the images, delete the template, or add `*.webp`/`*.png` ambient declarations.
- [ ] PR: `chore(ci): clean pre-existing lint + typecheck errors so strict CI passes`. **No sign-off needed.**

### Day 2-4 — P0-1 Stripe webhook handler + plan persistence + enforcement

**Why it's first:** money handling is currently decorative. Recent commits shipped the front half (checkout creation, billing page); back half (webhook → DB → enforcement) is missing per Audit 6.

- [ ] Day 2 — New route `app/api/webhooks/stripe/route.ts`. Call `stripe.webhooks.constructEvent` with `STRIPE_WEBHOOK_SECRET`. Idempotency via `processed_stripe_events(event_id PRIMARY KEY)` table. Handle `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.payment_failed`. Write subscription state to `tenants` (see Day 3 for schema).
- [ ] Day 3 — **🛑 NEEDS CORN SIGN-OFF (schema migration).** Per decision #3, kill `tenants.plan` enum and add `tenants.seat_count` + `tenants.price_per_seat_cents` + `tenants.subscription_status` + `tenants.current_period_end`. Migration `0050_seat_based_pricing.sql` with backfill. Also: add `tenants.stripe_customer_id`, `tenants.stripe_subscription_id`. Drop the hardcoded Stripe test price IDs at `lib/billing/stripe.ts:17-20`.
- [ ] Day 4 — Wire enforcement. `lib/billing/plan-features.ts` `canUse` / `hasFeature` / `checkLimit` must actually run at: `app/api/integrations/google/route.ts` (mailbox count check), `app/api/integrations/microsoft/route.ts`, `app/api/scan/*`. Stripe checkout `quantity = mailbox_count` not hardcoded `1`. Cross-org collision in `lib/billing/stripe.ts` checkout (email-based dedup) → look up by `metadata.tenantId`.
- [ ] Tests: signature-verified webhook test, idempotency test, plan-limit-gate tests. Real `stripe trigger` against local server.

### Day 5-8 — P0-11 RLS enforcement at query layer

**Why it's critical:** Audit 4 found RLS is *defined* but Neon HTTP driver doesn't preserve `set_config(..., true)` across requests; `withTenant()` is called in 5/119 files using `@/lib/db`. Tenant isolation is currently WHERE-clauses-only.

- [ ] Day 5 — Decide enforcement model. Option A: route all queries through a `withTenant()` helper that sets `app.tenant_id` per query (works with Neon serverless HTTP). Option B: switch DB driver to use sessions/connections. Option C: enforce per-table at the query helper level (Drizzle middleware). **🛑 ARCHITECTURAL DECISION — needs Corn input.** Recommend A.
- [ ] Day 6-7 — Rewrite the 114 query sites to flow through `withTenant`. Add ESLint rule banning direct `sql\`` outside `lib/db/`.
- [ ] Day 8 — Add a Vitest integration test that creates two tenants, inserts threats for each, runs every list-endpoint as tenant A, asserts no tenant B data leaks. Add to CI.

### Day 9-10 — P0-8 MSP god-mode flag replacement

- [ ] Day 9 — Replace the `is_msp_user` god-mode check at `app/api/msp/tenants/route.ts:40` with a proper join through `msp_tenant_access`. MSP staff can only see tenants they're explicitly granted access to.
- [ ] Day 10 — Fix the bonus bugs Audit 7 found: `clerk_org_id` UUID/string mismatch at `app/api/msp/tenants/route.ts:204,222`; wrong table name `audit_logs` → `audit_log` at `lib/msp/usage.ts:142`. Add a regression test for MSP cross-tenant denial.

### Day 11-15 — P0-7 M365 token rewiring + encryption

**Why it takes 5d:** Audit 5 found `app/api/auth/microsoft/route.ts` writes UNENCRYPTED tokens to `provider_connections` while the webhook reads from `integrations`. Plus stale Nango calls still in the webhook. The clean module `lib/integrations/o365.ts` is solid; the wiring around it is the work.

- [ ] Day 11 — Trace the full M365 token path: signup, refresh, webhook-receive. Inventory both tables.
- [ ] Day 12 — **🛑 NEEDS SIGN-OFF (data migration).** Decide single token table — recommend `integrations` (matches Gmail). Migration `0051_consolidate_provider_tokens.sql` that copies non-test rows from `provider_connections` → `integrations` and encrypts in flight.
- [ ] Day 13 — Rewrite `app/api/auth/microsoft/route.ts` to use `lib/oauth/token-manager.ts` (same path Gmail uses). Always encrypt.
- [ ] Day 14 — Remove dead Nango calls in webhook handler. Use `lib/integrations/o365.ts` end-to-end.
- [ ] Day 15 — Real M365 mailbox smoke test: connect → first scan → quarantine → claw-back via Graph. Add fixture-replay test for subscription-validation handshake (M365 has a `validationToken` echo step that breaks people).

### Day 16-17 — P0-5 First-scan job on OAuth success + P0-15 /api/analyze TODOs

**Combined because both are "missing wiring" not new architecture.**

- [ ] Day 16 — On OAuth success in `app/api/auth/google/route.ts` and `app/api/auth/microsoft/route.ts`, enqueue a first-scan job (`lib/workers/email-sync.ts` already exists). Cap at last 50 messages for the initial pass so it returns in <2 min. Surface progress in `/onboarding`.
- [ ] Day 17 — `/api/analyze` route lines 109/112 — actually store the verdict in `threats` and trigger remediation if score ≥ quarantine threshold. Remove the TODO comments. Add test.

### Day 18-19 — P0-9 ENCRYPTION_KEY version prefix + rotation system

- [ ] Day 18 — Fix the length-in-chars-vs-bytes bug at `lib/security/encryption.ts:25`. Add version prefix to ciphertext (e.g., `v1:` prefix). Add `decrypt()` that reads prefix and dispatches.
- [ ] Day 19 — **🛑 NEEDS SIGN-OFF (data migration).** Re-encrypt existing rows: `integrations.access_token`, `integrations.refresh_token`. Script `scripts/reencrypt-tokens.mjs` that pages through rows. Adds `v1:` prefix to legacy ciphertext.

### Day 20-22 — Dep bumps (Clerk + Drizzle + Next.js)

Each bump is ~1 day with smoke testing. Run sequentially so we can isolate regressions.

- [ ] Day 20 — **`@clerk/nextjs` + `@clerk/backend`** to a version that fixes GHSA-vqx2-fgx2-5wq9 (CRIT middleware bypass) + GHSA-w24r-5266-9c3c (HIGH authz bypass on org/billing). Run all auth/middleware tests. Click through signup → org switch → MSP impersonation flow manually. Check that `auth()` still works at route boundaries.
- [ ] Day 21 — **`drizzle-orm`** to fixed version. SQL injection via SQL identifiers. Search codebase for any `sql.identifier()` or dynamic identifier patterns; rerun the multi-tenant isolation tests from Day 8. Watch for the breaking-change footguns the Drizzle changelog flags.
- [ ] Day 22 — **`next`** to a version that fixes the 7 HIGH advisories (middleware bypasses ×4, WebSocket SSRF, DoS ×2). Run `next build`, click every dashboard page, run E2E suite (Playwright). Manually exercise: a) middleware route protection still gates `/dashboard/*`, b) any rewrites/redirects you use, c) image optimization endpoint.

### Day 23-25 — Stream A reserve

Buffer for:
- Phase 1 unknowns surfacing (e.g., Google verification block)
- Test fallout from dep bumps
- Reviewer feedback rounds

### Sign-off items summary (escalation list)

| Item | Reason |
|---|---|
| Day 3 — `0050_seat_based_pricing.sql` | Schema migration, drops `tenants.plan` enum |
| Day 5 — RLS enforcement model | Architecture decision (Option A/B/C) |
| Day 12 — `0051_consolidate_provider_tokens.sql` | Data migration across token tables |
| Day 19 — `scripts/reencrypt-tokens.mjs` | Re-encrypts all token rows in place |
| Phase 1 follow-ups | Google app verification status + CRON_SECRET rotation in Vercel |

### Effort total

- Phase 1 done: 0.5d (already shipped)
- Phase 2 day count: 22 active days + 3 reserve = 25 days
- Parallel opportunity with Stream C: Day 5-8 RLS work can overlap with C's observability wiring (different files)
- Parallel opportunity with Stream D: Day 2-4 Stripe webhook is essentially Stream D's billing scope — recommend Stream A and D coordinate to do it once, not twice
