# Stream D — Auto-Remediation Gaps + Real Stripe Wiring + Per-Mailbox Pricing

**Owner:** Backend swarm (single coder + reviewer per PR)
**Calendar:** 20 working days, two parallel sub-streams converging on day 18 for end-to-end smoke
**Plan author:** Stream D planner fork, 2026-05-28
**Locked decisions in play:** #1 (MSP +60), #3 (pure per-mailbox $3-8, kill tier names), #4 (open self-serve), #6 (response-learner freeze)

---

## Verification pass — what I confirmed by reading

| Claim | Verified at | Status |
|---|---|---|
| `tenants.plan VARCHAR(50) DEFAULT 'starter'` is the only billing column on tenants | `lib/db/schema.sql:13-23` | Confirmed — no `stripe_customer_id`, no `seat_count`, no `subscription_status`, no `current_period_end` |
| No Stripe webhook handler exists | `app/api/webhooks/` → clerk, email, gmail, health, microsoft, o365, smtp. **No stripe.** | Confirmed |
| `lib/billing/stripe.ts:9` boots with `'sk_test_placeholder'` if env missing | Read of entire file | Confirmed |
| Test price IDs as fallbacks | `stripe.ts:17-20`, `checkout/route.ts:14-16` | Confirmed |
| `SubscriptionTier = 'free' \| 'pro' \| 'enterprise'` (note: `free`, not `starter` as in schema) | `stripe.ts:13` vs `schema.sql:18` | Confirmed — schema and code disagree on the first tier name |
| `quantity: 1` hardcoded in checkout | `stripe.ts:213` | Confirmed |
| `BillingService.handleWebhook()` is dead-code stub | `stripe.ts:252-295`, no callers via grep | Confirmed |
| `PlanFeatures.hasFeature` / `UsageTracker.checkLimit` have zero callers | Confirmed by grep across `/app`+`/lib` excluding self+tests | Confirmed |
| `UsageTracker` is in-memory — `private usage: UsageRecord[] = []` | `stripe.ts:327` | Confirmed (useless in serverless) |
| Email-based customer dedup (cross-org collision) | `checkout/route.ts:59-65`, `portal/route.ts:32-37` | Confirmed |
| Clerk publicMetadata is **read** but never **written** after customer creation | `checkout/route.ts:55, 68-74` — no `clerkClient.users.updateUser` call anywhere in checkout flow | Confirmed — second checkout re-runs global email lookup |
| `lib/msp/usage.ts:77-99` hardcodes $99/$499/$1999 flat tiers | Read | Confirmed |
| `lib/msp/usage.ts:141` queries `audit_logs` (plural), schema has `audit_log` (singular) | Read; also line 150 | Confirmed — usage stats query is broken at runtime |
| `reportToStripe` misuses `subscriptionItemId` as `stripe_customer_id` | `stripe.ts:411-426` | Confirmed |
| `autoRemediate` does not read `autoQuarantine` policy flag | Read of `remediation.ts:786-960`; no policy lookup before quarantine call | Confirmed |
| Two parallel quarantine impls | `lib/quarantine/service.ts` (763 LOC) + `lib/workers/remediation.ts` (960 LOC) both have quarantine/release/delete paths | Confirmed — Audit 3 numbers off (remediation.ts is 960 not 786) |
| `sendNotification` only routes to admin/security configs, no end-recipient path | `lib/notifications/service.ts:53-122`, configs come from `notification_configs` table (tenant-scoped, not user-scoped) | Confirmed |
| Last migration filename | `migrations/009_safe_uuid_function.sql` | Confirmed — next migration is `010_*` |

Cross-stream dependency noticed but **out of my scope:**
- Audit 4 found RLS defined but not enforced (only 5/119 db files call `withTenant()`). This affects every webhook DB write I'm about to add. **Flagging:** the new Stripe webhook handler must explicitly scope tenant-ID lookups; do NOT assume RLS will save us. Stream A owns the RLS enforcement work.

---

## Sub-stream D1 — Auto-remediation gaps (days 1-9)

Goal: Make the "AI auto-remediates without a human" claim defensible by closing the 3 HIGH-severity gaps from Audit 3 + the MSP rollup gap.

### D1.1 — End-recipient notification (days 1-4)

**Why this is the priority gap:** Audit 3 named this HIGH because Swordfish currently yanks mail without telling the affected user. A security product that silently mutates inboxes feels like mail-stealing. Per decision #3 and the "famous-for: AI auto-remediates no human" claim, the user MUST see what happened.

**TDD order:**
1. Write `tests/notifications/recipient-notification.test.ts` for the new path before code.
2. Write `tests/integration/remediation-recipient-notify.test.ts` to assert end-recipient gets the notification on a real quarantine.

**Code:**
1. Schema migration `migrations/010_recipient_notifications.sql`:
   - New table `recipient_notifications (id UUID PK, tenant_id UUID NOT NULL REFERENCES tenants, threat_id UUID NOT NULL REFERENCES threats, recipient_email VARCHAR(320) NOT NULL, channel VARCHAR(20) NOT NULL, status VARCHAR(20) DEFAULT 'pending', delivered_at TIMESTAMPTZ, opened_at TIMESTAMPTZ, action_taken VARCHAR(20), created_at TIMESTAMPTZ DEFAULT NOW())`.
   - Index on `(tenant_id, recipient_email, created_at DESC)`.
   - RLS enabled mirroring `audit_log` policy.
2. New `lib/notifications/recipient.ts` exposing `notifyRecipient({tenantId, threatId, recipientEmail, summary, topSignals, releaseUrl})`. Channels: in-product (preferred — uses existing `notifications` table with `user_id` scoping if user exists) → email fallback via Resend (uses `RESEND_API_KEY`).
3. New email template `lib/notifications/templates/recipient-quarantine.tsx` (React Email). Content: "We removed a suspicious message claiming to be from {{ sender }}. Subject: {{ subject }}. Why: {{ top3Signals }}. [Release to my inbox] [Confirm phish]". The release/confirm links carry signed tokens (HMAC over `{notificationId, action, exp}` using `URL_SIGNATURE_SECRET` — note Stream A is fixing the `|| ''` fallback so we can rely on that env).
4. Wire `notifyRecipient` call inside `autoRemediate` at `remediation.ts:786-960` **after** successful quarantine, **inside the same transaction as the audit log write** to prevent split-brain.
5. New route `app/api/recipient-action/[notificationId]/route.ts` to handle one-click release/confirm. Validates signed token, then calls `releaseQuarantine` or marks threat confirmed. Updates `recipient_notifications.action_taken`.

**Estimate:** 4 days (incl. tests + template).

### D1.2 — Enforce `autoQuarantine` policy gate (days 4-5, parallel to D1.1 tail)

**Why:** Audit 3 found `autoQuarantine: boolean` policy exposed in `app/admin/policies/page.tsx:247, 420-424` but **zero** references in `/lib`. Every tenant gets auto-action whether they opted in or not.

**TDD order:**
1. `tests/policies/auto-quarantine-gate.test.ts` — fixture: tenant policy with `autoQuarantine: false`; expectation: detection produces threat row with status `flagged_only`, NO mailbox mutation.

**Code:**
1. New `lib/policies/auto-quarantine.ts` exposing `shouldAutoQuarantine(tenantId): Promise<boolean>`. Reads from `tenant_policies` table (existing, per Audit 7).
2. Gate inserted at 4 dispatch sites identified in Audit 3:
   - `lib/workers/email-sync.ts:231`
   - `lib/webhooks/handlers/gmail.ts:140`
   - `lib/webhooks/handlers/microsoft.ts:178` (verify line number)
   - `app/api/workers/gmail-queue/route.ts:157`
3. When gate is off: write threat row with `status='flagged_only'`, **skip** `autoRemediate` call. Notification still fires to admin (Slack/email per existing config).
4. Add `status='flagged_only'` to the threats enum; migration `010_recipient_notifications.sql` (bundle).

**Estimate:** 1.5 days.

### D1.3 — Consolidate to single quarantine implementation (days 5-7)

**Why:** Two implementations (`lib/quarantine/service.ts` 763 LOC + `lib/workers/remediation.ts` 960 LOC) drift on retry behavior, audit-log shape, and notification trigger points. Drift risk is real.

**Decision (per Audit 3 recommendation):** `lib/workers/remediation.ts` is canonical. Delete `lib/quarantine/service.ts` after migrating callers.

**TDD order:**
1. Run existing `tests/api/quarantine/quarantine.test.ts` + `tests/remediation.test.ts` + `tests/workers/remediation-transaction.test.ts` to capture current behavior.
2. Write `tests/quarantine/consolidation-parity.test.ts` proving the new path matches old behavior for: release, delete, and quarantine on both Gmail + O365.

**Code:**
1. Identify callers of `lib/quarantine/service.ts`:
   - `app/api/v1/quarantine/route.ts`
   - `app/api/v1/threats/[id]/route.ts`
   - `app/api/v1/policies/route.ts`
2. Migrate each to call `releaseQuarantine` / `deleteQuarantine` / `autoRemediate` from `lib/workers/remediation.ts`.
3. Delete `lib/quarantine/service.ts`.
4. Re-run full test suite.

**Estimate:** 2 days.

### D1.4 — MSP-scoped audit-log rollup view (days 7-9)

**Why:** Decision #1 defers MSP tier to +60 BUT keeps a "read-only rollup view" for early-access AE-managed MSPs. Per Audit 3 Gap 5.

**Constraint per decision #1:** No MSP write paths. Read-only aggregation only.

**TDD order:**
1. `tests/msp/audit-rollup.test.ts` — fixture: MSP org with 3 child tenants, expect rollup view returns merged audit_log rows respecting `msp_tenant_access` (not the god-mode `is_msp_user` flag — that bypasses isolation per Audit 7).

**Code:**
1. New `lib/msp/audit-rollup.ts` exposing `getMspAuditFeed(mspOrgId, { since, limit })`. Joins `msp_tenant_access` × `audit_log`. Must be auth-gated by `withMspAccess(mspOrgId)` (Stream A is replacing the `is_msp_user` god-mode flag with table-based check; we depend on that landing first or build a temporary inline join).
2. Add to `lib/msp/usage.ts` (or new view at `app/admin/msp/audit/page.tsx` — RSC, no `'use client'`).
3. Fix `audit_logs` → `audit_log` typo at `lib/msp/usage.ts:141, 150` while we're in the file.

**Estimate:** 2 days (incl. coordinating on the god-mode flag fix landing first; can stub interim).

---

## Sub-stream D2 — Real Stripe wiring + per-mailbox pricing (days 1-12, parallel to D1)

Goal: Money collected → DB plan state updated → features actually gated → per-mailbox quantity tracked → tax + dunning works.

### D2.1 — Schema migration: tenants billing columns (**NEEDS CORN SIGN-OFF**) (days 1-2)

**Why this needs sign-off:** Schema change touches the canonical multi-tenant table. Per Corn's `Autonomy & Plan Mode` rule: schema/migration changes are plan-then-ask.

**Proposed `migrations/010_billing_per_mailbox.sql`:**
```sql
-- Per decision #3: pure per-mailbox $3-8 + volume discounts at 100/500/1k.
-- Drop tier names from canonical truth. Stripe Price IDs become the only "tier."
BEGIN;

-- Keep `plan` column for backward-compat during cutover; will drop at +30 after webhook stabilizes.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS seat_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255) UNIQUE;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR(255) UNIQUE;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(50) DEFAULT 'inactive';
  -- inactive | trialing | active | past_due | canceled | unpaid
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS current_period_end TIMESTAMPTZ;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS price_per_seat_cents INTEGER;

CREATE INDEX IF NOT EXISTS idx_tenants_stripe_customer ON tenants(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_tenants_subscription_status ON tenants(subscription_status);

-- Idempotency for webhook
CREATE TABLE IF NOT EXISTS stripe_webhook_events (
  event_id VARCHAR(255) PRIMARY KEY,
  type VARCHAR(100) NOT NULL,
  received_at TIMESTAMPTZ DEFAULT NOW(),
  processed_at TIMESTAMPTZ,
  payload JSONB
);

COMMIT;
```

**Sign-off questions for Corn:**
1. **Cutover plan:** keep `tenants.plan` column for 2 weeks post-launch, then drop in `011_drop_plan_column.sql`. Acceptable, or drop immediately and migrate `lib/msp/usage.ts:186-188` references in the same PR?
2. **Volume-discount pricing:** ladder is $8/seat at 1-99, $6 at 100-499, $4 at 500-999, $3 at 1000+. Confirm or override.
3. **Stripe Prices setup:** I'll create 4 per-unit Stripe Prices (one per ladder rung). You give me the price IDs to put in env vars. **Cannot do without Stripe dashboard access.**
4. **Free tier?** Brief says $3-8. Default `seat_count=0, subscription_status='inactive'` = unable to use product. Or do we want a 14-day trial? (Default trial: 14 days, `subscription_status='trialing'`, seat_count=1 of mailbox they connect first.)

**Estimate:** 0.5d migration write + 1-2d cutover work depending on answer to Q1. **BLOCKED on sign-off.**

### D2.2 — Stripe webhook handler (days 2-4)

**TDD first:**
1. `tests/webhooks/stripe.test.ts` covering:
   - Invalid signature → 400
   - Missing signature header → 400
   - Replay (same `event.id`) → 200 idempotent
   - `checkout.session.completed` → tenant updated, `subscription_status='active'`, `seat_count` set
   - `customer.subscription.updated` → period_end + status + seat_count synced
   - `customer.subscription.deleted` → `subscription_status='canceled'`
   - `invoice.payment_failed` → status → `past_due`, notification fired

**Code:**
1. New `app/api/webhooks/stripe/route.ts`:
   - Read raw body via `request.text()` (must be raw for signature)
   - `stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET!)` — fail closed if env missing
   - Idempotency: `INSERT INTO stripe_webhook_events(event_id) ON CONFLICT DO NOTHING`. If conflict → 200 (already processed).
   - Route to handler functions in `lib/billing/webhook-handlers.ts` (new file, <300 LOC per project rule).
   - Always log to structured logger; never `console.*`.
2. New `lib/billing/webhook-handlers.ts`:
   - `handleCheckoutCompleted(event)` — reads `client_reference_id` (= tenantId, see D2.3) and `subscription.metadata.tenantId` (double safety). Updates tenant via `withTenant(tenantId)`. NEVER trusts customer.metadata over checkout.session.client_reference_id.
   - `handleSubscriptionUpdated(event)` — re-syncs `seat_count`, `subscription_status`, `current_period_end`, `price_per_seat_cents`.
   - `handleSubscriptionDeleted(event)` — sets status to canceled, schedules `data_retention` job.
   - `handlePaymentFailed(event)` — sets `past_due`, calls `sendNotification` with `type='payment_failed'` severity `critical`.
   - `handlePaymentSucceeded(event)` — bump `current_period_end`, clear `past_due` if set.

**Estimate:** 2.5 days.

### D2.3 — Update checkout flow for per-mailbox quantity (days 4-6)

**Why:** Brief is per-mailbox; code is `quantity: 1`. Per decision #3, kill tier names.

**Code:**
1. Modify `app/api/billing/checkout/route.ts`:
   - Compute `quantity` from `SELECT COUNT(*) FROM integrations WHERE tenant_id = ? AND status = 'connected'`. Fall back to 1 if zero (first checkout before mailbox connect).
   - Pick `priceId` from volume-ladder helper: `lib/billing/pricing.ts → resolvePriceId(quantity): string`.
   - Replace `ALLOWED_PRICE_IDS` set with `Object.values(VOLUME_PRICE_IDS)`.
   - Add `client_reference_id: tenantId` and `subscription_data: { metadata: { tenantId } }` to checkout session.
   - Add `automatic_tax: { enabled: true }`, `tax_id_collection: { enabled: true }`, `billing_address_collection: 'required'`, `customer_update: { address: 'auto', name: 'auto' }`.
   - Add `idempotency_key` derived from `${tenantId}:${priceId}:${currentDayUTC}`.
   - Stop creating new Stripe customer when one exists with `metadata.tenantId == tenantId`. Look up by `stripe.customers.search({ query: \`metadata['tenantId']:'${tenantId}'\` })` (Search API supports metadata).
   - **Write Stripe customer ID to `tenants.stripe_customer_id`** after creation (so we stop relying on Clerk publicMetadata + email lookup, which causes the cross-org collision).
2. Modify `app/api/billing/portal/route.ts` analogously — look up by `tenants.stripe_customer_id`, not email.
3. New `lib/billing/pricing.ts`:
   - `VOLUME_TIERS = [{ min: 1, pricePerSeatCents: 800, priceId: env.STRIPE_PRICE_TIER_1_99 }, { min: 100, pricePerSeatCents: 600, priceId: env.STRIPE_PRICE_TIER_100_499 }, { min: 500, pricePerSeatCents: 400, priceId: env.STRIPE_PRICE_TIER_500_999 }, { min: 1000, pricePerSeatCents: 300, priceId: env.STRIPE_PRICE_TIER_1000_PLUS }]`
   - `resolvePriceId(seatCount)`, `resolvePricePerSeatCents(seatCount)`.
   - Fail closed if any env var missing.
4. Delete the test-price-ID fallbacks in `stripe.ts:17-20` and `checkout/route.ts:14-16`. Throw at module load if env vars missing (production safety per Stream A's CI gate).

**Tests:**
- `tests/billing/checkout-quantity.test.ts` — connect 0, 50, 200, 600, 1500 mailboxes → assert correct price tier + quantity.
- `tests/billing/customer-collision.test.ts` — same email in two Clerk orgs → assert separate Stripe customers per tenant.

**Estimate:** 2 days.

### D2.4 — Plan-limit enforcement at boundaries (days 6-9)

**Why:** Audit 6 found `PlanFeatures.hasFeature` and `UsageTracker.checkLimit` have zero callers. A starter user gets every "enterprise" feature.

**Decision-aligned redesign:** Since decision #3 kills tier names, "features" collapse to a small set of metered limits:
- `mailbox_count` (hard limit = paid `seat_count`; soft 14-day trial = 1)
- `scan_volume_per_day` (soft cap, then queue throttle — protects against runaway costs from a compromised tenant)
- `retention_days` (everyone gets 365, no enforcement needed pre-launch)
- `api_rate` (per-tenant Redis token bucket — existing, just gate-on)

**Code:**
1. Delete the `TierFeatures` types + `PlanFeatures` class + `UsageTracker` class from `lib/billing/stripe.ts` (lines 35-81 + 305-438). Replace with `lib/billing/limits.ts`.
2. `lib/billing/limits.ts` exposes:
   - `canConnectMailbox(tenantId): Promise<{ allowed: boolean; reason?: string }>` — reads `tenants.seat_count` + counts current connected integrations + checks `subscription_status`.
   - `enforceMailboxLimit(tenantId)` — throws `PlanLimitError` if exceeded.
3. Wire enforcement at:
   - `app/api/integrations/google/connect/route.ts` (the OAuth grant callback) — call `enforceMailboxLimit` before persisting connection.
   - `app/api/integrations/microsoft/connect/route.ts` — same.
   - Also in the new `lib/notifications/recipient.ts` (D1.1) — if `subscription_status='past_due'` for 14+ days, downgrade notifications to in-product only (no email charges).
4. `app/dashboard/billing/page.tsx` — replace tier-card UI with seat-count slider + price ladder. Drop the Starter/Pro/Business component. Show `seat_count`, `subscription_status`, `current_period_end`, next charge amount.

**Tests:**
- `tests/billing/limits.test.ts` — fixtures: seat_count=2 tenant connecting 3rd mailbox → blocked; same tenant after Stripe webhook bumps seat_count → allowed.

**Estimate:** 3 days.

### D2.5 — Dunning + payment failure UX (days 9-11)

**Why:** Audit 6 P1: no webhook → no `invoice.payment_failed` reaction → silent churn.

**Code:**
1. In `handlePaymentFailed` (D2.2): write `past_due`, send `sendNotification` with `type='payment_failed', severity='critical'` to admin configs.
2. Background banner: new `components/billing/PastDueBanner.tsx` (RSC) renders on every `/dashboard/*` page when `subscription_status='past_due'`. Click → portal.
3. After 14 days of `past_due` (Stripe smart retries should have exhausted), set `subscription_status='unpaid'` via subscription.updated webhook, downgrade `notifyRecipient` to in-product only, and queue mailbox disconnect after another 7 days. (Tested at +30 via Stream A's cron evaluator — for launch, just write the status and surface the banner.)

**Tests:**
- `tests/billing/dunning-flow.test.ts` — simulate payment-failed → past-due banner appears → simulate resume → cleared.

**Estimate:** 1.5 days.

### D2.6 — Fix `reportToStripe` bug + remove `UsageTracker` references (day 11)

**Why:** `stripe.ts:411-426` passes `subscriptionItemId` as `stripe_customer_id` to `meterEvents.create`. Confirmed bug. Plus `UsageTracker` is in-memory (Audit 6 P2) and replaced by D2.4.

**Code:** Delete the broken `reportToStripe` method. Per decision #3 (pure seat-licensed pricing, not metered), we don't need metered events at all. If +30 wants per-scan metering, that's a separate decision.

**Estimate:** 0.5 day.

### D2.7 — Receipts / invoices UI (days 11-12)

**Why:** Audit 6 P1: `listInvoices` exists in lib but no UI consumes it.

**Code:** Add `<InvoiceHistory />` RSC to `app/dashboard/billing/page.tsx`. Call `BillingService.listInvoices(stripe_customer_id)` (now sourced from `tenants` table, not Clerk metadata).

**Estimate:** 0.5 day.

---

## Convergence — days 18-20

Days 13-17 are buffer + cross-stream PR review. By day 18:
1. **End-to-end smoke** — Test Gmail tenant signs up, connects mailbox, hits Stripe checkout in test mode, completes purchase. Webhook fires. Tenant `subscription_status='active'`, `seat_count=1`. Connect 2nd mailbox → blocked until checkout updates quantity → unblocked. Quarantine a real test phish → recipient gets in-product notification → one-click release → audit log shows release with actor_id. Cancel subscription → status flows to canceled.
2. **Tax check** — Use a test EU billing address; confirm tax line appears, VAT collection works.
3. **Dunning check** — Stripe test card `4000 0000 0000 0341` (always fails after attach) → confirm `past_due` set + banner appears.
4. **MSP rollup check** — Fixture MSP org with 2 child tenants; produce a real auto-remediation in each; confirm rollup view shows both in correct chronological order.

---

## NEEDS CORN SIGN-OFF (consolidated)

1. **Schema migration `migrations/010_billing_per_mailbox.sql`** — adds 6 columns to `tenants` + new `stripe_webhook_events` table. Cutover plan question: keep legacy `plan` column for 2 weeks or drop now?
2. **Volume-discount price ladder** — $8 / $6 / $4 / $3 at 1 / 100 / 500 / 1000 seats. Confirm or override before I write `lib/billing/pricing.ts`.
3. **Stripe Dashboard setup** — I cannot create Stripe Prices for you. You create 4 per-unit Prices in test + live mode, give me the price IDs as env vars. Same for new portal configurations if MSP rollup needs distinct config.
4. **Free / trial policy** — default to 14-day trial with seat_count=1, or hard paywall at signup?
5. **Tax handling region** — Stripe Tax US-only is free; full-region Stripe Tax is paid. Confirm budget.
6. **Drop the in-memory `UsageTracker` and `PlanFeatures` classes entirely** (D2.4 + D2.6) — anyone external depending on these imports? (Internal grep says no, but checking with you.)
7. **Renaming `audit_logs` → `audit_log` in `lib/msp/usage.ts`** — this is a bug fix (schema is singular) but worth confirming because if `audit_logs` queries are hitting a view I didn't see, they could be working in some envs. Will verify via prod logs (Stream C) before merge.

---

## Risk register (Stream D)

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| D-R1 | Webhook delivers before app deploy (Stripe retries fast) — race | Medium | Idempotency table is the safety net; first deploy in maintenance window |
| D-R2 | Cross-org customer collision survives migration (legacy customers in Stripe with email-only dedup) | High | Backfill script: for each existing Stripe customer with `metadata.tenantId`, write to `tenants.stripe_customer_id`. Ones missing metadata get re-quoted at next checkout. |
| D-R3 | Decision #4 (open self-serve) + plan-limit enforcement bug → free tenants connect 1000 mailboxes | Critical | D2.4 tests must pass before launch. Also: hard server-side cap of 25 mailboxes for `subscription_status='trialing'` regardless. |
| D-R4 | Stream A RLS enforcement lands after webhook → webhook writes bypass tenant scope | Medium | Webhook handler explicitly calls `withTenant(tenantId)` for all updates; doesn't rely on session-level RLS |
| D-R5 | Recipient notification template flagged as spam by recipient's own mail provider | Medium | Use Resend's domain reputation; SPF/DKIM/DMARC for `cornelius@chuqlab.com` already passing per `.env` config; prefer in-product when user exists |
| D-R6 | autoQuarantine policy default unclear — new tenants default to off → no auto-action → "AI auto-remediates" claim is wrong on day 1 | High | Default `autoQuarantine: true` for new tenants. Audit log records the default. Add to onboarding wizard (Stream C) as opt-out checkbox. |
| D-R7 | Volume-discount ladder doesn't match Stripe Prices Corn creates → checkout passes wrong price | High | `lib/billing/pricing.ts` reads price IDs from env; throw at boot if any tier is missing. CI checks env presence in prod build. |
| D-R8 | UsageTracker removal breaks tests | Low | Run test suite after delete; expect ~5-10 failing tests in `/tests/billing/`; fix or delete those tests as part of D2.4. |

---

## What I'm NOT touching (out of scope)

- M365 token-table mismatch (Stream A — security wiring)
- Detection corpus / eval harness (Stream B)
- Sentry / instrumentation / observability (Stream C)
- MSP bulk onboarding, white-label, billing rollup (decision #1 defers to +60)
- `response-learner.ts` refactor (decision #6 — freeze)
- Architecture cleanup (file size violations, RSC drift)
- Slack message scanning, Teams (deferred to +30/+60)

---

## Summary

Stream D ships **per-mailbox billing that actually persists state** + **auto-remediation with end-recipient notification + policy enforcement + single canonical implementation** in 12-14 working days, leaving 6-8 days of buffer/convergence. Total claimed scope from Audits 3+6+7 was 12-19 days; the planned schedule fits, but **two items block on Corn**: the schema migration sign-off (~1 day delay if questions sit) and the Stripe Dashboard Price ID creation (cannot proceed beyond D2.3 setup without it). Recommend Corn answers the 7 sign-off questions in one batch so D2 can begin day 1.
