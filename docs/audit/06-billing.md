# Audit 06 — Billing & Plans Wiring (Stripe)

**Scope:** Verify commits `daaa01e` (wire up Stripe checkout, portal, billing page) and `f0012e3` (billing page UI) actually work end-to-end and are production-safe.
**Method:** Static read of all billing/Stripe code paths in `/Users/corn/swordfish`.
**Verdict:** **NOT production-ready.** The flow looks complete from the UI but is **decorative end-to-end** — money can be collected but plan state is never written to the DB and no feature is actually gated. Critical primitives (webhook, signature verification, plan persistence, enforcement, tax) are missing.

---

## Summary table

| # | Step | Rating | Evidence |
|---|------|--------|----------|
| 1 | Checkout session creation | **partial** | `app/api/billing/checkout/route.ts:78-83`, `lib/billing/stripe.ts:204-217` |
| 2 | Webhook handler | **missing** | No `app/api/webhooks/stripe/route.ts` exists; `lib/billing/stripe.ts:252-295` is an unused stub |
| 3 | Subscription persistence | **broken** | `lib/db/schema.sql:18` `tenants.plan` defaults to `starter` and is **never updated** anywhere on payment |
| 4 | Plan-limit enforcement | **missing (decorative)** | `lib/billing/stripe.ts:72-81` (`PlanFeatures.hasFeature`) has zero callers in routes/pages; `lib/msp/usage.ts:239` only used for billing math, not gating |
| 5 | Customer portal | **partial** | `app/api/billing/portal/route.ts:50-54` — works, but org-scoping is fragile (email-based dedup) |
| 6 | Dunning / failed payment | **missing** | No webhook → no DB write → no suspension → no email |
| 7 | Tax | **missing** | No `automatic_tax`, no `tax_id_collection`, no `billing_address_collection` anywhere |
| 8 | Receipts / invoices | **partial (Stripe-side only)** | `BillingService.listInvoices()` exists at `lib/billing/stripe.ts:237-240` but no UI consumes it; relies on Stripe email receipts |

---

## 1. Checkout flow — **PARTIAL**

**Where:** `app/api/billing/checkout/route.ts:19-100` → `BillingService.createCheckoutSession()` at `lib/billing/stripe.ts:204-217`.

What works:
- Server-side price ID allowlist (`route.ts:13-17`) prevents arbitrary price injection ✓
- Customer create/lookup is server-side (`route.ts:55-75`) ✓
- `successUrl` includes `{CHECKOUT_SESSION_ID}` template var ✓

What's missing/wrong:
- **No `client_reference_id`** on the session — standard pattern to map session → tenant on webhook. (`stripe.ts:210-216`)
- **No `subscription_data.metadata`** — `orgId`/`tenantId` are not attached to the subscription. The `tenantId` is added to the *customer* metadata (`stripe.ts:101`), but not to the subscription. When a webhook fires, you cannot map `subscription.id` → tenant without an extra Stripe API roundtrip.
- **No `idempotency_key`** on `stripe.checkout.sessions.create` — retries can create duplicate sessions.
- **`quantity: 1` is hardcoded** (`stripe.ts:213`). The brief is **per-mailbox $3-8/seat/mo**. There is no per-seat scaling, no quantity calculation from connected mailboxes, no `usage_type=licensed` or metered pricing model. The current pricing is flat tier ($0 / $49 / $199), which contradicts the stated business model.
- **Hardcoded test price IDs as fallbacks** (`stripe.ts:17-20`, `route.ts:14-16`, `app/dashboard/billing/page.tsx:42-46`). If env vars are missing in prod, real customers hit test prices. Should fail closed.
- **Three different "tiers" exist across the code:**
  - `schema.sql:18`: `starter / pro / enterprise`
  - `lib/billing/stripe.ts:13`: `free / pro / enterprise` (note: `free`, not `starter`)
  - `app/dashboard/billing/page.tsx:9`: `starter / pro / enterprise`
  - `lib/msp/usage.ts:77-99`: yet another model, $99/$499/$1999 with overage rates
  Four sources of truth, three of them disagree.

---

## 2. Webhook handler — **MISSING (CRITICAL)**

**There is no `app/api/webhooks/stripe/route.ts`.** Verified via `ls app/api/webhooks/` → `clerk`, `email`, `gmail`, `health`, `microsoft`, `o365`, `smtp`. **No `stripe`.**

- `STRIPE_WEBHOOK_SECRET` is documented in `.env.example:200` but is **never read by any code in the repo**. Verified: `grep -r "STRIPE_WEBHOOK_SECRET"` returns zero hits in app code.
- `stripe.webhooks.constructEvent` is **never called anywhere outside `tests/billing/stripe.test.ts`**.
- `BillingService.handleWebhook()` (`lib/billing/stripe.ts:252-295`) is a stub: returns `{handled: true, action: 'X'}` for the right event names but is **not invoked by any route**. Dead code.
- Consequence: **Stripe has no way to tell Swordfish when a payment succeeded, failed, or a subscription changed.** The Stripe state and the application state cannot be reconciled.

This is the single most critical gap.

---

## 3. Subscription persistence — **BROKEN**

`tenants.plan` (`lib/db/schema.sql:18`) is the sole plan-state column.

- It defaults to `'starter'` and there is **no code path that ever writes a non-default value as a result of a payment**.
- No table for `subscriptions`, `stripe_customers`, `invoices`, or `payment_methods`.
- No `tenants.stripe_customer_id`, `tenants.stripe_subscription_id`, `tenants.subscription_status`, `tenants.current_period_end`, `tenants.trial_ends_at` columns.
- The Stripe customer ID is stored in **Clerk public metadata** (`route.ts:55`, `portal/route.ts:29`). This is fragile: requires a Clerk write that doesn't happen in this codebase (no `clerkClient.users.updateUser({publicMetadata})` call in the checkout route — just reads); on second checkout, the code re-runs `customers.list({email})` which is a global lookup, not org-scoped, and returns the wrong customer if the user has multiple orgs.

Net: **after a successful Stripe checkout, the DB still says `plan=starter`.** The billing page reads `currentTenant.plan` (`page.tsx:205`) and will always display the starter plan even after payment.

---

## 4. Plan-limit enforcement — **MISSING (DECORATIVE)**

The `PlanFeatures` class (`lib/billing/stripe.ts:72-81`) and the `UsageTracker` class (`lib/billing/stripe.ts:326-438`) have **zero callers in route handlers, server components, server actions, or middleware**.

Verified by grep across `/app` and `/lib` excluding `lib/billing/stripe.ts`, `lib/msp/usage.ts`, and tests:
- `PlanFeatures` — 0 hits
- `hasFeature` — 0 hits
- `checkLimit` (Stripe usage tracker) — 0 hits in callers
- `canUse` — 0 hits in callers
- `enforce` — only ATO-related (`lib/ato/response-actions.ts`), unrelated to billing

`lib/msp/usage.ts:239` reads `tenant.plan` but only to **calculate billable overage for reporting**, not to **gate** anything. Mailbox limits, retention, SSO, advanced threat detection — all unenforced. A starter user can connect unlimited mailboxes and use every "enterprise" feature.

`UsageTracker` is also **in-memory** (`stripe.ts:327-328`: `private usage: UsageRecord[] = []`). Even if it were called, it would lose all state on every request in a serverless deploy.

---

## 5. Customer portal — **PARTIAL**

`app/api/billing/portal/route.ts:12-64` works mechanically. Issues:

- **Email-based customer dedup is fragile** (`portal/route.ts:32-37`, same pattern as checkout). If a user belongs to two Clerk orgs with the same email, the *second* org's portal opens the *first* org's billing.
- The customer is **looked up by email globally** rather than by `metadata.tenantId` (which is the right key — it's set on creation at `stripe.ts:101`).
- `STRIPE_PORTAL_CONFIG_ID` (`stripe.ts:20`) is hardcoded as a single config. For MSP wholesale + per-tenant retail (per the brief), you'll need per-tier or per-MSP portal configurations — not addressed.
- No CSRF protection on the POST (`portal/route.ts:12`); Clerk auth gates it but the POST has no nonce or origin check. Lower-severity but worth flagging.

---

## 6. Dunning / failed payment — **MISSING**

- No webhook handler → `invoice.payment_failed` is never observed.
- No `tenants.subscription_status` column → can't represent `past_due` / `unpaid` / `canceled`.
- No retry policy, no email to admin, no in-app banner, no service suspension after N failures.
- Stripe's automatic retries will fire, but without a webhook handler the application will not react when they exhaust.

---

## 7. Tax — **MISSING**

`stripe.checkout.sessions.create` call at `stripe.ts:210-217` does **not** set:
- `automatic_tax: { enabled: true }`
- `tax_id_collection: { enabled: true }`
- `billing_address_collection: 'required'`
- `customer_update: { address: 'auto', name: 'auto' }`

For US-only B2B at low volume this is survivable, but for EU customers it's non-compliant. For per-mailbox SaaS pitched at mid-market and MSPs, this will break onboarding for any non-US org with a finance team.

---

## 8. Receipts / invoices — **PARTIAL**

- `BillingService.listInvoices()` and `getInvoice()` exist (`stripe.ts:237-247`) but **no UI page consumes them**.
- The billing page (`app/dashboard/billing/page.tsx`) does not render invoice history, payment method, next-bill date, or seat count.
- Customer-facing receipts depend entirely on Stripe Dashboard email-receipts setting; not enforced in code.

---

## Pricing-model schema gap (against the brief)

The brief: **per-mailbox SaaS, $3–$8/seat/month**.
The code: **flat tier pricing**, $0 / $49 / $199 (`page.tsx:29-33`, `stripe.ts:29-33`), `quantity: 1` hardcoded in checkout (`stripe.ts:213`).

To support per-mailbox pricing you need:
1. Stripe Price configured as **per-unit** (already supported by the API call shape, but the prices in dashboard need to be per-unit, not flat).
2. `quantity` passed from the route handler, computed from `mailbox_connections WHERE tenant_id = ?`.
3. Webhook handler for `customer.subscription.updated` to re-quantify when mailboxes are added/removed.
4. A reconciliation job (cron) to call `subscriptions.update({ items: [{ id, quantity: <currentMailboxCount> }] })` on a schedule, or use **Stripe metered billing** with `meterEvents.create` (the code at `stripe.ts:418-426` already gestures at this, but is not wired).

None of this exists today.

---

## Risk register (billing-only)

| Severity | Risk | Trigger |
|----------|------|---------|
| **P0** | User pays, plan never upgrades in DB | Any successful checkout |
| **P0** | No webhook signature verification (when added, must be there day 1) | Future webhook impl |
| **P0** | All "premium" features available to free-tier users | Already true today |
| **P1** | Pricing model in code does not match the business model in the brief | Pricing decision |
| **P1** | Cross-org customer collision on shared email | Any user in 2+ orgs |
| **P1** | EU customers cannot purchase compliantly | First EU lead |
| **P1** | Failed payments cause silent churn (no dunning) | Any card decline |
| **P2** | Hardcoded test price IDs ship to prod if env unset | Misconfig |
| **P2** | Stripe API version `2025-12-15.clover` (very recent) — pin and version-test | Stripe API drift |
| **P2** | UsageTracker is in-memory, useless in serverless | If/when wired |
| **P3** | No CSRF nonce on portal POST (Clerk auth covers basic case) | Targeted attacker with valid Clerk session |

---

## Minimum to call this "production wired"

1. Create `app/api/webhooks/stripe/route.ts` with `stripe.webhooks.constructEvent` signature verification + idempotency table.
2. Add `tenants.stripe_customer_id`, `tenants.stripe_subscription_id`, `tenants.subscription_status`, `tenants.current_period_end` columns + migration.
3. Wire webhook → `tenants.plan` and `tenants.subscription_status` updates for `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.payment_failed`, `invoice.payment_succeeded`.
4. Pass `client_reference_id: tenantId` and `subscription_data.metadata: { tenantId }` in checkout creation.
5. Decide pricing model (per-seat vs flat tier) and align Stripe Prices, code, UI, and `lib/msp/usage.ts`. Eliminate the four-source-of-truth divergence.
6. Add **at least one real enforcement gate** (e.g., mailbox connect handler returns 402 if `connectedMailboxCount >= plan.mailboxLimit`) so a tier means something.
7. Add `automatic_tax: { enabled: true }`, `billing_address_collection: 'required'`, `tax_id_collection: { enabled: true }` to checkout.
8. Look up customers by `metadata.tenantId`, not email.
9. Fail-closed on missing env (no hardcoded test price ID fallbacks in prod).
10. Render invoice history + payment method in the billing UI.
