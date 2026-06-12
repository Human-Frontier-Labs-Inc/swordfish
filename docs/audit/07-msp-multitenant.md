# Audit 07 — MSP Multi-Tenancy

**Verdict:** Bones exist, but MSP tier is **not credible today**. The schema gestures toward a real MSP model, the access-control logic ignores it, the billing model doesn't support rollup, and the differentiating MSP affordances (bulk onboarding, white-label, per-client policy overrides, cross-tenant dashboard) are either missing or stubbed.

**Effort to credible MSP tier:** ~**20–25 person-days** of focused work. Not 30 days *plus* the other 7 audit areas.

---

## 1. Parent–child org model — Partial

**What exists** (`lib/db/schema.sql`):

- `tenants` (line 13): client orgs. **No `parent_msp_id` FK** on tenants.
- `msp_organizations` (line 41): parent MSP rows, with `branding JSONB` for white-label.
- `msp_tenant_access` (line 51): many-to-many join `(msp_org_id, tenant_id)` — the right shape, but…
- `users.tenant_id` (line 33): **users are scoped to a single tenant**. MSP staff are a "user" with `is_msp_user=true` flag and role `msp_admin`. There is no per-staff scoping to a subset of client tenants — `is_msp_user` is god-mode across all tenants.

**The hole:** `msp_tenant_access` exists but is **dead code in the auth path**. `app/api/msp/tenants/route.ts:40` decides cross-tenant visibility purely from `is_msp_user`. The join table is never consulted. So today, an MSP user assigned to one client can see *every* tenant in the database. This is a multi-tenancy isolation defect, not just a feature gap.

## 2. UI — Bolted on, not first-class

- `app/admin/tenants/{page.tsx, new, [id]}` — list + create + detail pages.
- `app/api/msp/tenants/{route.ts, [tenantId]}` — list/create/CRUD.
- `app/api/msp/usage/route.ts` — aggregate usage.
- `components/msp/{ClientCard, OnboardingWizard, TenantSwitcher}.tsx`.

There is **no dedicated MSP control plane** — no `/msp` route group, no cross-tenant overview dashboard, no MSP-branded shell. It's "the admin pages, with a switcher." `TenantSwitcher` uses `?tenant=xxx` query-param switching with no server-side enforcement at the switch point.

## 3. Bulk operations — Absent

- No bulk client onboarding endpoint. `OnboardingWizard.tsx` is one-client-at-a-time.
- No bulk policy push API. `policy_templates` table is correctly scoped to `msp_org_id` (line 168), but there is no endpoint to apply a template to N tenants at once — `tenant_policies` inserts are one-by-one only.
- No CSV import for clients/users.

## 4. White-label / branding — Schema only, zero usage

- `msp_organizations.branding JSONB` exists.
- `grep -rln "branding" lib/ app/ components/` returns **only `schema.sql`**. No API, no UI, no theme provider consumes it. White-label is a database column, not a feature.
- No per-tenant subdomain or custom-domain support.

## 5. Billing rollup — Missing the core architecture

- **No `stripe_customer_id` on `tenants` or `msp_organizations`** — confirmed by `grep "stripe_customer_id"` over `schema.sql` and `migrations/`. No subscriptions table, no `msp_billing_account` table.
- `lib/billing/stripe.ts` operates on a per-tenant tier model (`free | pro | enterprise`) — incompatible with both the stated **$3–8/mailbox/mo** pricing AND with MSP wholesale + child-org rollup.
- `lib/msp/usage.ts:77` hardcodes flat tier prices ($99/$499/$1999). These don't match the per-mailbox model and aren't connected to Stripe at all — the export is CSV-only.
- `reportToStripe` (line 411) misuses `subscriptionItemId` as `stripe_customer_id` — bug.

There is no path today for one MSP Stripe customer to consolidate seats across many child tenants. That's the core MSP commercial mechanic.

## 6. RBAC — Concept right, enforcement wrong

- Roles defined (`lib/auth/tenant-context.tsx:7`): `msp_admin | tenant_admin | analyst | viewer`.
- Permissions derived (lines 226–228): `canManageTenant`, `canViewAllTenants`, `canManagePolicies`.
- **But authorization is `is_msp_user`-flag based, not access-table based.** No per-MSP-staff client scoping. No distinction between "MSP staff who can see all your clients" and "MSP staff scoped to clients A, B, C only."

## 7. Other defects found in pass

- `app/api/msp/tenants/route.ts:204` — INSERT into `policies (tenant_id, …) VALUES (clerk_org_id, …)`. `policies.tenant_id` is UUID; `clerk_org_id` is a string like `msp_tenant_<nanoid>`. **This default-policies path will fail at runtime.** Same shape bug at line 222 for `audit_log.tenant_id`.
- `lib/msp/usage.ts:142` queries `audit_logs` (plural) but the schema defines `audit_log` (singular, line 244). Usage stats query is broken.

---

## Effort to make MSP tier credible

| Workstream | Days |
|---|---|
| Switch authz from `is_msp_user` flag → `msp_tenant_access` table; per-staff scoping | 1.5 |
| Add Stripe customer/subscription model to MSP + tenant; rollup billing | 3.5 |
| Bulk client onboarding (CSV + API + queued OAuth handoff) | 2.0 |
| Bulk policy push (apply template to N tenants, with per-tenant override) | 1.5 |
| Wire branding (admin UI + theme provider + optional subdomain) | 3.0 |
| Dedicated MSP dashboard (cross-tenant overview, threats-by-client, billing) | 3.5 |
| Per-tenant policy override on top of MSP template | 2.0 |
| MSP-staff vs tenant-admin RBAC split + scoped invitations | 1.5 |
| Fix policies/audit_log/audit_logs bugs from the pass above | 0.5 |
| Tests across all of the above | 2.5 |
| **Total** | **~21.5 days** |

Realistic for one engineer with Claude parallelism in 30 days **only if MSP is the sole workstream**. Cannot ship alongside M365 + auto-remediation + detection rebuild + observability in the same window.

---

## Recommendations

1. **Decide now:** Is MSP a launch wedge or a +60/+90 expansion? Today the codebase says "marketed as MSP, built as single-tenant with a switcher."
2. If launch wedge: cut Slack/Teams/SIEM from launch and concentrate the 30 days on MSP + M365 + detection.
3. **Fix the `is_msp_user` god-mode bug regardless of MSP scope decision** — it's a multi-tenancy isolation defect that will haunt SOC 2 controls work (audit 4).
4. Adopt `parent_msp_id` denormalization on `tenants` alongside `msp_tenant_access`, for query simplicity at scale.
5. Move billing model to per-mailbox immediately — the existing tier-based Stripe layer needs to be replaced, not extended.
