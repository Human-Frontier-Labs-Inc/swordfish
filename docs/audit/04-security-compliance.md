# Audit 04 — Security & SOC 2 Type II Readiness

**Scope:** Read-only review of /Users/corn/swordfish against SOC 2 Type II controls (Trust Services Criteria CC1–CC9), excluding external pentest. Goal posture: "more secure than the standard."
**Verdict:** **NOT launchable today.** Strong primitives (encryption, audit immutability, webhook HMAC, RLS schema) are present, but five enforcement gaps make the product exploitable on day 1 and would fail Type II observation.

---

## Top 5 Critical Gaps (fix before any paying customer)

| # | Gap | Why critical | Effort |
|---|-----|--------------|--------|
| **C1** | **Stripe webhook handler missing.** `app/api/billing/checkout/route.ts:78` creates Checkout Sessions; there is **no `app/api/webhooks/stripe/route.ts`**. `STRIPE_WEBHOOK_SECRET` is referenced only in `lib/deployment/health.ts:136`. Subscriptions, invoice paid, payment failed, customer deleted — none sync to your DB. Customers will pay and remain on free tier forever. | Revenue loss + audit trail gap (CC7.2) | 1 d |
| **C2** | **Debug routes are publicly callable and tenant-blind.** `app/api/debug/db-state/route.ts:9` and `app/api/debug/register-push/route.ts:12` enumerate **every tenant's** Gmail integration (config blob, nango_connection_id, status, sync timestamps). The register-push endpoint additionally **mutates** Google Pub/Sub subscriptions for every tenant on POST. `proxy.ts:10` whitelists `/api/webhooks(.*)` but `/api/debug/*` is hit only by Clerk auth (which would suffice — except neither route checks auth). **No auth, no tenant scope.** | IDOR + cross-tenant info disclosure + cross-tenant write (CC6.1, CC6.6) | 0.5 d (delete or gate) |
| **C3** | **Row-Level Security defined but not enforced.** `lib/db/schema.sql:548-553` enables RLS on six tenant tables and `migrations/004,006` create per-table `current_setting('app.current_tenant_id')` policies. The runtime helper `lib/db/index.ts:270-276` (`withTenant`) is called in **5 places** across **119 files** that import `@/lib/db`. The `set_config(..., true)` 3rd arg is `is_local=true` — only valid inside a transaction; Neon's HTTP driver opens a fresh "session" per query. **In practice, RLS does nothing**; tenant isolation is 100% application-mediated WHERE clauses. One missing `WHERE tenant_id = …` in any of 119 files = cross-tenant breach. | CC6.1 (logical access controls) — defense-in-depth absent | 5 d (transactional helper + per-route audit) |
| **C4** | **CI lint + typecheck explicitly suppress failures.** `.github/workflows/ci.yml:32` `npm run lint \|\| echo "::warning::"` + `continue-on-error: true`. Same pattern at line 54 for typecheck. Build job depends on these jobs but they always pass. The "no `any`" rule in CLAUDE.md is unenforceable. Insecure code lands on `main` unblocked. | CC8.1 (change management) — failed control | 0.5 d (remove `continue-on-error`, fix backlog separately) |
| **C5** | **`ENCRYPTION_KEY` length check is wrong unit.** `lib/security/encryption.ts:25` requires `key.length === 32` (characters) and then `Buffer.from(key, 'utf8')`. For ASCII this is 32 bytes (correct AES-256). For any non-ASCII char it produces <32 bytes → `createCipheriv('aes-256-gcm', key, …)` will throw, but a 32-char key with multi-byte chars can also accidentally produce wrong-length buffer. Plus: **single static key, no rotation, no key versioning** in token format (`iv:authTag:ciphertext`). Cannot satisfy CC6.7 evidence ("we rotated keys this period"). | CC6.7 (key management) | 1 d (require base64 32-byte key + add `v1:` prefix for future rotation) |

---

## Full Scorecard

### 1. Multi-tenant isolation — **PARTIAL**
- `lib/auth/tenant.ts:39` `getTenantId()` returns `orgId` (or `personal_${userId}`) — clean.
- `verifyResourceAccess` (`tenant.ts:127`) covers 9 tables via switch. **Adequate but additive only** — no central enforcement; relies on every route calling it.
- `verifyMSPAccess` (`tenant.ts:186`) checks `msp_tenant_relationships` — sound model.
- 12 routes with **no recognizable auth/tenant call**: debug/*, webhooks/*, integrations/{o365,gmail}/callback, invitation/details, integrations/sync-nango (deprecated stub OK). Webhook routes verify provider signatures (acceptable — see §8). Callbacks parse `state` param; not audited here for CSRF.
- **RLS not enforced at runtime** — see C3.
- **Remediation:** transactional `withTenantTx()` helper, codemod 119 files, add ESLint rule blocking `sql\`SELECT … FROM <tenant_table>\`` without tenant predicate. **Effort: 5 d.**

### 2. Secrets — **PARTIAL**
- Grep for `sk_live_/pk_live_` in `lib/`, `app/`, `scripts/`: clean (only `sf_live_` template literal in `lib/api/auth.ts:53`).
- All sensitive env vars referenced via `process.env.*` (`lib/oauth/token-manager.ts:171,184`, `lib/security/encryption.ts:19`, etc.). No hardcoded fallbacks except non-secret defaults (`URL_SIGNATURE_SECRET || ''` at `lib/protection/url-rewriter.ts:126` — that empty fallback is a **bug**: HMAC with empty secret is forgeable).
- `lib/security/secrets-manager.ts` exists (429 lines) but not yet read in this audit.
- No `.env*` files committed; `.gitignore` not validated here (suggested follow-up).
- **Remediation:** fail-closed validation at boot (`URL_SIGNATURE_SECRET` empty → throw); add `dotenv-vault` or Vercel env-only policy. **Effort: 0.5 d.**

### 3. Encryption — **PARTIAL**
- **At-rest (tokens):** AES-256-GCM with 12-byte IV, 16-byte auth tag, format `iv:authTag:ciphertext` — `lib/security/encryption.ts:37`. Correct construction.
- **In-transit:** HSTS `max-age=63072000; includeSubDomains; preload` set in `vercel.json:66`. ✔
- **DB at-rest:** Neon provides at-rest encryption; no documented key custody. Sensitive PII (subjects, body) appears stored plaintext in `email_verdicts` — needed for forensics, but should be flagged for retention policy.
- **Gaps:** see C5; no token-level versioning; no envelope encryption (data key wrapped by KEK in KMS) → cannot rotate without downtime/migration.
- **Remediation:** prepend `v1:` to ciphertext, write rotation runbook, plan envelope encryption for v2. **Effort: 2 d.**

### 4. Audit logs — **PARTIAL→GOOD**
- `lib/db/audit.ts:26` `logAuditEvent()` inserts to `audit_log` with actor + before/after state.
- **DB-level immutability** via `CREATE RULE audit_log_no_update / audit_log_no_delete DO INSTEAD NOTHING` (`lib/db/schema.sql`). ✔ Stronger than most SOC 2 candidates.
- **Gaps:** no hash chain (DB superuser could insert backdated records undetectably); 14 of 125 routes log audits, others don't. No retention policy.
- **Remediation:** add `prev_hash`/`row_hash` columns + trigger; mandate `logAuditEvent()` in every state-changing route via lint rule. **Effort: 2 d.**

### 5. RBAC — **PARTIAL**
- Clerk `orgRole` checked inline: `app/api/admin/quarantine/route.ts:27`, `app/api/admin/threats/route.ts:26`, `app/api/admin/tenants/[id]/route.ts:100,183`. Pattern: `orgRole === 'org:admin' || user.is_msp_user || user.role === 'msp_admin'`.
- **No centralized `requireAdmin()` / `requireMspAdmin()` helper** — copy-paste. Future routes will skip the check.
- API key scopes (`lib/api/auth.ts:35`) are well-defined; v1 routes enforce via `hasScope()`.
- `proxy.ts:76` allows ALL `/api/admin*` through global middleware regardless of role — relies entirely on per-route check.
- **Remediation:** wrapper `withAdmin(handler)` returning 403 when role missing; codemod replace per-route inlines. **Effort: 1 d.**

### 6. Change management — **WEAK**
- CI present (`.github/workflows/ci.yml`) — lint, typecheck, test, build, coverage.
- **`continue-on-error: true` on lint + typecheck** = neither blocks merge — see C4.
- **No CODEOWNERS file** at `.github/CODEOWNERS`.
- **Branch protection / required reviews:** not in repo (configured at GitHub UI level — verify in dashboard).
- **Signed commits:** not enforced; recent log shows mixed commit metadata.
- **Remediation:** remove `continue-on-error`, add CODEOWNERS, enforce 1 review + status checks + signed commits in branch protection. **Effort: 0.5 d in repo, ~1 hr in GitHub UI.**

### 7. Backup / recovery — **MISSING DOCUMENTATION**
- Neon Postgres provides automated PITR (default 7-day retention on free, longer on paid). Not configured/documented in repo.
- No `docs/runbooks/` for: DB restore, key compromise, tenant data export/delete (GDPR DSAR).
- No tested recovery drill.
- **Remediation:** define RTO (target ≤4h) / RPO (≤15m) SLA; verify Neon plan supports it; write 4 runbooks; do one tabletop restore. **Effort: 2 d.**

### 8. Webhook signature verification — **GOOD with caveats**
- **Clerk:** `app/api/webhooks/clerk/route.ts:84` uses `svix.Webhook.verify()` ✔
- **Custom outbound:** `lib/security/webhooks.ts` HMAC-SHA256 over `${timestamp}.${payload}`, 5-min replay window, `timingSafeEqual`. Correct.
- **Google Pub/Sub:** `lib/webhooks/validation.ts:41` verifies JWT via `OAuth2Client.verifyIdToken()` against expected audience. ✔
- **Microsoft Graph:** `lib/webhooks/validation.ts:110` checks `clientState` constant — Microsoft's documented model, accepted.
- **Caveats:**
  - `lib/webhooks/validation.ts:50-52`: dev bypass `ALLOW_UNSIGNED_WEBHOOKS=true` — **risk of preview/staging being mis-flagged** as dev. Lock to `process.env.VERCEL_ENV !== 'production'`.
  - **Stripe webhook handler doesn't exist at all** (C1). The infra (`STRIPE_WEBHOOK_SECRET` env var) is wired in `lib/deployment/health.ts:136` but unused.
  - Cron routes verify `Bearer ${CRON_SECRET}` (`app/api/cron/sync/route.ts:23`, others) ✔ — but `app/api/cron/sync/route.ts:22` only enforces in `NODE_ENV === 'production'`; preview deployments are open. Tighten.

---

## Beyond-Standard ("more secure than the standard") Recommendations

| # | Control | Status |
|---|---------|--------|
| B1 | Audit log hash-chain for tamper detection | ✗ add |
| B2 | Envelope encryption (DEK per tenant, KEK in KMS) | ✗ add |
| B3 | Webhook idempotency keys + retry DLQ | partial — Gmail handler caps work but no DLQ |
| B4 | Per-tenant rate limits at edge (Upstash) | partial — `lib/api/rate-limit.ts` exists, applied to v1 only |
| B5 | OWASP CSP + Permissions-Policy headers (vercel.json adds basics, no CSP) | ✗ add |
| B6 | Mandatory MFA for admin & MSP roles (Clerk policy) | unverified |
| B7 | Field-level encryption of email body & subject (search via blind-index) | ✗ — cleartext today |
| B8 | Customer-Managed Keys (CMK) for enterprise tier | ✗ future |
| B9 | Anomaly detection on audit_log (impossible travel, unusual exports) | ✗ |
| B10 | Penetration test ledger + auto-fail Type II if pentest stale (despite excluding pentest, document the policy) | ✗ |

---

## Aggregate Effort Estimate (closing all gaps)

| Bucket | Effort |
|---|---|
| Top 5 criticals | **8 d** |
| Full scorecard fixes (RBAC helper, audit chain, runbooks, CSP) | **6 d** |
| Beyond-standard B1-B5 | **8 d** |
| **Total to "more secure than the standard"** | **~22 dev-days** |

Realistic with parallelism: 2 weeks calendar with one engineer + Claude. The C1 (Stripe webhook) and C2 (debug routes) are pre-launch blockers — neither takes more than a day. C3 (RLS enforcement) is the biggest hidden risk and where a Type II auditor will probe hardest.
