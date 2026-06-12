# Auto-Remediation Audit

**Verdict: WORKING PIPELINE with material gaps.** Most of the plumbing is real and end-to-end — Gmail and O365 mutation APIs are wired, an immutable audit log exists at the DB level, retries are in place, and `autoRemediate` is invoked from four ingestion paths. The "no-human" claim is *almost* defensible, but three concrete gaps stand between the current state and a credible market claim.

## What exists today

### 1. Quarantine + claw-back via provider APIs
Two parallel implementations exist (duplication risk — see Gap 4).

- `lib/workers/remediation.ts` — newer, retry-wrapped, used by ingestion pipelines.
  - O365 quarantine: `moveO365Email` to "SwordPhish Quarantine" mailFolder (`remediation.ts:522-545`)
  - O365 release: move back to `inbox` (`remediation.ts:547-570`)
  - O365 delete: move to `deleteditems` (`remediation.ts:572-595`)
  - Gmail quarantine: `messages.modify` adding `SwordPhish-Quarantine` label, removing `INBOX` (`remediation.ts:601-626`)
  - Gmail release: optionally `untrash`, then re-add `INBOX` label (`remediation.ts:628-757`) — includes RFC 5322 ↔ Gmail-ID resolver with retry
  - Gmail delete: `trashGmailMessage` (`remediation.ts:759-780`)
  - All wrapped in `retryWithBackoff` with provider-specific retryable error detection (`remediation.ts:42-71`)
- `lib/quarantine/service.ts` — older, direct fetch calls to Graph + Gmail APIs (`service.ts:432-763`). Still referenced by routes.

### 2. End-to-end auto-remediation flow
`autoRemediate()` in `remediation.ts:786-960` is the production entry point. Wired from:
- `lib/workers/email-sync.ts:234, 403` (poll-based O365 + Gmail sync)
- `lib/webhooks/handlers/gmail.ts:156` and `.../microsoft.ts:195` (push notification handlers)
- `app/api/webhooks/gmail/route.ts:249`, `app/api/webhooks/o365/route.ts:214` (route-level)
- `app/api/workers/gmail-queue/route.ts:157` (queue worker)

Trigger logic (`email-sync.ts:231`, `webhooks/handlers/gmail.ts:140`, etc.):
```ts
if (verdict.verdict === 'quarantine' || verdict.verdict === 'block') {
  await autoRemediate({ ... });
}
```
No human-in-the-loop step exists between detection and mailbox mutation. The `autoRemediate` function uses `INSERT ... ON CONFLICT` on `threats` to atomically record a `remediation_pending` row, then attempts the mailbox API call, then sets status to `quarantined` or `remediation_failed` (`remediation.ts:856-934`). State is honest — failed mutations are not labeled "quarantined."

### 3. Immutable audit trail
`lib/db/schema.sql:244-261`:
- `audit_log` table with `tenant_id`, `actor_id`, `action`, `resource_type`, `resource_id`, `before_state`, `after_state`, `ip_address`, `user_agent`, `created_at`.
- **Immutable at DB level** via PostgreSQL rules: `CREATE RULE audit_log_no_update AS ON UPDATE TO audit_log DO INSTEAD NOTHING` and the equivalent for DELETE.
- Row-level security enabled (`schema.sql:552`).
- Writes via `lib/db/audit.ts` `logAuditEvent()` and inline transactions in `remediation.ts` (`remediation.ts:241-248, 344-351, 444-451`). Every quarantine/release/delete is logged within the same DB transaction as the status change.

### 4. Notifications
`lib/notifications/service.ts` writes to in-app `notifications` table and dispatches to email (Resend), Slack webhook, generic webhook. Triggered on quarantine + release events (`remediation.ts:252-260, 354-362`). Severity-gated, per-tenant configs.

### 5. Test coverage
- `tests/remediation.test.ts`
- `tests/api/quarantine/quarantine.test.ts`
- `tests/workers/remediation-transaction.test.ts`

## Gaps to a credible "no-human auto-remediation" claim

### Gap 1: No end-recipient notification (HIGH)
Notifications go to **admin/security configs only** (`notifications/service.ts:88-118` reads from `notification_configs`). The user whose inbox an email was just yanked from gets nothing. If Swordfish brand promise is "AI auto-remediates without a human," the *affected mailbox owner* must see a polite "we removed a suspicious message claiming to be from X — view in your safe inbox / report mistake" notification, or the experience feels like silent mail-stealing. This is also the safest social-engineering deterrent: an attacker can't pretext an unaware user.

**What's missing:** A `notifyRecipient()` path that sends an in-product (or email-fallback) message to `recipient_email` when their mail is auto-actioned, with a one-click release-or-confirm flow.

### Gap 2: Policy gate is UI-only, not enforced (HIGH)
`app/admin/policies/page.tsx:247, 420-424` exposes a `autoQuarantine: boolean` policy toggle. **Zero references in `/lib`** — the trigger code in `email-sync.ts`, webhook handlers, and `remediation.ts` does not read this flag. Every tenant gets auto-action whether they opted in or not. For mid-market and MSP customers who require monitor-only or staged rollouts, this is a no-go.

**What's missing:** Enforce the policy at the dispatch site — read tenant policy in `email-sync.ts:231` / webhook handlers and skip `autoRemediate()` when disabled, falling back to "flag-only" mode that still records the threat row.

### Gap 3: Score → action mapping is implicit (MEDIUM)
The detection pipeline emits a verdict (`pass | suspicious | quarantine | block`) and a numeric score, but there is no per-tenant configurable threshold for what score becomes which verdict. Customers will eventually want "auto-quarantine ≥85, alert-only 70-84, monitor 50-69." Right now the verdict is decided in `lib/detection/pipeline.ts` with hardcoded logic.

**What's missing:** Per-tenant threshold table + reading it during verdict assignment.

### Gap 4: Two parallel quarantine implementations (MEDIUM, debt)
`lib/quarantine/service.ts` and `lib/workers/remediation.ts` both contain quarantine/release/delete + Gmail/O365 specifics. They differ on: retry behavior (only the workers version retries), audit log shape (slightly different fields), and notification trigger points. Routes call into the older one in some places. Drift risk and double-write risk are real.

**What's missing:** Decide which is canonical (recommendation: `lib/workers/remediation.ts`), migrate route handlers (`app/api/v1/quarantine/route.ts`, `app/api/v1/threats/[id]/route.ts`, `app/api/v1/policies/route.ts`) to use it, delete the legacy file.

### Gap 5: MSP rollup absent (MEDIUM)
The audit log is per-tenant. There is no MSP-level view that aggregates "across all 47 of my client tenants, here are today's auto-remediations." `lib/msp/usage.ts` does counts but no remediation timeline. The MSP control-plane positioning the user asked for (modern Proofpoint replacement, MSP-friendly) needs a parent-tenant audit feed.

**What's missing:** MSP-scoped query + dashboard surface that joins child tenants' audit_log rows.

### Gap 6: No reversibility window / cooldown (LOW)
`autoRemediate()` mutates the mailbox immediately. There's no "stage for 30 seconds, then commit if no admin override" buffer. For a "no-human" product this is fine — but if a customer wants safety net for a high-confidence-but-occasionally-wrong model, there's no native way to delay execution.

## What it would take to honestly claim "no-human auto-remediation" at 30-day launch

Concretely, in priority order:

1. **Build `notifyRecipient()`** — in-product banner (or fallback email) to the affected mailbox owner whenever their mail is auto-quarantined. Include: claimed sender, subject, why it was caught (top 3 signals from `verdict.signals`), one-click "release to my inbox" and "this was definitely phishing — confirm" actions. Without this, the product feels invisible/spooky to the user it's protecting. **Estimate: 3–5 days.**

2. **Enforce `autoQuarantine` policy at dispatch** — read tenant policy in the four ingestion paths before calling `autoRemediate()`. Add a `flag_only` mode that records the threat row but skips mailbox mutation. **Estimate: 1–2 days.**

3. **Add per-tenant score thresholds** — `tenant_thresholds` table + read in pipeline. Default values match current hardcoded logic. **Estimate: 2 days.**

4. **Consolidate to `lib/workers/remediation.ts`** — delete `lib/quarantine/service.ts`, migrate three API routes. **Estimate: 1–2 days.**

5. **MSP-scoped audit feed** — query all child-tenant `audit_log` rows for an MSP parent, surface in MSP dashboard. **Estimate: 2–3 days.**

6. **Real-world validation** — wire a labeled corpus (PhishTank + internal samples) through the pipeline end-to-end and measure: precision, recall, time-to-quarantine p50/p95, recipient notification delivery rate, false-positive release rate. Without measurable numbers in the demo, "AI auto-remediates" is a claim. With them, it's a product. **Estimate: 3–5 days, but parallel to other work.**

**Bottom line:** the technical core is real; the product story isn't complete until the recipient sees what happened, the admin can opt in/out, and you can quote a precision/recall number under load.
