# Production Readiness Migration Plan (Gmail + Scale)

This document is a practical, staged guide to take Swordfish to production readiness with a focus on Gmail ingestion reliability and scale. It includes database migrations, architecture changes, operational config, and verification steps.

---

## 0) Goals and Success Criteria

Goals:
- No dropped emails during Gmail ingestion.
- Webhook processing always returns quickly (no timeouts).
- System handles bursty Gmail traffic without Neon connection errors.
- Security and multi-tenant isolation meet production expectations.

Success Criteria:
- Gmail webhook p95 < 2s, p99 < 5s.
- No `value too long for type character varying(100)` in logs.
- No `Too many connections attempts` during normal load.
- Emails appear in Swordfish within 5 minutes (cron backstop) and within seconds in normal operation.

---

## 1) Phase A: Fix Schema Drift and Hard Failures (Blocking)

### A1. Identify current production schema
- Dump current production schema for `notifications`, `audit_log`, `threats`, `email_verdicts`.
- Confirm which migrations are applied and which are missing.

### A2. Apply schema alignment migrations
Required changes:
- **Notifications table**: add `resource_type` and `resource_id` or update insert logic to match existing columns.
- **VARCHAR(100) hotspots**: widen to `VARCHAR(255)` or `TEXT` for fields that receive dynamic values:
  - `notifications.type`
  - `audit_log.action`
  - `audit_log.resource_type`
  - `threats.threat_type`

### A3. Add truncation safeguards
Make truncation consistent in any write path that touches fixed-length columns:
- `sendNotification` should truncate `type`, `title`, and any resource fields.
- Threat writes should truncate `threat_type` and other string fields before insert.

Deliverables:
- One migration file (SQL) with schema changes.
- One utility helper used consistently for truncation.

Verification:
- Send a Gmail email with long subject/sender/labels.
- Confirm no 22001 errors and the verdict is stored.

---

## 2) Phase B: Decouple Gmail Webhook (Long-Term Fix)

### B1. Make webhook ultra-thin
Webhook should only:
- Validate Pub/Sub.
- Decode message to `{ emailAddress, historyId }`.
- Enqueue a job.
- Return HTTP 200.

### B2. Introduce a durable queue (Upstash Queue)
Use Upstash Queue (serverless‑friendly, minimal ops) for Gmail ingestion jobs.

Queue payload:
```
{ tenantId, emailAddress, historyId, receivedAt }
```

Environment:
- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`
- `UPSTASH_QUEUE_NAME` (e.g. `gmail-ingest`)

Dependencies:
- Add `@upstash/queue` (preferred) or `@upstash/redis` for custom queue ops.

### B3. Create a worker endpoint (Vercel cron)
Implement a serverless worker endpoint (e.g. `POST /api/workers/gmail-queue`) that:
- Dequeues a batch (e.g. 5–10 jobs).
- Fetches Gmail history + messages.
- Runs detection with `skipLLM: true`.
- Writes to Neon with controlled concurrency.
- Updates `historyId` only after core writes succeed.

Cron trigger:
- Add a Vercel cron to call the worker endpoint every minute.
- Pass `CRON_SECRET` for auth.

Controls:
- Per‑invocation batch limit.
- Per‑invocation time budget (e.g. 45s).
- Exponential backoff when Neon is saturated.
- Dead‑letter queue for jobs that fail N times.

Deliverables:
- New worker module/service.
- Queue provisioning config.
- Updated webhook route.

Verification:
- Flood Gmail with multiple emails.
- Confirm webhook responds fast (enqueue only).
- Worker processes jobs steadily without timeouts.

---

## 3) Phase C: Performance and Backpressure

### C1. Separate fast verdict and LLM enrichment
- Real-time pipeline uses `skipLLM: true`.
- Secondary job runs LLM enrichment for high-risk emails.

### C2. Rate limits and circuit breakers
- Add circuit breaker around Gmail API calls.
- Add per-tenant rate limits for enqueueing and processing.

### C3. Optimize DB usage
- Ensure batched inserts where possible.
- Use a shared Neon client per worker instance.
- Add indexes for high-traffic queries (by tenant_id, message_id, created_at).

Verification:
- p95 processing latency < target.
- No Neon connection saturation under expected load.

---

## 4) Phase D: Security and Compliance

### D1. Token storage
- Remove all plaintext token storage in legacy callbacks.
- Use Nango exclusively.

### D2. RLS and tenant isolation
- Define RLS policies for all tenant-scoped tables.
- Ensure app sets `app.current_tenant_id` for all DB queries.

### D3. Webhook authentication
- Configure Pub/Sub push to send OIDC token with correct `aud`.
- Enable `STRICT_WEBHOOK_VALIDATION=true` in production.

Verification:
- Attempt cross-tenant query access; confirm denied.
- Webhook rejects invalid signatures.

---

## 5) Phase E: Operational Readiness

### E1. Cron hardening
- Confirm `CRON_SECRET` is set.
- Verify `/api/cron/sync-emails` and `/api/cron/renew-subscriptions` runs on schedule.

### E2. Observability
Add metrics:
- Webhook QPS / error rate.
- Queue depth / oldest job age.
- Worker throughput and latency.
- Neon connection errors.

Set alerts:
- No emails processed for 15 minutes.
- Queue age > 10 minutes.
- Neon connection errors > threshold.

### E3. Runbooks
Create runbooks for:
- Re-register Gmail watch.
- Reprocess failed messages from dead-letter queue.
- Manual cron trigger procedures.

---

## 6) Rollout Strategy

### Step-by-step
1) Apply schema migration in staging.
2) Deploy truncation safeguards and verify.
3) Deploy queue + worker in staging.
4) Switch webhook to enqueue-only.
5) Load test with Gmail burst scenarios.
6) Roll out to production in a low-traffic window.

### Rollback plan
- Keep old webhook logic behind a feature flag.
- If queue/worker fails, revert to cron-only ingestion until fixed.

---

## 7) Implementation Checklist (Condensed)

- [ ] Schema migration applied (notifications, audit_log, threats).
- [ ] Truncation helper used in all write paths.
- [ ] Webhook enqueue-only.
- [ ] Queue provisioned and worker running.
- [ ] Backpressure and retries implemented.
- [ ] LLM enrichment moved to async job.
- [ ] RLS policies enforced.
- [ ] Token storage fixed (Nango only).
- [ ] Webhook signature validation enabled.
- [ ] Metrics and alerts live.

---

## 8) Estimated Timeline

- Phase A: 1-2 days
- Phase B: 3-5 days
- Phase C: 2-4 days
- Phase D: 2-4 days
- Phase E: 1-2 days

Total: ~2-3 weeks for full production hardening.

---

## 9) Gmail Specific Long-Term Fix Summary

**Current issue**: Heavy webhook processing + DB schema mismatches cause timeouts and dropped emails.

**Long-term fix**:
- Webhook enqueues only.
- Durable queue + worker with controlled concurrency.
- `skipLLM` in real-time; LLM enrichment deferred.
- Schema alignment and truncation to prevent 22001 errors.
- Cron remains as fallback, not primary path.
