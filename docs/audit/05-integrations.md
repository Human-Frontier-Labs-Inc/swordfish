# Audit 05 — Integrations Gap Analysis

**Goal at launch:** Gmail + Microsoft 365 + Slack + Teams + SIEM/SOAR webhooks.
**Verdict:** Gmail is production-grade. M365 is **80% built but broken** (split-brain auth, stale webhook handler). SIEM = Splunk only. Slack/Teams require real builds.

---

## 1. Gmail / Google Workspace — Production-grade ✅

Files: `lib/integrations/gmail.ts` (649 lines), `lib/integrations/gmail/sync-worker.ts` (577 lines), `lib/oauth/token-manager.ts` (373 lines), `app/api/auth/google/route.ts` (283 lines), `app/api/webhooks/gmail/route.ts` (400 lines), `lib/queue/gmail.ts`, `lib/integrations/domain-wide/google-workspace.ts` (389 lines).

### OAuth scopes requested
```
https://www.googleapis.com/auth/gmail.readonly
https://www.googleapis.com/auth/gmail.modify
https://www.googleapis.com/auth/userinfo.email
```
- `access_type=offline`, `prompt=consent`, PKCE supported (`code_challenge_method=S256`), `login_hint` for prefill.

### Token storage & refresh flow
- Tokens **encrypted at rest** in `integrations` table (`oauth_access_token`, `oauth_refresh_token`) via `lib/security/encryption`.
- `lib/oauth/token-manager.ts:getAccessToken(tenantId, 'gmail')` is the single read path.
- 5-minute refresh buffer (`TOKEN_REFRESH_BUFFER_MS = 5 * 60 * 1000`).
- On refresh failure, marks integration `status='error'` so user is forced to reconnect.
- `revokeTokens()` calls Google's `oauth2.googleapis.com/revoke` on disconnect.

### Push vs poll
- **Push model**: Pub/Sub via `watchGmailInbox(topicName, labelIds=['INBOX'])`. Pub/Sub auth validated against `GOOGLE_WEBHOOK_AUDIENCE` (gated by `STRICT_WEBHOOK_VALIDATION` in prod).
- **History-based delta**: `getGmailHistory(startHistoryId, types=['messageAdded'])` per webhook. HistoryId stored in integration `config.historyId`; idempotent — duplicate Pub/Sub deliveries with stale historyId are dropped via `BigInt` comparison.
- **Watch lifecycle**: `watchExpiration` stored on integration; needs renewal cron (Gmail watches expire after 7 days; not seeing renewal worker — **gap**).

### Gmail API surface used
`users/me/profile`, `users/me/messages` (list), `messages/{id}` (get, format=full), `messages/{id}/modify` (labels), `messages/{id}/trash`, `messages/{id}/untrash`, `users/me/labels` (list/create), `users/me/watch`, `users/me/stop`, `users/me/history`, search by `rfc822msgid:`. Retry wrapper `gmailFetchWithRetry` with exponential backoff, honors `Retry-After`, retries 429/5xx up to 3 attempts capped at 30s.

### Webhook quality
- Per-tenant lookup by **verified `connected_email`** (no cross-tenant fallback — good).
- Time-budget 45s with `MAX_MESSAGES_PER_WEBHOOK=10` cap to dodge Vercel timeouts.
- Optional QStash queue offload (`isGmailQueueConfigured`) to keep webhook fast.
- Calls full pipeline: `analyzeEmail` (skipLLM=true in webhook), `storeVerdict`, `sendThreatNotification`, `autoRemediate`.
- Domain-wide branch routes Workspace mailboxes through `processDomainWideGmail` using application-level service-account tokens.

### Reusable vs Gmail-specific
Reusable across providers (already provider-agnostic):
- `lib/oauth/token-manager.ts` — `IntegrationType` is parametrized over `'gmail' | 'o365' | 'smtp'`.
- `lib/detection/pipeline.ts:analyzeEmail`, `lib/detection/storage.ts:storeVerdict`.
- `lib/notifications/service.ts:sendThreatNotification`.
- `lib/workers/remediation.ts:autoRemediate` (dispatches by `integrationType`).
- `lib/security/encryption` for token-at-rest.

Gmail-specific (acceptable):
- `parseGmailEmail` in `lib/detection/parser.ts` (Gmail JSON shape vs Graph shape).
- Pub/Sub validation (`validateGooglePubSub`) — Microsoft uses different signature scheme.
- Retry wrapper is duplicated in `gmail.ts`; should be lifted to a shared `lib/integrations/http.ts`.

### Gmail gaps to close before launch
- **G-1.** `watch` renewal cron — watches expire after 7 days; nothing scheduled. ~0.5d.
- **G-2.** `parseGmailEmail` test coverage against real Gmail payloads (multipart/HTML/encoded). ~1d.
- **G-3.** Domain-wide flow is sophisticated but unverified end-to-end. ~1d.

---

## 2. Microsoft 365 — 80% built, BROKEN wiring ⚠️

Files: `lib/integrations/o365.ts` (417 lines), `lib/integrations/o365/sync-worker.ts` (432 lines), `lib/integrations/domain-wide/microsoft-365.ts` (457 lines), `app/api/auth/microsoft/route.ts` (265 lines), `app/api/webhooks/microsoft/route.ts` (192 lines).

### What exists (good)
`lib/integrations/o365.ts` is a full clean Graph API client:
- OAuth: `getO365AuthUrl` / `exchangeO365Code` / `refreshO365Token` with PKCE, scopes `Mail.Read Mail.ReadWrite User.Read offline_access`.
- API: `listO365Emails`, `getO365Email`, `moveO365Email` (quarantine), `createO365Subscription`, `renewO365Subscription`, `deleteO365Subscription`, `getOrCreateQuarantineFolder`.
- Subscriptions: 4230 minute (max) lifetime, `clientState` for verification.
- Domain-wide flow: app-permission Graph access for org-wide mailbox monitoring.

### Critical break #1 — split-brain OAuth storage
**Two competing implementations write to two different tables.**

`app/api/auth/microsoft/route.ts` (the route the UI actually hits) writes to `provider_connections`:
- Provider name: `'microsoft'`.
- **Tokens stored UNENCRYPTED** (`access_token`, `refresh_token` columns are plaintext) — `app/api/auth/microsoft/route.ts:111-112`.
- No code path through `lib/oauth/token-manager.ts:storeTokens()`.

`lib/oauth/token-manager.ts` and `lib/integrations/o365.ts` expect tokens in `integrations` table:
- Provider name: `'o365'`.
- Encrypted via `lib/security/encryption`.
- This is what `getO365AccessToken(tenantId)` reads from.

**Result**: connecting Microsoft via the UI populates one table; the webhook + sync worker read a different table. Connection appears "successful" in UI but mail processing **cannot retrieve a token** from the storage the webhook expects.

### Critical break #2 — webhook handler references removed code
`app/api/webhooks/microsoft/route.ts:74-96` still queries `nango_connection_id` and calls `getO365AccessToken(nangoConnectionId)`. The current signature is `getO365AccessToken(tenantId)` (`lib/integrations/o365.ts:21`). At runtime this passes a connection ID (or null) where a tenantId is expected → guaranteed token-fetch failure. This is dead code as written.

### Build-out gap (effort: 5–7 person-days)
- **M-1.** Delete or rewrite `app/api/auth/microsoft/route.ts` to call `lib/integrations/o365.ts:getO365AuthUrl` + `exchangeO365Code` + `lib/oauth/token-manager.ts:storeTokens` (matches Gmail flow). ~1d.
- **M-2.** Fix webhook handler: drop `nango_connection_id`, look up integration by `subscriptionId` in `integrations.config`, call `getO365AccessToken(tenantId)`. Add `clientState` HMAC validation. ~1d.
- **M-3.** Subscription lifecycle worker: renew every 3 days (Graph max is ~70.5h for `/messages` resources, NOT 4230min — current code is wrong for mailbox subscriptions). ~1d.
- **M-4.** End-to-end test: connect tenant, send phishing email, verify quarantine + verdict + notification. ~1d.
- **M-5.** Drop legacy `provider_connections.microsoft` rows OR migrate to `integrations`. Decide canonical table. Migration ~0.5d.
- **M-6.** Throttling: Graph returns 429 with `Retry-After` for large orgs; o365.ts has no retry wrapper today. Lift Gmail's `gmailFetchWithRetry` to shared `graphFetchWithRetry`. ~0.5d.
- **M-7.** Exchange-on-prem hybrid orgs and B2B guest accounts: tenant-specific quirks (`/common` vs tenant-scoped authority). The current code uses `/common` everywhere — works for most, breaks for guest-only or strict CA-policy tenants. Document, not block. ~0.5d.

### Known M365 gotchas (document for ops)
- Subscription resource must be `/me/mailFolders('inbox')/messages` (current code) for delegated; switch to `/users/{id}/mailFolders('inbox')/messages` for application permissions.
- Graph subscriptions emit `lifecycleNotificationUrl` events — not currently handled. If we don't reauthorize on `reauthorizationRequired`, subs go silent.
- Conditional Access policies can block daemon-style refresh. Surface this as a connection-state error, not a 500.
- Application permissions require admin consent (`/adminconsent` endpoint) — domain-wide setup wizard exists but unverified.

---

## 3. Slack — Notification only, NO scanning ❌

What exists today: outbound webhook notifier in `lib/notifications/service.ts:326-375` (`sendSlackNotification`). Posts threat alerts to a customer-provided Slack incoming webhook URL. **This is alerting, not security**. Swordfish does not scan Slack messages.

### Build-out gap to do "real" Slack security (effort: 7–10 person-days)
- **S-1.** Slack OAuth app + bot install: distribute via Slack App Directory, `slack.com/oauth/v2/authorize`, scopes `channels:history channels:read groups:history im:history mpim:history users:read`. Per-workspace install record. ~2d.
- **S-2.** Events API webhook (`app/api/webhooks/slack/route.ts`): URL verification challenge, signing-secret HMAC validation (`X-Slack-Signature` + `X-Slack-Request-Timestamp`, 5-min replay window). ~1d.
- **S-3.** Message-scanning event handler: `message.channels` / `message.groups` / `link_shared` events; rate-limit-aware Web API client for `conversations.history` backfill. ~2d.
- **S-4.** New `parseSlackMessage` adapter to feed `analyzeEmail` (or branch to `analyzeMessage`); URLs, files, mentions, sender. ~1d.
- **S-5.** Slack-side remediation: `chat.delete` (only by author or admin token), `pins.add` for security review, DM-the-user warnings. Slack is more constrained than mail — most "remediation" will be admin notification + audit. ~1d.
- **S-6.** Workspace-scoped quotas vs per-mailbox pricing — billing model needs clarification. Slack is per-workspace seat count. ~0.5d clarification, no code.

Gotchas: Slack rate limits are aggressive (Tier 2 = 20/min for `conversations.history`); per-channel monitoring requires bot-channel join; private channels need explicit invite; DLP-style scanning needs Enterprise Grid for Discovery API.

---

## 4. Microsoft Teams — ZERO code today ❌

Confirmed by grep: no Teams-specific code anywhere. The string `"teams"` appears only in unrelated UI/util.

### Build-out gap (effort: 10–14 person-days)
- **T-1.** Teams app manifest + Resource-Specific Consent (RSC) permissions: `ChannelMessage.Read.Group`, `Chat.Read`, `TeamsAppInstallation.ReadWriteSelfForChat`. App must be uploaded to AAD app catalog or installed per-team. ~2d.
- **T-2.** Graph subscriptions for `chats/getAllMessages` (tenant-scoped) and per-team `teams/{id}/channels/{id}/messages`. Subscriptions for chat messages have **1-hour max lifetime**, not 4230min — needs aggressive renewal cron. ~2d.
- **T-3.** Encrypted-payload subscriptions: Teams chat messages require `encryptionCertificate` + decrypt-with-private-key flow; payloads are AES-256 wrapped. Non-trivial crypto. ~2d.
- **T-4.** Message parser + URL/attachment extractor for Teams JSON shape; reuse detection pipeline. ~2d.
- **T-5.** Remediation: Graph supports `chatMessage.softDelete` only for caller's own messages; admin-level deletion requires `Chat.ReadWrite.All` + `ChannelMessage.Delete.Group` and channel ownership. ~1d.
- **T-6.** Tenant-wide install via admin consent flow + side-loading enablement (admin policy required). Onboarding doc + UI flow. ~1d.

Gotchas: Teams subscriptions are dramatically more complex than Outlook subscriptions — encrypted payloads, short TTL, RSC scoping; **easy to underestimate by 2x**.

---

## 5. SIEM/SOAR webhooks — Splunk only, partial generic ⚠️

### What exists (good)
`lib/integrations/splunk.ts` (370 lines) is production-quality:
- HEC + CEF format, proper escaping, `sendToSplunk` + `sendBatchToSplunk`, per-tenant config in `splunk_integrations` table.
- Dispatchers for threat / policy / quarantine events, delivery audit table `splunk_deliveries`.
- Configurable `eventTypes`, `sourceType`, `index`, `source`. Test connection method.

### Generic outbound webhook
`sendWebhookNotification(webhookUrl, payload)` in `lib/notifications/service.ts:377-390` posts JSON to a single URL. **No HMAC signing, no retries, no delivery audit, no schema versioning** — not safe for downstream SIEM ingestion.

### Build-out gap (effort: 3–5 person-days)
- **W-1.** Generic webhook v2 with HMAC-SHA256 signing (`X-Swordfish-Signature` header), `X-Swordfish-Timestamp`, retry-with-backoff (3 tries), per-tenant secret rotation. Delivery audit table mirroring `splunk_deliveries`. ~1d.
- **W-2.** Microsoft Sentinel direct: Log Analytics Data Collector API (HMAC over shared key, custom log type). Cleaner than generic webhook for Sentinel customers. ~1d.
- **W-3.** Tines / Torq / generic SOAR adapters: same HMAC-signed JSON, but documented schema + sample stories/playbooks. Stretch; format is the same as W-1, just docs. ~0.5d.
- **W-4.** UI to configure outbound webhooks per-tenant with a connection-test button. ~1d.
- **W-5.** Replace ad-hoc `sendWebhookNotification` callers with the new audited path. ~0.5d.

Gotchas: SOAR systems (Tines/Torq) typically expect `application/json` with idempotency keys; Sentinel's Log Analytics ingestion has a hard 30MB/payload, 32KB/field limit; Splunk HEC has its own 1MB default cap. Document all three.

---

## 6. Cross-cutting gaps

- **No formal `MailProvider` interface.** `gmail.ts` and `o365.ts` have parallel function shapes but no shared TypeScript contract. This is biting us in `autoRemediate` (works by string-switching `integrationType`). Lift to `MailProvider { listMessages; getMessage; quarantineMessage; release; deleteMessage; createWatch; renewWatch; stopWatch }`. ~1.5d, pays back across all integrations.
- **Retry wrapper is Gmail-only.** Move to `lib/integrations/http.ts` and use everywhere.
- **Two OAuth storage tables** (`integrations` vs `provider_connections`) — pick one (recommend `integrations` since it's encrypted), migrate, drop the other. ~1d.
- **Watch/subscription renewal worker exists for nothing.** Need a single cron that renews Gmail watches (7d), M365 subs (3d for mailbox, 1h for Teams chat). ~1d.
- **Connection health UI**: no per-tenant view of "Gmail watch expires in X, M365 sub status, last successful sync". Required before pricing per-mailbox. ~1d.

---

## 30-day Realistic Recommendation

### Ship at launch (≈ 14–17 person-days of integration work)
1. **Gmail** — already shipped; close G-1/G-2/G-3 (~2.5d).
2. **Microsoft 365** — consolidate split-brain auth, fix webhook handler, add subscription renewal cron, end-to-end test (M-1 through M-6, ~5–7d).
3. **Splunk HEC** — already done; add UI config + test button if not present (~0.5d).
4. **Generic outbound webhook v2** with HMAC + retries + audit (W-1, W-4, W-5, ~2.5d).
5. **Sentinel direct** if cheap to add (W-2, ~1d) — strong sales signal for mid-market.
6. **Cross-cutting**: shared `MailProvider` interface + shared retry wrapper + storage consolidation + renewal worker + connection-health UI (~5d).

### Slip to +30 days (post-launch)
- **Slack message scanning** (S-1 through S-6, ~7–10d).
- **Tines/Torq/SOAR-specific docs + sample playbooks** (W-3, ~0.5d).

### Slip to +60 days
- **Microsoft Teams** (T-1 through T-6, ~10–14d). Encrypted-payload subscriptions are the long pole and high-risk for a 30-day timeline.

### Honest call on "all integrations at launch"
Doing **Gmail + M365 + Slack message scanning + Teams + SIEM webhooks** in 30 days is not feasible without cutting quality on M365 (the highest-revenue integration) or shipping a half-built Teams. Recommend launching with **Gmail + M365 + Splunk + Sentinel + generic webhook**, and positioning Slack/Teams as "Q2" on the marketing site. That keeps the M365 build solid (which is what mid-market and MSPs actually buy) and avoids a Teams encryption-key disaster on day 30.

---

## Summary table

| Integration | State today | Effort to launch-ready | Launch / +30 / +60 |
|---|---|---|---|
| Gmail | Production-grade | 2.5d polish | Launch |
| Microsoft 365 | 80% built, broken wiring | 5–7d (M-1..M-6) | Launch |
| Slack (alerting only) | 25 lines, outbound only | 0d (already works) | Launch |
| Slack (message scanning) | Not built | 7–10d (S-1..S-6) | +30 |
| Microsoft Teams | Not built | 10–14d (T-1..T-6) | +60 |
| Splunk HEC | Production-grade | 0.5d UI polish | Launch |
| Microsoft Sentinel | Not built | 1d (W-2) | Launch |
| Tines / Torq / SOAR | Generic webhook only | 1d HMAC + docs (W-1, W-3) | Launch |
| Cross-cutting (interface, renewals, storage) | Mixed | ~5d | Launch (blocking) |

**Total launch-blocking effort: ~17–20 person-days** of focused integration work, assuming detection pipeline + auto-remediation + billing audits don't blow up scope.
