# 019 - End-to-End Gmail Sync Test Gap

**Severity:** Info (testing limitation, not a product bug)
**Status:** Documented
**Date Found:** 2026-04-11

## What was tested
- Gmail OAuth connection: **Pass**
- Gmail sync (Clerk emails): **Pass** — 2 emails synced and analyzed correctly
- Detection pipeline via /api/test/inject-email: **Pass** — all threat types detected
- Detection pipeline via /api/analyze: **Pass** — scoring verified

## What still needs manual testing
- Send actual phishing/BEC/malware emails from an external account to claudetestguy@gmail.com
- Trigger Sync Now and verify the full pipeline: Gmail inbox → sync → detect → score → store → display in UI
- Gmail's `messages.import` API doesn't reliably place messages in INBOX for the sync query (`in:inbox after:timestamp`) to find them

## How to test manually
1. From another email account, send a suspicious email to claudetestguy@gmail.com
   - Example: spoof a bank name in the subject, include a sketchy URL
2. Go to SwordPhish → Integrations → Sync Now
3. Check Emails page — the email should appear with a threat verdict
4. Check Dashboard — threat stats should update

## Test infrastructure available
- `/api/test/inject-email` — bypasses Gmail, runs detection + stores verdict directly
- `/api/test/gmail-inject` — inserts into Gmail inbox (import API), useful for populating inbox
