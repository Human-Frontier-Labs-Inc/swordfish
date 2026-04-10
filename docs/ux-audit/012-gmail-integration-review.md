# 012 - Gmail Integration Code Review

**Severity:** Info (code review, not a live bug)
**Status:** Reviewed
**Date Found:** 2026-04-10
**Affected Pages:** Integrations > Connect Gmail / Google Workspace

## Testing Limitation

Google blocks OAuth from headless browsers ("This browser or app may not be secure"), so we couldn't complete the full integration flow via Puppeteer. The OAuth redirect itself works correctly — reaches Google's consent page with proper callback URL.

## Code Review Findings

### What works correctly:
- OAuth callback at `/api/integrations/gmail/callback/route.ts` — proper code-to-token exchange
- Tokens are **encrypted (AES-256-GCM)** before database storage
- Cross-tenant isolation via unique index on `(connected_email, type)`
- Email sync worker fully implemented (`/lib/integrations/gmail/sync-worker.ts`)
- History-based incremental sync + full sync fallback
- Signal analysis: SPF/DKIM/DMARC, suspicious attachments, URL extraction

### Issues found:
1. **Legacy route should be removed** — `/app/api/auth/google/route.ts` has schema mismatches with the current `oauth_states` table structure. Not actively used but could cause confusion.
2. **Gmail push notifications** depend on `GOOGLE_PUBSUB_TOPIC` env var — if not configured, real-time sync won't activate after OAuth.

## Recommendation

- Complete the Gmail OAuth manually in a real browser to verify end-to-end
- Verify `GOOGLE_PUBSUB_TOPIC` is configured in Vercel env vars
- Delete or archive the legacy `/app/api/auth/google/route.ts`
