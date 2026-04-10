# 001 - Onboarding Completion Not Persisting

**Severity:** P0
**Status:** Fixed
**Date Found:** 2026-04-10
**Affected Flow:** Onboarding -> Dashboard access

## Symptoms

1. Completing all 6 onboarding steps, clicking "Go to Dashboard" does nothing
2. Navigating directly to `/dashboard` always redirects back to `/onboarding`
3. All protected routes (`/settings`, `/admin`, etc.) also redirect to `/onboarding`
4. API call `GET /api/onboarding` returns `{"completed": false}` even after completing flow

## Root Cause

**Type mismatch between application code and database schema.**

The `onboarding_progress` table (migration `006_tenant_settings.sql`) defines:
- `completed_steps INTEGER[]` (Postgres native array)
- `skipped_steps INTEGER[]` (Postgres native array)

But `app/api/onboarding/route.ts` writes these fields using `JSON.stringify()`:
```typescript
completed_steps = ${JSON.stringify(completedSteps)},  // produces "[1,2,3]" string
skipped_steps = ${JSON.stringify(skippedSteps)},       // produces "[]" string
```

Postgres rejects inserting a JSON string `"[1,2,3]"` into an `INTEGER[]` column, causing the entire PUT request to fail with a 500 error. The catch block returns a generic `"Failed to update onboarding"` with no user-facing feedback.

## Impact

- **No user can complete onboarding** — the app is effectively unusable past the onboarding screen
- Every session requires re-walking the onboarding flow
- Dashboard, threat detection, settings, billing — all inaccessible

## Fix

Changed array serialization from `JSON.stringify()` to Postgres array literal format `{1,2,3}`:

**File:** `app/api/onboarding/route.ts`

- UPDATE query (line 122-123): Use Postgres array casting
- INSERT query (line 144-145): Use Postgres array casting

## Secondary Issues Found

- P2: No error toast/feedback when completion API fails — user sees button do nothing
- P2: "What's Next?" items on step 6 are plain text, not clickable links
