# 013 - Systemic UUID Cast Failures Across API Routes

**Severity:** P0
**Status:** Partially fixed (user/me), systemic fix needed
**Date Found:** 2026-04-10

## Symptoms

Multiple API routes use `tenant_id::uuid = t.id` to join against the tenants table. When `tenant_id` contains a non-UUID string (e.g., Clerk org/user IDs), Postgres throws:

```
operator does not exist: uuid = character varying
```

This crashes the `/api/user/me` route (blocking Gmail OAuth callback) and potentially 14+ other routes.

## Affected Files (14+ locations)

- `app/api/user/me/route.ts` — **FIXED** (added UUID format regex guard)
- `app/api/admin/users/[id]/reactivate/route.ts`
- `app/api/admin/users/[id]/suspend/route.ts`
- `app/api/admin/audit/route.ts`
- `app/api/admin/stats/route.ts`
- `app/api/webhooks/clerk/route.ts`
- `app/api/invitation/details/route.ts`
- `app/api/invitation/accept/route.ts`
- `app/api/analytics/overview/route.ts` (6 occurrences)

## Root Cause

The codebase has two tenant ID schemes:
1. **tenants table:** `id UUID` (internal)
2. **Everything else:** `tenant_id VARCHAR` storing either UUIDs or Clerk strings like `personal_user_xxx`

The `::uuid` cast assumes the VARCHAR always contains a valid UUID, which breaks for Clerk-format strings.

## Recommended Systemic Fix

Create a helper SQL function or use the pattern from admin routes:
```sql
-- Safe: regex check before cast
WHERE tenant_id ~ '^[0-9a-f]{8}-...' AND tenant_id::uuid = t.id
-- Or: text comparison with OR fallback
WHERE tenant_id::text = t.clerk_org_id OR tenant_id::uuid = t.id
```

Apply consistently across all affected files.
