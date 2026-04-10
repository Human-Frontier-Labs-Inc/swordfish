# 010 - Policy Creation Fails (UUID Type Mismatch)

**Severity:** P0
**Status:** Fixed
**Date Found:** 2026-04-10
**Affected Pages:** Policies > Create Policy

## Symptoms

Clicking "Create Policy" after filling out the form does nothing. No success message, no error feedback, policy doesn't appear. The API returns:

```json
{"error":"invalid input syntax for type uuid: \"user_3CAnmCPc14JuHCcW3DYCiWAYznk\""}
```

## Root Cause

`app/api/policies/route.ts` line 139 passes the Clerk user ID string directly to the `created_by` column, which is a UUID with a foreign key to `users(id)`.

The `users` table has both `id UUID` and `clerk_user_id VARCHAR`. The API needs to look up the user's internal UUID first.

## Fix

Added a lookup query before the INSERT:
```typescript
const userRows = await sql`SELECT id FROM users WHERE clerk_user_id = ${userId} LIMIT 1`;
const userUuid = userRows.length > 0 ? userRows[0].id : null;
```

Then pass `userUuid` instead of `userId` to `created_by`.

## Impact

No user can create any detection policies — core feature completely broken.
