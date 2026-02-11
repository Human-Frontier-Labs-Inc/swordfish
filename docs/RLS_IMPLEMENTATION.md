# Row Level Security (RLS) Implementation

**Status**: Migration ready, application updates needed
**Priority**: CRITICAL for enterprise deployment
**Migration**: `migrations/008_rls_policies.sql`

---

## What Was Done

### 1. Created RLS Policies (008_rls_policies.sql)

Added proper tenant isolation policies for ALL tenant-scoped tables:

| Table | Policy Type | Notes |
|-------|-------------|-------|
| tenants | Own tenant + MSP access | |
| users | Tenant isolation + MSP | |
| email_verdicts | Tenant isolation + MSP | |
| quarantine | Tenant isolation + MSP | |
| threats | Tenant isolation + MSP | VARCHAR tenant_id |
| feedback | Tenant isolation + MSP | VARCHAR tenant_id |
| policies | Tenant isolation + MSP | |
| tenant_policies | Tenant isolation + MSP | |
| sender_lists | Tenant isolation + MSP | VARCHAR tenant_id |
| integrations | Tenant isolation + MSP | |
| provider_connections | Tenant isolation + MSP | VARCHAR tenant_id |
| integration_states | Tenant isolation | |
| notifications | Tenant isolation + MSP | VARCHAR tenant_id |
| webhooks | Tenant isolation + MSP | VARCHAR tenant_id |
| audit_log | Tenant isolation + MSP | SELECT only, INSERT allowed |
| usage_metrics | Tenant isolation + MSP | |
| scheduled_reports | Tenant isolation + MSP | VARCHAR tenant_id |
| report_jobs | Tenant isolation + MSP | VARCHAR tenant_id |
| export_jobs | Tenant isolation + MSP | VARCHAR tenant_id |
| user_invitations | Tenant isolation + MSP | |
| msp_organizations | MSP org members only | |
| msp_tenant_access | MSP org or own tenant | |
| policy_templates | MSP org or global | |

**Shared tables (no RLS needed):**
- url_analyses (cache, no tenant data)
- file_analyses (cache, no tenant data)

### 2. Enhanced Database Helpers (lib/db/index.ts)

Added context-setting helpers:

```typescript
// Standard tenant isolation
const threats = await withTenant(tenantId, async () => {
  return sql`SELECT * FROM threats WHERE status = 'quarantined'`;
});

// MSP cross-tenant access
const allThreats = await withMspAccess(tenantId, mspOrgId, async () => {
  return sql`SELECT * FROM threats`;
});

// MSP context only (all managed tenants)
const aggregated = await withMspContext(mspOrgId, async () => {
  return sql`SELECT tenant_id, COUNT(*) FROM threats GROUP BY tenant_id`;
});

// System context (bypass RLS - use carefully!)
await withSystemContext(async () => {
  return sql`DELETE FROM expired_sessions`;
});
```

---

## How RLS Works

1. **Before each query**, set the tenant context:
   ```sql
   SELECT set_config('app.current_tenant_id', '<tenant_id>', true);
   ```

2. **For MSP users**, also set:
   ```sql
   SELECT set_config('app.msp_org_id', '<msp_org_id>', true);
   ```

3. **RLS policies automatically filter** results to only show rows the tenant can access.

4. **If context is not set**, queries return empty results (fail-safe).

---

## Migration Path

### Phase 1: Deploy Migration (Immediate)

Run the migration to enable RLS policies:

```bash
# Via Neon console or psql
psql $DATABASE_URL -f migrations/008_rls_policies.sql
```

**Effect**: 
- RLS is now enforced at database level
- Queries without tenant context return empty results
- This is SAFE — data won't leak, but some features may break

### Phase 2: Update High-Traffic Queries (This Week)

Priority files to update:

1. **API Routes** (`app/api/**/*.ts`)
   - These handle user requests and should use `withTenant()`
   - Get tenant ID from Clerk auth context

2. **Webhook Handlers** (`lib/webhooks/handlers/*.ts`)
   - Gmail and Microsoft handlers process incoming emails
   - Tenant context comes from integration lookup

3. **Threat Management** (`lib/threats/*.ts`)
   - Quarantine, release, delete operations
   - Critical for core functionality

### Phase 3: Update Remaining Queries (This Month)

There are ~708 `await sql` calls in the codebase. Most fall into categories:

| Category | Count (approx) | Priority |
|----------|----------------|----------|
| API routes | 150 | HIGH |
| Webhook handlers | 80 | HIGH |
| Detection pipeline | 100 | MEDIUM |
| Reports/Analytics | 120 | MEDIUM |
| Background jobs | 60 | MEDIUM |
| Admin operations | 100 | LOW |
| Utilities | 98 | LOW |

### Pattern for Updates

**Before:**
```typescript
const threats = await sql`
  SELECT * FROM threats 
  WHERE tenant_id = ${tenantId} 
  AND status = 'quarantined'
`;
```

**After:**
```typescript
const threats = await withTenant(tenantId, async () => {
  return sql`
    SELECT * FROM threats 
    WHERE status = 'quarantined'
  `;
  // Note: tenant_id filter is now automatic via RLS
});
```

**For MSP routes:**
```typescript
// In API route, check if user is MSP admin
const { tenantId, mspOrgId, isMspUser } = await getAuthContext(req);

const threats = isMspUser && mspOrgId
  ? await withMspAccess(tenantId, mspOrgId, async () => {
      return sql`SELECT * FROM threats WHERE status = 'quarantined'`;
    })
  : await withTenant(tenantId, async () => {
      return sql`SELECT * FROM threats WHERE status = 'quarantined'`;
    });
```

---

## Testing RLS

### Manual Test

```sql
-- As tenant A, try to see tenant B's data
SELECT set_config('app.current_tenant_id', 'tenant-a-id', true);
SELECT * FROM threats WHERE tenant_id = 'tenant-b-id';
-- Should return 0 rows (RLS blocks it)

-- As MSP admin
SELECT set_config('app.msp_org_id', 'msp-org-id', true);
SELECT set_config('app.current_tenant_id', 'tenant-a-id', true);
SELECT * FROM threats;
-- Should return all threats for MSP-managed tenants
```

### Automated Tests

Add to test suite:

```typescript
describe('RLS Policies', () => {
  it('should not allow tenant A to see tenant B data', async () => {
    await withTenant('tenant-a', async () => {
      const threats = await sql`SELECT * FROM threats WHERE tenant_id = 'tenant-b'`;
      expect(threats.length).toBe(0);
    });
  });

  it('should allow MSP to see managed tenant data', async () => {
    await withMspAccess('tenant-a', 'msp-org', async () => {
      const threats = await sql`SELECT * FROM threats`;
      expect(threats.length).toBeGreaterThan(0);
    });
  });
});
```

---

## Security Notes

1. **RLS is defense-in-depth** — Keep WHERE tenant_id clauses in queries as backup
2. **Don't bypass RLS carelessly** — `withSystemContext()` should only be used for migrations/cron
3. **Audit critical operations** — All data access should be logged
4. **Test cross-tenant leakage** — Include in security test suite

---

## Questions?

This implementation follows PostgreSQL RLS best practices. The key insight is that RLS provides **database-level enforcement** that can't be bypassed by application bugs.

Even if a developer forgets a WHERE clause, the database won't return data from other tenants.
