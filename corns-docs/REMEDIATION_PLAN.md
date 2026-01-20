# Swordfish Remediation Plan - TDD Approach

## Executive Summary

This document outlines a phased, Test-Driven Development (TDD) approach to fix critical issues in the Swordfish email security platform. The issues fall into three categories:

1. **Database Schema Mismatches** - Missing columns, type inconsistencies
2. **Tenant Architecture Flaws** - Personal users not in database, UUID/VARCHAR mismatches
3. **Test Coverage Gaps** - No E2E tests, limited API tests

---

## Current Issues Analysis

### Issue 1: Database Schema Mismatches

**Symptoms:**
- `column "status" does not exist` error in policy evaluation
- `relation "list_entries" does not exist` error

**Root Cause:**
Migration `002_policies_and_threats.sql` was never run. The `policies` table is missing:
- `status` VARCHAR(50)
- `name` VARCHAR(255)
- `description` TEXT
- `rules` JSONB
- `scope` JSONB
- `updated_by` UUID

### Issue 2: Tenant ID Type Mismatch

**Symptoms:**
- JOINs with `tenants` table fail for personal users
- Type casting required in queries

**Root Cause:**
Two conflicting patterns:
- **UUID tables**: `email_verdicts`, `quarantine`, `policies`, `integrations`, `users`
- **VARCHAR tables**: `threats`, `feedback`, `notifications`, `webhooks`, `list_entries`

Personal users get `personal_${userId}` (string) which can't be cast to UUID.

### Issue 3: Personal Tenants Not in Database

**Symptoms:**
- FK constraint violations
- Orphaned records
- No tenant-level settings for personal users

**Root Cause:**
`TenantContext` creates virtual tenant objects in memory/localStorage but never inserts into `tenants` table.

---

## Phase 1: Immediate Database Fixes (Day 1)

### 1.1 Run Missing Migrations

**Test First:**
```typescript
// tests/db/schema.test.ts
describe('Database Schema', () => {
  it('should have status column in policies table', async () => {
    const result = await sql`
      SELECT column_name FROM information_schema.columns
      WHERE table_name = 'policies' AND column_name = 'status'
    `;
    expect(result.length).toBe(1);
  });

  it('should have list_entries table', async () => {
    const result = await sql`
      SELECT table_name FROM information_schema.tables
      WHERE table_name = 'list_entries'
    `;
    expect(result.length).toBe(1);
  });
});
```

**Implementation:**
```sql
-- Add missing columns to policies table
ALTER TABLE policies ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'active';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS name VARCHAR(255);
ALTER TABLE policies ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS rules JSONB DEFAULT '[]';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS scope JSONB;
```

### 1.2 Standardize tenant_id to VARCHAR(255)

**Rationale:** VARCHAR is more flexible and already used in newer tables. Converting UUID→VARCHAR is safer than VARCHAR→UUID.

**Test First:**
```typescript
// tests/db/tenant-types.test.ts
describe('Tenant ID Types', () => {
  it('should accept string tenant IDs in all tables', async () => {
    const tenantId = 'personal_test_user_123';

    // Should not throw
    await sql`INSERT INTO integrations (tenant_id, type, status)
              VALUES (${tenantId}, 'gmail', 'connected')
              ON CONFLICT DO NOTHING`;

    const result = await sql`SELECT * FROM integrations WHERE tenant_id = ${tenantId}`;
    expect(result.length).toBeGreaterThanOrEqual(0);
  });
});
```

**Implementation:**
```sql
-- Convert UUID tenant_id columns to VARCHAR(255)
ALTER TABLE email_verdicts ALTER COLUMN tenant_id TYPE VARCHAR(255);
ALTER TABLE quarantine ALTER COLUMN tenant_id TYPE VARCHAR(255);
ALTER TABLE policies ALTER COLUMN tenant_id TYPE VARCHAR(255);
ALTER TABLE integrations ALTER COLUMN tenant_id TYPE VARCHAR(255);
ALTER TABLE audit_log ALTER COLUMN tenant_id TYPE VARCHAR(255);
ALTER TABLE usage_metrics ALTER COLUMN tenant_id TYPE VARCHAR(255);
ALTER TABLE users ALTER COLUMN tenant_id TYPE VARCHAR(255);

-- Drop FK constraints (they reference tenants.id which is UUID)
ALTER TABLE email_verdicts DROP CONSTRAINT IF EXISTS email_verdicts_tenant_id_fkey;
ALTER TABLE quarantine DROP CONSTRAINT IF EXISTS quarantine_tenant_id_fkey;
-- ... etc for all tables
```

---

## Phase 2: Tenant Architecture Standardization (Days 2-3)

### 2.1 Auto-Create Tenant on First Access

**Test First:**
```typescript
// tests/auth/tenant-creation.test.ts
describe('Tenant Creation', () => {
  it('should create tenant record for personal user on first access', async () => {
    const userId = 'user_test123';
    const tenantId = `personal_${userId}`;

    await ensureTenantExists(tenantId, userId);

    const result = await sql`SELECT * FROM tenants WHERE clerk_org_id = ${tenantId}`;
    expect(result.length).toBe(1);
    expect(result[0].name).toBe('Personal Workspace');
  });

  it('should be idempotent - not create duplicate on second call', async () => {
    const userId = 'user_test456';
    const tenantId = `personal_${userId}`;

    await ensureTenantExists(tenantId, userId);
    await ensureTenantExists(tenantId, userId);

    const result = await sql`SELECT * FROM tenants WHERE clerk_org_id = ${tenantId}`;
    expect(result.length).toBe(1);
  });
});
```

**Implementation:**
```typescript
// lib/auth/ensure-tenant.ts
export async function ensureTenantExists(
  tenantId: string,
  userId: string,
  userEmail?: string
): Promise<void> {
  const isPersonal = tenantId.startsWith('personal_');

  await sql`
    INSERT INTO tenants (id, clerk_org_id, name, plan, status)
    VALUES (
      uuid_generate_v4(),
      ${tenantId},
      ${isPersonal ? 'Personal Workspace' : tenantId},
      'starter',
      'active'
    )
    ON CONFLICT (clerk_org_id) DO NOTHING
  `;
}
```

### 2.2 Update TenantContext to Call ensureTenantExists

**Test First:**
```typescript
// tests/auth/tenant-context.test.ts
describe('TenantContext', () => {
  it('should ensure tenant exists when setting current tenant', async () => {
    const mockUserId = 'user_abc123';

    // Simulate what happens when user accesses dashboard
    const { result } = renderHook(() => useTenant());

    await act(async () => {
      await result.current.setCurrentTenant({
        id: `personal_${mockUserId}`,
        name: 'Personal Workspace'
      });
    });

    // Verify tenant was created in DB
    const dbResult = await sql`
      SELECT * FROM tenants WHERE clerk_org_id = ${'personal_' + mockUserId}
    `;
    expect(dbResult.length).toBe(1);
  });
});
```

### 2.3 Update Integration Callbacks

**Test First:**
```typescript
// tests/integrations/gmail-callback.test.ts
describe('Gmail OAuth Callback', () => {
  it('should create tenant if not exists before saving integration', async () => {
    const userId = 'user_newuser123';
    const tenantId = `personal_${userId}`;

    // Mock the callback request
    const request = createMockRequest({
      searchParams: { code: 'mock_code', state: 'valid_state' }
    });

    // Verify tenant doesn't exist yet
    let tenants = await sql`SELECT * FROM tenants WHERE clerk_org_id = ${tenantId}`;
    expect(tenants.length).toBe(0);

    // Process callback
    await handleGmailCallback(request, { userId, tenantId });

    // Verify tenant now exists
    tenants = await sql`SELECT * FROM tenants WHERE clerk_org_id = ${tenantId}`;
    expect(tenants.length).toBe(1);
  });
});
```

---

## Phase 3: Playwright E2E Tests (Days 4-5)

### 3.1 Setup Playwright

```bash
npm install -D @playwright/test
npx playwright install
```

**playwright.config.ts:**
```typescript
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
  },
});
```

### 3.2 Authentication Flow Tests

```typescript
// tests/e2e/auth.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Authentication Flow', () => {
  test('should redirect unauthenticated user to sign-in', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/sign-in/);
  });

  test('should show sign-up page', async ({ page }) => {
    await page.goto('/sign-up');
    await expect(page.locator('text=Sign up')).toBeVisible();
  });

  test('should redirect to dashboard after sign-in', async ({ page }) => {
    // Use Clerk test mode or mock
    await page.goto('/sign-in');
    // ... complete sign-in flow
    await expect(page).toHaveURL('/dashboard');
  });
});
```

### 3.3 Integration Connection Tests

```typescript
// tests/e2e/integrations.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Email Integrations', () => {
  test.beforeEach(async ({ page }) => {
    // Login with test user
    await loginAsTestUser(page);
  });

  test('should display integration cards', async ({ page }) => {
    await page.goto('/dashboard/integrations');

    await expect(page.locator('text=Microsoft 365')).toBeVisible();
    await expect(page.locator('text=Gmail / Google Workspace')).toBeVisible();
    await expect(page.locator('text=SMTP Relay')).toBeVisible();
  });

  test('should show connected status for Gmail', async ({ page }) => {
    await page.goto('/dashboard/integrations');

    // Assuming Gmail is connected
    await expect(page.locator('[data-testid="gmail-status"]')).toContainText('Connected');
  });

  test('should trigger sync when clicking Sync Now', async ({ page }) => {
    await page.goto('/dashboard/integrations');

    const syncButton = page.locator('button:has-text("Sync Now")');
    await syncButton.click();

    // Should show syncing state
    await expect(syncButton).toContainText('Syncing');

    // Should complete (or show error message)
    await expect(page.locator('.sync-result')).toBeVisible({ timeout: 60000 });
  });
});
```

### 3.4 Threat Management Tests

```typescript
// tests/e2e/threats.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Threat Management', () => {
  test('should display threats page', async ({ page }) => {
    await loginAsTestUser(page);
    await page.goto('/dashboard/threats');

    await expect(page.locator('h1')).toContainText('Threats');
  });

  test('should filter threats by status', async ({ page }) => {
    await loginAsTestUser(page);
    await page.goto('/dashboard/threats');

    await page.click('button:has-text("Quarantined")');

    // URL should update
    await expect(page).toHaveURL(/status=quarantined/);
  });

  test('should show empty state when no threats', async ({ page }) => {
    await loginAsTestUser(page);
    await page.goto('/dashboard/threats');

    // May show empty state or threat list
    const content = await page.textContent('body');
    expect(
      content.includes('No threats found') ||
      content.includes('Email')
    ).toBe(true);
  });
});
```

---

## Phase 4: API Integration Tests (Days 6-7)

### 4.1 Sync API Tests

```typescript
// tests/api/sync.test.ts
describe('POST /api/sync', () => {
  it('should return 401 for unauthenticated request', async () => {
    const response = await fetch('/api/sync', { method: 'POST' });
    expect(response.status).toBe(401);
  });

  it('should return sync results for authenticated user', async () => {
    const response = await authenticatedFetch('/api/sync', { method: 'POST' });
    expect(response.status).toBe(200);

    const data = await response.json();
    expect(data).toHaveProperty('totalIntegrations');
    expect(data).toHaveProperty('totalEmailsProcessed');
    expect(data).toHaveProperty('totalThreatsFound');
  });

  it('should handle no connected integrations gracefully', async () => {
    // Test with user that has no integrations
    const response = await authenticatedFetch('/api/sync', {
      method: 'POST',
      userId: 'user_no_integrations'
    });

    const data = await response.json();
    expect(data.totalIntegrations).toBe(0);
  });
});
```

### 4.2 Policy Engine Tests

```typescript
// tests/policies/engine.test.ts
describe('Policy Engine', () => {
  beforeEach(async () => {
    // Setup test policies
    await sql`DELETE FROM policies WHERE tenant_id = 'test_tenant'`;
    await sql`DELETE FROM list_entries WHERE tenant_id = 'test_tenant'`;
  });

  it('should allow email from allowlisted sender', async () => {
    // Add to allowlist
    await sql`
      INSERT INTO list_entries (tenant_id, list_type, entry_type, value, created_by)
      VALUES ('test_tenant', 'allowlist', 'email', 'trusted@example.com', 'test')
    `;

    const email = createTestEmail({ from: 'trusted@example.com' });
    const result = await evaluatePolicies(email, 'test_tenant');

    expect(result.matched).toBe(true);
    expect(result.action).toBe('allow');
  });

  it('should block email from blocklisted domain', async () => {
    await sql`
      INSERT INTO list_entries (tenant_id, list_type, entry_type, value, created_by)
      VALUES ('test_tenant', 'blocklist', 'domain', 'malicious.com', 'test')
    `;

    const email = createTestEmail({ from: 'attacker@malicious.com' });
    const result = await evaluatePolicies(email, 'test_tenant');

    expect(result.matched).toBe(true);
    expect(result.action).toBe('block');
  });

  it('should return no match for neutral email', async () => {
    const email = createTestEmail({ from: 'unknown@neutral.com' });
    const result = await evaluatePolicies(email, 'test_tenant');

    expect(result.matched).toBe(false);
  });
});
```

---

## Phase 5: CI/CD Integration (Day 8)

### 5.1 GitHub Actions Workflow

```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm run test:coverage
      - uses: codecov/codecov-action@v3

  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npx playwright install --with-deps
      - run: npm run test:e2e
      - uses: actions/upload-artifact@v3
        if: failure()
        with:
          name: playwright-report
          path: playwright-report/

  type-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npx tsc --noEmit
```

---

## Implementation Timeline

| Phase | Duration | Focus | Deliverables |
|-------|----------|-------|--------------|
| **1** | Day 1 | Database Fixes | Schema migrations, column additions |
| **2** | Days 2-3 | Tenant Architecture | Auto-create tenants, update context |
| **3** | Days 4-5 | Playwright E2E | Auth, integrations, threats tests |
| **4** | Days 6-7 | API Tests | Sync, policies, quarantine tests |
| **5** | Day 8 | CI/CD | GitHub Actions, coverage reports |

---

## Quick Start: Fix Current Sync Error

To unblock the current sync functionality immediately:

```sql
-- Run this SQL to add missing columns to policies table
ALTER TABLE policies ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'active';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS name VARCHAR(255);
ALTER TABLE policies ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS rules JSONB DEFAULT '[]';
ALTER TABLE policies ADD COLUMN IF NOT EXISTS scope JSONB;

-- Update any existing policies to have status
UPDATE policies SET status = 'active' WHERE status IS NULL;
```

---

## Success Metrics

1. **Sync button works** - No database errors during email sync
2. **Personal users work** - Full feature parity with org users
3. **Test coverage > 70%** - Unit + integration + E2E
4. **Zero type errors** - All tenant_id columns accept strings
5. **CI passes** - All tests green on every PR
