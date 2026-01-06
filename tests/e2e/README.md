# E2E Test Suite

Comprehensive Playwright end-to-end tests for Swordfish email security platform.

## Quick Start

```bash
# Run all E2E tests
npm run test:e2e

# Run specific test file
npm run test:e2e -- tests/e2e/threat-management.spec.ts

# Run with UI mode
npm run test:e2e -- --ui

# Run headed (see browser)
npm run test:e2e -- --headed
```

## Test Files

| File | Description |
|------|-------------|
| `auth.spec.ts` | Authentication flows and protected routes |
| `threat-management.spec.ts` | MSP admin threat management features |
| `threats.spec.ts` | Threat dashboard and quarantine |
| `full-user-journey.spec.ts` | Complete user journey tests |
| `email-integration.spec.ts` | Real email integration tests |
| `webhooks.spec.ts` | Webhook endpoint tests |
| `integrations.spec.ts` | OAuth and integration flows |
| `onboarding-journey.spec.ts` | New user onboarding |
| `settings-journey.spec.ts` | Settings and preferences |

## Real Email Integration Testing

To run tests with real email accounts, set environment variables:

### Gmail Testing

```bash
# Get a Gmail App Password: https://myaccount.google.com/apppasswords
export TEST_GMAIL_ADDRESS="your-test@gmail.com"
export TEST_GMAIL_APP_PASSWORD="xxxx-xxxx-xxxx-xxxx"

npm run test:e2e -- tests/e2e/email-integration.spec.ts
```

### Microsoft 365 Testing

```bash
export TEST_M365_EMAIL="your-test@yourdomain.com"
export TEST_M365_PASSWORD="your-password"
export TEST_M365_TENANT_ID="your-tenant-id"

npm run test:e2e -- tests/e2e/email-integration.spec.ts
```

### Authenticated User Testing

```bash
# For regular user journey tests
export TEST_USER_EMAIL="user@example.com"
export TEST_USER_PASSWORD="password"

# For MSP admin journey tests
export TEST_ADMIN_EMAIL="admin@example.com"
export TEST_ADMIN_PASSWORD="password"

npm run test:e2e -- tests/e2e/full-user-journey.spec.ts
```

## Test Categories

### 1. Unauthenticated Tests
- Public page accessibility
- Protected route redirects
- API authentication requirements

### 2. API Endpoint Tests
- Request/response validation
- Input sanitization
- Error handling

### 3. Data Integrity Tests
- Score range validation (0-100)
- Valid verdict values
- Valid status values

### 4. Performance Tests
- Response time SLAs
- Concurrent request handling
- Webhook latency

### 5. Integration Tests
- Gmail webhook processing
- Microsoft 365 webhook processing
- OAuth flow endpoints

## Writing New Tests

```typescript
import { test, expect } from '@playwright/test';

test.describe('Feature Name', () => {
  test('should do something', async ({ page, request }) => {
    // Page tests
    await page.goto('/some-route');
    await expect(page.locator('h1')).toBeVisible();

    // API tests
    const response = await request.get('/api/endpoint');
    expect(response.status()).toBe(200);
  });
});
```

## CI/CD Integration

Tests run automatically in GitHub Actions on:
- Pull requests to `main`
- Push to `main`
- Manual workflow dispatch

## Debugging

```bash
# Run with debug logging
DEBUG=pw:api npm run test:e2e

# Generate trace on failure
npm run test:e2e -- --trace on

# Open last trace
npx playwright show-trace test-results/*/trace.zip
```

## Coverage

Current test coverage:
- **127+ passing tests** across all E2E test files
- Authentication flows
- Threat management
- Quarantine operations
- Reports generation
- Webhook processing
- API security
