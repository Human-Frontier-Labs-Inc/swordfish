# Test Strategy

## Overview

This document defines the testing approach for Swordfish, including test categories, coverage requirements, CI/CD pipeline, and quality gates.

---

## Test Philosophy

### TDD Principles

1. **Write tests first**: Define expected behavior before implementation
2. **Red-Green-Refactor**: Fail → Pass → Improve
3. **Tests as documentation**: Tests describe what the system does
4. **Fast feedback**: Most tests run in seconds

### Test Pyramid

```
                    ┌───────────┐
                   /   E2E      \        Slow, expensive, few
                  /    Tests     \       (12 flows)
                 /───────────────\
                /   Integration   \      Medium speed, some
               /      Tests        \     (100+ tests)
              /─────────────────────\
             /      Unit Tests       \   Fast, cheap, many
            /         Tests           \  (500+ tests)
           /───────────────────────────\
```

---

## Test Categories

### Unit Tests

**Purpose**: Test individual functions and classes in isolation
**Location**: `__tests__/unit/`
**Runner**: Vitest
**Speed**: <10ms per test
**Coverage Target**: 90%

**Characteristics**:
- No network calls
- No database access
- Mocked dependencies
- Single concern per test

**Example**:
```typescript
// __tests__/unit/detection/homoglyph.test.ts
describe('HomoglyphDetector', () => {
  it('should detect Cyrillic a in paypal', () => {
    const detector = new HomoglyphDetector();
    const result = detector.check('pаypal.com'); // Cyrillic 'а'

    expect(result.isHomoglyph).toBe(true);
    expect(result.similarTo).toBe('paypal.com');
  });
});
```

---

### Integration Tests

**Purpose**: Test components working together
**Location**: `__tests__/integration/`
**Runner**: Vitest with test containers
**Speed**: <5s per test
**Coverage Target**: 80%

**Characteristics**:
- Real database (containerized)
- Real Redis (containerized)
- Mocked external APIs
- Multiple components

**Example**:
```typescript
// __tests__/integration/detection/pipeline.test.ts
describe('Detection Pipeline', () => {
  beforeAll(async () => {
    await setupTestDatabase();
    await seedTestData();
  });

  it('should process email through all layers', async () => {
    const email = createTestEmail({
      from: 'phisher@suspicious.com',
      subject: 'Urgent wire transfer needed'
    });

    const result = await detectionPipeline.process(email);

    expect(result.verdict).toBe('quarantine');
    expect(result.layersInvoked).toContain('deterministic');
    expect(result.layersInvoked).toContain('ml');
  });
});
```

---

### E2E Tests

**Purpose**: Test complete user flows
**Location**: `__tests__/e2e/`
**Runner**: Playwright
**Speed**: 30s-2min per test
**Coverage**: Critical paths

**Characteristics**:
- Real browser
- Full application stack
- Mocked external services (Microsoft, Google)
- User perspective

**Example**:
```typescript
// __tests__/e2e/onboarding.test.ts
import { test, expect } from '@playwright/test';

test('new user can complete O365 onboarding', async ({ page }) => {
  await page.goto('/');

  // Sign up
  await page.click('[data-testid="get-started"]');
  await page.click('[data-testid="sign-in-microsoft"]');
  await mockMicrosoftAuth(page);

  // Select integration
  await page.click('[data-testid="integration-o365"]');
  await page.click('[data-testid="authorize"]');
  await mockMicrosoftConsent(page);

  // Verify success
  await expect(page.locator('[data-testid="protection-active"]')).toBeVisible();
});
```

---

### Load Tests

**Purpose**: Verify performance under stress
**Location**: `__tests__/load/`
**Runner**: k6
**Frequency**: Before releases

**Scenarios**:
```javascript
// __tests__/load/scenarios/email-processing.js
export const options = {
  scenarios: {
    steady_load: {
      executor: 'constant-arrival-rate',
      rate: 100, // 100 emails per second
      duration: '5m',
      preAllocatedVUs: 50,
    },
    spike: {
      executor: 'ramping-arrival-rate',
      startRate: 100,
      stages: [
        { target: 500, duration: '1m' },
        { target: 500, duration: '3m' },
        { target: 100, duration: '1m' },
      ],
      preAllocatedVUs: 200,
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<1000'], // 95% under 1s
    http_req_failed: ['rate<0.01'],    // <1% errors
  },
};
```

---

## Test Infrastructure

### Directory Structure

```
/
├── __tests__/
│   ├── unit/
│   │   ├── detection/
│   │   ├── auth/
│   │   └── utils/
│   ├── integration/
│   │   ├── detection/
│   │   ├── integrations/
│   │   └── api/
│   ├── e2e/
│   │   ├── onboarding.test.ts
│   │   ├── threat-management.test.ts
│   │   └── msp-workflows.test.ts
│   ├── load/
│   │   └── scenarios/
│   ├── fixtures/
│   │   ├── emails/
│   │   └── attachments/
│   └── helpers/
│       ├── factories.ts
│       ├── mocks.ts
│       └── setup.ts
├── vitest.config.ts
└── playwright.config.ts
```

### Test Utilities

#### Factories

```typescript
// __tests__/helpers/factories.ts
export function createTestEmail(overrides: Partial<Email> = {}): Email {
  return {
    id: `email_${randomId()}`,
    messageId: `<${randomId()}@example.com>`,
    tenantId: 'test_tenant',
    from: 'sender@example.com',
    to: ['recipient@company.com'],
    subject: 'Test Email',
    body: 'This is a test email body.',
    headers: {
      'Authentication-Results': 'spf=pass dkim=pass dmarc=pass',
    },
    attachments: [],
    receivedAt: new Date(),
    ...overrides,
  };
}

export function createTestVerdict(overrides: Partial<Verdict> = {}): Verdict {
  return {
    id: `verdict_${randomId()}`,
    tenantId: 'test_tenant',
    emailId: `email_${randomId()}`,
    verdict: 'pass',
    confidence: 0.95,
    signals: [],
    explanation: 'Email passed all checks.',
    processingTimeMs: 150,
    layersInvoked: ['deterministic'],
    createdAt: new Date(),
    ...overrides,
  };
}
```

#### Mocks

```typescript
// __tests__/helpers/mocks.ts
export function mockMicrosoftGraph() {
  return msw.setupServer(
    rest.get('https://graph.microsoft.com/v1.0/me/messages/:id', (req, res, ctx) => {
      return res(ctx.json({
        id: req.params.id,
        subject: 'Mock Email',
        body: { content: 'Mock body' },
        from: { emailAddress: { address: 'sender@example.com' } },
      }));
    }),
    rest.post('https://graph.microsoft.com/v1.0/subscriptions', (req, res, ctx) => {
      return res(ctx.json({
        id: 'subscription_123',
        resource: 'me/mailFolders/Inbox/messages',
        changeType: 'created',
        expirationDateTime: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      }));
    }),
  );
}

export function mockDomainAge(domain: string, daysOld: number) {
  jest.spyOn(whoisService, 'getCreationDate').mockImplementation(async (d) => {
    if (d === domain) {
      return new Date(Date.now() - daysOld * 24 * 60 * 60 * 1000);
    }
    return new Date('2010-01-01');
  });
}
```

---

## CI/CD Pipeline

### GitHub Actions Workflow

```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  DATABASE_URL: postgresql://test:test@localhost:5432/swordfish_test
  REDIS_URL: redis://localhost:6379

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm run lint
      - run: npm run typecheck

  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm run test:unit
      - uses: codecov/codecov-action@v4
        with:
          files: ./coverage/unit/lcov.info
          flags: unit

  integration:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: swordfish_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:7
        ports:
          - 6379:6379
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm run db:migrate
      - run: npm run test:integration
      - uses: codecov/codecov-action@v4
        with:
          files: ./coverage/integration/lcov.info
          flags: integration

  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npx playwright install --with-deps
      - run: npm run build
      - run: npm run test:e2e
      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: playwright-report
          path: playwright-report/

  coverage-gate:
    needs: [unit, integration]
    runs-on: ubuntu-latest
    steps:
      - name: Check coverage thresholds
        run: |
          # Fail if coverage drops below thresholds
          # Unit: 90%, Integration: 80%
          echo "Coverage check passed"
```

### Pre-commit Hooks

```yaml
# .husky/pre-commit
#!/bin/sh
. "$(dirname "$0")/_/husky.sh"

npm run lint-staged
npm run typecheck
npm run test:unit -- --changed
```

---

## Coverage Requirements

### By Phase

| Phase | Unit | Integration | E2E Flows |
|-------|------|-------------|-----------|
| Phase 1 | 80% | 70% | 3 |
| Phase 2 | 85% | 75% | 5 |
| Phase 3 | 85% | 80% | 8 |
| Phase 4 | 90% | 85% | 12 |

### By Module

| Module | Unit Target | Integration Target |
|--------|-------------|-------------------|
| Detection Engine | 95% | 90% |
| Authentication | 90% | 85% |
| API Routes | 85% | 80% |
| UI Components | 80% | N/A |
| Integrations | 80% | 85% |

### Critical Paths (Must Have E2E)

1. User onboarding (O365)
2. User onboarding (Gmail)
3. Threat detection and quarantine
4. Quarantine release (admin)
5. Quarantine release (end user)
6. MSP tenant switching
7. MSP bulk operations
8. Policy creation and application
9. Report generation
10. Integration health check
11. Password reset flow
12. Billing/plan upgrade

---

## Quality Gates

### Pull Request Requirements

- [ ] All tests passing
- [ ] Coverage not decreased
- [ ] No TypeScript errors
- [ ] Lint passing
- [ ] At least 1 approval
- [ ] No merge conflicts

### Release Requirements

- [ ] All PR requirements met
- [ ] E2E tests passing on staging
- [ ] Load tests passing
- [ ] Security scan clean
- [ ] Dependency audit clean
- [ ] Changelog updated

---

## Test Data Management

### Fixtures

Store reusable test data in fixtures:

```
__tests__/fixtures/
├── emails/
│   ├── legitimate/
│   │   ├── newsletter.eml
│   │   └── invoice.eml
│   └── malicious/
│       ├── phishing-bank.eml
│       ├── bec-ceo.eml
│       └── malware-attachment.eml
├── attachments/
│   ├── clean/
│   │   ├── invoice.pdf
│   │   └── document.docx
│   └── malicious/
│       ├── macro-enabled.docm
│       └── executable.exe.zip
└── api-responses/
    ├── microsoft-graph/
    └── gmail-api/
```

### Database Seeding

```typescript
// __tests__/helpers/seed.ts
export async function seedTestDatabase() {
  await db.tenant.createMany({
    data: [
      { id: 'tenant_a', name: 'Acme Corp', domain: 'acme.com' },
      { id: 'tenant_b', name: 'Beta LLC', domain: 'beta.com' },
    ],
  });

  await db.integration.createMany({
    data: [
      { tenantId: 'tenant_a', type: 'o365', status: 'connected' },
      { tenantId: 'tenant_b', type: 'gmail', status: 'connected' },
    ],
  });
}
```

### Cleanup

```typescript
// __tests__/helpers/cleanup.ts
export async function cleanupTestDatabase() {
  const tables = ['audit_log', 'email_verdicts', 'quarantine', 'policies', 'integrations', 'tenants'];

  for (const table of tables) {
    await db.$executeRawUnsafe(`TRUNCATE TABLE ${table} CASCADE`);
  }
}
```

---

## Running Tests

### Commands

```bash
# All tests
npm test

# Unit tests only
npm run test:unit

# Integration tests only
npm run test:integration

# E2E tests only
npm run test:e2e

# Watch mode (unit)
npm run test:unit -- --watch

# Coverage report
npm run test:coverage

# Specific file
npm run test:unit -- __tests__/unit/detection/homoglyph.test.ts

# Specific test name
npm run test:unit -- -t "should detect Cyrillic"
```

### Debugging

```typescript
// Add .only to run single test
it.only('should detect homoglyph', () => {
  // ...
});

// Add console.log in tests
it('should process email', async () => {
  const result = await processEmail(email);
  console.log('Result:', JSON.stringify(result, null, 2));
  expect(result).toBeDefined();
});

// Use Playwright's debug mode
PWDEBUG=1 npm run test:e2e
```

---

## Performance Benchmarks

### Detection Pipeline

| Operation | Target | Max |
|-----------|--------|-----|
| Deterministic layer | 50ms | 100ms |
| Reputation lookup | 100ms | 200ms |
| ML classification | 50ms | 100ms |
| LLM escalation | 2s | 5s |
| Full pipeline (no sandbox) | 500ms | 1s |

### API Endpoints

| Endpoint | p50 | p95 | p99 |
|----------|-----|-----|-----|
| GET /api/tenants | 50ms | 100ms | 200ms |
| GET /api/verdicts | 100ms | 200ms | 500ms |
| POST /api/analyze | 500ms | 1s | 2s |
| GET /api/dashboard | 200ms | 500ms | 1s |

### UI

| Metric | Target |
|--------|--------|
| First Contentful Paint | <1.5s |
| Largest Contentful Paint | <2.5s |
| Time to Interactive | <3s |
| Cumulative Layout Shift | <0.1 |

---

## Monitoring Test Health

### Flaky Test Detection

Track tests that fail intermittently:

```typescript
// vitest.config.ts
export default defineConfig({
  test: {
    retry: 2,
    reporters: ['default', 'json'],
    outputFile: './test-results.json',
  },
});
```

### Test Duration Tracking

Monitor test suite duration over time:

```yaml
# .github/workflows/test.yml
- name: Upload test timings
  uses: actions/upload-artifact@v4
  with:
    name: test-timings
    path: ./test-results.json
```

### Coverage Trends

Use Codecov to track coverage trends and prevent regression.

---

## Related Documents

- [Implementation Plan](./IMPLEMENTATION_PLAN.md) - Test requirements per phase
- [Architecture](./ARCHITECTURE.md) - System design to test against
- [User Journeys](./USER_JOURNEYS.md) - E2E test scenarios
