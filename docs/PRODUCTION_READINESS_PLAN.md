# Swordfish Production Readiness Plan
## Vertical Slice Development with TDD

**Document Version:** 1.0
**Created:** January 2025
**Target:** 100% Production Ready
**Methodology:** Vertical Slice Development + Test-Driven Development (TDD)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Development Philosophy](#development-philosophy)
3. [Phase Overview](#phase-overview)
4. [Phase 1: Foundation & Core Fix](#phase-1-foundation--core-fix)
5. [Phase 2: Security Hardening](#phase-2-security-hardening)
6. [Phase 3: Threat Intelligence](#phase-3-threat-intelligence)
7. [Phase 4: Observability & Reliability](#phase-4-observability--reliability)
8. [Phase 5: Scale & Performance](#phase-5-scale--performance)
9. [Phase 6: Production Polish](#phase-6-production-polish)
10. [Success Metrics](#success-metrics)
11. [Risk Mitigation](#risk-mitigation)

---

## Executive Summary

### Current State
- **Production Readiness Score:** 38/100
- **Core Issue:** Detection works, but remediation doesn't execute
- **Critical Gaps:** 30 identified issues across 7 categories

### Target State
- **Production Readiness Score:** 100/100
- **All Features:** Fully functional with automated remediation
- **Test Coverage:** >90% on critical paths
- **Zero Critical/High vulnerabilities**

### Timeline
- **Phase 1:** 2 weeks (Foundation)
- **Phase 2:** 1.5 weeks (Security)
- **Phase 3:** 1.5 weeks (Threat Intel)
- **Phase 4:** 2 weeks (Observability)
- **Phase 5:** 1.5 weeks (Scale)
- **Phase 6:** 1.5 weeks (Polish)
- **Total:** ~10 weeks to production ready

---

## Development Philosophy

### Vertical Slice Development

Each feature is built as a complete vertical slice:
```
┌─────────────────────────────────────────┐
│              UI/API Layer               │
├─────────────────────────────────────────┤
│           Business Logic                │
├─────────────────────────────────────────┤
│            Data Access                  │
├─────────────────────────────────────────┤
│         External Services               │
└─────────────────────────────────────────┘
         ↑ Complete Slice ↑
```

**Principles:**
1. Build complete features, not layers
2. Each slice is independently deployable
3. Each slice has full test coverage
4. Each slice delivers user value

### TDD Workflow (Red-Green-Refactor)

```
┌─────────────────────────────────────────┐
│  1. RED: Write failing test first       │
│     - Define expected behavior          │
│     - Test must fail initially          │
├─────────────────────────────────────────┤
│  2. GREEN: Write minimal code to pass   │
│     - Only enough to make test pass     │
│     - No premature optimization         │
├─────────────────────────────────────────┤
│  3. REFACTOR: Clean up                  │
│     - Improve code quality              │
│     - Tests must still pass             │
└─────────────────────────────────────────┘
```

### Definition of Done (DoD)

A slice is complete when:
- [ ] All acceptance tests pass (written first)
- [ ] Unit test coverage >90%
- [ ] Integration tests pass
- [ ] No TypeScript errors
- [ ] No ESLint warnings
- [ ] Code reviewed
- [ ] Documentation updated
- [ ] Deployed to staging
- [ ] Manual smoke test passed

---

## Phase Overview

```
┌────────────────────────────────────────────────────────────────────┐
│ PHASE 1: Foundation & Core Fix (2 weeks)                          │
│ Score: 38 → 55                                                     │
│ • Email remediation (Gmail + O365)                                 │
│ • Database schema fixes                                            │
│ • Webhook/sync pipeline fixes                                      │
│ • CI/CD setup                                                      │
├────────────────────────────────────────────────────────────────────┤
│ PHASE 2: Security Hardening (1.5 weeks)                           │
│ Score: 55 → 70                                                     │
│ • OAuth token encryption                                           │
│ • Tenant isolation enforcement                                     │
│ • Input validation complete                                        │
│ • Webhook signature verification                                   │
├────────────────────────────────────────────────────────────────────┤
│ PHASE 3: Threat Intelligence (1.5 weeks)                          │
│ Score: 70 → 80                                                     │
│ • Real IP reputation (DNSBL)                                       │
│ • VirusTotal integration                                           │
│ • URLScan integration                                              │
│ • Sandbox analysis                                                 │
├────────────────────────────────────────────────────────────────────┤
│ PHASE 4: Observability & Reliability (2 weeks)                    │
│ Score: 80 → 88                                                     │
│ • Structured logging                                               │
│ • Distributed tracing                                              │
│ • Alert system wiring                                              │
│ • Circuit breakers & retries                                       │
├────────────────────────────────────────────────────────────────────┤
│ PHASE 5: Scale & Performance (1.5 weeks)                          │
│ Score: 88 → 95                                                     │
│ • Redis caching                                                    │
│ • Job queue (Kafka)                                                │
│ • Performance optimization                                         │
│ • Load testing                                                     │
├────────────────────────────────────────────────────────────────────┤
│ PHASE 6: Production Polish (1.5 weeks)                            │
│ Score: 95 → 100                                                    │
│ • E2E test suite complete                                          │
│ • Security audit & pen test                                        │
│ • Documentation complete                                           │
│ • Disaster recovery                                                │
└────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Foundation & Core Fix

**Duration:** 2 weeks
**Goal:** Make the core email security feature actually work
**Score Impact:** 38 → 55 (+17 points)

### Slice 1.1: Gmail Email Remediation

**Business Value:** Automatically quarantine/delete malicious emails in Gmail

**TDD Test Suite (Write First):**

```typescript
// tests/remediation/gmail-actions.test.ts

describe('Gmail Email Remediation', () => {
  describe('quarantineGmailEmail', () => {
    it('should create quarantine label if not exists', async () => {
      // RED: Test that label creation is called when label doesn't exist
    });

    it('should move email to quarantine label', async () => {
      // RED: Test that gmail.modify is called with correct label IDs
    });

    it('should remove INBOX label when quarantining', async () => {
      // RED: Test INBOX removal
    });

    it('should handle rate limiting with retry', async () => {
      // RED: Test 429 response triggers retry with backoff
    });

    it('should refresh token on 401 error', async () => {
      // RED: Test token refresh flow
    });

    it('should update threat status to quarantined', async () => {
      // RED: Test database update after successful quarantine
    });

    it('should create audit log entry', async () => {
      // RED: Test audit logging
    });
  });

  describe('releaseGmailEmail', () => {
    it('should add INBOX label back', async () => {});
    it('should remove quarantine label', async () => {});
    it('should update threat status to released', async () => {});
    it('should log release action', async () => {});
  });

  describe('deleteGmailEmail', () => {
    it('should move email to trash', async () => {});
    it('should permanently delete if configured', async () => {});
    it('should update threat status to deleted', async () => {});
  });

  describe('autoRemediate integration', () => {
    it('should quarantine email when verdict is quarantine', async () => {});
    it('should delete email when verdict is block', async () => {});
    it('should handle Nango connection errors gracefully', async () => {});
    it('should write to threats table after remediation', async () => {});
  });
});
```

**Implementation Files:**
- `lib/integrations/gmail/remediation.ts` (new)
- `lib/workers/remediation.ts` (update autoRemediate)
- `lib/integrations/gmail.ts` (add modify/trash functions)

**Acceptance Criteria:**
- [ ] Test email sent → detected as threat → automatically moved to quarantine label
- [ ] Quarantine label created if doesn't exist
- [ ] Threat appears in Threats page with status "quarantined"
- [ ] Release action moves email back to inbox
- [ ] Delete action moves email to trash
- [ ] All actions logged in audit trail

**DoD Checklist:**
- [ ] 15+ unit tests passing
- [ ] 5+ integration tests passing
- [ ] Manual test with real Gmail account
- [ ] Error handling for all failure modes

---

### Slice 1.2: O365 Email Remediation

**Business Value:** Automatically quarantine/delete malicious emails in Office 365

**TDD Test Suite (Write First):**

```typescript
// tests/remediation/o365-actions.test.ts

describe('O365 Email Remediation', () => {
  describe('quarantineO365Email', () => {
    it('should create quarantine folder if not exists', async () => {});
    it('should move email to quarantine folder', async () => {});
    it('should use Graph API move endpoint', async () => {});
    it('should handle rate limiting (429)', async () => {});
    it('should handle token expiration', async () => {});
  });

  describe('releaseO365Email', () => {
    it('should move email back to inbox', async () => {});
    it('should handle missing email gracefully', async () => {});
  });

  describe('deleteO365Email', () => {
    it('should move to deletedItems folder', async () => {});
    it('should support permanent delete option', async () => {});
  });

  describe('O365 folder management', () => {
    it('should get or create quarantine folder', async () => {});
    it('should cache folder ID', async () => {});
  });
});
```

**Implementation Files:**
- `lib/integrations/o365/remediation.ts` (new)
- `lib/integrations/o365.ts` (add move/delete functions)

**Acceptance Criteria:**
- [ ] Test email in O365 → detected → moved to Quarantine folder
- [ ] Quarantine folder auto-created
- [ ] Release moves back to Inbox
- [ ] Delete moves to Deleted Items

---

### Slice 1.3: Database Schema Consolidation

**Business Value:** Data integrity, prevent orphan records, enable proper tenant isolation

**TDD Test Suite (Write First):**

```typescript
// tests/db/schema-integrity.test.ts

describe('Database Schema Integrity', () => {
  describe('tenant_id consistency', () => {
    it('should use VARCHAR(255) for tenant_id in all tables', async () => {
      // Query information_schema to verify column types
    });

    it('should have foreign key from threats to tenants', async () => {});
    it('should have foreign key from feedback to tenants', async () => {});
    it('should have foreign key from notifications to tenants', async () => {});
    it('should have foreign key from webhooks to tenants', async () => {});
  });

  describe('cascade delete behavior', () => {
    it('should delete threats when tenant is deleted', async () => {});
    it('should delete feedback when tenant is deleted', async () => {});
    it('should delete notifications when tenant is deleted', async () => {});
  });

  describe('orphan prevention', () => {
    it('should not allow threat without valid tenant', async () => {});
    it('should not have any orphaned threats', async () => {});
    it('should not have any orphaned feedback', async () => {});
  });

  describe('required indexes', () => {
    it('should have index on threats(tenant_id, status)', async () => {});
    it('should have index on threats(tenant_id, created_at)', async () => {});
    it('should have GIN index on threats(signals)', async () => {});
  });
});
```

**Implementation Files:**
- `lib/db/migrations/009_consolidate_tenant_id.sql` (new)
- `lib/db/migrations/010_add_foreign_keys.sql` (new)
- `lib/db/migrations/011_add_indexes.sql` (new)

**Acceptance Criteria:**
- [ ] All tables use VARCHAR(255) for tenant_id
- [ ] All tenant-scoped tables have FK to tenants
- [ ] Cascade delete works correctly
- [ ] No orphan records exist
- [ ] Required indexes created

---

### Slice 1.4: Email Sync Pipeline Fix

**Business Value:** Ensure all incoming emails are processed

**TDD Test Suite (Write First):**

```typescript
// tests/sync/email-sync-pipeline.test.ts

describe('Email Sync Pipeline', () => {
  describe('Gmail sync', () => {
    it('should fetch new emails via History API', async () => {});
    it('should fall back to full sync when history expired', async () => {});
    it('should process each email through detection pipeline', async () => {});
    it('should call autoRemediate for threat verdicts', async () => {});
    it('should handle sync timeout gracefully', async () => {});
  });

  describe('Gmail webhook', () => {
    it('should validate Pub/Sub JWT token', async () => {});
    it('should trigger sync on new email notification', async () => {});
    it('should deduplicate notifications', async () => {});
  });

  describe('Watch registration', () => {
    it('should register Gmail watch on integration connect', async () => {});
    it('should renew watch before expiration', async () => {});
    it('should store history ID after watch', async () => {});
  });

  describe('Nango connection sync', () => {
    it('should sync nango_connection_id to integrations table', async () => {});
    it('should update connection status on sync', async () => {});
  });
});
```

**Implementation Files:**
- `lib/integrations/gmail/watch.ts` (update)
- `lib/workers/email-sync.ts` (update)
- `app/api/webhooks/gmail/route.ts` (update)
- `app/api/cron/renew-subscriptions/route.ts` (update)

**Acceptance Criteria:**
- [ ] New email arrives → webhook received → sync triggered → email processed
- [ ] Watch auto-renewed before 7-day expiration
- [ ] History ID tracked correctly
- [ ] Nango connection ID always populated

---

### Slice 1.5: CI/CD Pipeline

**Business Value:** Automated testing on every commit

**TDD Test Suite (Write First):**

```yaml
# .github/workflows/test.yml (the tests ARE the acceptance criteria)

name: Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Type check
        run: npm run typecheck

      - name: Lint
        run: npm run lint

      - name: Unit tests
        run: npm run test -- --coverage

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          fail_ci_if_error: true

  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Playwright
        run: npx playwright install --with-deps
      - name: Run E2E tests
        run: npm run test:e2e
```

**Implementation Files:**
- `.github/workflows/test.yml` (new)
- `.github/workflows/deploy.yml` (new)
- `codecov.yml` (new)

**Acceptance Criteria:**
- [ ] Tests run on every push
- [ ] Tests run on every PR
- [ ] Coverage report generated
- [ ] Build fails if tests fail
- [ ] Coverage threshold: 70% minimum

---

### Phase 1 Completion Checklist

| Slice | Tests Written | Tests Passing | Deployed | Score Impact |
|-------|--------------|---------------|----------|--------------|
| 1.1 Gmail Remediation | [ ] | [ ] | [ ] | +5 |
| 1.2 O365 Remediation | [ ] | [ ] | [ ] | +5 |
| 1.3 Database Schema | [ ] | [ ] | [ ] | +3 |
| 1.4 Sync Pipeline | [ ] | [ ] | [ ] | +2 |
| 1.5 CI/CD | [ ] | [ ] | [ ] | +2 |
| **Total** | | | | **+17** |

**Phase 1 Exit Criteria:**
- [ ] Send test email → auto-quarantined in Gmail/O365
- [ ] Threat appears in dashboard with correct status
- [ ] Release/delete actions work from UI
- [ ] CI pipeline runs on all PRs
- [ ] No critical database integrity issues

---

## Phase 2: Security Hardening

**Duration:** 1.5 weeks
**Goal:** Close all security vulnerabilities
**Score Impact:** 55 → 70 (+15 points)

### Slice 2.1: OAuth Token Encryption

**Business Value:** Protect customer email access if database is compromised

**TDD Test Suite (Write First):**

```typescript
// tests/security/token-encryption.test.ts

describe('OAuth Token Encryption', () => {
  describe('encrypt/decrypt', () => {
    it('should encrypt token with AES-256-GCM', async () => {
      const token = 'ya29.a0AfH6SMB...';
      const encrypted = encrypt(token);
      expect(encrypted).not.toBe(token);
      expect(encrypted).toMatch(/^[a-f0-9]+:[a-f0-9]+:[a-f0-9]+$/); // iv:tag:ciphertext
    });

    it('should decrypt token correctly', async () => {
      const token = 'ya29.a0AfH6SMB...';
      const encrypted = encrypt(token);
      const decrypted = decrypt(encrypted);
      expect(decrypted).toBe(token);
    });

    it('should use unique IV for each encryption', async () => {
      const token = 'same_token';
      const enc1 = encrypt(token);
      const enc2 = encrypt(token);
      expect(enc1).not.toBe(enc2); // Different IVs
    });

    it('should fail decryption with wrong key', async () => {
      // Test tamper detection
    });

    it('should fail decryption with corrupted data', async () => {
      // Test integrity verification
    });
  });

  describe('token storage', () => {
    it('should store encrypted tokens in integrations table', async () => {});
    it('should decrypt tokens when retrieved via Nango', async () => {});
    it('should migrate existing plaintext tokens', async () => {});
  });
});
```

**Implementation Files:**
- `lib/security/encryption.ts` (new)
- `lib/db/migrations/012_encrypt_tokens.sql` (new)
- `lib/integrations/nango.ts` (update)

**Acceptance Criteria:**
- [ ] All OAuth tokens encrypted at rest
- [ ] Encryption key in environment variable only
- [ ] Key rotation support
- [ ] Migration encrypts existing tokens

---

### Slice 2.2: Tenant Isolation Enforcement

**Business Value:** Prevent data leakage between customers

**TDD Test Suite (Write First):**

```typescript
// tests/security/tenant-isolation.test.ts

describe('Tenant Isolation', () => {
  describe('API endpoint isolation', () => {
    it('should reject request for another tenant\'s threat', async () => {
      const tenantA = 'personal_user_a';
      const tenantB = 'personal_user_b';
      const threatId = await createThreat(tenantA);

      // Attempt access from tenant B
      const response = await request(app)
        .get(`/api/threats/${threatId}`)
        .set('Authorization', `Bearer ${tenantBToken}`);

      expect(response.status).toBe(404); // Not 403, to avoid info leak
    });

    it('should not return other tenant\'s threats in list', async () => {});
    it('should not allow modifying other tenant\'s policies', async () => {});
    it('should not expose other tenant\'s integrations', async () => {});
  });

  describe('database RLS', () => {
    it('should enforce RLS on threats table', async () => {});
    it('should enforce RLS on email_verdicts table', async () => {});
    it('should set tenant context before queries', async () => {});
  });

  describe('admin cross-tenant access', () => {
    it('should allow MSP admin to access managed tenants', async () => {});
    it('should log all cross-tenant access', async () => {});
    it('should require explicit tenant selection', async () => {});
  });
});
```

**Implementation Files:**
- `lib/db/migrations/013_enable_rls.sql` (new)
- `lib/middleware/tenant-context.ts` (new)
- Update all API routes with tenant verification

**Acceptance Criteria:**
- [ ] Cannot access another tenant's data via API
- [ ] Cannot enumerate tenant IDs
- [ ] RLS enabled on all tenant-scoped tables
- [ ] Cross-tenant access logged

---

### Slice 2.3: Input Validation Complete

**Business Value:** Prevent injection attacks, ensure data quality

**TDD Test Suite (Write First):**

```typescript
// tests/security/input-validation.test.ts

describe('Input Validation', () => {
  describe('API endpoint validation', () => {
    it('should reject invalid email format in policies', async () => {});
    it('should reject XSS in webhook URLs', async () => {});
    it('should reject SQL injection in search', async () => {});
    it('should enforce max length on all string fields', async () => {});
    it('should validate JSON schema on POST bodies', async () => {});
  });

  describe('webhook payload validation', () => {
    it('should reject malformed Gmail webhook', async () => {});
    it('should reject malformed O365 webhook', async () => {});
    it('should validate required fields', async () => {});
  });

  describe('sanitization', () => {
    it('should sanitize HTML in email display', async () => {});
    it('should sanitize user-provided names', async () => {});
    it('should strip dangerous protocols from URLs', async () => {});
  });
});
```

**Implementation Files:**
- `lib/api/validation.ts` (new - Zod schemas)
- Update all POST/PUT routes with validation middleware

**Acceptance Criteria:**
- [ ] All API endpoints validate input
- [ ] Zod schemas for all request bodies
- [ ] Clear error messages for validation failures
- [ ] No unvalidated user input reaches database

---

### Slice 2.4: Webhook Security

**Business Value:** Prevent unauthorized webhook calls

**TDD Test Suite (Write First):**

```typescript
// tests/security/webhook-security.test.ts

describe('Webhook Security', () => {
  describe('Gmail Pub/Sub validation', () => {
    it('should verify JWT signature from Google', async () => {});
    it('should reject expired tokens', async () => {});
    it('should reject tokens with wrong audience', async () => {});
    it('should reject tokens from non-Google issuers', async () => {});
  });

  describe('O365 webhook validation', () => {
    it('should verify clientState matches', async () => {});
    it('should use timing-safe comparison', async () => {});
    it('should reject missing clientState', async () => {});
  });

  describe('generic webhook validation', () => {
    it('should verify HMAC signature', async () => {});
    it('should reject replay attacks (timestamp)', async () => {});
  });

  describe('development mode', () => {
    it('should NOT allow unsigned webhooks in production', async () => {});
  });
});
```

**Implementation Files:**
- `lib/webhooks/validation.ts` (update)
- `app/api/webhooks/gmail/route.ts` (update)

**Acceptance Criteria:**
- [ ] Full JWT verification for Google webhooks
- [ ] No development-mode bypass in production
- [ ] Replay attack prevention
- [ ] All webhook failures logged

---

### Phase 2 Completion Checklist

| Slice | Tests Written | Tests Passing | Deployed | Score Impact |
|-------|--------------|---------------|----------|--------------|
| 2.1 Token Encryption | [ ] | [ ] | [ ] | +5 |
| 2.2 Tenant Isolation | [ ] | [ ] | [ ] | +5 |
| 2.3 Input Validation | [ ] | [ ] | [ ] | +3 |
| 2.4 Webhook Security | [ ] | [ ] | [ ] | +2 |
| **Total** | | | | **+15** |

**Phase 2 Exit Criteria:**
- [ ] Security scan shows 0 critical/high vulnerabilities
- [ ] Penetration test of tenant isolation passes
- [ ] All tokens encrypted in database
- [ ] Webhook replay attack blocked

---

## Phase 3: Threat Intelligence

**Duration:** 1.5 weeks
**Goal:** Complete threat detection capabilities
**Score Impact:** 70 → 80 (+10 points)

### Slice 3.1: Real IP Reputation (DNSBL)

**TDD Test Suite (Write First):**

```typescript
// tests/threat-intel/ip-reputation.test.ts

describe('IP Reputation via DNSBL', () => {
  describe('DNS lookup', () => {
    it('should query Spamhaus ZEN', async () => {});
    it('should query Barracuda RBL', async () => {});
    it('should query SORBS', async () => {});
    it('should handle DNS timeout', async () => {});
    it('should cache results', async () => {});
  });

  describe('scoring', () => {
    it('should return high score for listed IP', async () => {});
    it('should return low score for clean IP', async () => {});
    it('should aggregate multiple DNSBL results', async () => {});
  });
});
```

### Slice 3.2: VirusTotal Integration

**TDD Test Suite (Write First):**

```typescript
// tests/threat-intel/virustotal.test.ts

describe('VirusTotal Integration', () => {
  describe('URL scanning', () => {
    it('should submit URL for analysis', async () => {});
    it('should poll for results', async () => {});
    it('should parse detection results', async () => {});
    it('should respect rate limits', async () => {});
  });

  describe('file hash lookup', () => {
    it('should check file hash reputation', async () => {});
    it('should return threat categories', async () => {});
  });

  describe('error handling', () => {
    it('should handle API key invalid', async () => {});
    it('should handle rate limit exceeded', async () => {});
    it('should fall back to other services', async () => {});
  });
});
```

### Slice 3.3: URLScan Integration

```typescript
// tests/threat-intel/urlscan.test.ts

describe('URLScan Integration', () => {
  describe('URL submission', () => {
    it('should submit URL for scanning', async () => {});
    it('should retrieve scan results', async () => {});
    it('should extract malicious indicators', async () => {});
  });

  describe('screenshot analysis', () => {
    it('should detect phishing page indicators', async () => {});
  });
});
```

### Slice 3.4: Basic Sandbox Analysis

```typescript
// tests/threat-intel/sandbox.test.ts

describe('Sandbox Analysis', () => {
  describe('static analysis', () => {
    it('should detect dangerous file extensions', async () => {});
    it('should detect macro-enabled documents', async () => {});
    it('should extract file metadata', async () => {});
    it('should calculate file hashes', async () => {});
  });

  describe('VirusTotal file submission', () => {
    it('should submit suspicious files', async () => {});
    it('should wait for analysis completion', async () => {});
  });
});
```

### Phase 3 Completion Checklist

| Slice | Tests Written | Tests Passing | Deployed | Score Impact |
|-------|--------------|---------------|----------|--------------|
| 3.1 IP Reputation | [ ] | [ ] | [ ] | +3 |
| 3.2 VirusTotal | [ ] | [ ] | [ ] | +3 |
| 3.3 URLScan | [ ] | [ ] | [ ] | +2 |
| 3.4 Sandbox | [ ] | [ ] | [ ] | +2 |
| **Total** | | | | **+10** |

---

## Phase 4: Observability & Reliability

**Duration:** 2 weeks
**Goal:** Production-grade monitoring and reliability
**Score Impact:** 80 → 88 (+8 points)

### Slice 4.1: Structured Logging

**TDD Test Suite (Write First):**

```typescript
// tests/observability/logging.test.ts

describe('Structured Logging', () => {
  describe('log format', () => {
    it('should output JSON format', async () => {});
    it('should include timestamp in ISO format', async () => {});
    it('should include log level', async () => {});
    it('should include correlation ID', async () => {});
    it('should include tenant ID when available', async () => {});
  });

  describe('PII handling', () => {
    it('should redact email addresses', async () => {});
    it('should redact API keys', async () => {});
    it('should redact OAuth tokens', async () => {});
  });

  describe('log levels', () => {
    it('should respect LOG_LEVEL environment variable', async () => {});
    it('should not log debug in production', async () => {});
  });
});
```

**Implementation Files:**
- `lib/logging/logger.ts` (new - using Pino)
- `lib/logging/redaction.ts` (new)
- Replace all console.* calls

### Slice 4.2: Distributed Tracing

```typescript
// tests/observability/tracing.test.ts

describe('Distributed Tracing', () => {
  describe('correlation ID', () => {
    it('should generate correlation ID for each request', async () => {});
    it('should propagate correlation ID through async calls', async () => {});
    it('should include correlation ID in all logs', async () => {});
    it('should return correlation ID in response headers', async () => {});
  });

  describe('span tracking', () => {
    it('should create span for API request', async () => {});
    it('should create child span for database queries', async () => {});
    it('should create child span for external API calls', async () => {});
    it('should record span duration', async () => {});
  });
});
```

### Slice 4.3: Alert System Wiring

```typescript
// tests/observability/alerts.test.ts

describe('Alert System', () => {
  describe('alert triggers', () => {
    it('should trigger on high threat volume', async () => {});
    it('should trigger on critical threat', async () => {});
    it('should trigger on integration error', async () => {});
    it('should respect cooldown period', async () => {});
  });

  describe('alert delivery', () => {
    it('should send Slack notification', async () => {});
    it('should send email alert', async () => {});
    it('should call webhook', async () => {});
  });
});
```

### Slice 4.4: Circuit Breakers & Retries

```typescript
// tests/reliability/resilience.test.ts

describe('Resilience Patterns', () => {
  describe('circuit breaker', () => {
    it('should open after threshold failures', async () => {});
    it('should reject requests when open', async () => {});
    it('should half-open after timeout', async () => {});
    it('should close after successful request', async () => {});
  });

  describe('retry with backoff', () => {
    it('should retry on transient failure', async () => {});
    it('should use exponential backoff', async () => {});
    it('should add jitter to prevent thundering herd', async () => {});
    it('should give up after max retries', async () => {});
  });

  describe('timeout handling', () => {
    it('should timeout slow external calls', async () => {});
    it('should abort in-flight requests on timeout', async () => {});
  });
});
```

### Phase 4 Completion Checklist

| Slice | Tests Written | Tests Passing | Deployed | Score Impact |
|-------|--------------|---------------|----------|--------------|
| 4.1 Structured Logging | [ ] | [ ] | [ ] | +2 |
| 4.2 Distributed Tracing | [ ] | [ ] | [ ] | +2 |
| 4.3 Alert Wiring | [ ] | [ ] | [ ] | +2 |
| 4.4 Circuit Breakers | [ ] | [ ] | [ ] | +2 |
| **Total** | | | | **+8** |

---

## Phase 5: Scale & Performance

**Duration:** 1.5 weeks
**Goal:** Handle enterprise-scale email volumes
**Score Impact:** 88 → 95 (+7 points)

### Slice 5.1: Redis Caching

```typescript
// tests/infrastructure/redis-cache.test.ts

describe('Redis Caching', () => {
  describe('rate limiting', () => {
    it('should persist rate limits across instances', async () => {});
    it('should handle Redis connection failure gracefully', async () => {});
  });

  describe('threat feed cache', () => {
    it('should cache threat feed lookups', async () => {});
    it('should invalidate cache on feed refresh', async () => {});
  });

  describe('session cache', () => {
    it('should cache API key lookups', async () => {});
    it('should cache tenant settings', async () => {});
  });
});
```

### Slice 5.2: Job Queue (Kafka)

```typescript
// tests/infrastructure/job-queue.test.ts

describe('Job Queue', () => {
  describe('email sync jobs', () => {
    it('should enqueue sync job on webhook', async () => {});
    it('should process jobs in order', async () => {});
    it('should retry failed jobs', async () => {});
    it('should move to DLQ after max retries', async () => {});
  });

  describe('remediation jobs', () => {
    it('should enqueue remediation async', async () => {});
    it('should track job status', async () => {});
  });
});
```

### Slice 5.3: Performance Optimization

```typescript
// tests/performance/optimization.test.ts

describe('Performance', () => {
  describe('database queries', () => {
    it('should use indexes for common queries', async () => {});
    it('should batch inserts for email verdicts', async () => {});
    it('should paginate large result sets', async () => {});
  });

  describe('API response time', () => {
    it('should respond within 200ms p95', async () => {});
    it('should respond within 500ms p99', async () => {});
  });
});
```

### Slice 5.4: Load Testing

```typescript
// tests/load/stress.test.ts (using k6 or artillery)

describe('Load Testing', () => {
  it('should handle 100 concurrent email syncs', async () => {});
  it('should handle 1000 API requests/minute', async () => {});
  it('should maintain <500ms response under load', async () => {});
  it('should not drop webhooks under load', async () => {});
});
```

### Phase 5 Completion Checklist

| Slice | Tests Written | Tests Passing | Deployed | Score Impact |
|-------|--------------|---------------|----------|--------------|
| 5.1 Redis Caching | [ ] | [ ] | [ ] | +2 |
| 5.2 Job Queue | [ ] | [ ] | [ ] | +2 |
| 5.3 Performance | [ ] | [ ] | [ ] | +2 |
| 5.4 Load Testing | [ ] | [ ] | [ ] | +1 |
| **Total** | | | | **+7** |

---

## Phase 6: Production Polish

**Duration:** 1.5 weeks
**Goal:** Production-grade quality and documentation
**Score Impact:** 95 → 100 (+5 points)

### Slice 6.1: Comprehensive E2E Tests

```typescript
// tests/e2e/complete-flows.spec.ts

describe('Complete User Flows', () => {
  describe('new user onboarding', () => {
    it('should complete signup → connect Gmail → receive first threat', async () => {});
  });

  describe('threat lifecycle', () => {
    it('should detect → quarantine → review → release', async () => {});
    it('should detect → quarantine → review → delete', async () => {});
    it('should mark false positive → add to allowlist', async () => {});
  });

  describe('admin workflows', () => {
    it('should manage policies end-to-end', async () => {});
    it('should manage users and roles', async () => {});
    it('should generate compliance reports', async () => {});
  });
});
```

### Slice 6.2: Security Audit

- [ ] Run automated security scan (Snyk/npm audit)
- [ ] Third-party penetration test
- [ ] OWASP Top 10 verification
- [ ] Dependency vulnerability check
- [ ] Secret scanning

### Slice 6.3: Documentation Complete

- [ ] API documentation (OpenAPI 3.0 complete)
- [ ] User documentation
- [ ] Admin documentation
- [ ] Runbook for operations
- [ ] Incident response procedures

### Slice 6.4: Disaster Recovery

```typescript
// tests/dr/disaster-recovery.test.ts

describe('Disaster Recovery', () => {
  describe('database backup', () => {
    it('should have automated daily backups', async () => {});
    it('should restore from backup successfully', async () => {});
  });

  describe('failover', () => {
    it('should handle database failover', async () => {});
    it('should handle Redis failover', async () => {});
  });
});
```

### Phase 6 Completion Checklist

| Slice | Tests Written | Tests Passing | Deployed | Score Impact |
|-------|--------------|---------------|----------|--------------|
| 6.1 E2E Tests | [ ] | [ ] | [ ] | +2 |
| 6.2 Security Audit | [ ] | [ ] | [ ] | +1 |
| 6.3 Documentation | [ ] | [ ] | [ ] | +1 |
| 6.4 Disaster Recovery | [ ] | [ ] | [ ] | +1 |
| **Total** | | | | **+5** |

---

## Success Metrics

### Test Coverage Targets

| Category | Current | Phase 1 | Phase 3 | Phase 6 |
|----------|---------|---------|---------|---------|
| Unit Tests | ~60% | 70% | 80% | 90% |
| Integration | ~40% | 60% | 75% | 85% |
| E2E | ~10% | 30% | 50% | 80% |
| Critical Paths | ~30% | 80% | 95% | 100% |

### Performance Targets

| Metric | Current | Target |
|--------|---------|--------|
| API p95 response | Unknown | <200ms |
| API p99 response | Unknown | <500ms |
| Email processing | Unknown | <5s |
| Detection pipeline | Unknown | <2s |

### Reliability Targets

| Metric | Target |
|--------|--------|
| Uptime | 99.9% |
| Error rate | <0.1% |
| Alert response | <5 min |
| Incident resolution | <1 hour |

---

## Risk Mitigation

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Gmail API rate limits | High | Medium | Implement adaptive throttling |
| O365 webhook expiry | Medium | High | Auto-renewal cron job |
| Database migration fails | Low | High | Test on staging first, rollback plan |
| LLM API unavailable | Medium | Medium | Fallback to deterministic-only |

### Schedule Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Scope creep | High | High | Strict DoD, no gold-plating |
| Integration complexity | Medium | Medium | Spike early, adjust estimates |
| External dependencies | Low | High | Mock services for development |

---

## Appendix: Test File Structure

```
tests/
├── unit/
│   ├── detection/
│   │   ├── pipeline.test.ts
│   │   ├── bec.test.ts
│   │   ├── impersonation.test.ts
│   │   └── llm.test.ts
│   ├── remediation/
│   │   ├── gmail-actions.test.ts      # NEW
│   │   ├── o365-actions.test.ts       # NEW
│   │   ├── quarantine.test.ts         # NEW
│   │   └── workflow.test.ts           # NEW
│   ├── security/
│   │   ├── token-encryption.test.ts   # NEW
│   │   ├── tenant-isolation.test.ts   # NEW
│   │   ├── input-validation.test.ts   # NEW
│   │   └── webhook-security.test.ts   # NEW
│   └── threat-intel/
│       ├── ip-reputation.test.ts      # UPDATE
│       ├── virustotal.test.ts         # NEW
│       ├── urlscan.test.ts            # NEW
│       └── sandbox.test.ts            # UPDATE
├── integration/
│   ├── gmail-sync.test.ts
│   ├── o365-sync.test.ts
│   ├── detection-to-remediation.test.ts  # NEW
│   └── database-integrity.test.ts        # NEW
├── e2e/
│   ├── auth.spec.ts
│   ├── onboarding.spec.ts
│   ├── threat-lifecycle.spec.ts       # NEW
│   ├── admin-workflows.spec.ts        # NEW
│   └── complete-flows.spec.ts         # NEW
├── load/
│   └── stress.test.ts                 # NEW
└── dr/
    └── disaster-recovery.test.ts      # NEW
```

---

## Quick Start: Phase 1, Slice 1.1

To begin immediately, run:

```bash
# Create test file first (TDD)
touch tests/remediation/gmail-actions.test.ts

# Run in watch mode while developing
npm run test:watch -- tests/remediation/gmail-actions.test.ts

# The test will fail (RED) - this is correct!
# Now implement the feature (GREEN)
# Then refactor (REFACTOR)
```

---

**Document Maintained By:** Engineering Team
**Last Updated:** January 2025
**Next Review:** After each phase completion
