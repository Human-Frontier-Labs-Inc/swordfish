# Swordfish Implementation Plan v1

## Executive Summary

This document outlines a phased implementation plan to elevate Swordfish from its current state (28/100) to enterprise-grade email security (80/100). The plan uses Test-Driven Development (TDD) methodology with clear deliverables at each phase milestone.

**Current State**: 28/100 - Detection logic exists but operational components are broken/stubbed
**Target State**: 80/100 - Production-ready enterprise email security platform
**Timeline**: 8 phases over ~16 weeks
**Methodology**: TDD with Playwright E2E + Vitest unit tests

---

## Phase Overview

| Phase | Name | Duration | Entry Score | Exit Score | Key Deliverable |
|-------|------|----------|-------------|------------|-----------------|
| 1 | Foundation | 2 weeks | 28 | 40 | Working real-time sync |
| 2 | Real-Time | 2 weeks | 40 | 50 | Webhook-based monitoring |
| 3 | Intelligence | 2 weeks | 50 | 58 | Threat feed integration |
| 4 | Detection | 2 weeks | 58 | 65 | Enhanced BEC/ML detection |
| 5 | Actions | 2 weeks | 65 | 70 | Full action repertoire |
| 6 | MSP/Multi-Tenant | 2 weeks | 70 | 75 | Multi-tenant support |
| 7 | Integration | 2 weeks | 75 | 78 | SIEM/API ecosystem |
| 8 | Operations | 2 weeks | 78 | 80 | SOC dashboard + polish |

---

## Phase 1: Foundation (Weeks 1-2)

### Objective
Fix critical operational issues to achieve a working email security system.

### Entry Criteria
- Current score: 28/100
- Cron job is stubbed (TODO comment, no actual sync)
- Sync times out on Vercel (30s limit)
- Priority type mismatch (INTEGER vs string)

### User Stories
- US-001: Connect Google Workspace
- US-002: Connect Microsoft 365
- US-003: Real-Time Webhook Processing (partial)

### TDD Test Suite

#### Unit Tests (Vitest)

```typescript
// tests/unit/cron/email-sync.test.ts
describe('Email Sync Cron', () => {
  test('should fetch integrations with sync enabled', async () => {
    // Arrange
    const mockIntegrations = [...]

    // Act
    const result = await getActiveIntegrations()

    // Assert
    expect(result).toHaveLength(2)
    expect(result[0].config.syncEnabled).toBe(true)
  })

  test('should process emails in batches of 10', async () => {
    // Test batch processing
  })

  test('should skip already processed emails', async () => {
    // Test deduplication
  })

  test('should handle token refresh', async () => {
    // Test OAuth token refresh flow
  })

  test('should timeout gracefully at 55 seconds', async () => {
    // Test timeout handling for non-Vercel deployment
  })
})

// tests/unit/detection/pipeline.test.ts
describe('Detection Pipeline', () => {
  test('should execute layers in correct order', async () => {
    // Test layer execution order
  })

  test('should skip ML layer when deterministic score > 80', async () => {
    // Test layer gating
  })

  test('should aggregate scores correctly', async () => {
    // Test score aggregation
  })
})

// tests/unit/policies/priority.test.ts
describe('Policy Priority', () => {
  test('should convert string priority to integer', () => {
    expect(priorityToInt('critical')).toBe(0)
    expect(priorityToInt('high')).toBe(1)
    expect(priorityToInt('medium')).toBe(2)
    expect(priorityToInt('low')).toBe(3)
  })

  test('should convert integer priority to string', () => {
    expect(intToPriority(0)).toBe('critical')
    expect(intToPriority(1)).toBe('high')
  })

  test('should order policies by priority correctly', async () => {
    // Test SQL ORDER BY priority ASC
  })
})
```

#### E2E Tests (Playwright)

```typescript
// tests/e2e/integrations/google-connect.spec.ts
test.describe('Google Workspace Integration', () => {
  test('should complete OAuth flow', async ({ page }) => {
    await page.goto('/dashboard/integrations')
    await page.click('[data-testid="connect-google"]')

    // Mock OAuth flow
    await expect(page).toHaveURL(/accounts.google.com/)

    // After redirect
    await page.goto('/dashboard/integrations?code=mock-code')
    await expect(page.locator('[data-testid="google-status"]')).toHaveText('Connected')
  })

  test('should show sync status after connection', async ({ page }) => {
    // Test sync status display
  })

  test('should display error on OAuth failure', async ({ page }) => {
    // Test error handling
  })
})

// tests/e2e/sync/manual-sync.spec.ts
test.describe('Manual Sync', () => {
  test('should trigger sync and show progress', async ({ page }) => {
    await page.goto('/dashboard/integrations')
    await page.click('[data-testid="sync-now"]')

    await expect(page.locator('[data-testid="sync-status"]')).toHaveText('Syncing...')
    await expect(page.locator('[data-testid="sync-status"]')).toHaveText('Complete', { timeout: 60000 })
  })
})
```

### Implementation Tasks

#### Task 1.1: Wire up Cron Job (3 days)
```
Files to modify:
- app/api/cron/sync/route.ts (remove TODO, implement actual sync)
- lib/workers/email-sync.ts (increase timeout for non-Vercel)
- vercel.json (add cron configuration OR plan migration)

Tests first:
- [ ] Unit test: Cron handler calls syncIntegration
- [ ] Unit test: Cron respects rate limits
- [ ] Integration test: Full cron execution
```

#### Task 1.2: Fix Vercel Timeout (2 days)
```
Options:
A) Migrate to Railway/Render (recommended for long-running)
B) Use Vercel Functions with streaming
C) Use background job service (Inngest, Trigger.dev)

Files to modify:
- lib/workers/email-sync.ts
- package.json (add background job dependency)
- New: lib/jobs/email-sync-job.ts

Tests first:
- [ ] Unit test: Job queue integration
- [ ] Unit test: Job timeout handling
- [ ] Integration test: Background job execution
```

#### Task 1.3: Database Schema Alignment (2 days)
```
Files to modify:
- scripts/migrations/001-fix-priority.sql
- lib/policies/engine.ts (already fixed)
- app/api/policies/route.ts (already fixed)

Tests first:
- [ ] Unit test: All priority conversions
- [ ] Integration test: Policy CRUD with priorities
- [ ] E2E test: Create policy with priority
```

#### Task 1.4: Integration Status Dashboard (3 days)
```
Files to modify:
- app/dashboard/integrations/page.tsx
- components/integrations/StatusCard.tsx
- app/api/integrations/status/route.ts

Tests first:
- [ ] Component test: StatusCard renders states
- [ ] E2E test: View integration status
- [ ] E2E test: Manual sync button works
```

### Deliverables

| Deliverable | Acceptance Criteria | Test Coverage |
|-------------|---------------------|---------------|
| Working cron job | Syncs every 5 minutes | 90% unit, E2E |
| No Vercel timeouts | Processes 50+ emails | Load test |
| Priority type fix | All CRUD operations work | 100% unit |
| Integration dashboard | Shows live status | E2E |

### Exit Criteria
- [ ] Cron job runs successfully every 5 minutes
- [ ] No timeout errors in logs
- [ ] Emails are being processed
- [ ] Dashboard shows integration status
- [ ] All Phase 1 tests passing
- **Score: 40/100**

---

## Phase 2: Real-Time Protection (Weeks 3-4)

### Objective
Implement webhook-based real-time email monitoring.

### Entry Criteria
- Phase 1 complete (score: 40/100)
- Sync is working but still polling-based

### User Stories
- US-003: Real-Time Webhook Processing (complete)
- US-008: Automatic Quarantine

### TDD Test Suite

```typescript
// tests/unit/webhooks/google-pubsub.test.ts
describe('Google Pub/Sub Webhook', () => {
  test('should validate webhook signature', async () => {
    const validPayload = {...}
    const validSignature = '...'

    expect(validateGoogleSignature(validPayload, validSignature)).toBe(true)
  })

  test('should parse notification payload', async () => {
    // Test payload parsing
  })

  test('should fetch email content on notification', async () => {
    // Test email fetch
  })

  test('should process within 5 second SLA', async () => {
    const start = Date.now()
    await processWebhook(payload)
    expect(Date.now() - start).toBeLessThan(5000)
  })
})

// tests/unit/webhooks/microsoft-graph.test.ts
describe('Microsoft Graph Webhook', () => {
  test('should respond to validation request', async () => {
    // Test validation challenge response
  })

  test('should validate client state', async () => {
    // Test client state validation
  })

  test('should handle change notifications', async () => {
    // Test notification processing
  })
})

// tests/e2e/webhooks/realtime.spec.ts
test.describe('Real-Time Protection', () => {
  test('should process email within 5 seconds of webhook', async ({ request }) => {
    // Send mock webhook
    const response = await request.post('/api/webhooks/google', {
      data: mockGoogleNotification
    })

    expect(response.status()).toBe(200)

    // Verify email was processed
    const verdict = await getVerdict(emailId)
    expect(verdict).toBeDefined()
  })
})
```

### Implementation Tasks

#### Task 2.1: Google Pub/Sub Integration (4 days)
```
Files to create:
- app/api/webhooks/google/route.ts
- lib/integrations/google-pubsub.ts
- lib/webhooks/google-handler.ts

Tests first:
- [ ] Unit test: Signature validation
- [ ] Unit test: Payload parsing
- [ ] Integration test: Pub/Sub subscription
- [ ] E2E test: Webhook to verdict flow
```

#### Task 2.2: Microsoft Graph Subscriptions (4 days)
```
Files to create:
- app/api/webhooks/microsoft/route.ts
- lib/integrations/graph-subscriptions.ts
- lib/webhooks/microsoft-handler.ts

Tests first:
- [ ] Unit test: Validation challenge
- [ ] Unit test: Change notification parsing
- [ ] Integration test: Subscription lifecycle
- [ ] E2E test: Webhook to verdict flow
```

#### Task 2.3: Quarantine Action Implementation (3 days)
```
Files to modify:
- lib/actions/quarantine.ts
- lib/integrations/gmail.ts (add move to label)
- lib/integrations/o365.ts (add move to folder)

Tests first:
- [ ] Unit test: Quarantine decision logic
- [ ] Integration test: Gmail quarantine
- [ ] Integration test: O365 quarantine
- [ ] E2E test: Threat → quarantine flow
```

#### Task 2.4: Webhook Infrastructure (3 days)
```
Files to create:
- lib/webhooks/queue.ts (webhook processing queue)
- lib/webhooks/retry.ts (retry logic)
- app/api/webhooks/health/route.ts

Tests first:
- [ ] Unit test: Queue processing
- [ ] Unit test: Retry with exponential backoff
- [ ] Integration test: Queue under load
```

### Deliverables

| Deliverable | Acceptance Criteria | Test Coverage |
|-------------|---------------------|---------------|
| Google Pub/Sub webhook | < 5s processing | 95% unit, E2E |
| Microsoft Graph webhook | < 5s processing | 95% unit, E2E |
| Quarantine action | Emails moved to quarantine | E2E |
| Webhook infrastructure | 99.9% delivery | Load test |

### Exit Criteria
- [ ] Webhooks processing within 5 seconds
- [ ] Quarantine working for both providers
- [ ] Webhook queue handling 100 req/min
- [ ] All Phase 2 tests passing
- **Score: 50/100** (Barracuda parity!)

---

## Phase 3: Threat Intelligence (Weeks 5-6)

### Objective
Integrate external threat feeds for enhanced detection.

### Entry Criteria
- Phase 2 complete (score: 50/100)
- Real-time protection working

### User Stories
- US-006: Phishing URL Detection (enhanced)
- Threat feed integration (new)

### TDD Test Suite

```typescript
// tests/unit/threat-intel/feeds.test.ts
describe('Threat Intelligence Feeds', () => {
  test('should fetch PhishTank feed', async () => {
    const urls = await fetchPhishTankFeed()
    expect(urls.length).toBeGreaterThan(0)
  })

  test('should check URL against feeds', async () => {
    const result = await checkUrlReputation('http://malicious.com/phish')
    expect(result.verdict).toBe('malicious')
    expect(result.source).toBe('phishtank')
  })

  test('should cache feed data', async () => {
    // Test caching
  })

  test('should handle feed unavailability gracefully', async () => {
    // Test fallback behavior
  })
})

// tests/unit/threat-intel/domain-age.test.ts
describe('Domain Age Analysis', () => {
  test('should flag domains < 30 days old', async () => {
    const result = await analyzeDomainAge('new-domain.com')
    expect(result.signal.type).toBe('domain_age')
    expect(result.signal.severity).toBe('warning')
  })
})
```

### Implementation Tasks

#### Task 3.1: Threat Feed Aggregator (4 days)
```
Files to create:
- lib/threat-intel/feeds/index.ts
- lib/threat-intel/feeds/phishtank.ts
- lib/threat-intel/feeds/urlhaus.ts
- lib/threat-intel/feeds/openphish.ts
- lib/threat-intel/cache.ts

Tests first:
- [ ] Unit test: Each feed parser
- [ ] Unit test: Feed aggregation
- [ ] Unit test: Caching layer
- [ ] Integration test: Real feed fetch
```

#### Task 3.2: Domain Intelligence (3 days)
```
Files to create:
- lib/threat-intel/domain/age.ts
- lib/threat-intel/domain/whois.ts
- lib/threat-intel/domain/reputation.ts

Tests first:
- [ ] Unit test: WHOIS parsing
- [ ] Unit test: Age calculation
- [ ] Unit test: Reputation scoring
```

#### Task 3.3: IP Reputation (3 days)
```
Files to create:
- lib/threat-intel/ip/reputation.ts
- lib/threat-intel/ip/geolocation.ts
- lib/threat-intel/ip/blocklists.ts

Tests first:
- [ ] Unit test: IP blocklist check
- [ ] Unit test: Geolocation anomaly detection
```

#### Task 3.4: Integration with Detection Pipeline (4 days)
```
Files to modify:
- lib/detection/layers/reputation.ts
- lib/detection/pipeline.ts

Tests first:
- [ ] Unit test: Reputation layer integration
- [ ] Integration test: Full pipeline with threat intel
- [ ] E2E test: Known malicious URL detection
```

### Deliverables

| Deliverable | Acceptance Criteria | Test Coverage |
|-------------|---------------------|---------------|
| Threat feed integration | 3+ feeds active | 90% unit |
| Domain intelligence | Age + WHOIS + reputation | 90% unit |
| IP reputation | Blocklist + geo | 90% unit |
| Pipeline integration | Signals in verdicts | E2E |

### Exit Criteria
- [ ] At least 3 threat feeds integrated
- [ ] Domain age detection working
- [ ] IP reputation checking working
- [ ] All Phase 3 tests passing
- **Score: 58/100**

---

## Phase 4: Enhanced Detection (Weeks 7-8)

### Objective
Improve ML detection and add BEC-specific detection.

### Entry Criteria
- Phase 3 complete (score: 58/100)
- Threat intelligence integrated

### User Stories
- US-007: BEC Detection
- ML model improvements

### TDD Test Suite

```typescript
// tests/unit/detection/bec.test.ts
describe('BEC Detection', () => {
  test('should detect CEO impersonation', async () => {
    const email = {
      from: { displayName: 'John Smith CEO', address: 'john@external.com' },
      // ... executive name from company directory
    }
    const result = await detectBEC(email, tenantId)
    expect(result.signals).toContainEqual(
      expect.objectContaining({ type: 'display_name_spoof' })
    )
  })

  test('should detect wire transfer requests', async () => {
    const email = {
      body: { text: 'Please wire $50,000 to this account urgently' }
    }
    const result = await detectBEC(email, tenantId)
    expect(result.signals).toContainEqual(
      expect.objectContaining({ type: 'financial_request' })
    )
  })

  test('should detect urgency + financial combination', async () => {
    // Test compound pattern detection
  })
})

// tests/unit/detection/ml-classifier.test.ts
describe('ML Classifier', () => {
  test('should classify phishing email correctly', async () => {
    const features = extractFeatures(phishingEmail)
    const result = await classify(features)
    expect(result.label).toBe('phishing')
    expect(result.confidence).toBeGreaterThan(0.8)
  })

  test('should handle edge cases gracefully', async () => {
    // Test edge cases
  })
})
```

### Implementation Tasks

#### Task 4.1: VIP/Executive List Management (3 days)
```
Files to create:
- lib/detection/bec/vip-list.ts
- app/api/settings/vip/route.ts
- components/settings/VIPManagement.tsx

Tests first:
- [ ] Unit test: VIP list CRUD
- [ ] Unit test: VIP matching logic
- [ ] E2E test: Add/remove VIP
```

#### Task 4.2: BEC Detection Engine (5 days)
```
Files to create:
- lib/detection/bec/detector.ts
- lib/detection/bec/patterns.ts
- lib/detection/bec/impersonation.ts

Tests first:
- [ ] Unit test: Each BEC pattern
- [ ] Unit test: Impersonation detection
- [ ] Integration test: BEC email samples
```

#### Task 4.3: ML Model Enhancement (4 days)
```
Files to modify:
- lib/detection/layers/ml.ts
- lib/ml/classifier.ts
- lib/ml/feature-extraction.ts

Tests first:
- [ ] Unit test: Feature extraction
- [ ] Unit test: Model inference
- [ ] Benchmark test: Model accuracy
```

#### Task 4.4: LLM Analysis Optimization (2 days)
```
Files to modify:
- lib/detection/layers/llm.ts
- lib/detection/prompts/analysis.ts

Tests first:
- [ ] Unit test: Prompt generation
- [ ] Unit test: Response parsing
- [ ] Integration test: LLM analysis
```

### Deliverables

| Deliverable | Acceptance Criteria | Test Coverage |
|-------------|---------------------|---------------|
| VIP management | CRUD + UI | E2E |
| BEC detection | 5+ BEC patterns | 95% unit |
| ML improvements | 90%+ accuracy | Benchmark |
| LLM optimization | < 2s analysis | Performance |

### Exit Criteria
- [ ] BEC detection catching impersonation attempts
- [ ] ML classifier improved accuracy
- [ ] VIP list management working
- [ ] All Phase 4 tests passing
- **Score: 65/100**

---

## Phase 5: Action Repertoire (Weeks 9-10)

### Objective
Complete the action system with all response capabilities.

### Entry Criteria
- Phase 4 complete (score: 65/100)
- Enhanced detection working

### User Stories
- US-009: Warning Banner Injection
- US-010: Link Rewriting

### TDD Test Suite

```typescript
// tests/unit/actions/banner.test.ts
describe('Warning Banner', () => {
  test('should inject banner into HTML email', () => {
    const originalHtml = '<html><body>Hello</body></html>'
    const result = injectBanner(originalHtml, warningConfig)
    expect(result).toContain('data-swordfish-banner')
    expect(result).toContain('This email may be suspicious')
  })

  test('should preserve original content', () => {
    // Test content preservation
  })

  test('should handle plain text emails', () => {
    // Test plain text handling
  })
})

// tests/unit/actions/link-rewrite.test.ts
describe('Link Rewriting', () => {
  test('should rewrite suspicious URLs', () => {
    const url = 'http://suspicious.com/login'
    const rewritten = rewriteUrl(url, emailId)
    expect(rewritten).toMatch(/swordfish.app\/click\//)
  })

  test('should not rewrite safe URLs', () => {
    // Test safe URL passthrough
  })

  test('should handle encoded URLs', () => {
    // Test URL encoding
  })
})

// tests/e2e/actions/click-protection.spec.ts
test.describe('Click-Time Protection', () => {
  test('should show warning on suspicious click', async ({ page }) => {
    await page.goto('/click/abc123')
    await expect(page.locator('.warning-interstitial')).toBeVisible()
    await expect(page.locator('.original-url')).toContainText('suspicious.com')
  })

  test('should block malicious clicks', async ({ page }) => {
    await page.goto('/click/malicious123')
    await expect(page.locator('.blocked-message')).toBeVisible()
  })
})
```

### Implementation Tasks

#### Task 5.1: Banner Injection System (4 days)
```
Files to create:
- lib/actions/banner/inject.ts
- lib/actions/banner/templates.ts
- lib/actions/banner/styles.ts

Tests first:
- [ ] Unit test: HTML injection
- [ ] Unit test: Template rendering
- [ ] Integration test: Gmail banner
- [ ] Integration test: O365 banner
```

#### Task 5.2: Link Rewriting (4 days)
```
Files to create:
- lib/actions/links/rewrite.ts
- lib/actions/links/proxy.ts
- app/click/[id]/page.tsx

Tests first:
- [ ] Unit test: URL rewriting
- [ ] Unit test: Click tracking
- [ ] E2E test: Full click flow
```

#### Task 5.3: Click-Time Analysis (3 days)
```
Files to create:
- lib/actions/links/click-time-check.ts
- app/api/click/[id]/route.ts

Tests first:
- [ ] Unit test: Click-time reputation check
- [ ] Unit test: Interstitial decision logic
- [ ] E2E test: Warning interstitial
```

#### Task 5.4: Action Audit Trail (3 days)
```
Files to modify:
- lib/db/audit.ts
- lib/actions/logger.ts

Tests first:
- [ ] Unit test: Action logging
- [ ] Unit test: Audit trail queries
- [ ] E2E test: View action history
```

### Deliverables

| Deliverable | Acceptance Criteria | Test Coverage |
|-------------|---------------------|---------------|
| Banner injection | Works for HTML + plain text | 95% unit, E2E |
| Link rewriting | All suspicious links rewritten | 95% unit |
| Click-time check | Real-time reputation at click | E2E |
| Audit trail | All actions logged | E2E |

### Exit Criteria
- [ ] Warning banners visible in emails
- [ ] Links rewritten and protected
- [ ] Click-time checking working
- [ ] Full audit trail
- [ ] All Phase 5 tests passing
- **Score: 70/100**

---

## Phase 6: Multi-Tenant & MSP (Weeks 11-12)

### Objective
Enable MSP/multi-tenant deployment model.

### Entry Criteria
- Phase 5 complete (score: 70/100)
- Full action repertoire working

### User Stories
- US-020: MSP Dashboard
- US-021: Client Onboarding
- US-022: Per-Client Billing

### TDD Test Suite

```typescript
// tests/unit/multitenancy/isolation.test.ts
describe('Tenant Isolation', () => {
  test('should isolate data by tenant', async () => {
    const tenant1Data = await getThreats('tenant-1')
    const tenant2Data = await getThreats('tenant-2')

    expect(tenant1Data.every(t => t.tenantId === 'tenant-1')).toBe(true)
    expect(tenant2Data.every(t => t.tenantId === 'tenant-2')).toBe(true)
  })

  test('should prevent cross-tenant access', async () => {
    // Test authorization
  })
})

// tests/e2e/msp/dashboard.spec.ts
test.describe('MSP Dashboard', () => {
  test('should show all clients', async ({ page }) => {
    await page.goto('/msp/dashboard')
    await expect(page.locator('[data-testid="client-card"]')).toHaveCount(5)
  })

  test('should aggregate statistics', async ({ page }) => {
    // Test aggregation
  })

  test('should drill down to client', async ({ page }) => {
    await page.click('[data-testid="client-card"]:first-child')
    await expect(page).toHaveURL(/\/dashboard\/tenant-/)
  })
})
```

### Implementation Tasks

#### Task 6.1: MSP Dashboard (5 days)
```
Files to create:
- app/msp/dashboard/page.tsx
- components/msp/ClientCard.tsx
- app/api/msp/clients/route.ts

Tests first:
- [ ] Component test: ClientCard
- [ ] Unit test: MSP data aggregation
- [ ] E2E test: MSP dashboard
```

#### Task 6.2: Client Onboarding Flow (4 days)
```
Files to create:
- app/msp/onboarding/page.tsx
- lib/msp/onboarding.ts
- components/msp/OnboardingWizard.tsx

Tests first:
- [ ] Unit test: Onboarding steps
- [ ] E2E test: Full onboarding flow
```

#### Task 6.3: Tenant Switching (3 days)
```
Files to create:
- components/msp/TenantSwitcher.tsx
- lib/msp/context.ts

Tests first:
- [ ] Unit test: Tenant context
- [ ] E2E test: Switch between tenants
```

#### Task 6.4: Usage Tracking (2 days)
```
Files to create:
- lib/msp/usage.ts
- app/api/msp/usage/route.ts

Tests first:
- [ ] Unit test: Usage calculation
- [ ] Unit test: Billing export
```

### Deliverables

| Deliverable | Acceptance Criteria | Test Coverage |
|-------------|---------------------|---------------|
| MSP dashboard | All clients visible | E2E |
| Client onboarding | < 15 min flow | E2E |
| Tenant switching | Instant switch | E2E |
| Usage tracking | Accurate counts | Unit |

### Exit Criteria
- [ ] MSP can manage multiple clients
- [ ] Onboarding flow complete
- [ ] Usage tracking working
- [ ] All Phase 6 tests passing
- **Score: 75/100**

---

## Phase 7: Integration Ecosystem (Weeks 13-14)

### Objective
Build API and SIEM integrations for enterprise.

### Entry Criteria
- Phase 6 complete (score: 75/100)
- Multi-tenant working

### User Stories
- US-023: REST API Access
- US-024: Webhook Notifications
- US-025: Splunk Integration

### TDD Test Suite

```typescript
// tests/unit/api/authentication.test.ts
describe('API Authentication', () => {
  test('should validate API key', async () => {
    const result = await validateApiKey('valid-key')
    expect(result.valid).toBe(true)
    expect(result.tenantId).toBeDefined()
  })

  test('should reject invalid key', async () => {
    await expect(validateApiKey('invalid')).rejects.toThrow()
  })

  test('should enforce rate limits', async () => {
    // Test rate limiting
  })
})

// tests/integration/api/threats.test.ts
describe('Threats API', () => {
  test('GET /api/v1/threats should return threats', async () => {
    const response = await fetch('/api/v1/threats', {
      headers: { 'Authorization': `Bearer ${apiKey}` }
    })
    expect(response.status).toBe(200)
    const data = await response.json()
    expect(data.threats).toBeInstanceOf(Array)
  })
})

// tests/unit/integrations/splunk.test.ts
describe('Splunk Integration', () => {
  test('should format event as CEF', () => {
    const event = formatCEF(threatData)
    expect(event).toMatch(/CEF:0\|/)
  })

  test('should send to HEC', async () => {
    // Test HEC delivery
  })
})
```

### Implementation Tasks

#### Task 7.1: REST API v1 (5 days)
```
Files to create:
- app/api/v1/threats/route.ts
- app/api/v1/quarantine/route.ts
- app/api/v1/policies/route.ts
- lib/api/auth.ts
- lib/api/rate-limit.ts

Tests first:
- [ ] Unit test: Authentication middleware
- [ ] Unit test: Rate limiting
- [ ] Integration test: Each endpoint
- [ ] Contract test: OpenAPI validation
```

#### Task 7.2: Webhook System (3 days)
```
Files to create:
- lib/webhooks/outbound.ts
- app/api/settings/webhooks/route.ts
- components/settings/WebhookConfig.tsx

Tests first:
- [ ] Unit test: Webhook delivery
- [ ] Unit test: Retry logic
- [ ] E2E test: Webhook configuration
```

#### Task 7.3: Splunk Integration (3 days)
```
Files to create:
- lib/integrations/splunk/hec.ts
- lib/integrations/splunk/cef.ts
- app/api/settings/siem/route.ts

Tests first:
- [ ] Unit test: CEF formatting
- [ ] Unit test: HEC client
- [ ] Integration test: Splunk delivery
```

#### Task 7.4: API Documentation (3 days)
```
Files to create:
- app/api-docs/page.tsx
- lib/api/openapi.ts
- docs/api/README.md

Tests first:
- [ ] Contract test: OpenAPI spec matches implementation
```

### Deliverables

| Deliverable | Acceptance Criteria | Test Coverage |
|-------------|---------------------|---------------|
| REST API v1 | Full CRUD | Contract tests |
| Webhooks | Configurable + retry | E2E |
| Splunk integration | CEF events in Splunk | Integration |
| API docs | OpenAPI spec | Contract |

### Exit Criteria
- [ ] REST API fully functional
- [ ] Webhook notifications working
- [ ] Splunk receiving events
- [ ] API documentation complete
- [ ] All Phase 7 tests passing
- **Score: 78/100**

---

## Phase 8: Operations & Polish (Weeks 15-16)

### Objective
Final polish, SOC features, and production readiness.

### Entry Criteria
- Phase 7 complete (score: 78/100)
- API and integrations working

### User Stories
- US-016: Compliance Audit Report
- SOC dashboard features
- Performance optimization

### TDD Test Suite

```typescript
// tests/e2e/compliance/audit-report.spec.ts
test.describe('Audit Reports', () => {
  test('should generate SOC 2 report', async ({ page }) => {
    await page.goto('/reports/compliance')
    await page.selectOption('#report-type', 'soc2')
    await page.click('[data-testid="generate-report"]')

    await expect(page.locator('.report-preview')).toBeVisible()
    await expect(page.locator('.download-pdf')).toBeEnabled()
  })
})

// tests/performance/load.test.ts
describe('Load Testing', () => {
  test('should handle 100 concurrent webhooks', async () => {
    const promises = Array(100).fill(null).map(() =>
      sendWebhook(mockPayload)
    )
    const results = await Promise.all(promises)

    expect(results.every(r => r.status === 200)).toBe(true)
    expect(results.every(r => r.duration < 5000)).toBe(true)
  })
})
```

### Implementation Tasks

#### Task 8.1: SOC Dashboard (4 days)
```
Files to create:
- app/soc/dashboard/page.tsx
- components/soc/ThreatTimeline.tsx
- components/soc/InvestigationPanel.tsx

Tests first:
- [ ] Component test: SOC components
- [ ] E2E test: SOC workflow
```

#### Task 8.2: Compliance Reports (3 days)
```
Files to create:
- lib/reports/compliance/soc2.ts
- lib/reports/compliance/hipaa.ts
- lib/reports/pdf-generator.ts

Tests first:
- [ ] Unit test: Report data collection
- [ ] Unit test: PDF generation
- [ ] E2E test: Generate and download
```

#### Task 8.3: Performance Optimization (3 days)
```
Files to modify:
- lib/detection/pipeline.ts
- lib/db/queries.ts
- Various components

Tests first:
- [ ] Load test: 100 concurrent requests
- [ ] Performance test: P95 < 5s
```

#### Task 8.4: Production Hardening (4 days)
```
Files to modify/create:
- lib/monitoring/metrics.ts
- lib/monitoring/alerts.ts
- scripts/healthcheck.ts
- Dockerfile (if not Vercel)

Tests first:
- [ ] Integration test: Health checks
- [ ] Integration test: Metrics export
```

### Deliverables

| Deliverable | Acceptance Criteria | Test Coverage |
|-------------|---------------------|---------------|
| SOC dashboard | Investigation workflow | E2E |
| Compliance reports | PDF generation | E2E |
| Performance | P95 < 5s, 100 concurrent | Load test |
| Production readiness | Health checks, metrics | Integration |

### Exit Criteria
- [ ] SOC dashboard functional
- [ ] Compliance reports generating
- [ ] Performance targets met
- [ ] Production monitoring in place
- [ ] All Phase 8 tests passing
- **Score: 80/100** 🎉

---

## Test Coverage Requirements

### By Phase

| Phase | Unit Coverage | E2E Coverage | Load Tests |
|-------|---------------|--------------|------------|
| 1 | 80% | 5 tests | - |
| 2 | 85% | 10 tests | 1 test |
| 3 | 90% | 12 tests | - |
| 4 | 90% | 15 tests | - |
| 5 | 90% | 18 tests | - |
| 6 | 85% | 22 tests | - |
| 7 | 90% | 25 tests | 1 test |
| 8 | 90% | 30 tests | 3 tests |

### Critical Path Tests

These tests MUST pass before each phase completion:

```typescript
// Critical path for Phase 1
test.describe.parallel('Phase 1 Critical', () => {
  test('cron job executes successfully')
  test('integration connects successfully')
  test('email is processed and stored')
  test('dashboard shows data')
})

// Critical path for Phase 2
test.describe.parallel('Phase 2 Critical', () => {
  test('webhook received within 3s of email')
  test('verdict rendered within 5s')
  test('quarantine action executes')
})

// ... etc for each phase
```

---

## Risk Management

### High-Risk Items

| Risk | Mitigation | Phase |
|------|------------|-------|
| Vercel timeout | Migrate to Railway or use background jobs | 1 |
| OAuth token expiry | Proactive refresh, error handling | 1 |
| Webhook volume | Queue with backpressure, scaling | 2 |
| False positives | ML tuning, user feedback loop | 4 |
| Multi-tenant isolation | Row-level security, testing | 6 |

### Contingency Plans

**If Phase 1 exceeds 2 weeks:**
- Skip some Phase 1 polish items
- Move to Phase 2 with known limitations
- Track tech debt for later

**If ML accuracy is poor:**
- Rely more heavily on rule-based detection
- Increase LLM analysis frequency
- Plan ML improvement as separate initiative

---

## Success Metrics

### Technical Metrics

| Metric | Phase 2 Target | Phase 8 Target |
|--------|----------------|----------------|
| Email processing time | < 10s | < 5s |
| Webhook latency | < 5s | < 3s |
| Detection accuracy | 85% | 95% |
| False positive rate | < 5% | < 1% |
| Uptime | 99% | 99.9% |

### Business Metrics

| Metric | Phase 4 Target | Phase 8 Target |
|--------|----------------|----------------|
| Threats blocked | 100/day | 1000/day |
| Active tenants | 5 | 50 |
| MSP clients | 0 | 10 |
| API integrations | 0 | 5 |

---

## Appendix: TDD Workflow

### For Each Feature

1. **Write failing E2E test** that describes user behavior
2. **Write failing unit tests** for each component
3. **Implement minimum code** to pass tests
4. **Refactor** while keeping tests green
5. **Add edge case tests** as discovered
6. **Update documentation** with new behavior

### Test File Organization

```
tests/
├── unit/                    # Vitest unit tests
│   ├── detection/
│   ├── actions/
│   ├── policies/
│   └── webhooks/
├── integration/             # Integration tests
│   ├── api/
│   └── database/
├── e2e/                     # Playwright E2E tests
│   ├── auth/
│   ├── dashboard/
│   ├── integrations/
│   └── threats/
└── performance/             # Load tests
    └── load.test.ts
```

### Running Tests

```bash
# Unit tests
npm run test:unit

# E2E tests
npm run test:e2e

# All tests
npm run test

# Coverage report
npm run test:coverage
```
