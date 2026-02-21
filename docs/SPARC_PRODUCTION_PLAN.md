# SwordPhish Production Plan: SPARC + TDD Methodology
## Comprehensive Phased Implementation to Crush Sublime Security

**Version:** 1.0
**Created:** 2026-01-31
**Methodology:** SPARC (Specification, Pseudocode, Architecture, Refinement, Completion) + TDD
**Target:** Production-ready email security platform for SMB/MSP market

---

## Executive Summary

This plan transforms SwordPhish from 72% production-ready to a market-leading email security platform. Based on comprehensive research of competitor patterns (Barracuda, Proofpoint, Abnormal), pricing analysis, and internal security audits, we've identified 6 phases with clear success criteria.

**Core Principles:**
- ZERO tolerance for security vulnerabilities (especially cross-tenant)
- TDD for all new code (tests written BEFORE implementation)
- Explainability as competitive differentiator vs Sublime's MQL complexity
- Target <0.1% false positive rate (better than industry 0.5-2%)

---

## Phase 0: Critical Security Fixes (PRIORITY: BLOCKING)

**Timeline:** Immediate - No other work until complete
**Success Criteria:** All 7 vulnerabilities patched, security tests passing

### 0.1 Cross-Tenant Data Leakage Vulnerabilities

#### CRITICAL-001: Gmail Webhook Missing Tenant Validation
**File:** `app/api/webhooks/gmail/route.ts`
**Issue:** Webhook processes messages without verifying tenant ownership
**TDD Approach:**
```
TEST: "should reject webhook for message not belonging to tenant"
TEST: "should validate integration_id matches tenant before processing"
TEST: "should return 403 for cross-tenant access attempts"
```
**Fix:** Add tenant_id validation before any message processing

#### CRITICAL-002: O365 Webhook Missing Tenant Validation
**File:** `app/api/webhooks/o365/route.ts`
**Issue:** Same pattern as Gmail - no tenant ownership check
**TDD Approach:**
```
TEST: "should validate subscription belongs to requesting tenant"
TEST: "should reject notifications for unowned subscriptions"
```

#### CRITICAL-003: Threat Query Missing Tenant Filter
**File:** `lib/db/queries/threats.ts`
**Issue:** Some queries don't enforce tenant_id in WHERE clause
**TDD Approach:**
```
TEST: "getThreatById should return null for threats from other tenants"
TEST: "listThreats should only return current tenant's threats"
TEST: "updateThreat should fail for cross-tenant updates"
```

### 0.2 Authentication/Authorization Gaps

#### HIGH-001: API Routes Missing Auth Middleware
**Files:** Multiple API routes
**Issue:** Some internal API endpoints lack Clerk auth checks
**TDD Approach:**
```
TEST: "should return 401 for unauthenticated requests"
TEST: "should validate session token on every request"
```

#### HIGH-002: MSP Portal Missing Tenant Context Switch Validation
**File:** `app/api/msp/switch-tenant/route.ts`
**Issue:** MSP admins can potentially switch to unmanaged tenants
**TDD Approach:**
```
TEST: "should only allow switching to tenants under MSP management"
TEST: "should validate MSP has active contract with tenant"
```

### 0.3 Fail-Open Vulnerabilities

#### HIGH-003: Threat Intel Returns "Safe" on API Error
**File:** `lib/threat-intel/intel-service.ts`
**Issue:** When external APIs fail, system marks as safe instead of unknown
**TDD Approach:**
```
TEST: "should return 'unknown' status when API times out"
TEST: "should NOT return 'safe' when unable to verify"
TEST: "should queue for retry when external service unavailable"
```

#### HIGH-004: Gmail Message Lookup Has No Fallback
**File:** `lib/integrations/gmail.ts`
**Issue:** If message lookup fails, remediation proceeds with wrong ID
**TDD Approach:**
```
TEST: "should abort remediation if message ID cannot be verified"
TEST: "should log warning and require manual review on lookup failure"
```

### 0.4 Security Test Suite
Create comprehensive security test file: `tests/security/cross-tenant.test.ts`

```typescript
describe('Cross-Tenant Security', () => {
  describe('Threat Access Control', () => {
    it('should never return threats from other tenants');
    it('should enforce tenant_id on all threat queries');
    it('should reject cross-tenant remediation attempts');
  });

  describe('Webhook Validation', () => {
    it('should validate Gmail webhook ownership');
    it('should validate O365 subscription ownership');
    it('should reject forged webhook payloads');
  });

  describe('MSP Isolation', () => {
    it('should isolate MSP tenant data completely');
    it('should validate MSP-to-tenant relationships');
    it('should audit all cross-tenant operations');
  });
});
```

**Deliverables:**
- [ ] All 7 vulnerabilities patched
- [ ] Security test suite with 100% pass rate
- [ ] Penetration test report (cross-tenant focus)
- [ ] Updated SECURITY_AUDIT.md with remediation proof

---

## Phase 1: False Positive Reduction (Target: <0.1%)

**Timeline:** Week 1-2 after Phase 0
**Success Criteria:** FP rate drops from ~2% to <0.1%

### 1.1 Detection Pipeline Tuning

Based on audit findings, implement these 8 specific fixes:

#### FP-001: Reduce First-Contact Sender Amplification
**File:** `lib/detection/reputation-layer.ts`
**Current:** 1.5x score multiplier for first-time senders
**Fix:** Reduce to 1.2x, add domain age check
**TDD:**
```
TEST: "first-contact from 10+ year domain should not amplify score"
TEST: "first-contact from <30 day domain should amplify 1.5x"
TEST: "first-contact from established .gov/.edu should not amplify"
```

#### FP-001: First-Contact Sender Score Reduction
**Current:** 1.5x multiplier for unknown senders
**Recommendation:** Reduce to 1.2x, add domain age exemption
```typescript
// TDD Tests
TEST: "should not penalize senders from domains >5 years old"
TEST: "should reduce first-contact penalty from 1.5x to 1.2x"
TEST: "should exempt .gov and .edu domains from first-contact penalty"
```

#### FP-002: Government/Institutional Domain Whitelist
**File:** `lib/detection/lookalike-layer.ts`
**Issue:** Government emails flagged due to unusual TLDs
**TDD:**
```
TEST: "should not flag emails from verified .gov domains"
TEST: "should maintain whitelist of known government domains"
TEST: "should check SPF/DKIM before trusting whitelist"
```

#### FP-003: Thread Context Awareness
**File:** `lib/detection/bec-layer.ts`
**Issue:** Reply-to-self and existing threads flagged
**TDD:**
```
TEST: "should reduce score for emails in existing thread"
TEST: "should not flag self-replies"
TEST: "should track conversation history for context"
```

#### FP-004: Attachment Analysis Refinement
**File:** `lib/detection/sandbox-layer.ts`
**Issue:** Common business documents over-flagged
**TDD:**
```
TEST: "should not flag standard PDF invoices from known vendors"
TEST: "should check document metadata before sandbox"
TEST: "should cache analysis results for repeated attachments"
```

#### FP-005: LLM Prompt Optimization
**File:** `lib/detection/llm-layer.ts`
**Issue:** LLM too aggressive on urgency language
**TDD:**
```
TEST: "should distinguish business urgency from threat urgency"
TEST: "should consider sender reputation in urgency assessment"
TEST: "should not flag 'ASAP' from internal senders"
```

#### FP-006: ML Model Retraining Data
**File:** `lib/detection/ml-layer.ts`
**Issue:** Model trained on skewed dataset
**TDD:**
```
TEST: "should include false positive feedback in training data"
TEST: "should weight recent feedback higher than historical"
TEST: "should have separate models for different email categories"
```

#### FP-007: Score Aggregation Formula
**File:** `lib/detection/scoring.ts`
**Issue:** Additive scoring causes small signals to compound
**TDD:**
```
TEST: "should use weighted geometric mean not additive"
TEST: "should require multiple high-confidence signals for threat"
TEST: "should apply diminishing returns for similar signal types"
```

#### FP-008: Feedback Loop Integration
**File:** `lib/detection/feedback.ts`
**Issue:** User feedback not reaching detection pipeline
**TDD:**
```
TEST: "should immediately apply user 'not spam' feedback"
TEST: "should track per-tenant false positive patterns"
TEST: "should auto-adjust thresholds based on feedback rate"
```

### 1.2 Feedback Loop Architecture

**New Component:** Real-time feedback integration

```typescript
// lib/feedback/feedback-processor.ts
interface FeedbackEvent {
  threatId: string;
  tenantId: string;
  userId: string;
  action: 'false_positive' | 'false_negative' | 'confirmed_threat';
  timestamp: Date;
}

// Required behaviors (TDD):
TEST: "should update threat status within 100ms of feedback"
TEST: "should propagate feedback to ML model training queue"
TEST: "should adjust sender reputation based on feedback"
TEST: "should notify detection pipeline of threshold changes"
```

**Deliverables:**
- [ ] All 8 FP fixes implemented with tests
- [ ] Feedback loop fully wired
- [ ] FP rate monitoring dashboard
- [ ] Weekly FP report automation

---

## Phase 2: UX Overhaul

**Timeline:** Week 2-4
**Success Criteria:** User can complete all workflows without confusion

### 2.1 Dashboard Redesign (Based on Barracuda/Abnormal Patterns)

**Current Issue:** Users feel "lost" - no clear information hierarchy

**New Dashboard Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│  THREAT OVERVIEW                              [Last 24h ▼]  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │ 🔴 12    │ │ 🟡 34    │ │ 🟢 1,847 │ │ ⚡ 99.3%     │   │
│  │ Blocked  │ │ Quarantine│ │ Delivered│ │ Accuracy    │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  ⚠️ REQUIRES ATTENTION (3)                    [View All →]  │
│  ├─ High-confidence threat pending review                   │
│  ├─ New sender pattern detected                             │
│  └─ Integration sync warning                                │
├─────────────────────────────────────────────────────────────┤
│  📊 THREAT TRENDS                            [7d | 30d | 90d]│
│  [Sparkline chart: threats over time]                       │
├─────────────────────────────────────────────────────────────┤
│  🎯 TOP THREAT TYPES           │  📧 RECENT ACTIVITY       │
│  1. Phishing (45%)             │  • user@co flagged threat │
│  2. BEC (30%)                  │  • Admin released email   │
│  3. Malware (15%)              │  • New integration added  │
│  4. Spam (10%)                 │                           │
└─────────────────────────────────────────────────────────────┘
```

**TDD for Dashboard:**
```
TEST: "should load dashboard in <2 seconds"
TEST: "should show real-time threat count updates"
TEST: "should highlight items requiring user action"
TEST: "should provide one-click access to quarantine"
```

### 2.2 Quarantine Management

**New Quarantine View:**
```
┌─────────────────────────────────────────────────────────────┐
│  QUARANTINE                    🔍 Search    [Filter ▼]      │
├─────────────────────────────────────────────────────────────┤
│  □ | From              | Subject           | Score | Action │
│  ──────────────────────────────────────────────────────────│
│  ☑ │ attacker@bad.com  │ URGENT: Wire...  │ 95%  │ [🗑️][✉️] │
│  ☑ │ unknown@new.com   │ Invoice #1234    │ 72%  │ [🗑️][✉️] │
│  □ │ govt@state.gov    │ RE: Application  │ 45%  │ [🗑️][✉️] │
├─────────────────────────────────────────────────────────────┤
│  BULK ACTIONS: [Release Selected] [Delete Selected]         │
│                [Report False Positive]                       │
├─────────────────────────────────────────────────────────────┤
│  THREAT DETAILS (click row to expand)                       │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ WHY FLAGGED:                                            ││
│  │ • First-time sender from domain registered 2 days ago  ││
│  │ • Subject contains urgency language (URGENT, ASAP)     ││
│  │ • Similar to known phishing template (87% match)       ││
│  │                                                         ││
│  │ RECOMMENDATION: Block - High confidence phishing       ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

**TDD for Quarantine:**
```
TEST: "should explain WHY each email was flagged"
TEST: "should support bulk release/delete operations"
TEST: "should track false positive reports"
TEST: "should show sender history on hover"
```

### 2.3 MSP Multi-Tenant Portal

**MSP Dashboard:**
```
┌─────────────────────────────────────────────────────────────┐
│  MSP OVERVIEW                              [Add Tenant +]   │
├─────────────────────────────────────────────────────────────┤
│  MANAGED TENANTS (12)                                       │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ Tenant          │ Users │ Threats │ Status  │ Actions   ││
│  │────────────────────────────────────────────────────────│││
│  │ Acme Corp       │ 150   │ 3 new   │ 🟢 OK   │ [Manage]  ││
│  │ Smith LLC       │ 45    │ 0       │ 🟢 OK   │ [Manage]  ││
│  │ Jones & Co      │ 80    │ 12 new  │ 🔴 ATTN │ [Manage]  ││
│  └─────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────┤
│  AGGREGATE METRICS                                          │
│  • Total protected mailboxes: 2,847                        │
│  • Threats blocked this month: 1,234                       │
│  • Estimated MRR: $11,388                                  │
├─────────────────────────────────────────────────────────────┤
│  BILLING SUMMARY                           [Export CSV]     │
│  [Per-tenant usage breakdown for invoicing]                │
└─────────────────────────────────────────────────────────────┘
```

**TDD for MSP Portal:**
```
TEST: "should show aggregate stats across all tenants"
TEST: "should allow one-click switch to tenant context"
TEST: "should enforce MSP-tenant relationship validation"
TEST: "should generate per-tenant billing reports"
TEST: "should support white-label branding options"
```

### 2.4 End-User Self-Service Portal

**User View (non-admin):**
```
┌─────────────────────────────────────────────────────────────┐
│  MY QUARANTINED EMAILS                                      │
├─────────────────────────────────────────────────────────────┤
│  These emails were flagged as potential threats.            │
│  Request release if you recognize the sender.               │
│                                                             │
│  From: newsletter@company.com                               │
│  Subject: Weekly Update                                     │
│  Flagged: Unrecognized sender pattern                       │
│  [Request Release] [Confirm Threat]                         │
├─────────────────────────────────────────────────────────────┤
│  DIGEST SETTINGS                                            │
│  ☑ Send daily quarantine digest at 9:00 AM                 │
│  ☐ Notify me immediately for each quarantined email        │
└─────────────────────────────────────────────────────────────┘
```

**TDD for Self-Service:**
```
TEST: "should only show user's own quarantined emails"
TEST: "should require admin approval for release requests"
TEST: "should send configurable digest emails"
```

**Deliverables:**
- [ ] Dashboard redesign complete
- [ ] Quarantine with explainability
- [ ] MSP portal functional
- [ ] End-user self-service live
- [ ] Usability testing passed (5+ users)

---

## Phase 3: MSP Portal Hardening

**Timeline:** Week 4-5
**Success Criteria:** MSPs can onboard and manage clients autonomously

### 3.1 Tenant Onboarding Wizard

```
Step 1: Basic Info
┌─────────────────────────────────────────┐
│ Company Name: [____________]            │
│ Primary Contact: [____________]         │
│ Email Domain(s): [____________] [+Add]  │
│                                         │
│ [Next →]                                │
└─────────────────────────────────────────┘

Step 2: Integration Setup
┌─────────────────────────────────────────┐
│ Connect Email Provider:                 │
│                                         │
│ [🔵 Google Workspace]  [Connect →]      │
│ [🟦 Microsoft 365]     [Connect →]      │
│                                         │
│ ✅ OAuth connected successfully         │
│                                         │
│ [← Back] [Next →]                       │
└─────────────────────────────────────────┘

Step 3: Initial Scan
┌─────────────────────────────────────────┐
│ Scanning mailboxes...                   │
│ ████████████░░░░░░░░ 60%               │
│                                         │
│ Found: 12 potential threats             │
│ Scanned: 1,847 emails                   │
│                                         │
│ [Skip to Dashboard] [Wait for Complete] │
└─────────────────────────────────────────┘
```

**TDD for Onboarding:**
```
TEST: "should validate email domain ownership"
TEST: "should handle OAuth flow errors gracefully"
TEST: "should queue initial mailbox scan"
TEST: "should send welcome email with quick start guide"
```

### 3.2 White-Label Configuration

**MSP Branding Settings:**
```
┌─────────────────────────────────────────────────────────────┐
│  WHITE-LABEL SETTINGS                                       │
├─────────────────────────────────────────────────────────────┤
│  Logo: [Upload]  📎 logo.png (uploaded)                    │
│  Primary Color: [#1a73e8] 🎨                               │
│  Company Name: [SecureMail Pro]                            │
│  Support Email: [support@yourcompany.com]                  │
│  Custom Domain: [security.yourcompany.com]                 │
│                                                             │
│  PREVIEW:                                                   │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 🛡️ SecureMail Pro                    [Dashboard]       ││
│  └─────────────────────────────────────────────────────────┘│
│                                                             │
│  [Save Settings]                                            │
└─────────────────────────────────────────────────────────────┘
```

**TDD for White-Label:**
```
TEST: "should apply MSP branding to all tenant views"
TEST: "should support custom domain CNAME setup"
TEST: "should include MSP branding in email notifications"
```

### 3.3 MSP Billing Integration

**Billing Dashboard:**
```
┌─────────────────────────────────────────────────────────────┐
│  BILLING & USAGE                        [Export Report]     │
├─────────────────────────────────────────────────────────────┤
│  Current Period: January 2026                               │
│                                                             │
│  Tenant          │ Mailboxes │ Plan    │ Your Cost │ Margin │
│  ────────────────────────────────────────────────────────── │
│  Acme Corp       │ 150       │ Pro     │ $375.00   │ 40%    │
│  Smith LLC       │ 45        │ Starter │ $112.50   │ 35%    │
│  Jones & Co      │ 80        │ Pro     │ $200.00   │ 40%    │
│  ────────────────────────────────────────────────────────── │
│  TOTAL           │ 275       │         │ $687.50   │ $275   │
│                                                             │
│  💳 Next invoice: Feb 1, 2026                              │
│  [Update Payment Method] [View Invoice History]             │
└─────────────────────────────────────────────────────────────┘
```

**Deliverables:**
- [ ] Tenant onboarding wizard
- [ ] White-label configuration
- [ ] Per-tenant billing tracking
- [ ] MSP margin reporting
- [ ] Automated invoice generation

---

## Phase 4: Pricing & Stripe Integration

**Timeline:** Week 5-6
**Success Criteria:** Self-service signup and payment working

### 4.1 Pricing Tiers (Based on Research)

| Tier | Price/mailbox/mo | Features | Target |
|------|------------------|----------|--------|
| **Starter** | $2.50 | Basic detection, 7-day quarantine, email support | <50 mailboxes |
| **Professional** | $4.00 | + Advanced detection, API access, 30-day retention | 50-500 mailboxes |
| **Business** | $6.00 | + Custom rules, priority support, SIEM integration | 500+ mailboxes |
| **Enterprise** | Custom | + Dedicated support, SLA, custom integrations | 1000+ mailboxes |
| **MSP** | $2.00-4.00 | 30-50% margin, white-label, multi-tenant | Partners |

### 4.2 Stripe Integration Architecture

```typescript
// lib/billing/stripe-service.ts

interface StripeService {
  // Customer management
  createCustomer(tenant: Tenant): Promise<Stripe.Customer>;
  updateCustomer(tenantId: string, data: UpdateData): Promise<void>;

  // Subscription management
  createSubscription(tenantId: string, plan: PricingTier): Promise<Stripe.Subscription>;
  updateSubscription(subscriptionId: string, newPlan: PricingTier): Promise<void>;
  cancelSubscription(subscriptionId: string): Promise<void>;

  // Usage-based billing
  reportUsage(tenantId: string, mailboxCount: number): Promise<void>;

  // Webhooks
  handleWebhook(event: Stripe.Event): Promise<void>;
}
```

**TDD for Stripe:**
```
TEST: "should create Stripe customer on tenant signup"
TEST: "should sync mailbox count for usage billing"
TEST: "should handle payment failures gracefully"
TEST: "should downgrade access on subscription cancellation"
TEST: "should process refunds for billing errors"
```

### 4.3 Self-Service Signup Flow

```
Step 1: Choose Plan
┌─────────────────────────────────────────────────────────────┐
│  Choose Your Plan                                           │
│                                                             │
│  ┌─────────┐  ┌─────────────┐  ┌──────────┐               │
│  │ Starter │  │ Professional│  │ Business │               │
│  │ $2.50   │  │ $4.00 ⭐    │  │ $6.00    │               │
│  │ /user   │  │ /user       │  │ /user    │               │
│  │         │  │ POPULAR     │  │          │               │
│  │[Select] │  │ [Select]    │  │ [Select] │               │
│  └─────────┘  └─────────────┘  └──────────┘               │
│                                                             │
│  All plans include 14-day free trial                       │
└─────────────────────────────────────────────────────────────┘

Step 2: Account Setup
┌─────────────────────────────────────────────────────────────┐
│  Create Your Account                                        │
│                                                             │
│  Work Email: [____________]                                │
│  Company Name: [____________]                              │
│  Password: [____________]                                  │
│                                                             │
│  [Continue with Google] or [Create Account]                │
└─────────────────────────────────────────────────────────────┘

Step 3: Payment
┌─────────────────────────────────────────────────────────────┐
│  Payment Details                                            │
│                                                             │
│  [Stripe Elements Card Input]                              │
│                                                             │
│  ☑ I agree to Terms of Service and Privacy Policy          │
│                                                             │
│  Summary:                                                   │
│  Professional Plan - 14-day trial then $4.00/user/month    │
│  Estimated: 50 mailboxes = $200/month                      │
│                                                             │
│  [Start Free Trial]                                        │
└─────────────────────────────────────────────────────────────┘
```

### 4.4 Billing Database Schema

```sql
-- New billing tables
CREATE TABLE subscriptions (
  id UUID PRIMARY KEY,
  tenant_id UUID REFERENCES tenants(id),
  stripe_subscription_id TEXT UNIQUE,
  stripe_customer_id TEXT,
  plan_tier TEXT NOT NULL,
  status TEXT NOT NULL, -- 'active', 'trialing', 'past_due', 'canceled'
  current_period_start TIMESTAMP,
  current_period_end TIMESTAMP,
  mailbox_count INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE invoices (
  id UUID PRIMARY KEY,
  tenant_id UUID REFERENCES tenants(id),
  stripe_invoice_id TEXT UNIQUE,
  amount_cents INTEGER,
  status TEXT, -- 'draft', 'open', 'paid', 'void'
  period_start TIMESTAMP,
  period_end TIMESTAMP,
  pdf_url TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE usage_records (
  id UUID PRIMARY KEY,
  tenant_id UUID REFERENCES tenants(id),
  recorded_at TIMESTAMP DEFAULT NOW(),
  mailbox_count INTEGER,
  threats_blocked INTEGER,
  emails_processed INTEGER
);
```

**Deliverables:**
- [ ] Stripe integration complete
- [ ] Self-service signup flow
- [ ] Usage-based billing working
- [ ] Invoice generation automated
- [ ] Payment failure handling
- [ ] Subscription management UI

---

## Phase 5: Production Launch Checklist

**Timeline:** Week 6-7
**Success Criteria:** Production deployment with monitoring

### 5.1 Infrastructure Checklist

- [ ] **Vercel Production Environment**
  - [ ] Environment variables configured
  - [ ] Custom domain with SSL
  - [ ] Edge functions optimized
  - [ ] Rate limiting enabled

- [ ] **Neon PostgreSQL**
  - [ ] Production database provisioned
  - [ ] Connection pooling configured
  - [ ] Automated backups verified
  - [ ] Read replicas for reporting

- [ ] **Security Hardening**
  - [ ] All Phase 0 fixes deployed
  - [ ] Penetration test completed
  - [ ] SOC 2 Type 1 preparation
  - [ ] GDPR compliance verified

### 5.2 Monitoring & Alerting

```yaml
# Required alerts
alerts:
  - name: cross_tenant_access_attempt
    condition: "any request accessing data from different tenant"
    severity: critical
    action: page_on_call

  - name: high_false_positive_rate
    condition: "FP rate > 0.5% over 1 hour"
    severity: warning
    action: slack_notification

  - name: detection_pipeline_latency
    condition: "p95 latency > 5s"
    severity: warning
    action: slack_notification

  - name: payment_failure
    condition: "Stripe webhook payment_failed"
    severity: high
    action: email_customer_success
```

### 5.3 Documentation & Support

- [ ] **User Documentation**
  - [ ] Getting started guide
  - [ ] Admin configuration guide
  - [ ] MSP onboarding guide
  - [ ] API documentation

- [ ] **Support Runbooks**
  - [ ] False positive escalation
  - [ ] Integration troubleshooting
  - [ ] Billing dispute resolution
  - [ ] Security incident response

### 5.4 Launch Sequence

```
T-7 days:  Final security audit
T-5 days:  Load testing (10x expected traffic)
T-3 days:  Staging environment freeze
T-2 days:  Production deployment
T-1 day:   Smoke testing & monitoring verification
T-0:       Public launch
T+1 day:   24/7 on-call monitoring
T+7 days:  First week retrospective
```

### 5.5 Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Uptime | 99.9% | Vercel status page |
| Detection latency | <3s p95 | Datadog APM |
| False positive rate | <0.1% | Internal dashboard |
| Customer support response | <4 hours | Intercom metrics |
| Trial-to-paid conversion | >15% | Stripe analytics |
| Net promoter score | >50 | Post-onboarding survey |

---

## Appendix A: Test Coverage Requirements

```
Minimum coverage by phase:
├── Phase 0 (Security): 100% coverage
├── Phase 1 (Detection): 90% coverage
├── Phase 2 (UX): 80% coverage (E2E tests)
├── Phase 3 (MSP): 85% coverage
├── Phase 4 (Billing): 95% coverage
└── Phase 5 (Integration): 90% coverage

Test types required:
├── Unit tests (Vitest)
├── Integration tests (Vitest + test DB)
├── E2E tests (Playwright)
├── Security tests (custom + OWASP ZAP)
└── Load tests (k6)
```

## Appendix B: SPARC Phase Mapping

| Phase | SPARC Stage | Primary Activities |
|-------|-------------|-------------------|
| 0 | Specification + Refinement | Security requirements, vulnerability fixes |
| 1 | Refinement | Detection tuning, feedback loop |
| 2 | Architecture + Completion | UX redesign, component architecture |
| 3 | Completion | MSP features, integration |
| 4 | Completion | Billing integration |
| 5 | Completion | Production deployment |

## Appendix C: Resource Allocation

**Recommended Team:**
- 1 Security Engineer (Phase 0-1)
- 2 Full-stack Engineers (Phase 2-4)
- 1 DevOps Engineer (Phase 5)
- 1 UX Designer (Phase 2 consultation)

**Timeline:** 6-7 weeks to production launch

---

*This plan was generated based on comprehensive research including competitor analysis (Barracuda, Proofpoint, Abnormal), pricing models, false positive audit, and cross-tenant security review.*
