# Swordphish Acquisition Due Diligence Report

**Date**: 2026-01-07
**Reviewers**: HFL Technical Team
**Purpose**: Validate product claims before Sophos discussions

---

## Executive Summary

**Overall Assessment**: MIXED - Solid core with significant gaps and misrepresentations
**Production Readiness**: 65-70% - Not ready for enterprise deployment
**Risk Level**: MEDIUM-HIGH for Sophos discussions

### The Good News

| Area | Assessment |
|------|------------|
| Detection Pipeline | 85% complete - deterministic layer, LLM (Claude), threat intel all solid |
| BEC Detection | EXCELLENT - 7 attack categories, 100+ patterns, VIP lists (bonus, not even in pitch) |
| O365 Integration | PRODUCTION-READY - Real Graph API, webhooks, quarantine |
| Gmail Integration | PRODUCTION-READY - Real API, Pub/Sub, label-based quarantine |
| Auth/RBAC | PRODUCTION-READY - Clerk, 4-tier RBAC, MSP multi-tenant, API keys |
| Frontend | 90% complete - 28 pages, real data fetching, Cmd+K switcher |
| Test Coverage | EXCEEDS CLAIMS - 44 test files vs. "12+ suites" claimed |

### Critical Issues (Deal Discussion Points)

#### SECURITY VULNERABILITIES (HIGH SEVERITY)

| Issue | Impact |
|-------|--------|
| **OAuth tokens in PLAINTEXT** | SOC2 failure, compliance blocker. Code has `// TODO: Encrypt` comments. |
| **RLS enabled but NO policies** | Tenant isolation is app-level only. One missing WHERE clause = data leak. |
| **LLM rate limiting not enforced** | Config exists but never checked. Unbounded Claude API costs possible. |

#### MATERIAL MISREPRESENTATIONS (RED FLAGS FOR SOPHOS)

| Claim | Reality |
|-------|---------|
| **"SMTP Gateway written in Go"** | **DOES NOT EXIST.** Zero Go files in repo. Only a webhook receiver exists. |
| **"ML Classification models"** | Actually weighted rule-based scoring. No .model/.pkl/.pt files. |
| **"Sandbox VM detonation"** | API client stub only. Pipeline checks file extensions, never calls sandbox. |
| **"Drizzle ORM"** | Not used. All queries are raw SQL with manual TypeScript interfaces. |
| **"QR phishing detection"** | Completely missing. Claimed in pitch but zero code. |
| **"Warning banner injection"** | Not implemented for O365/Gmail. |

#### NOT REVENUE-READY

| Issue | Status |
|-------|--------|
| Stripe integration | SDK implemented but NOT CONNECTED (placeholder keys) |
| Stripe webhook route | Handler exists, no API route exposes it |
| Price IDs | Placeholders like `price_free`, not real Stripe products |
| Two pricing systems | `stripe.ts`: $0/$99/$299 vs `usage.ts`: $99/$499/$1999 |
| PDF reports | Returns HTML, no actual PDF conversion |

### Risk Matrix for Sophos Discussion

| Risk | Severity | Mitigation Effort |
|------|----------|-------------------|
| SMTP Gateway claims | **CRITICAL** | Would need to build from scratch (Go MTA = months) |
| Token encryption | **HIGH** | 1-2 weeks |
| Sandbox integration | **HIGH** | Need VirusTotal/Hybrid Analysis API keys + integration (2-4 weeks) |
| Billing connection | **MEDIUM** | 2-3 weeks (Stripe setup, webhooks, pricing alignment) |
| ML model training | **MEDIUM** | Current rule-based approach works; real ML is months |
| QR phishing | **LOW** | 1-2 weeks with image processing library |

### Bottom Line

**What Corn Built**: A legitimate ~70% complete email security platform with excellent BEC detection, working cloud integrations (O365/Gmail), solid auth, and good test coverage.

**What Corn Claimed**: A production-ready platform with features that don't exist (SMTP gateway, sandbox, ML models).

**Recommendation for Sophos Call**:
1. Do NOT claim SMTP gateway capability
2. Reframe "ML" as "heuristic classification with ML infrastructure ready"
3. Acknowledge sandbox as "integration-ready" not "implemented"
4. Fix OAuth token encryption BEFORE any technical diligence
5. Price the product appropriately for its actual state

---

## 1. Detection Pipeline (Claimed: 5-Layer System)

### Claims to Validate:
- [x] Layer 1: Deterministic (SPF/DKIM/DMARC, headers, domain age, homoglyphs, URL analysis, attachment analysis, QR phishing)
- [~] Layer 2: ML Classification (phishing/BEC models, sender anomaly, thread context)
- [x] Layer 3: LLM Analysis (Claude 3.5 Haiku integration, intent analysis, explanations)
- [x] Layer 4: Threat Intel (PhishTank, URLhaus, OpenPhish, WHOIS)
- [~] Layer 5: Sandbox (VM detonation, behavioral analysis, IOC extraction)

### Findings:

**OVERALL VERDICT: MOSTLY IMPLEMENTED (~85%)**

The detection pipeline is well-architected with real algorithmic logic, but some claimed features are stubs or missing. The core is solid.

---

#### LAYER 1: DETERMINISTIC ANALYSIS - [x] IMPLEMENTED

**File:** `/home/willy/hfl-projects/swordfish/lib/detection/deterministic.ts` (501 lines)
**File:** `/home/willy/hfl-projects/swordfish/lib/detection/parser.ts` (285 lines)

| Capability | Status | Evidence |
|------------|--------|----------|
| SPF/DKIM/DMARC verification | [x] IMPLEMENTED | Lines 126-191 - `analyzeAuthentication()` parses Authentication-Results header, assigns scores (SPF fail=20, DKIM fail=15, DMARC fail=30) |
| Header anomaly detection | [x] IMPLEMENTED | Lines 265-289 - `analyzeHeaders()` checks From/Reply-To mismatch, missing Message-ID |
| Display name spoofing | [x] IMPLEMENTED | Lines 457-476 - `detectDisplayNameSpoof()` checks brand impersonation + authority terms (CEO, CFO) with freemail |
| Domain homoglyph detection | [x] IMPLEMENTED | Lines 396-434 - `detectHomoglyph()` with comprehensive homoglyph map (Lines 30-58) including Cyrillic chars |
| Cousin domain detection | [x] IMPLEMENTED | Lines 439-452 - `detectCousinDomain()` checks if domain contains brand name |
| Domain age/reputation | [x] IMPLEMENTED | Deferred to Layer 4 threat intel, integrated via `/lib/threat-intel/domain/age.ts` (279 lines) with WHOIS lookups |
| URL lexical analysis | [x] IMPLEMENTED | Lines 337-391 - `analyzeUrls()` checks IP URLs, suspicious patterns, shorteners, data:/javascript: protocols |
| Attachment static analysis | [~] PARTIAL | Lines 411-455 in pipeline.ts - checks file extensions only (exe, docm, zip) - NO actual file content analysis |
| QR-code phishing detection | [ ] MISSING | No implementation found. Grep for "qr" only shows doc references, no actual code |

**Quality Assessment:** Real algorithmic logic with proper scoring (0-100), detailed signal types, and comprehensive pattern matching.

---

#### LAYER 2: ML CLASSIFICATION - [~] PARTIAL IMPLEMENTATION

**File:** `/home/willy/hfl-projects/swordfish/lib/detection/ml/classifier.ts` (621 lines)
**File:** `/home/willy/hfl-projects/swordfish/lib/ml/training-pipeline.ts` (614 lines)

| Capability | Status | Evidence |
|------------|--------|----------|
| Phishing classification | [~] RULE-BASED | Lines 109-152 - `classifyEmail()` uses feature extraction + weighted scoring, NOT a trained ML model |
| BEC classification | [~] RULE-BASED | Line 590 - category determination via signal analysis, not neural network |
| Sender anomaly detection | [x] IMPLEMENTED | Lines 305-334 - `checkDisplayNameMismatch()` with fuzzy parsing |
| Thread context analysis | [ ] MISSING | Only checks `Re:` prefix (line 192), no actual thread history analysis |
| Grammar anomalies | [x] IMPLEMENTED | Lines 244-263 - `calculateGrammarScore()` checks caps ratio, punctuation, spam patterns |
| Feature extraction | [x] IMPLEMENTED | Lines 157-226 - `extractFeatures()` extracts 17+ features (urgency, threats, links, attachments) |

**CRITICAL FINDING:** There are **NO trained ML model files** (.model, .pkl, .pt, .onnx) in the codebase. The "ML classifier" is actually a **rule-based scoring system** using hand-crafted features and weights. The training pipeline (`/lib/ml/training-pipeline.ts`) is infrastructure for **future ML** but produces simulated metrics (line 380: "Simulated metrics for now").

**Code Evidence (classifier.ts lines 129-134):**
```typescript
const rawScore =
  textScore * weights.text +          // 0.25
  structuralScore * weights.structural + // 0.20
  senderScore * weights.sender +      // 0.25
  contentScore * weights.content +    // 0.15
  behavioralScore * weights.behavioral; // 0.15
```

This is weighted feature scoring, not ML inference.

---

#### LAYER 3: LLM ANALYSIS - [x] IMPLEMENTED

**File:** `/home/willy/hfl-projects/swordfish/lib/detection/llm.ts` (339 lines)

| Capability | Status | Evidence |
|------------|--------|----------|
| Claude integration | [x] IMPLEMENTED | Lines 6-9, 99-109 - Real Anthropic SDK usage with `claude-3-5-haiku-20241022` |
| BEC pattern detection | [x] IMPLEMENTED | Lines 12-71 - Comprehensive system prompt for wire fraud, gift cards, invoice fraud, payroll, impersonation |
| Human-readable explanations | [x] IMPLEMENTED | Lines 237-279 - `convertToSignals()` extracts explanation and recommendation from LLM response |
| Intent analysis | [x] IMPLEMENTED | System prompt lines 26-60 covers BEC attack patterns with detailed guidance |
| Conditional invocation | [x] IMPLEMENTED | Lines 324-338 - `shouldInvokeLLM()` only calls LLM when score 30-70 or ML confidence uncertain |

**Quality Assessment:** Production-ready LLM integration with proper error handling, token estimation, JSON response parsing, and cost optimization (conditional invocation).

---

#### LAYER 4: THREAT INTELLIGENCE - [x] IMPLEMENTED

**File:** `/home/willy/hfl-projects/swordfish/lib/threat-intel/feeds/index.ts` (378 lines)
**File:** `/home/willy/hfl-projects/swordfish/lib/threat-intel/feeds/phishtank.ts` (238 lines)
**File:** `/home/willy/hfl-projects/swordfish/lib/threat-intel/feeds/urlhaus.ts` (181 lines)
**File:** `/home/willy/hfl-projects/swordfish/lib/threat-intel/feeds/openphish.ts` (154 lines)
**File:** `/home/willy/hfl-projects/swordfish/lib/threat-intel/domain/age.ts` (279 lines)
**File:** `/home/willy/hfl-projects/swordfish/lib/threat-intel/ip/blocklists.ts` (452 lines)

| Capability | Status | Evidence |
|------------|--------|----------|
| PhishTank integration | [x] IMPLEMENTED | Lines 87-122 in phishtank.ts - Real API fetch with fallback to pattern-based detection + 25 sample URLs |
| URLhaus integration | [x] IMPLEMENTED | Lines 49-93 in urlhaus.ts - Real JSON API fetch from abuse.ch |
| OpenPhish integration | [x] IMPLEMENTED | Lines 22-52 in openphish.ts - Real feed.txt fetch |
| Feed aggregation | [x] IMPLEMENTED | feeds/index.ts - Unified `checkUrlReputation()` checking all 3 feeds |
| Domain age/WHOIS | [x] IMPLEMENTED | domain/age.ts Lines 60-169 - `checkDomainAge()` with WHOIS lookup, risk thresholds (7d critical, 30d high) |
| IP blocklists | [x] IMPLEMENTED | ip/blocklists.ts - 5 DNSBL sources (Spamhaus, Barracuda, SORBS, SpamCop, UCEPROTECT) |
| Caching | [x] IMPLEMENTED | `/lib/threat-intel/cache.ts` - ThreatFeedCache with TTLs |

**Quality Assessment:** Real feed integrations with proper fallbacks, caching, and batch processing. PhishTank note: "API registration closed" - using pattern-based fallback.

---

#### LAYER 5: SANDBOX - [~] STUB/SCAFFOLDING

**File:** `/home/willy/hfl-projects/swordfish/lib/threat-intel/sandbox.ts` (380 lines)
**File:** `/home/willy/hfl-projects/swordfish/lib/detection/pipeline.ts` Lines 386-455

| Capability | Status | Evidence |
|------------|--------|----------|
| Attachment detonation | [~] API STUB | sandbox.ts - `SandboxService` class with provider configs but NO actual detonation logic |
| VM behavioral analysis | [ ] NOT IMPLEMENTED | All methods just make HTTP calls to undefined endpoints (line 83: `baseUrl || ''`) |
| IOC extraction | [~] STUB | Lines 238-256 - `getBehaviors()` and `getMitreTechniques()` just parse API responses |
| Hash checking | [~] STUB | Lines 262-295 - `checkHash()` calls external API |
| File analysis in pipeline | [~] EXTENSION-ONLY | pipeline.ts Lines 410-444 - Only checks file extensions, doesn't invoke sandbox service |

**Code Evidence (sandbox.ts line 88-89):**
```typescript
baseUrl: config.baseUrl || PROVIDER_URLS[config.provider] || '',
// PROVIDER_URLS maps to external APIs: 'hybrid-analysis', 'virustotal', etc.
```

**CRITICAL FINDING:** The sandbox is an **API client scaffold**, not an actual sandbox implementation. It expects external services (VirusTotal, Hybrid Analysis, etc.) but there's no API key configuration or actual integration. The pipeline's `runSandboxAnalysis()` (Lines 386-455) only checks file extensions - it NEVER calls the sandbox service.

---

#### BEC DETECTION - [x] BONUS LAYER (NOT IN CLAIMS)

**File:** `/home/willy/hfl-projects/swordfish/lib/detection/bec/detector.ts` (360 lines)
**File:** `/home/willy/hfl-projects/swordfish/lib/detection/bec/patterns.ts` (455 lines)
**File:** `/home/willy/hfl-projects/swordfish/lib/detection/bec/impersonation.ts` (395 lines)
**File:** `/home/willy/hfl-projects/swordfish/lib/detection/bec/vip-list.ts` (469 lines)

**This is EXCELLENT work not even in the product claims:**
- Wire fraud pattern detection (keywords + regex)
- Gift card scam detection
- Invoice fraud detection
- Payroll diversion detection
- Urgency/secrecy/authority manipulation
- Executive impersonation via VIP list
- Unicode homoglyph detection (Cyrillic chars)
- Domain lookalike with Levenshtein distance
- Compound attack detection (multiple vectors)
- Financial amount extraction and risk assessment

**Quality Assessment:** Production-grade BEC detection with 7 attack categories, 100+ patterns, and VIP/executive list management.

---

### SUMMARY TABLE

| Layer | Claimed | Actual Status | Gap Severity |
|-------|---------|---------------|--------------|
| 1. Deterministic | SPF/DKIM/DMARC, homoglyphs, URL analysis | Fully implemented except QR phishing | LOW (QR is niche) |
| 2. ML Classification | ML models, trained classifier | Rule-based scoring system, no trained models | MEDIUM (marketing vs reality) |
| 3. LLM Analysis | Claude 3.5 Haiku | Fully implemented with proper SDK | NONE |
| 4. Threat Intel | PhishTank, URLhaus, OpenPhish, WHOIS | All implemented with real API calls | NONE |
| 5. Sandbox | VM detonation, behavioral analysis | API client stub only, not integrated | HIGH |
| BEC Detection | (Not claimed) | Excellent implementation | BONUS |

### CRITICAL GAPS

1. **QR Phishing Detection:** Completely missing despite being in product claims
2. **ML Models:** No trained models - "ML Classification" is actually weighted feature scoring
3. **Sandbox:** Stub code only - no actual attachment detonation capability
4. **Thread Context:** Only checks Re: prefix, no actual conversation history analysis

### FILES REVIEWED

- `/home/willy/hfl-projects/swordfish/lib/detection/pipeline.ts` (752 lines) - Main orchestrator
- `/home/willy/hfl-projects/swordfish/lib/detection/deterministic.ts` (501 lines)
- `/home/willy/hfl-projects/swordfish/lib/detection/llm.ts` (339 lines)
- `/home/willy/hfl-projects/swordfish/lib/detection/ml/classifier.ts` (621 lines)
- `/home/willy/hfl-projects/swordfish/lib/detection/bec/*.ts` (4 files, ~1700 lines)
- `/home/willy/hfl-projects/swordfish/lib/threat-intel/*.ts` (11 files, ~2500 lines)
- `/home/willy/hfl-projects/swordfish/lib/ml/training-pipeline.ts` (614 lines)
- `/home/willy/hfl-projects/swordfish/lib/detection/reputation/service.ts` (746 lines)

---

## 2. Email Integrations (Claimed: O365, Gmail, SMTP Gateway)

### Claims to Validate:
- [x] Microsoft 365: Graph API subscriptions, real-time webhooks, quarantine, banner injection
- [x] Google Workspace: Gmail API, Pub/Sub watch, label-based quarantine
- [ ] SMTP Gateway: Inline MTA (Go), block/forward, DKIM signing

### Findings:

> [Agent 2 findings here]

---

## 3. Database & Multi-Tenancy

### Claims to Validate:
- [ ] Neon PostgreSQL serverless setup
- [ ] Drizzle ORM schema matching ARCHITECTURE.md
- [ ] Row-level security (RLS) implemented
- [ ] Tenant isolation verified
- [ ] MSP access grants table

### Findings:

> [Agent 3 findings here]

---

## 4. API Completeness

### Claims to Validate:
- [ ] /api/tenants CRUD
- [ ] /api/tenants/:id/policies
- [ ] /api/tenants/:id/integrations (o365, gmail, smtp)
- [ ] /api/analyze (decision engine)
- [ ] /api/verdicts
- [ ] /api/audit
- [ ] Webhook endpoints for O365/Gmail

### Findings:

> [Agent 4 findings here]

---

## 5. Authentication & RBAC

### Claims to Validate:
- [ ] Clerk integration working
- [ ] Multi-tenant org support
- [ ] RBAC roles: msp_admin, tenant_admin, analyst, viewer
- [ ] MSP cross-tenant access controls
- [ ] API key authentication

### Findings:

> [Agent 5 findings here]

---

## 6. Billing & Stripe Integration

### Claims to Validate:
- [x] Stripe integration implemented
- [x] Usage tracking per tenant
- [~] Plan tiers (Starter $99, Pro $499, Enterprise $1999+)
- [x] Overage billing logic
- [~] LLM call rate limiting by plan

### Findings:

**Overall Assessment: PARTIALLY IMPLEMENTED - Not Production-Ready**

The billing system has well-structured code but critical gaps prevent it from being production-ready. The foundation is solid, but key integrations are missing.

---

#### 1. Stripe Integration: IMPLEMENTED BUT NOT CONNECTED

**Files Reviewed:**
- `/home/willy/hfl-projects/swordfish/lib/billing/stripe.ts` (432 lines)
- `/home/willy/hfl-projects/swordfish/lib/billing/index.ts` (6 lines - exports only)
- `/home/willy/hfl-projects/swordfish/tests/billing/stripe.test.ts` (561 lines)

**What EXISTS:**
- `BillingService` class with full Stripe SDK integration (`stripe` v20.1.0 in package.json)
- Customer management: `createCustomer`, `getCustomer`, `updateCustomer`
- Subscription lifecycle: `createSubscription`, `upgradeSubscription`, `downgradeSubscription`, `cancelSubscription`, `resumeSubscription`
- Checkout: `createCheckoutSession`, `createBillingPortalSession`
- Invoice management: `listInvoices`, `getInvoice`
- Webhook handler with events: `customer.subscription.created/updated/deleted`, `invoice.payment_succeeded/failed`
- `UsageTracker` class for metered billing with Stripe Meter Events API
- Comprehensive test coverage (561 lines of mocked tests)

**CRITICAL GAPS:**
1. **Placeholder API key**: Code uses `'sk_test_placeholder'` as fallback - NO real Stripe account configured
2. **Placeholder Price IDs**: `price_free`, `price_pro_monthly` are placeholder strings, not real Stripe price IDs
3. **No Webhook Route**: No `/api/webhooks/stripe/route.ts` exists - webhook handler is implemented but never exposed
4. **No API Routes**: `BillingService` is never imported or used anywhere in `/app/api/` routes
5. **In-memory UsageTracker**: Usage data stored in memory array, not persisted to database
6. **Env vars commented out**: `.env.example` shows Stripe keys as OPTIONAL: `# STRIPE_SECRET_KEY=`

```typescript
// From stripe.ts - placeholder credentials
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder', {
  apiVersion: '2025-12-15.clover',
});

// Placeholder price IDs - not real Stripe products
const PRICE_IDS: Record<SubscriptionTier, { monthly: string; annual: string }> = {
  free: { monthly: 'price_free', annual: 'price_free' },
  pro: { monthly: 'price_pro_monthly', annual: 'price_pro_annual' },
  enterprise: { monthly: 'price_enterprise_monthly', annual: 'price_enterprise_annual' },
};
```

---

#### 2. Plan Tiers: MISMATCH WITH CLAIMS

**Claimed Pricing:**
- Starter: $99/mo, 25 users, 10K emails
- Pro: $499/mo, 250 users, 100K emails
- Enterprise: $1999+/mo, unlimited

**Implemented in `/lib/billing/stripe.ts`:**
```typescript
const PRICING: Record<SubscriptionTier, { monthly: number; annual: number }> = {
  free: { monthly: 0, annual: 0 },               // NOT IN CLAIMS
  pro: { monthly: 9900, annual: 99000 },         // $99/mo - MISMATCH (claimed $499)
  enterprise: { monthly: 29900, annual: 299000 }, // $299/mo - MISMATCH (claimed $1999+)
};
```

**Implemented in `/lib/msp/usage.ts` (different values!):**
```typescript
const PLAN_LIMITS = {
  starter: { users: 25, emailsPerMonth: 10000, basePrice: 99 },   // MATCHES claims
  pro: { users: 250, emailsPerMonth: 100000, basePrice: 499 },    // MATCHES claims
  enterprise: { users: Infinity, emailsPerMonth: Infinity, basePrice: 1999 }, // MATCHES claims
};
```

**PROBLEM:** Two different pricing systems exist:
1. `stripe.ts` uses `free/pro/enterprise` with $0/$99/$299 pricing
2. `msp/usage.ts` uses `starter/pro/enterprise` with $99/$499/$1999 pricing

These are INCONSISTENT and not linked together.

---

#### 3. Usage Tracking: WELL IMPLEMENTED

**Files Reviewed:**
- `/home/willy/hfl-projects/swordfish/lib/msp/usage.ts` (377 lines)
- `/home/willy/hfl-projects/swordfish/app/api/msp/usage/route.ts` (126 lines)
- `/home/willy/hfl-projects/swordfish/tests/msp/usage.test.ts` (500 lines)

**What EXISTS:**
- `getTenantUsage()` - queries database for email stats, user counts, API requests
- `getAllTenantsUsage()` - aggregates usage across multiple tenants
- `generateBillingExport()` - creates billing reports with overage calculations
- `billingExportToCSV()` - exports billing data to CSV format
- `getUsageTrends()` - historical usage trends
- API endpoint at `/api/msp/usage` with authentication and tenant authorization

**Usage Metrics Tracked:**
- Emails: total, scanned, threats, quarantined, delivered
- Users: total, active
- Storage: used MB, limit MB
- API: requests, errors
- Features: linkRewriting, bannerInjection, advancedAnalysis

**WHAT WORKS:**
- Database queries are real (using Neon PostgreSQL)
- API endpoint is protected with Clerk auth
- MSP users can view all tenants; regular users see only their tenant
- CSV export properly formatted with headers and totals

---

#### 4. Overage Billing: IMPLEMENTED (CALCULATION ONLY)

**From `/lib/msp/usage.ts`:**
```typescript
const PLAN_LIMITS = {
  starter: {
    users: 25,
    emailsPerMonth: 10000,
    basePrice: 99,
    overagePerEmail: 0.001,   // $0.001 per email over limit
    overagePerUser: 2,        // $2 per user over limit
  },
  pro: {
    overagePerEmail: 0.0005,  // Lower rate for Pro
    overagePerUser: 1.5,
  },
  enterprise: {
    overagePerEmail: 0,       // No overage (unlimited)
    overagePerUser: 0,
  },
};
```

**LIMITATION:** This calculates overages for REPORTING only. It does NOT:
- Connect to Stripe metered billing
- Actually charge customers
- Block usage when limits exceeded

---

#### 5. LLM Rate Limiting: PARTIALLY IMPLEMENTED

**Configuration exists in:**
- `/lib/detection/types.ts`: `llmDailyLimitPerTenant: 100` (default)
- `.env.example`: `LLM_DAILY_LIMIT_PER_TENANT=100`
- Settings UI shows LLM daily limit field

**CRITICAL GAP:** The `llmDailyLimitPerTenant` config exists but IS NEVER ENFORCED. There is NO:
- Counter tracking LLM calls per tenant per day
- Check against `llmDailyLimitPerTenant` before calling Claude
- Plan-based LLM limits (100/500/custom mentioned in claims)
- Database table or Redis key for tracking daily LLM usage

---

#### 6. API Rate Limiting: WELL IMPLEMENTED (SEPARATE FROM BILLING)

**Files:** `/lib/api/rate-limit.ts`, `/lib/security/rate-limiting.ts`

```typescript
export const RATE_LIMITS = {
  starter: { maxRequests: 100, windowMs: 60 * 1000 },    // 100/min
  pro: { maxRequests: 500, windowMs: 60 * 1000 },       // 500/min
  enterprise: { maxRequests: 2000, windowMs: 60 * 1000 }, // 2000/min
};
```

**LIMITATION:** In-memory store (`Map<string, RateLimitEntry>`) - resets on server restart.

---

### Summary Table

| Feature | Status | Notes |
|---------|--------|-------|
| Stripe SDK Integration | Implemented | v20.1.0, full API coverage |
| Stripe Account Connected | **NOT IMPLEMENTED** | Placeholder keys only |
| Stripe Webhook Route | **NOT IMPLEMENTED** | Handler exists, no route |
| Price IDs Configured | **NOT IMPLEMENTED** | Placeholders only |
| Usage Tracking | Implemented | Database-backed, real queries |
| Overage Calculation | Implemented | For reporting only, no charging |
| Plan Enforcement | **NOT IMPLEMENTED** | No blocking when limits exceeded |
| LLM Rate Limiting | Configured | Limit exists but **NOT ENFORCED** |
| API Rate Limiting | Implemented | In-memory, needs Redis |
| MSP Billing Export | Implemented | CSV export, manual process |
| Automated Billing | **NOT IMPLEMENTED** | No automated charging |

---

### Risk Assessment

**HIGH RISK:**
1. No actual payment processing - company cannot collect revenue
2. LLM costs uncontrolled - no enforcement means unbounded Claude API spend
3. Pricing inconsistency - two different systems will confuse customers

**MEDIUM RISK:**
4. In-memory rate limiting - DoS possible after server restart
5. No Stripe webhooks - subscription changes won't sync

**Estimated Effort to Production:** 2-4 weeks of focused development

---

### Files Inventory

| File | Lines | Purpose |
|------|-------|---------|
| `/lib/billing/stripe.ts` | 432 | Stripe SDK wrapper, BillingService, UsageTracker |
| `/lib/msp/usage.ts` | 377 | Tenant usage tracking, billing export |
| `/lib/api/rate-limit.ts` | 172 | API rate limiting middleware |
| `/lib/security/rate-limiting.ts` | 406 | Core rate limiter classes |
| `/tests/billing/stripe.test.ts` | 561 | Billing test coverage |
| `/tests/msp/usage.test.ts` | 500 | Usage tracking tests |
| `/app/api/msp/usage/route.ts` | 126 | Usage API endpoint |

---

## 7. Frontend & Dashboard

### Claims to Validate:
- [x] Threat Inbox with verdicts/explanations
- [x] Real-time dashboard metrics
- [x] Quarantine management UI
- [x] Policy management UI
- [x] Integration status page
- [x] MSP multi-tenant switcher (Cmd+K)
- [~] Report generation (PDF) - PARTIAL
- [x] Audit log viewer

### Findings:

**ASSESSMENT: SUBSTANTIALLY COMPLETE - Production-Ready UI with Minor Gaps**

#### Dashboard Page Structure Analysis

**Direct Customer Dashboard (`/app/dashboard/`)** - 17 pages exist:
| Route | Status | Data Fetching | Notes |
|-------|--------|---------------|-------|
| `/dashboard/page.tsx` | COMPLETE | Real API + fallback demo data | Main dashboard with stats, recent threats, quick actions |
| `/dashboard/threats/page.tsx` | COMPLETE | Real API (`/api/threats`) | Full threat list with filtering, status badges, actions |
| `/dashboard/threats/bulk/page.tsx` | EXISTS | - | Bulk actions page |
| `/dashboard/quarantine/page.tsx` | COMPLETE | Real API (`/api/threats`) | Full quarantine management with bulk select/release/delete |
| `/dashboard/quarantine/bulk/page.tsx` | EXISTS | - | Bulk quarantine actions |
| `/dashboard/policies/page.tsx` | COMPLETE | Real API (`/api/policies`, `/api/lists`) | Policy management, allowlist/blocklist with CRUD |
| `/dashboard/integrations/page.tsx` | COMPLETE | Real API (`/api/integrations`) | O365/Gmail OAuth flow, sync triggers, connection status |
| `/dashboard/reports/page.tsx` | COMPLETE | Real API (`/api/reports/scheduled`, `/api/analytics/performance`) | Overview, scheduled reports, export tabs |
| `/dashboard/reports/scheduled/page.tsx` | COMPLETE | Real API | Create/manage scheduled reports (PDF/CSV/XLSX) |
| `/dashboard/reports/exports/page.tsx` | COMPLETE | Real API (`/api/reports/exports`) | Export history with download links |
| `/dashboard/reports/compliance/page.tsx` | EXISTS | - | Compliance reports |
| `/dashboard/analytics/page.tsx` | COMPLETE | Real API (`/api/analytics/overview`) | Full analytics with trends, threat types, verdict distribution |
| `/dashboard/emails/page.tsx` | EXISTS | - | Email viewer |
| `/dashboard/settings/page.tsx` | EXISTS | - | Tenant settings |
| `/dashboard/settings/webhooks/page.tsx` | EXISTS | - | Webhook configuration |
| `/dashboard/api-docs/page.tsx` | EXISTS | - | API documentation |
| `/dashboard/layout.tsx` | COMPLETE | - | Wraps with TenantProvider and DashboardLayout |

**MSP Admin Dashboard (`/app/admin/`)** - 11 pages exist:
| Route | Status | Data Fetching | Notes |
|-------|--------|---------------|-------|
| `/admin/page.tsx` | COMPLETE | Real API (`/api/admin/stats`) | MSP overview with tenant counts, emails processed, threats blocked |
| `/admin/tenants/page.tsx` | COMPLETE | Real API (`/api/admin/tenants`) | Full tenant list with search, filter by plan/status |
| `/admin/tenants/[id]/page.tsx` | EXISTS | - | Individual tenant view |
| `/admin/tenants/new/page.tsx` | EXISTS | - | Create new tenant |
| `/admin/threats/page.tsx` | COMPLETE | Real API (`/api/admin/threats`) | Cross-tenant threat view with stats, tenant breakdown, filtering |
| `/admin/quarantine/page.tsx` | EXISTS | - | Cross-tenant quarantine management |
| `/admin/reports/page.tsx` | COMPLETE | Real API (`/api/admin/reports`) | Full MSP analytics with trends, tenant comparison, threat breakdown |
| `/admin/policies/page.tsx` | EXISTS | - | Policy templates |
| `/admin/users/page.tsx` | EXISTS | - | User management |
| `/admin/audit/page.tsx` | COMPLETE | Real API (`/api/admin/audit`) | Full audit log with filtering, pagination, detail modal |
| `/admin/layout.tsx` | COMPLETE | Admin access verification | Header with navigation, access control |

#### Feature-by-Feature Validation

**1. Threat Inbox with Verdicts/Explanations** - VERIFIED
- Location: `/app/dashboard/threats/page.tsx`
- Features: Threat type badges (phishing, malware, spam, BEC), score visualization with progress bars, status badges (quarantined, released, deleted), explanation text from verdict
- Data: Real API at `/api/threats` with filtering by status
- Quality: Production-ready table UI with sorting, filtering, and actions

**2. Real-time Dashboard Metrics** - VERIFIED
- Location: `/app/dashboard/page.tsx`
- Uses custom hook: `/lib/hooks/use-dashboard-data.ts`
- Metrics shown: Threats Blocked (7d), Quarantine Pending, Emails Scanned, Detection Rate
- Data fetching: Parallel calls to `/api/dashboard/stats`, `/api/dashboard/threats`, `/api/dashboard/quarantine`
- Live polling: `useLiveStats` hook with configurable interval (default 30s)
- Demo mode: Gracefully shows demo data when no emails scanned yet

**3. Quarantine Management UI** - VERIFIED
- Location: `/app/dashboard/quarantine/page.tsx`
- Features:
  - Stats cards (quarantined count, released count, last 24h, avg score)
  - Status filter tabs (quarantined, released, deleted, all)
  - Bulk selection with select-all checkbox
  - Individual release/delete actions with API calls
  - Bulk release/delete with confirmation dialogs
  - Score visualization and verdict badges
- API integration: `releaseThreat()`, `deleteThreat()`, `bulkAction()` - all functional

**4. Policy Management UI** - VERIFIED
- Location: `/app/dashboard/policies/page.tsx`
- Features:
  - Tabbed interface: Detection Policies, Allowlist, Blocklist
  - Policy list with status/priority badges, enable/disable toggle
  - Allowlist/blocklist CRUD with entry type selection (domain/email/IP)
  - Add form with reason field
  - Delete with confirmation
- API: `/api/policies`, `/api/lists`, `/api/lists/{id}`

**5. Integration Status Page** - VERIFIED
- Location: `/app/dashboard/integrations/page.tsx`
- Features:
  - Cards for Microsoft 365, Gmail/Google Workspace, SMTP Relay
  - OAuth connection flow for O365/Gmail
  - Connection status badges (connected, disconnected, error, pending)
  - Sync Now button with loading state
  - Disconnect with confirmation
  - Connected accounts detail card showing last sync time
- SMTP: Shows webhook endpoint URL, marked "Coming Soon"

**6. MSP Multi-Tenant Switcher (Cmd+K)** - VERIFIED
- Two components exist:
  1. `TenantSwitcher` (`/components/layout/tenant-switcher.tsx`): Dropdown in header for MSP users
  2. `CommandPalette` (`/components/layout/command-palette.tsx`): Full Cmd+K palette with navigation
  3. `TenantSwitcher` in MSP module (`/components/msp/TenantSwitcher.tsx`): Popover-based switcher with plan badges
- Integration: `DashboardLayout` registers Cmd+K keyboard shortcut, shows palette
- Features: Search tenants by name/domain, visual indicators for current selection, "Add new tenant" option for MSP admins
- Context: `useTenant` hook provides `currentTenant`, `availableTenants`, `setCurrentTenant`, `isMspUser`

**7. Report Generation (PDF)** - PARTIAL
- Location: `/lib/reports/pdf-generator.ts`
- Status: **HTML templates exist but PDF conversion is placeholder**
- What exists:
  - SOC 2 Type II report template (fully designed HTML)
  - HIPAA Security Rule report template (fully designed HTML)
  - Complete styling for professional PDF output
  - Functions: `generateSOC2PDF()`, `generateHIPAAPDF()`
- Gap: Returns HTML with `mimeType: 'text/html'` - needs Puppeteer/wkhtmltopdf/PDF service for actual PDF
- Comment in code: "For serverless, we return HTML that can be rendered to PDF client-side or use a PDF service API"
- Scheduled reports page allows PDF format selection, but backend would generate HTML not actual PDF
- Export page shows PDF as format option

**8. Audit Log Viewer** - VERIFIED
- Location: `/app/admin/audit/page.tsx`
- Features:
  - Full audit log table with timestamp, actor, tenant, action, resource, IP address
  - Action type badges (created=green, updated=blue, deleted=red, released=yellow)
  - Comprehensive filtering: actor email, action type, resource type, date range
  - Pagination with page controls
  - Detail modal showing before/after state, metadata, user agent
- API: `/api/admin/audit` with full query parameters
- Data model: Complete audit entry interface with beforeState, afterState, metadata

#### Component Library

**UI Components (`/components/ui/`)** - 11 shadcn/ui components:
- alert.tsx, badge.tsx, button.tsx, card.tsx, command.tsx, dialog.tsx, input.tsx, popover.tsx, skeleton.tsx

**Dashboard Components (`/components/dashboard/`)** - 6 components:
- charts.tsx, index.ts, integration-status.tsx, recent-threats.tsx, simple-chart.tsx, stat-card.tsx

**Layout Components (`/components/layout/`)** - 5 components:
- command-palette.tsx, dashboard-layout.tsx, index.ts, sidebar.tsx, tenant-switcher.tsx

**MSP Components (`/components/msp/`)** - 4 components:
- ClientCard.tsx, OnboardingWizard.tsx, TenantSwitcher.tsx, index.ts

**SOC Components (`/components/soc/`)** - 2 components:
- InvestigationPanel.tsx, ThreatTimeline.tsx

#### Data Fetching Architecture

**Pattern**: Client-side fetching with React hooks
- All pages use `'use client'` directive
- useState/useEffect for data loading
- Real API endpoints (not mock data) for all major features
- Demo mode fallback only when no actual data exists
- Error handling with user-friendly messages

**Custom Hook**: `useDashboardData` (`/lib/hooks/use-dashboard-data.ts`)
- Parallel API calls for stats, threats, quarantine
- Loading state management
- Error handling
- Refetch capability
- `useLiveStats` variant for polling

#### Gaps and Concerns

1. **PDF Generation**: The PDF generator only produces HTML. Actual PDF conversion requires:
   - Server-side Puppeteer/Playwright
   - OR cloud PDF service (html-pdf-service, pdf.co)
   - OR client-side jsPDF
   - Impact: "Executive-friendly PDFs" claim is NOT fully delivered

2. **White-label Reports**: No evidence of white-labeling capability for MSP reports (custom logos, colors, branding)

3. **Some Pages are Stubs**: Several pages exist but weren't fully examined:
   - `/dashboard/emails/page.tsx`
   - `/dashboard/settings/page.tsx`
   - `/admin/quarantine/page.tsx`
   - `/admin/policies/page.tsx`
   - `/admin/users/page.tsx`

4. **Charts**: Using simple CSS bar charts rather than a charting library (Recharts, Chart.js). Functional but basic.

#### Summary Table

| Claimed Feature | Status | Evidence |
|-----------------|--------|----------|
| Threat Inbox | COMPLETE | Full UI with verdicts, filtering, actions |
| Real-time Dashboard | COMPLETE | Live stats with 30s polling |
| Quarantine Management | COMPLETE | Bulk operations, release/delete |
| Policy Management | COMPLETE | Allow/blocklist CRUD |
| Integration Status | COMPLETE | O365/Gmail OAuth, sync |
| MSP Tenant Switcher | COMPLETE | Cmd+K + dropdown + context |
| PDF Reports | PARTIAL | HTML templates only, no PDF conversion |
| Audit Log Viewer | COMPLETE | Full filtering, pagination, detail view |
| MSP Overview Dashboard | COMPLETE | Cross-tenant stats and activity |
| MSP Threat Management | COMPLETE | Cross-tenant threat view |
| MSP Reports/Analytics | COMPLETE | Trends, tenant comparison |

**Files Reviewed**:
- `/app/dashboard/page.tsx` - Main dashboard
- `/app/dashboard/threats/page.tsx` - Threat inbox
- `/app/dashboard/quarantine/page.tsx` - Quarantine management
- `/app/dashboard/policies/page.tsx` - Policy management
- `/app/dashboard/integrations/page.tsx` - Integration status
- `/app/dashboard/reports/page.tsx` - Reports overview
- `/app/dashboard/reports/scheduled/page.tsx` - Scheduled reports
- `/app/dashboard/reports/exports/page.tsx` - Export history
- `/app/dashboard/analytics/page.tsx` - Analytics dashboard
- `/app/admin/page.tsx` - MSP dashboard
- `/app/admin/tenants/page.tsx` - Tenant management
- `/app/admin/threats/page.tsx` - Cross-tenant threats
- `/app/admin/reports/page.tsx` - MSP reports
- `/app/admin/audit/page.tsx` - Audit log
- `/components/layout/dashboard-layout.tsx` - Layout with Cmd+K
- `/components/layout/tenant-switcher.tsx` - Tenant dropdown
- `/components/layout/command-palette.tsx` - Command palette
- `/components/msp/TenantSwitcher.tsx` - MSP tenant switcher
- `/lib/hooks/use-dashboard-data.ts` - Dashboard data hook
- `/lib/reports/pdf-generator.ts` - PDF generation (HTML only)

---

## 8. Test Coverage

### Claims to Validate:
- [ ] "12+ test suites" - enumerate actual suites
- [ ] E2E tests (Playwright)
- [ ] Unit tests (Vitest)
- [ ] Integration tests
- [ ] Detection pipeline tests
- [ ] API endpoint tests

### Findings:

> [Agent 8 findings here]

---

## Critical Gaps Identified

| Gap | Severity | Impact on Deal |
|-----|----------|----------------|
| | | |

---

## Recommendations

1.
2.
3.

---

## Appendix: File Inventory

> [Summary of key files reviewed]
