# Phase 3: Email Authentication (DMARC/SPF/DKIM)

## Overview

**Goal**: Full email authentication validation and brand protection
**Duration**: 1 week
**Score Impact**:
- vs Barracuda: 50 → 54 (+4)
- Innovation: 44 → 46 (+2)
- Production Readiness: 90 → 92 (+2)

## Why This Matters

Email authentication is table stakes for enterprise email security:
- **SPF**: Verifies sender IP is authorized
- **DKIM**: Verifies email integrity via cryptographic signature
- **DMARC**: Policy layer that combines SPF + DKIM

Without this, we can't detect:
- Domain spoofing attacks
- Brand impersonation
- Supply chain email compromise

## Slices

### Slice 3.1: SPF Validation

**Goal**: Verify sender IP authorization

**User Story**:
> As a security analyst, I need to know if an email's sender IP is authorized by the domain owner so that I can detect spoofed emails.

**Acceptance Criteria**:
- [ ] Parse SPF records from DNS
- [ ] Validate sender IP against SPF mechanisms
- [ ] Handle all SPF qualifiers (pass, fail, softfail, neutral)
- [ ] Handle `include:` mechanism (nested lookups)
- [ ] Handle `redirect=` modifier
- [ ] Enforce 10 DNS lookup limit
- [ ] Cache SPF records with TTL
- [ ] Return detailed validation result

**SPF Mechanisms**:
```
ip4:192.168.1.0/24    - IPv4 range
ip6:2001:db8::/32     - IPv6 range
a                     - Domain's A record
mx                    - Domain's MX records
include:_spf.google.com - Nested lookup
redirect=_spf.example.com - Redirect
all                   - Catch-all
```

**Tests**:
```typescript
// tests/email-auth/spf.test.ts
describe('SPF Validation', () => {
  it('should parse SPF record')
  it('should validate IP against ip4 mechanism')
  it('should validate IP against ip6 mechanism')
  it('should resolve include mechanism')
  it('should handle redirect modifier')
  it('should enforce 10 lookup limit')
  it('should cache records with TTL')
  it('should return pass for authorized IP')
  it('should return fail for unauthorized IP')
  it('should return softfail for ~all')
  it('should return neutral for ?all')
});
```

**Implementation**:
- `lib/email-auth/spf.ts`
- `lib/email-auth/dns-resolver.ts`

---

### Slice 3.2: DKIM Validation

**Goal**: Verify email signature integrity

**User Story**:
> As a security analyst, I need to verify DKIM signatures so that I can confirm emails haven't been tampered with in transit.

**Acceptance Criteria**:
- [ ] Parse DKIM-Signature header
- [ ] Extract selector and domain
- [ ] Retrieve public key from DNS
- [ ] Verify signature against headers + body
- [ ] Handle multiple DKIM signatures
- [ ] Handle canonicalization (relaxed/simple)
- [ ] Handle partial body signing (l= tag)
- [ ] Check signature expiration (x= tag)

**DKIM-Signature Header**:
```
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1;
    c=relaxed/relaxed; q=dns/txt; t=1234567890; x=1234657890;
    h=from:to:subject:date;
    bh=base64_body_hash;
    b=base64_signature
```

**Tests**:
```typescript
// tests/email-auth/dkim.test.ts
describe('DKIM Validation', () => {
  it('should parse DKIM-Signature header')
  it('should extract selector and domain')
  it('should retrieve public key from DNS')
  it('should verify valid signature')
  it('should reject invalid signature')
  it('should handle relaxed canonicalization')
  it('should handle simple canonicalization')
  it('should handle partial body signing')
  it('should reject expired signature')
  it('should handle multiple signatures')
});
```

**Implementation**:
- `lib/email-auth/dkim.ts`
- `lib/email-auth/signature-verifier.ts`

---

### Slice 3.3: DMARC Policy Evaluation

**Goal**: Apply domain owner's email policy

**User Story**:
> As a security analyst, I need to evaluate emails against domain DMARC policies so that I can enforce the domain owner's authentication requirements.

**Acceptance Criteria**:
- [ ] Parse DMARC record from `_dmarc.domain.com`
- [ ] Evaluate SPF alignment (strict/relaxed)
- [ ] Evaluate DKIM alignment (strict/relaxed)
- [ ] Apply policy (none, quarantine, reject)
- [ ] Handle subdomain policy (sp= tag)
- [ ] Handle percentage (pct= tag)
- [ ] Generate aggregate report data (rua=)
- [ ] Generate forensic report data (ruf=)

**DMARC Record**:
```
v=DMARC1; p=reject; sp=quarantine; pct=100;
rua=mailto:dmarc-reports@example.com;
adkim=s; aspf=r
```

**Alignment Logic**:
```
SPF Alignment:
  - Strict: RFC5321.MailFrom domain == From header domain (exact)
  - Relaxed: Organizational domains match

DKIM Alignment:
  - Strict: DKIM d= domain == From header domain (exact)
  - Relaxed: Organizational domains match

DMARC Pass = (SPF pass + aligned) OR (DKIM pass + aligned)
```

**Tests**:
```typescript
// tests/email-auth/dmarc.test.ts
describe('DMARC Policy Evaluation', () => {
  it('should parse DMARC record')
  it('should evaluate strict SPF alignment')
  it('should evaluate relaxed SPF alignment')
  it('should evaluate strict DKIM alignment')
  it('should evaluate relaxed DKIM alignment')
  it('should apply none policy')
  it('should apply quarantine policy')
  it('should apply reject policy')
  it('should handle subdomain policy')
  it('should respect percentage tag')
  it('should pass when SPF aligned and passes')
  it('should pass when DKIM aligned and passes')
});
```

**Implementation**:
- `lib/email-auth/dmarc.ts`
- `lib/email-auth/alignment.ts`

---

### Slice 3.4: Brand Protection Dashboard

**Goal**: Visualize email authentication status

**User Story**:
> As an MSP administrator, I need a dashboard showing email authentication status across my clients so that I can identify domains with poor authentication and spoofing attempts.

**Acceptance Criteria**:
- [ ] Aggregate DMARC results per domain
- [ ] Show pass/fail/none trends over time
- [ ] Identify spoofing attempts (failed auth)
- [ ] List unauthorized senders by volume
- [ ] DMARC adoption recommendations
- [ ] Export compliance report (PDF/CSV)
- [ ] Alert on authentication failures

**Dashboard Metrics**:
```typescript
interface DomainAuthMetrics {
  domain: string;
  period: { start: Date; end: Date };
  totalEmails: number;
  dmarc: {
    pass: number;
    fail: number;
    none: number;  // No DMARC policy
  };
  spf: {
    pass: number;
    fail: number;
    softfail: number;
    neutral: number;
    none: number;
  };
  dkim: {
    pass: number;
    fail: number;
    none: number;
  };
  topUnauthorizedSenders: Array<{
    ip: string;
    count: number;
    country: string;
  }>;
  recommendations: string[];
}
```

**Tests**:
```typescript
// tests/email-auth/analytics.test.ts
describe('Brand Protection Dashboard', () => {
  it('should aggregate DMARC results by domain')
  it('should calculate pass/fail trends')
  it('should identify spoofing attempts')
  it('should list unauthorized senders')
  it('should generate recommendations')
  it('should export compliance report')
  it('should alert on auth failures')
});
```

**Implementation**:
- `lib/email-auth/analytics.ts`
- `app/api/v1/email-auth/route.ts`
- `app/api/v1/email-auth/report/route.ts`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   Email Authentication Pipeline                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Incoming Email                                                 │
│        │                                                         │
│        ▼                                                         │
│   ┌─────────────┐                                               │
│   │   Extract   │  From header, Return-Path, DKIM-Signature     │
│   │   Headers   │                                               │
│   └──────┬──────┘                                               │
│          │                                                       │
│   ┌──────┴──────┬──────────────┐                                │
│   │             │              │                                 │
│   ▼             ▼              ▼                                 │
│ ┌─────┐     ┌─────┐      ┌──────┐                               │
│ │ SPF │     │DKIM │      │DMARC │                               │
│ └──┬──┘     └──┬──┘      └──┬───┘                               │
│    │           │            │                                    │
│    │   ┌───────┴────────────┘                                   │
│    │   │                                                         │
│    ▼   ▼                                                         │
│ ┌────────────────┐                                              │
│ │   Alignment    │  Check domain alignment                      │
│ │    Check       │                                              │
│ └───────┬────────┘                                              │
│         │                                                        │
│         ▼                                                        │
│ ┌────────────────┐                                              │
│ │ Policy Decision│  none / quarantine / reject                  │
│ └───────┬────────┘                                              │
│         │                                                        │
│    ┌────┴────┐                                                  │
│    │         │                                                   │
│    ▼         ▼                                                   │
│ ┌──────┐ ┌───────┐                                              │
│ │Accept│ │Reject/│                                              │
│ │      │ │Quarant│                                              │
│ └──────┘ └───────┘                                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Database Schema

```sql
-- Email authentication results
CREATE TABLE email_auth_results (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  message_id VARCHAR(255) NOT NULL,
  from_domain VARCHAR(255) NOT NULL,
  envelope_from VARCHAR(255),
  sender_ip INET,

  -- SPF results
  spf_result VARCHAR(20),  -- pass, fail, softfail, neutral, none
  spf_domain VARCHAR(255),

  -- DKIM results
  dkim_result VARCHAR(20),  -- pass, fail, none
  dkim_domain VARCHAR(255),
  dkim_selector VARCHAR(100),

  -- DMARC results
  dmarc_result VARCHAR(20),  -- pass, fail, none
  dmarc_policy VARCHAR(20),  -- none, quarantine, reject
  dmarc_disposition VARCHAR(20),  -- none, quarantine, reject
  spf_aligned BOOLEAN,
  dkim_aligned BOOLEAN,

  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Domain authentication policies (cached)
CREATE TABLE domain_auth_policies (
  domain VARCHAR(255) PRIMARY KEY,
  spf_record TEXT,
  dmarc_record TEXT,
  dmarc_policy VARCHAR(20),
  dmarc_subdomain_policy VARCHAR(20),
  dmarc_percentage INTEGER,
  cached_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

-- Create indexes
CREATE INDEX idx_auth_results_tenant_domain
  ON email_auth_results(tenant_id, from_domain);
CREATE INDEX idx_auth_results_created
  ON email_auth_results(created_at);
```

## Success Metrics

| Metric | Before | After |
|--------|--------|-------|
| vs Barracuda | 50 | 54 |
| Innovation | 44 | 46 |
| Production Readiness | 90 | 92 |
| Test Count | 1,550 | 1,630 |
| Email Auth Coverage | None | SPF/DKIM/DMARC |
