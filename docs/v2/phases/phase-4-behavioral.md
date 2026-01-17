# Phase 4: Communication Graph & Behavioral AI

## Overview

**Goal**: Build behavioral intelligence for anomaly detection
**Duration**: 1.5 weeks
**Score Impact**:
- vs Barracuda: 54 → 58 (+4)
- Innovation: 46 → 56 (+10)
- Production Readiness: 92 → 94 (+2)

## Why This Matters

This is where we differentiate from legacy vendors:
- **Abnormal Security** built a $5B company on behavioral AI
- Traditional signature-based detection misses novel attacks
- Understanding "normal" enables detecting "abnormal"
- Communication graph reveals impersonation attempts

## Slices

### Slice 4.1: Contact Graph Building

**Goal**: Map communication relationships

**User Story**:
> As a security analyst, I need to understand who normally communicates with whom so that I can detect when someone pretends to be a known contact.

**Acceptance Criteria**:
- [ ] Extract sender/recipient pairs from emails
- [ ] Track communication frequency
- [ ] Track first contact date
- [ ] Track last contact date
- [ ] Detect bidirectional relationships
- [ ] Classify internal vs external contacts
- [ ] Persist and incrementally update graph
- [ ] Query graph for relationship strength

**Graph Data Model**:
```typescript
interface ContactEdge {
  id: string;
  tenantId: string;
  sourceEmail: string;
  targetEmail: string;

  // Relationship metrics
  firstContact: Date;
  lastContact: Date;
  messageCount: number;
  replyCount: number;  // Bidirectional indicator

  // Classification
  isInternal: boolean;
  relationship: 'frequent' | 'occasional' | 'rare' | 'first-time';
  trustScore: number;  // 0-100
}

interface ContactNode {
  email: string;
  tenantId: string;
  displayName: string;
  domain: string;
  isInternal: boolean;

  // Aggregates
  totalContacts: number;
  internalContacts: number;
  externalContacts: number;
  firstSeen: Date;
  lastSeen: Date;
}
```

**Tests**:
```typescript
// tests/behavioral/contact-graph.test.ts
describe('Contact Graph Building', () => {
  it('should create edge from email')
  it('should track communication frequency')
  it('should track first contact date')
  it('should detect bidirectional relationship')
  it('should classify internal contacts')
  it('should classify external contacts')
  it('should calculate relationship strength')
  it('should update existing edges')
  it('should query contacts for user')
});
```

**Implementation**:
- `lib/behavioral/contact-graph.ts`
- `lib/behavioral/graph-storage.ts`

---

### Slice 4.2: Communication Baselines

**Goal**: Establish normal patterns per user

**User Story**:
> As a security system, I need to understand each user's normal email behavior so that I can detect when their account behaves abnormally.

**Acceptance Criteria**:
- [ ] Calculate typical send volume (daily average)
- [ ] Calculate typical send times (hours of day)
- [ ] Calculate typical recipient patterns
- [ ] Calculate typical subject line patterns
- [ ] Rolling baseline updates (decay old data)
- [ ] Baseline confidence scoring
- [ ] Bootstrap new users with org baseline

**Baseline Metrics**:
```typescript
interface UserBaseline {
  userId: string;
  tenantId: string;
  email: string;

  // Volume metrics
  sendVolume: {
    dailyAvg: number;
    dailyStdDev: number;
    weeklyAvg: number;
    monthlyTotal: number;
  };

  // Time patterns
  timePatterns: {
    hourlyDistribution: number[];  // 24 buckets
    dayOfWeekDistribution: number[];  // 7 buckets
    typicalStartHour: number;
    typicalEndHour: number;
  };

  // Recipient patterns
  recipientPatterns: {
    avgRecipientsPerEmail: number;
    internalRatio: number;  // 0-1
    topDomains: Array<{ domain: string; percentage: number }>;
    topRecipients: Array<{ email: string; percentage: number }>;
  };

  // Content patterns
  contentPatterns: {
    avgSubjectLength: number;
    avgBodyLength: number;
    hasSignatureRatio: number;
    linkRatio: number;  // Emails with links
    attachmentRatio: number;
  };

  // Metadata
  confidence: number;  // 0-100, based on data volume
  dataPoints: number;
  periodStart: Date;
  periodEnd: Date;
  lastUpdated: Date;
}
```

**Tests**:
```typescript
// tests/behavioral/baselines.test.ts
describe('Communication Baselines', () => {
  it('should calculate daily send average')
  it('should calculate send time distribution')
  it('should calculate recipient patterns')
  it('should calculate content patterns')
  it('should update baseline with new data')
  it('should decay old data points')
  it('should calculate confidence score')
  it('should bootstrap new users')
  it('should handle users with no history')
});
```

**Implementation**:
- `lib/behavioral/baselines.ts`
- `lib/behavioral/statistics.ts`

---

### Slice 4.3: Anomaly Detection Engine

**Goal**: Score deviations from baseline

**User Story**:
> As a security analyst, I need automatic detection of anomalous email behavior so that I'm alerted when users deviate significantly from their normal patterns.

**Acceptance Criteria**:
- [ ] Detect volume anomalies (z-score)
- [ ] Detect time anomalies (outside typical hours)
- [ ] Detect recipient anomalies (unusual contacts)
- [ ] Detect content anomalies (unusual patterns)
- [ ] Calculate composite anomaly score
- [ ] Generate human-readable explanations
- [ ] Support false positive feedback loop
- [ ] Tune sensitivity per tenant

**Anomaly Types**:
```typescript
type AnomalyType =
  | 'volume_spike'      // Sending way more than usual
  | 'unusual_time'      // Sending at odd hours
  | 'unusual_recipient' // New or rare contact
  | 'unusual_domain'    // First time contacting this domain
  | 'unusual_content'   // Different content style
  | 'bulk_external'     // Mass external emails
  | 'rule_change'       // Inbox rule modified
  | 'forward_setup';    // Forwarding rule added

interface AnomalyResult {
  type: AnomalyType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  score: number;  // 0-100
  zScore: number;  // Standard deviations from mean
  baseline: any;  // What was expected
  actual: any;    // What was observed
  explanation: string;  // Human readable
}
```

**Tests**:
```typescript
// tests/behavioral/anomaly-engine.test.ts
describe('Anomaly Detection Engine', () => {
  it('should detect volume spike')
  it('should detect unusual send time')
  it('should detect unusual recipient')
  it('should detect unusual domain')
  it('should detect bulk external sends')
  it('should calculate composite score')
  it('should generate explanations')
  it('should respect sensitivity settings')
  it('should learn from false positives')
});
```

**Implementation**:
- `lib/behavioral/anomaly-engine.ts`
- `lib/behavioral/explainer.ts`

---

### Slice 4.4: First Contact Detection

**Goal**: Flag emails from unknown senders

**User Story**:
> As an email user, I need to know when I receive email from someone I've never communicated with before, especially if they claim to be someone I know.

**Acceptance Criteria**:
- [ ] Detect first-time external sender
- [ ] Detect lookalike of known contact
- [ ] Correlate with domain age
- [ ] Calculate risk score for first contact
- [ ] Extra scrutiny for VIP targets
- [ ] Detect supplier/vendor impersonation
- [ ] Visual indicator in email (banner)

**First Contact Risk Factors**:
```typescript
interface FirstContactRisk {
  isFirstContact: boolean;
  riskScore: number;  // 0-100

  factors: {
    neverContactedBefore: boolean;
    domainNeverSeen: boolean;
    domainAge: number;  // days
    lookalikeDomain: boolean;
    lookallikeSimilarity: number;  // 0-1
    claimsToKnowRecipient: boolean;
    urgentLanguage: boolean;
    requestsAction: boolean;
    targetIsVip: boolean;
    impersonatesSupplier: boolean;
  };

  explanation: string;
  recommendation: 'allow' | 'warn' | 'block';
}
```

**Tests**:
```typescript
// tests/behavioral/first-contact.test.ts
describe('First Contact Detection', () => {
  it('should detect first-time sender')
  it('should detect first-time domain')
  it('should detect lookalike domain')
  it('should correlate with domain age')
  it('should increase risk for VIP targets')
  it('should detect supplier impersonation')
  it('should generate risk explanation')
  it('should recommend action')
});
```

**Implementation**:
- `lib/behavioral/first-contact.ts`
- `lib/behavioral/lookalike-detector.ts`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Behavioral AI Pipeline                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Incoming Email                                                 │
│        │                                                         │
│        ▼                                                         │
│   ┌─────────────────┐                                           │
│   │ Feature Extract │  Sender, recipients, time, content        │
│   └────────┬────────┘                                           │
│            │                                                     │
│   ┌────────┴────────┬────────────────┐                          │
│   │                 │                │                          │
│   ▼                 ▼                ▼                          │
│ ┌───────────┐ ┌───────────┐ ┌─────────────┐                    │
│ │  Contact  │ │ Baseline  │ │   First     │                    │
│ │   Graph   │ │   Check   │ │  Contact    │                    │
│ │   Update  │ │           │ │   Check     │                    │
│ └─────┬─────┘ └─────┬─────┘ └──────┬──────┘                    │
│       │             │              │                            │
│       └─────────────┼──────────────┘                            │
│                     │                                            │
│            ┌────────▼────────┐                                  │
│            │ Anomaly Engine  │                                  │
│            └────────┬────────┘                                  │
│                     │                                            │
│            ┌────────▼────────┐                                  │
│            │  Risk Scoring   │                                  │
│            └────────┬────────┘                                  │
│                     │                                            │
│       ┌─────────────┼─────────────┐                             │
│       │             │             │                             │
│       ▼             ▼             ▼                             │
│   ┌───────┐    ┌────────┐   ┌─────────┐                        │
│   │ Allow │    │  Warn  │   │  Block  │                        │
│   │       │    │(Banner)│   │         │                        │
│   └───────┘    └────────┘   └─────────┘                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Database Schema

```sql
-- Contact graph edges
CREATE TABLE contact_edges (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  source_email VARCHAR(255) NOT NULL,
  target_email VARCHAR(255) NOT NULL,

  first_contact TIMESTAMPTZ NOT NULL,
  last_contact TIMESTAMPTZ NOT NULL,
  message_count INTEGER DEFAULT 1,
  reply_count INTEGER DEFAULT 0,

  is_internal BOOLEAN,
  trust_score INTEGER,

  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),

  UNIQUE(tenant_id, source_email, target_email)
);

-- User baselines
CREATE TABLE user_baselines (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  user_email VARCHAR(255) NOT NULL,

  send_volume JSONB,
  time_patterns JSONB,
  recipient_patterns JSONB,
  content_patterns JSONB,

  confidence INTEGER,
  data_points INTEGER,
  period_start TIMESTAMPTZ,
  period_end TIMESTAMPTZ,

  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),

  UNIQUE(tenant_id, user_email)
);

-- Anomaly events
CREATE TABLE anomaly_events (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  message_id VARCHAR(255) NOT NULL,
  user_email VARCHAR(255) NOT NULL,

  anomaly_type VARCHAR(50) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  score INTEGER NOT NULL,
  z_score DECIMAL(5, 2),

  baseline_value JSONB,
  actual_value JSONB,
  explanation TEXT,

  false_positive BOOLEAN DEFAULT FALSE,
  reviewed_at TIMESTAMPTZ,
  reviewed_by VARCHAR(255),

  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_contact_edges_tenant_source
  ON contact_edges(tenant_id, source_email);
CREATE INDEX idx_contact_edges_tenant_target
  ON contact_edges(tenant_id, target_email);
CREATE INDEX idx_user_baselines_tenant_email
  ON user_baselines(tenant_id, user_email);
CREATE INDEX idx_anomaly_events_tenant_user
  ON anomaly_events(tenant_id, user_email);
```

## Success Metrics

| Metric | Before | After |
|--------|--------|-------|
| vs Barracuda | 54 | 58 |
| Innovation | 46 | 56 |
| Production Readiness | 92 | 94 |
| Test Count | 1,630 | 1,730 |
| Behavioral Coverage | None | Full graph + baselines |
