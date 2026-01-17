# Phase 6: UX & Reporting

## Overview

**Goal**: Enterprise-grade user experience and reporting
**Duration**: 1 week
**Score Impact**:
- vs Barracuda: 64 → 68 (+4)
- Innovation: 64 → 66 (+2)
- Production Readiness: 96 → 100 (+4)

## Why This Matters

Features don't matter if users can't use them effectively:
- **Phish Report Button**: Turns users into sensors
- **Quarantine Management**: Admin control over false positives
- **Executive Dashboard**: Board-ready security metrics
- **Real-time Alerts**: Instant notification of threats

## Slices

### Slice 6.1: Phish Report Button

**Goal**: Enable end-users to report suspicious emails

**User Story**:
> As an email user, I need an easy way to report suspicious emails so that the security team can investigate potential threats I receive.

**Acceptance Criteria**:
- [ ] Outlook add-in for reporting
- [ ] Gmail add-on for reporting
- [ ] One-click report submission
- [ ] Automatic email forwarding to SOC
- [ ] User feedback on submission
- [ ] False positive handling
- [ ] Gamification (report counts, badges)
- [ ] Integration with threat analysis pipeline

**Report Flow**:
```
User clicks "Report Phish" button
    │
    ▼
Add-in captures email (headers + body)
    │
    ▼
Submit to Swordfish API
    │
    ├─► Acknowledge to user
    │
    ▼
Queue for analysis
    │
    ├─► Run through detection pipeline
    │
    ├─► THREAT: Add to threat database
    │       └─► Remove from all mailboxes (if policy allows)
    │
    └─► NOT THREAT: Mark as false positive
            └─► Optional: Notify user
```

**Tests**:
```typescript
// tests/reporting/phish-button.test.ts
describe('Phish Report Button', () => {
  it('should accept report submission')
  it('should validate email format')
  it('should queue for analysis')
  it('should acknowledge to user')
  it('should analyze reported email')
  it('should handle confirmed threat')
  it('should handle false positive')
  it('should track reporter statistics')
});
```

**Implementation**:
- `lib/reporting/phish-button.ts`
- `app/api/v1/report-phish/route.ts`

---

### Slice 6.2: Quarantine Management

**Goal**: Admin control over quarantined emails

**User Story**:
> As an MSP administrator, I need to manage quarantined emails across my clients so that I can release false positives and permanently delete confirmed threats.

**Acceptance Criteria**:
- [ ] List quarantined emails with filters
- [ ] Filter by tenant, date, threat type, status
- [ ] View full email content safely
- [ ] Release email from quarantine
- [ ] Delete email permanently
- [ ] Bulk operations (release/delete multiple)
- [ ] Release with whitelist option
- [ ] Full audit logging

**Quarantine States**:
```
QUARANTINED → RELEASED (back to inbox)
           → DELETED (permanently removed)
           → EXPIRED (auto-deleted after retention period)
```

**Tests**:
```typescript
// tests/quarantine/manager.test.ts
describe('Quarantine Management', () => {
  it('should list quarantined emails')
  it('should filter by tenant')
  it('should filter by date range')
  it('should filter by threat type')
  it('should release single email')
  it('should delete single email')
  it('should bulk release emails')
  it('should bulk delete emails')
  it('should whitelist on release')
  it('should audit log all actions')
});
```

**Implementation**:
- `lib/quarantine/manager.ts`
- `app/api/v1/quarantine/route.ts`
- `app/api/v1/quarantine/[id]/route.ts`

---

### Slice 6.3: Executive Dashboard

**Goal**: Board-ready security metrics

**User Story**:
> As an MSP administrator, I need executive-level security reports so that I can demonstrate value to my clients' leadership teams.

**Dashboard Metrics**:
```typescript
interface ExecutiveDashboard {
  period: { start: Date; end: Date };

  summary: {
    totalEmailsScanned: number;
    totalThreatsBlocked: number;
    protectionRate: number;  // Threats blocked / Total
  };

  threatBreakdown: {
    phishing: number;
    bec: number;
    malware: number;
    spam: number;
  };

  trends: {
    threatVolume: Array<{ date: string; count: number }>;
    topThreatTypes: Array<{ type: string; count: number }>;
  };

  riskProfile: {
    highRiskUsers: Array<{ email: string; threatCount: number }>;
    topTargetedDepartments: Array<{ name: string; count: number }>;
  };

  compliance: {
    dmarcCompliance: number;  // Percentage
    spfCompliance: number;
    dkimCompliance: number;
  };

  responseMetrics: {
    avgDetectionTime: number;  // seconds
    avgRemediationTime: number;
    autoRemediatedPercentage: number;
  };
}
```

**Acceptance Criteria**:
- [ ] Threat volume trends
- [ ] Threats blocked vs detected
- [ ] Top threat categories
- [ ] Most targeted users
- [ ] Response time metrics
- [ ] Industry benchmark comparison
- [ ] PDF export
- [ ] Scheduled email delivery

**Tests**:
```typescript
// tests/reporting/executive-dashboard.test.ts
describe('Executive Dashboard', () => {
  it('should calculate threat summary')
  it('should calculate threat breakdown')
  it('should generate trend data')
  it('should identify high-risk users')
  it('should calculate compliance metrics')
  it('should calculate response metrics')
  it('should compare to benchmarks')
  it('should export to PDF')
  it('should schedule email delivery')
});
```

**Implementation**:
- `lib/reporting/executive-dashboard.ts`
- `app/api/v1/reports/executive/route.ts`
- `lib/reporting/pdf-generator.ts`

---

### Slice 6.4: Real-time Alerts

**Goal**: Instant notification of threats

**User Story**:
> As a SOC analyst, I need real-time alerts when high-severity threats are detected so that I can respond immediately.

**Alert Channels**:
```
1. Slack webhook
2. Microsoft Teams webhook
3. Email alerts
4. PagerDuty integration (future)
```

**Alert Format**:
```typescript
interface ThreatAlert {
  id: string;
  timestamp: Date;
  severity: 'low' | 'medium' | 'high' | 'critical';

  threat: {
    type: string;
    confidence: number;
    summary: string;
  };

  target: {
    email: string;
    tenantId: string;
    tenantName: string;
  };

  details: {
    sender: string;
    subject: string;
    indicators: string[];
  };

  actions: {
    taken: string[];  // Auto-remediation actions
    recommended: string[];  // Manual actions needed
  };

  links: {
    investigate: string;  // Link to threat detail page
    release: string;  // Link to release if quarantined
  };
}
```

**Acceptance Criteria**:
- [ ] Slack webhook integration
- [ ] Teams webhook integration
- [ ] Email alert delivery
- [ ] Alert severity levels
- [ ] Alert throttling (prevent flood)
- [ ] Alert acknowledgment tracking
- [ ] Alert escalation rules
- [ ] Per-tenant alert preferences

**Tests**:
```typescript
// tests/alerts/real-time.test.ts
describe('Real-time Alerts', () => {
  it('should send Slack alert')
  it('should send Teams alert')
  it('should send email alert')
  it('should respect severity threshold')
  it('should throttle repeated alerts')
  it('should track acknowledgment')
  it('should escalate unacknowledged')
  it('should respect tenant preferences')
});
```

**Implementation**:
- `lib/alerts/slack.ts`
- `lib/alerts/teams.ts`
- `lib/alerts/email.ts`
- `lib/alerts/dispatcher.ts`
- `lib/alerts/throttler.ts`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      UX & Reporting Layer                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐    ┌─────────────────┐                     │
│  │  Phish Report   │    │   Quarantine    │                     │
│  │     Button      │    │   Management    │                     │
│  │                 │    │                 │                     │
│  │ ┌─────────────┐ │    │ ┌─────────────┐ │                     │
│  │ │   Outlook   │ │    │ │    List     │ │                     │
│  │ │   Add-in    │ │    │ │   Filter    │ │                     │
│  │ └─────────────┘ │    │ │   Release   │ │                     │
│  │ ┌─────────────┐ │    │ │   Delete    │ │                     │
│  │ │   Gmail     │ │    │ └─────────────┘ │                     │
│  │ │   Add-on    │ │    │                 │                     │
│  │ └─────────────┘ │    │                 │                     │
│  └────────┬────────┘    └────────┬────────┘                     │
│           │                      │                               │
│           └──────────┬───────────┘                               │
│                      │                                           │
│                      ▼                                           │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Core Platform                           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                      │                                           │
│           ┌──────────┴──────────┐                               │
│           │                     │                               │
│           ▼                     ▼                               │
│  ┌─────────────────┐   ┌─────────────────┐                     │
│  │   Executive     │   │   Real-time     │                     │
│  │   Dashboard     │   │     Alerts      │                     │
│  │                 │   │                 │                     │
│  │ ┌─────────────┐ │   │ ┌─────────────┐ │                     │
│  │ │   Charts    │ │   │ │    Slack    │ │                     │
│  │ │   Metrics   │ │   │ ├─────────────┤ │                     │
│  │ │   Export    │ │   │ │   Teams     │ │                     │
│  │ └─────────────┘ │   │ ├─────────────┤ │                     │
│  │                 │   │ │   Email     │ │                     │
│  │                 │   │ └─────────────┘ │                     │
│  └─────────────────┘   └─────────────────┘                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Success Metrics

| Metric | Before | After |
|--------|--------|-------|
| vs Barracuda | 64 | 68 |
| Innovation | 64 | 66 |
| Production Readiness | 96 | 100 |
| Test Count | 1,850 | 1,930 |
| Admin Features | Basic | Full quarantine + reporting + alerts |
