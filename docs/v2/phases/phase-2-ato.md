# Phase 2: Account Takeover Detection

## Overview

**Goal**: Detect and respond to compromised email accounts
**Duration**: 1.5 weeks
**Score Impact**:
- vs Barracuda: 42 → 50 (+8)
- Innovation: 38 → 44 (+6)
- Production Readiness: 88 → 90 (+2)

## Why This Matters

Account Takeover (ATO) is one of the most damaging attack vectors:
- Attacker gains access to legitimate account
- Sends phishing from trusted source
- Bypasses traditional email security
- Barracuda, Proofpoint, and Abnormal all have ATO detection
- **This is our biggest competitive gap**

## Slices

### Slice 2.1: Login Event Tracking

**Goal**: Capture all authentication events with context

**User Story**:
> As a security analyst, I need visibility into all login events so that I can detect suspicious authentication patterns.

**Acceptance Criteria**:
- [ ] Login success events recorded
- [ ] Login failure events recorded
- [ ] IP address captured
- [ ] User agent captured
- [ ] Geolocation resolved from IP
- [ ] Device fingerprint generated
- [ ] Session correlation tracked
- [ ] Events queryable by user/tenant

**Data Model**:
```typescript
interface LoginEvent {
  id: string;
  tenantId: string;
  userId: string;
  email: string;
  timestamp: Date;
  success: boolean;
  ipAddress: string;
  userAgent: string;
  geolocation: {
    country: string;
    city: string;
    latitude: number;
    longitude: number;
  };
  deviceFingerprint: string;
  sessionId: string;
  riskScore: number;
}
```

**Tests**:
```typescript
// tests/security/login-events.test.ts
describe('Login Event Tracking', () => {
  it('should record successful login')
  it('should record failed login')
  it('should capture IP address')
  it('should resolve geolocation')
  it('should generate device fingerprint')
  it('should correlate with session')
  it('should calculate initial risk score')
});
```

**Implementation**:
- `lib/security/login-events.ts`
- `lib/security/geolocation.ts`
- `lib/security/device-fingerprint.ts`

---

### Slice 2.2: Impossible Travel Detection

**Goal**: Flag logins from impossible locations

**User Story**:
> As a security analyst, I need automatic detection of impossible travel so that I'm alerted when an account is accessed from two distant locations in an impossibly short time.

**Acceptance Criteria**:
- [ ] Calculate distance between consecutive logins
- [ ] Calculate time difference between logins
- [ ] Flag travel speed > 500 mph as impossible
- [ ] Handle VPN/proxy with reduced confidence
- [ ] Whitelist known travel patterns (office locations)
- [ ] Generate alert for impossible travel
- [ ] Adjust risk score accordingly

**Algorithm**:
```
distance_km = haversine(location1, location2)
time_hours = (timestamp2 - timestamp1) / 3600000
speed_mph = (distance_km / time_hours) * 0.621371

if speed_mph > 500:
  flag as IMPOSSIBLE_TRAVEL
elif speed_mph > 200:
  flag as SUSPICIOUS_TRAVEL
```

**Tests**:
```typescript
// tests/ato/impossible-travel.test.ts
describe('Impossible Travel Detection', () => {
  it('should calculate distance between locations')
  it('should calculate travel speed')
  it('should flag impossible travel (>500mph)')
  it('should flag suspicious travel (>200mph)')
  it('should handle same-location logins')
  it('should detect VPN usage')
  it('should respect whitelisted locations')
  it('should generate alert')
});
```

**Implementation**:
- `lib/ato/impossible-travel.ts`
- `lib/ato/distance-calculator.ts`

---

### Slice 2.3: New Device Detection

**Goal**: Alert on logins from unknown devices

**User Story**:
> As a user, I want to be notified when my account is accessed from a new device so that I can verify it's actually me.

**Acceptance Criteria**:
- [ ] Generate consistent device fingerprint
- [ ] Maintain registry of known devices per user
- [ ] Detect new/unknown device login
- [ ] Generate alert for new device
- [ ] Support device trust/approval workflow
- [ ] Expire device trust after inactivity
- [ ] Track device metadata (OS, browser, etc.)

**Device Fingerprint Components**:
```typescript
interface DeviceFingerprint {
  hash: string;  // Combined hash
  components: {
    userAgent: string;
    screenResolution: string;
    timezone: string;
    language: string;
    platform: string;
    plugins: string[];
    canvas: string;  // Canvas fingerprint
  };
}
```

**Tests**:
```typescript
// tests/ato/device-detection.test.ts
describe('New Device Detection', () => {
  it('should generate consistent fingerprint')
  it('should register known device')
  it('should detect new device')
  it('should generate alert for new device')
  it('should allow device approval')
  it('should expire inactive devices')
  it('should track device metadata')
});
```

**Implementation**:
- `lib/ato/device-registry.ts`
- `lib/ato/device-trust.ts`

---

### Slice 2.4: Unusual Activity Patterns

**Goal**: Detect compromised account behavior

**User Story**:
> As a security analyst, I need to detect unusual email activity patterns so that I can identify accounts behaving abnormally after compromise.

**Acceptance Criteria**:
- [ ] Baseline normal sending frequency per user
- [ ] Detect sudden sending spikes
- [ ] Detect emails to unusual recipients
- [ ] Detect emails at unusual times
- [ ] Detect mass forwarding rule creation
- [ ] Detect inbox rule changes
- [ ] Calculate composite anomaly score

**Baseline Metrics**:
```typescript
interface UserBaseline {
  userId: string;
  metrics: {
    avgDailySendCount: number;
    stdDevSendCount: number;
    typicalSendHours: number[];  // 0-23
    typicalRecipientDomains: string[];
    internalVsExternalRatio: number;
    avgRecipientsPerEmail: number;
  };
  lastUpdated: Date;
  confidenceScore: number;  // Higher with more data
}
```

**Tests**:
```typescript
// tests/ato/activity-patterns.test.ts
describe('Unusual Activity Patterns', () => {
  it('should establish sending baseline')
  it('should detect sending spike')
  it('should detect unusual recipients')
  it('should detect unusual send time')
  it('should detect forwarding rule creation')
  it('should detect inbox rule changes')
  it('should calculate composite anomaly score')
  it('should handle new users without baseline')
});
```

**Implementation**:
- `lib/ato/activity-baseline.ts`
- `lib/ato/anomaly-detector.ts`

---

### Slice 2.5: ATO Response Actions

**Goal**: Automated response to account takeover

**User Story**:
> As a security analyst, I need automated response actions for detected ATO so that compromised accounts are contained before damage spreads.

**Acceptance Criteria**:
- [ ] Terminate active sessions
- [ ] Trigger password reset
- [ ] Enforce MFA on next login
- [ ] Notify admin via alert channel
- [ ] Notify user via secondary email/phone
- [ ] Temporarily lock account (configurable)
- [ ] Create detailed audit trail
- [ ] Configurable response severity levels

**Response Workflow**:
```
ATO Detected (risk score > threshold)
    │
    ├─► LOW RISK (score 50-70)
    │   └─► Alert admin + Log
    │
    ├─► MEDIUM RISK (score 70-85)
    │   └─► Alert admin + Notify user + Require MFA
    │
    └─► HIGH RISK (score 85+)
        └─► Alert admin + Lock account + Terminate sessions + Reset password
```

**Tests**:
```typescript
// tests/ato/response-actions.test.ts
describe('ATO Response Actions', () => {
  it('should terminate active sessions')
  it('should trigger password reset')
  it('should enforce MFA')
  it('should notify admin')
  it('should notify user')
  it('should lock account temporarily')
  it('should create audit trail')
  it('should respect severity thresholds')
  it('should allow manual override')
});
```

**Implementation**:
- `lib/ato/response-actions.ts`
- `lib/ato/notifications.ts`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Account Takeover Detection                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   Login      │    │  Activity    │    │   Device     │       │
│  │   Events     │    │  Monitor     │    │   Registry   │       │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘       │
│         │                   │                   │                │
│         └───────────────────┼───────────────────┘                │
│                             │                                    │
│                    ┌────────▼────────┐                          │
│                    │   Risk Scoring  │                          │
│                    │     Engine      │                          │
│                    └────────┬────────┘                          │
│                             │                                    │
│              ┌──────────────┼──────────────┐                    │
│              │              │              │                    │
│       ┌──────▼──────┐ ┌─────▼─────┐ ┌─────▼─────┐              │
│       │ Impossible  │ │    New    │ │  Unusual  │              │
│       │   Travel    │ │  Device   │ │  Activity │              │
│       └──────┬──────┘ └─────┬─────┘ └─────┬─────┘              │
│              │              │              │                    │
│              └──────────────┼──────────────┘                    │
│                             │                                    │
│                    ┌────────▼────────┐                          │
│                    │    Response     │                          │
│                    │    Actions      │                          │
│                    └─────────────────┘                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Database Schema

```sql
-- Login events table
CREATE TABLE login_events (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  user_id VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL,
  success BOOLEAN NOT NULL,
  ip_address INET NOT NULL,
  user_agent TEXT,
  country VARCHAR(2),
  city VARCHAR(100),
  latitude DECIMAL(10, 8),
  longitude DECIMAL(11, 8),
  device_fingerprint VARCHAR(64),
  session_id VARCHAR(255),
  risk_score INTEGER,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Known devices table
CREATE TABLE known_devices (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  user_id VARCHAR(255) NOT NULL,
  fingerprint VARCHAR(64) NOT NULL,
  name VARCHAR(100),
  trusted BOOLEAN DEFAULT FALSE,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  metadata JSONB,
  UNIQUE(tenant_id, user_id, fingerprint)
);

-- User baselines table
CREATE TABLE user_baselines (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  user_id VARCHAR(255) NOT NULL,
  metrics JSONB NOT NULL,
  confidence_score INTEGER,
  updated_at TIMESTAMPTZ NOT NULL,
  UNIQUE(tenant_id, user_id)
);

-- ATO alerts table
CREATE TABLE ato_alerts (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  user_id VARCHAR(255) NOT NULL,
  alert_type VARCHAR(50) NOT NULL,
  risk_score INTEGER NOT NULL,
  details JSONB NOT NULL,
  status VARCHAR(20) DEFAULT 'open',
  response_actions JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);
```

## Success Metrics

| Metric | Before | After |
|--------|--------|-------|
| vs Barracuda | 42 | 50 |
| Innovation | 38 | 44 |
| Production Readiness | 88 | 90 |
| Test Count | 1,450 | 1,550 |
| ATO Detection | None | Full coverage |
