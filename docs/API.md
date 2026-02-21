# Swordfish API Documentation

**Version:** 1.0.0
**Base URL:** `https://api.swordfish.app` (production) or `http://localhost:3000` (development)

## Authentication

All API endpoints (except `/api/health`) require authentication via Clerk.

```bash
Authorization: Bearer <clerk_session_token>
```

## Core Endpoints

### Health Check

Check system health for load balancers and monitoring.

```
GET /api/health
HEAD /api/health  # Liveness probe
```

**Response:**
```json
{
  "status": "healthy" | "degraded" | "unhealthy",
  "timestamp": "2026-01-30T12:00:00.000Z",
  "version": "1.0.0",
  "checks": [
    {
      "name": "database",
      "status": "pass" | "warn" | "fail",
      "latency": 5,
      "message": "Database connection successful"
    },
    {
      "name": "dependencies",
      "status": "pass",
      "message": "All dependencies configured"
    },
    {
      "name": "memory",
      "status": "pass",
      "message": "Heap: 128MB / 512MB (25.0%)"
    }
  ]
}
```

**HTTP Status Codes:**
- `200` - Healthy or Degraded
- `503` - Unhealthy

---

### Email Analysis

Analyze an email for security threats.

```
POST /api/analyze
```

**Request Body:**
```json
{
  // Option 1: Raw MIME format
  "rawMime": "From: sender@example.com\nTo: ...",

  // Option 2: Microsoft Graph API format
  "graphMessage": { /* MS Graph message object */ },

  // Option 3: Gmail API format
  "gmailMessage": { /* Gmail message object */ },

  // Option 4: Pre-parsed format
  "parsed": {
    "messageId": "unique-id",
    "from": { "name": "Sender", "email": "sender@example.com" },
    "to": [{ "name": "Recipient", "email": "recipient@company.com" }],
    "subject": "Email Subject",
    "body": {
      "plain": "Plain text body",
      "html": "<p>HTML body</p>"
    },
    "headers": {},
    "attachments": []
  },

  // Options
  "quickCheckOnly": false,  // Fast check without full analysis
  "skipLLM": false          // Skip AI analysis for cost savings
}
```

**Response (Full Analysis):**
```json
{
  "messageId": "unique-id",
  "verdict": "pass" | "suspicious" | "quarantine" | "block",
  "score": 75,
  "confidence": "high" | "medium" | "low",
  "explanation": "Multiple phishing indicators detected...",
  "recommendation": "Quarantine email and warn user",
  "signals": [
    {
      "type": "phishing_url",
      "severity": "high",
      "detail": "Suspicious URL detected: fake-login.xyz"
    }
  ],
  "processingTimeMs": 450,
  "llmUsed": true,
  "analyzedAt": "2026-01-30T12:00:00.000Z"
}
```

**Response (Quick Check):**
```json
{
  "messageId": "unique-id",
  "verdict": "pass",
  "quickCheck": true,
  "analyzedAt": "2026-01-30T12:00:00.000Z"
}
```

Or if inconclusive:
```json
{
  "messageId": "unique-id",
  "quickCheck": true,
  "needsFullAnalysis": true,
  "message": "Quick check inconclusive, full analysis recommended"
}
```

---

### Threats

List and manage detected threats.

#### List Threats
```
GET /api/threats
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| status | string | quarantined | Filter: quarantined, released, deleted, all |
| limit | number | 50 | Max results (1-100) |
| offset | number | 0 | Pagination offset |
| stats | boolean | false | Include statistics |

**Response:**
```json
{
  "threats": [
    {
      "id": "threat-uuid",
      "messageId": "email-message-id",
      "subject": "URGENT: Password Reset",
      "sender": "attacker@fake-domain.com",
      "recipient": "user@company.com",
      "threatType": "phishing",
      "score": 92,
      "status": "quarantined",
      "quarantinedAt": "2026-01-30T12:00:00.000Z"
    }
  ],
  "stats": {
    "quarantinedCount": 15,
    "last24Hours": 3
  },
  "pagination": {
    "limit": 50,
    "offset": 0,
    "hasMore": false
  }
}
```

#### Get Threat Details
```
GET /api/threats/{id}
```

#### Release Threat
```
POST /api/threats/{id}/release
```

**Request Body:**
```json
{
  "reason": "False positive - legitimate vendor email"
}
```

#### Bulk Operations
```
POST /api/threats/bulk
```

**Request Body:**
```json
{
  "action": "release" | "delete" | "report",
  "threatIds": ["id1", "id2", "id3"]
}
```

---

### Dashboard Statistics

```
GET /api/stats
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| period | string | 7d | Time period: 24h, 7d, 30d, 90d |

**Response:**
```json
{
  "summary": {
    "totalEmails": 15420,
    "passedEmails": 15100,
    "threatsDetected": 320,
    "quarantined": 45,
    "blocked": 12,
    "avgThreatScore": 78,
    "avgProcessingTime": 234,
    "detectionRate": "2.1",
    "activeQuarantined": 23,
    "last24Hours": 5
  },
  "timeline": [
    {
      "date": "2026-01-30",
      "total": 2500,
      "passed": 2450,
      "threats": 50
    }
  ],
  "topThreats": [
    {
      "signal_type": "phishing_url",
      "count": 45,
      "avg_score": 82.5
    }
  ],
  "topSenders": [
    {
      "sender": "suspicious@fake-domain.com",
      "email_count": 12,
      "avg_score": 88.3,
      "max_score": 95
    }
  ],
  "integrations": [
    {
      "provider": "gmail",
      "status": "active",
      "email": "admin@company.com",
      "last_sync": "2026-01-30T12:00:00.000Z"
    }
  ],
  "period": "7d"
}
```

---

### Analytics

#### Overview Analytics
```
GET /api/analytics/overview
```

#### Time Series Data
```
GET /api/analytics/timeseries
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| metric | string | emails | Metric: emails, threats, verdicts |
| period | string | 7d | Time period |
| groupBy | string | day | Grouping: hour, day, week |

#### Performance Analytics
```
GET /api/analytics/performance
```

---

### Quarantine Management

#### List Quarantined Emails
```
GET /api/quarantine
```

#### Release from Quarantine
```
POST /api/quarantine/{id}/release
```

#### Bulk Operations
```
POST /api/quarantine/bulk
```

---

### Notifications

#### List Notifications
```
GET /api/notifications
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| limit | number | 20 | Max results |
| unreadOnly | boolean | false | Only unread |

#### Mark as Read
```
POST /api/notifications/{id}/read
```

#### Mark All as Read
```
POST /api/notifications/read-all
```

#### Notification Configuration
```
GET /api/notifications/config
PUT /api/notifications/config
```

---

### Lists (Allow/Block)

#### List All Lists
```
GET /api/lists
```

#### Create List Entry
```
POST /api/lists
```

**Request Body:**
```json
{
  "type": "allow" | "block",
  "value": "trusted@domain.com",
  "valueType": "email" | "domain" | "ip",
  "reason": "Trusted vendor"
}
```

#### Delete Entry
```
DELETE /api/lists/{id}
```

#### Bulk Import
```
POST /api/lists/bulk
```

---

### Policies

#### List Policies
```
GET /api/policies
```

#### Create Policy
```
POST /api/policies
```

**Request Body:**
```json
{
  "name": "High Risk Users",
  "description": "Enhanced protection for executives",
  "enabled": true,
  "conditions": {
    "recipientGroups": ["executives"],
    "senderTrustLevel": "unknown"
  },
  "actions": {
    "quarantineThreshold": 60,
    "blockThreshold": 85,
    "notifyUser": true,
    "notifyAdmin": true
  }
}
```

#### Update Policy
```
PUT /api/policies/{id}
```

#### Delete Policy
```
DELETE /api/policies/{id}
```

---

### Settings

#### Get Settings
```
GET /api/settings
```

#### Update Settings
```
PUT /api/settings
```

#### VIP Protection
```
GET /api/settings/vip
POST /api/settings/vip
POST /api/settings/vip/import
```

#### Alert Configuration
```
GET /api/settings/alerts
PUT /api/settings/alerts
```

#### Webhooks
```
GET /api/settings/webhooks
POST /api/settings/webhooks
PUT /api/settings/webhooks/{id}
DELETE /api/settings/webhooks/{id}
POST /api/settings/webhooks/{id}/test
```

---

### Integrations

#### List Integrations
```
GET /api/integrations
```

#### Gmail Integration
```
GET /api/auth/google
GET /api/integrations/gmail/callback
POST /api/integrations/gmail/register-push
```

#### Microsoft/O365 Integration
```
GET /api/auth/microsoft
GET /api/integrations/o365/callback
```

#### Domain-Wide Delegation
```
GET /api/integrations/domain-wide
POST /api/integrations/domain-wide
POST /api/integrations/domain-wide/sync
```

---

### Reports

#### Generate Report
```
POST /api/reports/export
```

**Request Body:**
```json
{
  "type": "threats" | "analytics" | "compliance",
  "format": "csv" | "pdf",
  "period": "7d" | "30d" | "90d",
  "filters": {}
}
```

#### Scheduled Reports
```
GET /api/reports/scheduled
POST /api/reports/scheduled
PUT /api/reports/scheduled/{id}
DELETE /api/reports/scheduled/{id}
POST /api/reports/scheduled/{id}/run
```

#### Compliance Report
```
GET /api/reports/compliance
```

---

## Admin Endpoints

These require admin role permissions.

### User Management
```
GET /api/admin/users
POST /api/admin/users/invite
POST /api/admin/users/{id}/suspend
POST /api/admin/users/{id}/reactivate
```

### Tenant Management
```
GET /api/admin/tenants
GET /api/admin/tenants/{id}
PUT /api/admin/tenants/{id}
GET /api/admin/tenants/{id}/users
```

### System Stats
```
GET /api/admin/stats
```

### Audit Log
```
GET /api/admin/audit
```

### Verification
```
POST /api/admin/verify
```

---

## Webhooks (Incoming)

### Clerk Webhook
```
POST /api/webhooks/clerk
```
Handles user and organization events from Clerk.

### Webhook Health
```
GET /api/webhooks/health
```

---

## V1 API (Public)

External API for integrations.

### Report Phishing
```
POST /api/v1/report-phish
GET /api/v1/report-phish
GET /api/v1/report-phish/{id}
GET /api/v1/report-phish/stats
GET /api/v1/report-phish/leaderboard
GET /api/v1/report-phish/manifests
GET /api/v1/report-phish/reporters/{email}
```

### Threats (V1)
```
GET /api/v1/threats
GET /api/v1/threats/{id}
```

### Policies (V1)
```
GET /api/v1/policies
GET /api/v1/policies/{id}
```

### Quarantine (V1)
```
GET /api/v1/quarantine
```

---

## Metrics

Prometheus-compatible metrics endpoint.

```
GET /api/metrics
```

Returns metrics in Prometheus format for monitoring.

---

## Error Responses

All errors follow this format:

```json
{
  "error": "Error message",
  "message": "Detailed error description (optional)",
  "code": "ERROR_CODE (optional)"
}
```

**Common HTTP Status Codes:**
| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 429 | Rate Limited |
| 500 | Internal Server Error |
| 503 | Service Unavailable |

---

## Rate Limits

| Endpoint Type | Limit |
|---------------|-------|
| Analysis | 100 req/min |
| API Reads | 1000 req/min |
| API Writes | 100 req/min |
| Webhooks | 1000 req/min |

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1706616000
```

---

## SDK Examples

### JavaScript/TypeScript
```typescript
const response = await fetch('/api/analyze', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${sessionToken}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    parsed: {
      messageId: 'msg-123',
      from: { name: 'Sender', email: 'sender@example.com' },
      to: [{ name: 'Recipient', email: 'user@company.com' }],
      subject: 'Test Email',
      body: { plain: 'Hello world' }
    }
  })
});

const verdict = await response.json();
console.log(`Verdict: ${verdict.verdict}, Score: ${verdict.score}`);
```

### cURL
```bash
curl -X POST https://api.swordfish.app/api/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rawMime": "From: test@example.com\nTo: user@company.com\nSubject: Test\n\nHello"
  }'
```

---

*Last updated: January 30, 2026*
