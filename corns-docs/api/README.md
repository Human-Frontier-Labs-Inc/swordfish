# Swordfish API Reference

Enterprise email security API with ML-powered threat detection.

## Base URL

```
Production: https://api.swordfish.security/v1
Development: http://localhost:3000/api
```

## Authentication

All API requests require authentication via Clerk. Include the session token:

```bash
Authorization: Bearer <session_token>
```

## Quick Start

### 1. List Recent Threats

```bash
curl -X GET "https://api.swordfish.security/v1/threats?limit=10" \
  -H "Authorization: Bearer $TOKEN"
```

### 2. Get Dashboard Stats

```bash
curl -X GET "https://api.swordfish.security/v1/analytics?period=7d" \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Release Quarantined Email

```bash
curl -X POST "https://api.swordfish.security/v1/threats/{id}/release" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Endpoints

### Threats

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/threats` | List all threats |
| GET | `/threats/{id}` | Get threat details |
| DELETE | `/threats/{id}` | Delete threat |
| POST | `/threats/{id}/release` | Release from quarantine |
| POST | `/threats/bulk` | Bulk operations |

#### List Threats

```http
GET /threats?status=quarantine&limit=50&offset=0
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| status | string | Filter: `pass`, `suspicious`, `quarantine`, `block` |
| severity | string | Minimum severity: `low`, `medium`, `high`, `critical` |
| startDate | ISO date | Filter from date |
| endDate | ISO date | Filter to date |
| limit | integer | Results per page (1-100, default: 50) |
| offset | integer | Pagination offset |

**Response:**

```json
{
  "threats": [
    {
      "id": "uuid",
      "messageId": "msg-id",
      "from": "sender@example.com",
      "subject": "Email subject",
      "verdict": "quarantine",
      "score": 75,
      "signals": [...],
      "createdAt": "2024-01-01T00:00:00Z"
    }
  ],
  "stats": {
    "total": 100,
    "quarantined": 45,
    "blocked": 30
  },
  "pagination": {
    "total": 100,
    "limit": 50,
    "offset": 0,
    "hasMore": true
  }
}
```

#### Release Quarantined Email

```http
POST /threats/{id}/release
Content-Type: application/json

{
  "addToAllowlist": false
}
```

---

### Analytics

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/analytics` | Dashboard statistics |
| GET | `/analytics/timeseries` | Time series data |
| GET | `/analytics/performance` | Detection performance |

#### Dashboard Stats

```http
GET /analytics?period=7d
```

**Response:**

```json
{
  "stats": {
    "totalScanned": 10000,
    "threatsBlocked": 150,
    "threatsQuarantined": 230,
    "passedEmails": 9620,
    "avgProcessingTime": 45.2,
    "detectionRate": 0.038
  }
}
```

#### Time Series

```http
GET /analytics/timeseries?period=7d&metric=threats
```

**Response:**

```json
{
  "data": [
    { "timestamp": "2024-01-01T00:00:00Z", "value": 15 },
    { "timestamp": "2024-01-02T00:00:00Z", "value": 22 }
  ],
  "period": "7d",
  "metric": "threats"
}
```

---

### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/reports/export` | Export data |
| GET | `/reports/scheduled` | List scheduled reports |
| POST | `/reports/scheduled` | Create scheduled report |
| PATCH | `/reports/scheduled/{id}` | Update report |
| DELETE | `/reports/scheduled/{id}` | Delete report |

#### Export Data

```http
POST /reports/export
Content-Type: application/json

{
  "type": "verdicts",
  "format": "csv",
  "dateRange": {
    "start": "2024-01-01",
    "end": "2024-01-31"
  }
}
```

**Export Types:**
- `verdicts` - All detection verdicts
- `threats` - Blocked/quarantined threats only
- `audit_log` - Audit trail
- `executive_summary` - Summary report

**Formats:** `csv`, `json`

#### Create Scheduled Report

```http
POST /reports/scheduled
Content-Type: application/json

{
  "name": "Weekly Threat Summary",
  "frequency": "weekly",
  "recipients": ["admin@company.com"],
  "config": {
    "includeStats": true,
    "includeTopThreats": true
  }
}
```

---

### Notifications

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/notifications` | List notifications |
| GET | `/notifications/config` | Get config |
| PUT | `/notifications/config` | Update config |

#### Update Notification Config

```http
PUT /notifications/config
Content-Type: application/json

{
  "emailEnabled": true,
  "emailRecipients": ["security@company.com"],
  "slackEnabled": true,
  "slackWebhookUrl": "https://hooks.slack.com/...",
  "severityThreshold": "warning"
}
```

---

### Policies

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/policies` | List policies |
| POST | `/policies` | Create policy |
| GET | `/policies/allowlist` | List allowlist |
| POST | `/policies/allowlist` | Add to allowlist |
| GET | `/policies/blocklist` | List blocklist |
| POST | `/policies/blocklist` | Add to blocklist |

#### Add to Allowlist

```http
POST /policies/allowlist
Content-Type: application/json

{
  "pattern": "trusted-partner.com",
  "patternType": "domain",
  "name": "Trusted Partner"
}
```

**Pattern Types:** `email`, `domain`, `ip`

---

### Webhooks

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/webhooks/email` | Process incoming email |

#### Process Email (Webhook)

```http
POST /webhooks/email
X-Webhook-Token: <webhook_token>
Content-Type: application/json

{
  "messageId": "unique-id",
  "from": "sender@example.com",
  "to": ["recipient@company.com"],
  "subject": "Email subject",
  "body": {
    "text": "Plain text content",
    "html": "<html>...</html>"
  },
  "headers": {
    "received": "...",
    "spf": "pass"
  },
  "attachments": [
    {
      "filename": "document.pdf",
      "contentType": "application/pdf",
      "size": 12345
    }
  ]
}
```

**Response:**

```json
{
  "messageId": "unique-id",
  "verdict": "pass",
  "score": 15,
  "confidence": 0.92,
  "explanation": "Email passed security checks.",
  "recommendation": "This email appears to be safe.",
  "signals": [],
  "processingTimeMs": 42.5
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": "Error message",
  "details": { ... }
}
```

| Status | Description |
|--------|-------------|
| 400 | Bad request - invalid parameters |
| 401 | Unauthorized - missing or invalid auth |
| 403 | Forbidden - insufficient permissions |
| 404 | Not found - resource doesn't exist |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

---

## Rate Limits

| Tier | Limit |
|------|-------|
| Standard | 100 requests/minute |
| Enterprise | 1000 requests/minute |

Rate limit headers:
- `X-RateLimit-Limit`: Request limit
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Reset timestamp

---

## Verdict Types

| Verdict | Score Range | Description |
|---------|-------------|-------------|
| `pass` | 0-29 | Safe email |
| `suspicious` | 30-59 | Review recommended |
| `quarantine` | 60-79 | Held for admin review |
| `block` | 80-100 | Rejected |

---

## Signal Severities

| Severity | Description |
|----------|-------------|
| `info` | Informational, no action needed |
| `warning` | Suspicious, review recommended |
| `critical` | High-risk threat indicator |

---

## SDKs

Coming soon:
- JavaScript/TypeScript
- Python
- Go

---

## Support

- Documentation: https://docs.swordfish.security
- API Status: https://status.swordfish.security
- Email: support@swordfish.security
