# Swordfish v1 Architecture Design

## Vision

Swordfish v1 aims to be an **enterprise-grade email security platform** scoring **80/100** on our maturity scale, where 50 represents Barracuda Essentials parity. This positions Swordfish alongside Proofpoint, Mimecast, and Abnormal Security.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              SWORDFISH v1 ARCHITECTURE                          │
└─────────────────────────────────────────────────────────────────────────────────┘

                    ┌──────────────────────────────────────────┐
                    │            EMAIL PROVIDERS               │
                    │  ┌─────────────┐    ┌─────────────┐     │
                    │  │   Gmail     │    │  Microsoft  │     │
                    │  │  Workspace  │    │    365      │     │
                    │  └──────┬──────┘    └──────┬──────┘     │
                    └─────────┼──────────────────┼────────────┘
                              │                  │
                    ┌─────────▼──────────────────▼────────────┐
                    │         REAL-TIME INGESTION             │
                    │  ┌─────────────┐    ┌─────────────┐     │
                    │  │  Pub/Sub    │    │   Graph     │     │
                    │  │  Webhooks   │    │  Webhooks   │     │
                    │  └──────┬──────┘    └──────┬──────┘     │
                    └─────────┼──────────────────┼────────────┘
                              │                  │
                              ▼                  ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            MESSAGE QUEUE (Redis/BullMQ)                         │
│                                                                                 │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│   │  Incoming   │  │  Analysis   │  │ Remediation │  │  Reporting  │          │
│   │   Queue     │  │   Queue     │  │   Queue     │  │   Queue     │          │
│   └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         DETECTION ENGINE                                        │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    Layer 0: Policy Engine                               │   │
│  │         Allowlists → Blocklists → Custom Rules → DLP Policies           │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              │                                                  │
│                              ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                 Layer 1: Deterministic Analysis                         │   │
│  │    SPF/DKIM/DMARC │ Header Anomalies │ URL Patterns │ Sender Rep        │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              │                                                  │
│                              ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                 Layer 2: Threat Intelligence                            │   │
│  │  VirusTotal │ URLhaus │ PhishTank │ AbuseIPDB │ abuse.ch │ WHOIS        │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              │                                                  │
│                              ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    Layer 3: ML Classification                           │   │
│  │   Phishing Model │ BEC Detection │ Spam Filter │ Impersonation Check    │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              │                                                  │
│                              ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    Layer 4: Sandbox Analysis                            │   │
│  │        Joe Sandbox / Cuckoo │ URL Detonation │ Attachment Scan          │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              │                                                  │
│                              ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    Layer 5: LLM Analysis (Claude)                       │   │
│  │     Context Understanding │ Social Engineering Detection │ BEC          │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                              │                                                  │
│                              ▼                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    Verdict Engine                                       │   │
│  │   Score Aggregation │ Confidence Calculation │ Action Determination     │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
     ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
     │   DELIVER   │  │ QUARANTINE  │  │    BLOCK    │
     │             │  │             │  │             │
     │ Safe email  │  │ Hold for    │  │ Reject or   │
     │ to inbox    │  │ review      │  │ delete      │
     └─────────────┘  └──────┬──────┘  └─────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  USER PORTAL    │
                    │                 │
                    │ • View threats  │
                    │ • Release req   │
                    │ • Report FP/FN  │
                    └─────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                              DATA LAYER                                         │
│                                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │  PostgreSQL │  │    Redis    │  │  R2/S3      │  │  ClickHouse │           │
│  │  (Primary)  │  │  (Cache)    │  │  (Storage)  │  │  (Analytics)│           │
│  │             │  │             │  │             │  │             │           │
│  │ • Tenants   │  │ • Sessions  │  │ • Emails    │  │ • Metrics   │           │
│  │ • Verdicts  │  │ • Threat DB │  │ • Attachmts │  │ • Reports   │           │
│  │ • Policies  │  │ • Rate Lim  │  │ • Exports   │  │ • Trends    │           │
│  │ • Audit Log │  │ • Queues    │  │ • Backups   │  │             │           │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                           EXTERNAL INTEGRATIONS                                 │
│                                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │    SIEM     │  │   SOAR      │  │  Ticketing  │  │    SSO      │           │
│  │             │  │             │  │             │  │             │           │
│  │ • Splunk    │  │ • Tines     │  │ • Jira      │  │ • Okta      │           │
│  │ • Sentinel  │  │ • Phantom   │  │ • ServiceNw │  │ • Azure AD  │           │
│  │ • Chronicle │  │ • XSOAR     │  │ • Zendesk   │  │ • Google    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Real-Time Ingestion Layer

**Purpose**: Receive email events the moment they arrive, not through polling.

| Provider | Method | Latency | Implementation |
|----------|--------|---------|----------------|
| Gmail | Pub/Sub Push | <1 second | Google Cloud Pub/Sub subscription |
| Microsoft 365 | Graph Webhooks | <3 seconds | Change notifications subscription |

**Key Features**:
- Automatic subscription renewal
- Delivery guarantee with retry logic
- Dead letter queue for failed processing
- Rate limiting protection

### 2. Message Queue System

**Technology**: Redis + BullMQ

**Queues**:
| Queue | Purpose | Priority | Concurrency |
|-------|---------|----------|-------------|
| `incoming` | New emails from webhooks | Critical | 10 workers |
| `analysis` | Detection pipeline jobs | High | 5 workers |
| `remediation` | Quarantine/release actions | High | 3 workers |
| `reporting` | Report generation | Low | 1 worker |
| `threat-intel` | Async threat lookups | Medium | 5 workers |

### 3. Detection Engine Layers

#### Layer 0: Policy Engine
- Allowlist/blocklist evaluation (highest priority)
- Custom policy rules
- DLP pattern matching
- Tenant-specific overrides

#### Layer 1: Deterministic Analysis
- Email authentication (SPF, DKIM, DMARC)
- Header anomaly detection
- URL pattern matching (regex)
- Sender reputation (internal database)
- Attachment type analysis

#### Layer 2: Threat Intelligence
| Source | Data Type | Update Frequency |
|--------|-----------|------------------|
| VirusTotal | URL/File hashes | Real-time |
| URLhaus | Malicious URLs | Every 5 min |
| PhishTank | Phishing URLs | Every 30 min |
| AbuseIPDB | IP reputation | Real-time |
| abuse.ch | Malware hashes | Every 5 min |
| WHOIS | Domain age | On-demand |

#### Layer 3: ML Classification
- **Phishing Classifier**: Text + structural analysis
- **BEC Detector**: Executive impersonation patterns
- **Spam Filter**: Content classification
- **Impersonation Check**: Display name vs. email mismatch

#### Layer 4: Sandbox Analysis
- **Attachments**: Joe Sandbox API for detonation
- **URLs**: Safe browsing + screenshot capture
- **QR Codes**: Extraction and URL analysis

#### Layer 5: LLM Analysis (Claude)
- Only invoked for uncertain cases (score 30-70)
- Social engineering detection
- Context-aware analysis
- Business email compromise detection

### 4. Verdict Engine

**Scoring Model**:
```
Final Score = Σ(Layer_Score × Layer_Weight × Confidence)

Weights:
- Deterministic: 25%
- Threat Intel: 25%
- ML Classification: 20%
- Sandbox: 15%
- LLM: 15%
```

**Verdict Thresholds**:
| Score Range | Verdict | Action |
|-------------|---------|--------|
| 0-29 | Pass | Deliver to inbox |
| 30-49 | Suspicious | Deliver with warning |
| 50-69 | Review | Quarantine for admin review |
| 70-84 | Quarantine | Auto-quarantine |
| 85-100 | Block | Reject/delete |

### 5. Data Architecture

#### PostgreSQL Schema (Core)
```sql
-- Multi-tenant support
tenants (id, clerk_org_id, name, plan, settings)
users (id, clerk_user_id, tenant_id, role)

-- Email analysis
email_verdicts (id, tenant_id, message_id, verdict, score, signals)
threats (id, tenant_id, verdict_id, status, quarantined_at)

-- Policies
policies (id, tenant_id, name, type, rules, priority)
list_entries (id, tenant_id, list_type, entry_type, value)

-- Operations
audit_logs (id, tenant_id, actor_id, action, resource)
notifications (id, tenant_id, type, message, read_at)
```

#### Redis Structure (Cache)
```
threat_intel:{domain}     -> Reputation data (TTL: 24h)
threat_intel:{url_hash}   -> URL analysis (TTL: 24h)
threat_intel:{ip}         -> IP reputation (TTL: 1h)
rate_limit:{tenant_id}    -> API rate limits
session:{session_id}      -> User sessions
queue:incoming            -> BullMQ incoming queue
queue:analysis            -> BullMQ analysis queue
```

#### R2/S3 Storage
```
/emails/{tenant_id}/{year}/{month}/{message_id}.eml
/attachments/{tenant_id}/{hash}.bin
/exports/{tenant_id}/{export_id}.csv
/reports/{tenant_id}/{report_id}.pdf
```

---

## API Design

### REST API Endpoints

```
Authentication (Clerk)
├── POST   /api/auth/webhook          # Clerk webhook handler

Integrations
├── GET    /api/integrations          # List connected integrations
├── POST   /api/integrations/gmail    # Connect Gmail
├── POST   /api/integrations/o365     # Connect Microsoft 365
├── DELETE /api/integrations/:id      # Disconnect integration
├── POST   /api/integrations/:id/sync # Manual sync trigger

Email Analysis
├── GET    /api/threats               # List detected threats
├── GET    /api/threats/:id           # Get threat details
├── POST   /api/threats/bulk          # Bulk actions
├── GET    /api/quarantine            # List quarantined emails
├── POST   /api/quarantine/:id/release # Release from quarantine
├── POST   /api/quarantine/:id/delete # Delete quarantined email

Policies
├── GET    /api/policies              # List policies
├── POST   /api/policies              # Create policy
├── PUT    /api/policies/:id          # Update policy
├── DELETE /api/policies/:id          # Delete policy
├── GET    /api/lists                 # Get allow/block lists
├── POST   /api/lists                 # Add to list

Analytics
├── GET    /api/analytics/dashboard   # Dashboard metrics
├── GET    /api/analytics/threats     # Threat trends
├── GET    /api/analytics/detection   # Detection performance
├── POST   /api/reports/generate      # Generate report

Webhooks (Inbound)
├── POST   /api/webhooks/gmail        # Gmail Pub/Sub notifications
├── POST   /api/webhooks/graph        # Microsoft Graph notifications
├── POST   /api/webhooks/clerk        # Clerk user events

Admin
├── GET    /api/admin/tenants         # List tenants (MSP)
├── GET    /api/admin/audit           # Audit logs
├── POST   /api/admin/impersonate     # Tenant impersonation (MSP)
```

### Webhook Payloads

**Gmail Pub/Sub**:
```json
{
  "message": {
    "data": "base64_encoded_history_id",
    "messageId": "123456789",
    "publishTime": "2024-01-15T10:30:00Z"
  },
  "subscription": "projects/xxx/subscriptions/swordfish-gmail"
}
```

**Microsoft Graph**:
```json
{
  "value": [{
    "subscriptionId": "xxx",
    "changeType": "created",
    "resource": "users/xxx/messages/xxx",
    "resourceData": {
      "id": "message_id"
    }
  }]
}
```

---

## Security Architecture

### Authentication & Authorization
- **Clerk** for user authentication
- **JWT tokens** for API access
- **Role-based access control** (RBAC):
  - `msp_admin`: Full access across tenants
  - `admin`: Full access within tenant
  - `analyst`: View + remediate
  - `viewer`: Read-only access

### Data Security
- **Encryption at rest**: AES-256 (database, storage)
- **Encryption in transit**: TLS 1.3
- **PII handling**: Email content encrypted, minimal retention
- **Audit logging**: All actions logged with actor, timestamp, IP

### API Security
- Rate limiting per tenant
- API key authentication for integrations
- Webhook signature verification
- Input validation and sanitization

---

## Deployment Architecture

### Infrastructure (Railway/Render)

```
┌─────────────────────────────────────────────────────────────┐
│                    Load Balancer (Cloudflare)               │
└─────────────────────────────────┬───────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
        ▼                         ▼                         ▼
┌───────────────┐        ┌───────────────┐        ┌───────────────┐
│   Web App     │        │   Web App     │        │   Web App     │
│   (Next.js)   │        │   (Next.js)   │        │   (Next.js)   │
│   Instance 1  │        │   Instance 2  │        │   Instance 3  │
└───────────────┘        └───────────────┘        └───────────────┘
        │                         │                         │
        └─────────────────────────┼─────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
        ▼                         ▼                         ▼
┌───────────────┐        ┌───────────────┐        ┌───────────────┐
│    Worker     │        │    Worker     │        │    Worker     │
│   Instance 1  │        │   Instance 2  │        │   Instance 3  │
│  (BullMQ)     │        │  (BullMQ)     │        │  (BullMQ)     │
└───────────────┘        └───────────────┘        └───────────────┘
        │                         │                         │
        └─────────────────────────┼─────────────────────────┘
                                  │
                                  ▼
        ┌─────────────────────────────────────────────────────┐
        │                    Data Layer                       │
        │  ┌─────────┐  ┌─────────┐  ┌─────────┐             │
        │  │ Neon    │  │ Upstash │  │ R2      │             │
        │  │ Postgres│  │ Redis   │  │ Storage │             │
        │  └─────────┘  └─────────┘  └─────────┘             │
        └─────────────────────────────────────────────────────┘
```

### Environment Configuration

```bash
# Core
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
R2_BUCKET=swordfish-storage

# Authentication
CLERK_SECRET_KEY=sk_live_...
CLERK_WEBHOOK_SECRET=whsec_...

# Email Providers
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
MICROSOFT_CLIENT_ID=...
MICROSOFT_CLIENT_SECRET=...

# Threat Intelligence
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...

# Sandbox
JOE_SANDBOX_API_KEY=...

# AI
ANTHROPIC_API_KEY=...

# Monitoring
SENTRY_DSN=...
```

---

## Scalability Considerations

### Horizontal Scaling
- Stateless web instances (auto-scale based on CPU)
- Worker instances scale based on queue depth
- Database read replicas for analytics queries

### Performance Targets
| Metric | Target |
|--------|--------|
| Email processing latency | < 5 seconds |
| API response time (p95) | < 200ms |
| Webhook acknowledgment | < 500ms |
| Dashboard load time | < 2 seconds |

### Rate Limits
| Tier | Emails/hour | API calls/min |
|------|-------------|---------------|
| Starter | 1,000 | 60 |
| Pro | 10,000 | 300 |
| Enterprise | 100,000 | 1,000 |

---

## Monitoring & Observability

### Metrics (Prometheus/Grafana)
- Email processing throughput
- Detection latency by layer
- Queue depth and processing time
- Error rates by type
- API response times

### Logging (Structured JSON)
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "info",
  "service": "detection",
  "tenant_id": "xxx",
  "message_id": "xxx",
  "event": "email_analyzed",
  "verdict": "quarantine",
  "score": 75,
  "processing_time_ms": 2340
}
```

### Alerting
- Queue backlog > 1000 emails
- Error rate > 1%
- Processing latency > 30s
- Webhook delivery failures
- Sandbox API errors

---

## Disaster Recovery

### Backup Strategy
| Data | Frequency | Retention |
|------|-----------|-----------|
| PostgreSQL | Continuous (WAL) | 30 days |
| Redis | Every 6 hours | 7 days |
| R2 Storage | Real-time replication | 90 days |

### Recovery Objectives
- **RPO** (Recovery Point Objective): 1 hour
- **RTO** (Recovery Time Objective): 4 hours

### Failover
- Multi-region database (Neon)
- Redis cluster with automatic failover
- CDN caching for static assets
