# Swordfish: Technical Architecture

## Overview

Swordfish is a hybrid email security platform replacing Barracuda for SMB/mid-market customers. This document covers the technical architecture and infrastructure decisions.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLOUDFLARE EDGE                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   WAF       │  │  Workers    │  │     R2      │  │    DNS      │        │
│  │  (DDoS)     │  │ (URL Click) │  │ (Artifacts) │  │  (MX/TXT)   │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CORE COMPUTE (Hetzner k3s)                        │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │  control-plane  │  │ decision-engine │  │   smtp-gateway  │             │
│  │      API        │  │                 │  │      (Go)       │             │
│  │  ───────────    │  │  ───────────    │  │  ───────────    │             │
│  │  Tenant mgmt    │  │  Deterministic  │  │  Inline SMTP    │             │
│  │  Policies       │  │  ML inference   │  │  Block/Forward  │             │
│  │  Users/RBAC     │  │  LLM escalation │  │  DKIM signing   │             │
│  │  Billing hooks  │  │  Verdict cache  │  │                 │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   o365-worker   │  │  gmail-worker   │  │ sandbox-worker  │             │
│  │  ───────────    │  │  ───────────    │  │  ───────────    │             │
│  │  Graph API      │  │  Gmail API      │  │  Job consumer   │             │
│  │  Subscriptions  │  │  Pub/Sub watch  │  │  VM lifecycle   │             │
│  │  Quarantine     │  │  Label mgmt     │  │  IOC extraction │             │
│  │  Purge          │  │  Delete         │  │                 │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DATA LAYER                                     │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │      Neon       │  │    Upstash      │  │    Upstash      │             │
│  │   (Postgres)    │  │    (Redis)      │  │    (Kafka)      │             │
│  │  ───────────    │  │  ───────────    │  │  ───────────    │             │
│  │  Tenants        │  │  Verdict cache  │  │  Async jobs     │             │
│  │  Policies       │  │  Rate limits    │  │  Email queue    │             │
│  │  Verdicts       │  │  Session store  │  │  Sandbox queue  │             │
│  │  Audit logs     │  │  Deduplication  │  │                 │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

### Frontend
| Technology | Version | Purpose |
|------------|---------|---------|
| Next.js | 16.x | App framework (App Router) |
| React | 19.x | UI library |
| Tailwind CSS | 4.x | Styling |
| Clerk | 6.x | Authentication & organizations |

### Backend Services
| Service | Language | Purpose |
|---------|----------|---------|
| control-plane-api | TypeScript/Node | Tenant management, policies, RBAC |
| decision-engine | TypeScript/Node | Detection pipeline orchestration |
| smtp-gateway | Go | Inline SMTP processing |
| o365-worker | TypeScript/Node | Microsoft Graph API integration |
| gmail-worker | TypeScript/Node | Gmail API + Pub/Sub integration |
| sandbox-worker | TypeScript/Node | Sandbox job orchestration |
| rewrite-service | TypeScript | Cloudflare Worker for URL click-time |

### Data Stores
| Store | Service | Purpose |
|-------|---------|---------|
| PostgreSQL | Neon | Primary database (tenants, policies, verdicts, audit) |
| Redis | Upstash | Caching, rate limiting, deduplication |
| Kafka | Upstash | Async job queue |
| Object Storage | Cloudflare R2 | Artifacts, reports, evidence |

### Infrastructure
| Component | Provider | Rationale |
|-----------|----------|-----------|
| Edge/CDN | Cloudflare | Workers, R2, WAF, DNS |
| Compute | Hetzner | Best price/performance for k3s |
| Database | Neon | Serverless Postgres, SOC 2 compliant |
| Cache | Upstash | Serverless Redis, global edge |
| Queue | Upstash | Serverless Kafka |
| Sandbox | Joe Sandbox API (V1), Custom Firecracker (V2) | |

---

## Service Responsibilities

### control-plane-api
Central management service for the platform.

**Responsibilities**:
- Tenant CRUD operations
- Policy management (allowlists, blocklists, rules)
- User management and RBAC
- Integration configuration (O365, Gmail, SMTP)
- Billing webhooks
- Audit log queries

**API Endpoints**:
```
POST   /api/tenants
GET    /api/tenants/:id
PATCH  /api/tenants/:id
DELETE /api/tenants/:id

POST   /api/tenants/:id/policies
GET    /api/tenants/:id/policies
PATCH  /api/tenants/:id/policies/:policyId

GET    /api/tenants/:id/integrations
POST   /api/tenants/:id/integrations/o365
POST   /api/tenants/:id/integrations/gmail
POST   /api/tenants/:id/integrations/smtp

GET    /api/tenants/:id/audit
```

### decision-engine
Core email analysis service.

**Responsibilities**:
- Orchestrate detection pipeline
- Run deterministic rules
- Invoke ML classification (gated)
- Invoke LLM escalation (gated)
- Generate human-readable explanations
- Cache verdicts
- Track costs per tenant

**API Endpoints**:
```
POST   /api/analyze          # Analyze email, return verdict
GET    /api/verdicts/:id     # Get verdict details
POST   /api/verdicts/:id/feedback  # User feedback on verdict
```

### smtp-gateway
High-performance SMTP server for inline email processing.

**Responsibilities**:
- Accept mail on port 25/587
- STARTTLS support
- Extract email for analysis
- Block/quarantine/forward based on verdict
- DKIM signing for modified emails
- Connection rate limiting

**Protocol**: SMTP (RFC 5321)

### o365-worker
Microsoft 365 integration service.

**Responsibilities**:
- OAuth token management
- Graph API subscriptions for new mail
- Fetch email content
- Move to quarantine folder
- Delete (purge) malicious email
- Add warning banners
- Retroactive remediation

**Microsoft Graph Scopes**:
```
Mail.Read
Mail.ReadWrite
Mail.Send
User.Read.All
MailboxSettings.Read
```

### gmail-worker
Google Workspace integration service.

**Responsibilities**:
- OAuth token management
- Gmail watch setup (Pub/Sub)
- Process Pub/Sub notifications
- Fetch email content
- Apply quarantine labels
- Move to trash / permanent delete
- Retroactive remediation

**Gmail API Scopes**:
```
https://www.googleapis.com/auth/gmail.modify
https://www.googleapis.com/auth/gmail.readonly
https://www.googleapis.com/auth/pubsub
```

### sandbox-worker
Malware sandbox orchestration.

**Responsibilities**:
- Consume sandbox job queue
- Submit files to sandbox API (V1: Joe Sandbox)
- Poll for analysis completion
- Extract IOCs from results
- Cache verdicts by file hash
- Manage custom Firecracker VMs (V2)

### rewrite-service (Cloudflare Worker)
Edge service for URL click-time protection.

**Responsibilities**:
- Decode signed URL tokens
- Fetch cached verdict
- Trigger async deep inspection for unknown URLs
- Return allow/warn/block decision
- Log click events

---

## Data Flow

### Email Processing Flow

```
                    ┌─────────────────────────────────────────┐
                    │           EMAIL SOURCES                 │
                    │  ┌─────────┐ ┌─────────┐ ┌─────────┐   │
                    │  │  SMTP   │ │  O365   │ │  Gmail  │   │
                    │  │ Gateway │ │  Graph  │ │   API   │   │
                    │  └────┬────┘ └────┬────┘ └────┬────┘   │
                    └───────┼───────────┼───────────┼────────┘
                            │           │           │
                            ▼           ▼           ▼
                    ┌─────────────────────────────────────────┐
                    │         NORMALIZE TO COMMON FORMAT      │
                    │  {                                      │
                    │    message_id, tenant_id,               │
                    │    from, to, subject, body,             │
                    │    headers, attachments, urls           │
                    │  }                                      │
                    └─────────────────────┬───────────────────┘
                                          │
                                          ▼
                    ┌─────────────────────────────────────────┐
                    │           DECISION ENGINE               │
                    │                                         │
                    │  ┌─────────────────────────────────┐   │
                    │  │ 1. DETERMINISTIC (100%)         │   │
                    │  │    SPF/DKIM/DMARC, headers,     │   │
                    │  │    domain age, homoglyphs       │   │
                    │  └─────────────┬───────────────────┘   │
                    │                │                        │
                    │       [Score < 30?]──Yes──► PASS       │
                    │                │ No                     │
                    │                ▼                        │
                    │  ┌─────────────────────────────────┐   │
                    │  │ 2. REPUTATION APIs (gated)      │   │
                    │  │    IP, URL, file hash           │   │
                    │  └─────────────┬───────────────────┘   │
                    │                │                        │
                    │       [Score > 80?]──Yes──► BLOCK      │
                    │                │ No                     │
                    │                ▼                        │
                    │  ┌─────────────────────────────────┐   │
                    │  │ 3. ML CLASSIFIER (gated)        │   │
                    │  │    Phishing/BEC detection       │   │
                    │  └─────────────┬───────────────────┘   │
                    │                │                        │
                    │       [Confidence > 90%?]──Yes──► ACT  │
                    │                │ No                     │
                    │                ▼                        │
                    │  ┌─────────────────────────────────┐   │
                    │  │ 4. LLM ESCALATION (≤5%)         │   │
                    │  │    Intent analysis, explain     │   │
                    │  └─────────────┬───────────────────┘   │
                    │                │                        │
                    │                ▼                        │
                    │            VERDICT                      │
                    └─────────────────────┬───────────────────┘
                                          │
                                          ▼
                    ┌─────────────────────────────────────────┐
                    │              ACTIONS                    │
                    │  ┌─────────┐ ┌─────────┐ ┌─────────┐   │
                    │  │  PASS   │ │ WARNING │ │  BLOCK  │   │
                    │  │ Deliver │ │ Banner  │ │Quarantin│   │
                    │  └─────────┘ └─────────┘ └─────────┘   │
                    └─────────────────────────────────────────┘
```

### URL Click-Time Flow

```
User clicks rewritten URL
         │
         ▼
┌─────────────────────────────────┐
│    Cloudflare Worker (Edge)     │
│                                 │
│  1. Decode signed token         │
│  2. Extract original URL        │
│  3. Check verdict cache         │
│         │                       │
│    [Cached?]                    │
│      │    │                     │
│     Yes   No                    │
│      │    │                     │
│      ▼    ▼                     │
│   Return  Queue async           │
│   verdict inspection            │
│      │    │                     │
│      ▼    ▼                     │
│  ┌──────────────────────┐       │
│  │ ALLOW: Redirect      │       │
│  │ WARN:  Interstitial  │       │
│  │ BLOCK: Block page    │       │
│  └──────────────────────┘       │
└─────────────────────────────────┘
```

---

## Database Schema

### Core Tables

```sql
-- Tenants
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    clerk_org_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    domain TEXT UNIQUE NOT NULL,
    plan TEXT NOT NULL DEFAULT 'starter',
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- MSP Access (which MSPs can manage which tenants)
CREATE TABLE msp_tenant_access (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    msp_clerk_org_id TEXT NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by TEXT NOT NULL,
    UNIQUE(msp_clerk_org_id, tenant_id)
);

-- Integration configurations
CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK (type IN ('o365', 'gmail', 'smtp')),
    status TEXT NOT NULL DEFAULT 'pending',
    config JSONB NOT NULL DEFAULT '{}',
    credentials_encrypted BYTEA,
    last_sync_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, type)
);

-- Policies
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('allowlist', 'blocklist', 'rule')),
    config JSONB NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Email verdicts
CREATE TABLE email_verdicts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id TEXT NOT NULL,
    from_address TEXT NOT NULL,
    to_addresses TEXT[] NOT NULL,
    subject TEXT,
    verdict TEXT NOT NULL CHECK (verdict IN ('pass', 'warn', 'quarantine', 'block')),
    confidence FLOAT NOT NULL,
    signals JSONB NOT NULL DEFAULT '[]',
    explanation TEXT NOT NULL,
    processing_time_ms INTEGER NOT NULL,
    layers_invoked TEXT[] NOT NULL,
    action_taken TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, message_id)
);

-- Quarantine
CREATE TABLE quarantine (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    verdict_id UUID NOT NULL REFERENCES email_verdicts(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'released', 'deleted')),
    released_by TEXT,
    released_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log (append-only)
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    actor_id TEXT NOT NULL,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'system', 'api')),
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_verdicts_tenant_created ON email_verdicts(tenant_id, created_at DESC);
CREATE INDEX idx_verdicts_tenant_verdict ON email_verdicts(tenant_id, verdict);
CREATE INDEX idx_quarantine_tenant_status ON quarantine(tenant_id, status);
CREATE INDEX idx_audit_tenant_created ON audit_log(tenant_id, created_at DESC);

-- Row-level security
ALTER TABLE email_verdicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE quarantine ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
```

---

## Security Architecture

### Authentication & Authorization
- **User Auth**: Clerk (OAuth, MFA support)
- **Service Auth**: JWT tokens with short expiry
- **API Auth**: API keys with scope restrictions

### Multi-Tenancy Isolation
- Row-level security (RLS) on all tenant data
- Tenant ID required on every query
- Cross-tenant queries only for MSP admins with explicit grants

### Encryption
- **In Transit**: TLS 1.3 everywhere
- **At Rest**: AES-256 for sensitive fields (credentials, tokens)
- **Key Management**: Per-tenant encryption keys, rotated quarterly

### Secrets Management
- Environment variables for non-sensitive config
- Encrypted database columns for OAuth tokens
- No secrets in code or logs

---

## Scalability Considerations

### Horizontal Scaling
- All services stateless, scale via k8s replicas
- Database connection pooling via PgBouncer
- Redis cluster for cache distribution

### Performance Targets
| Metric | Target |
|--------|--------|
| Decision latency (p50) | <500ms |
| Decision latency (p99) | <2s |
| API response (p50) | <100ms |
| API response (p99) | <500ms |

### Cost Optimization
- Deterministic layer first (cheapest)
- Gating reduces expensive operations (ML, LLM, sandbox)
- Verdict caching by message/file hash
- LLM budget caps per tenant

---

## Monitoring & Observability

### Metrics (Datadog)
- Request latency by service
- Error rates by endpoint
- Detection layer invocation rates
- Verdict distribution (pass/warn/block)
- Queue depths

### Logging
- Structured JSON logs
- Correlation IDs across services
- PII redaction in logs

### Alerting
- Error rate > 1%
- Latency p99 > 5s
- Queue depth > 1000
- Integration sync failures

---

## Disaster Recovery

### Backup Strategy
- Database: Neon continuous backup, point-in-time recovery
- Config: Git-versioned infrastructure as code
- Artifacts: R2 cross-region replication

### Recovery Targets
- RPO (Recovery Point Objective): 1 hour
- RTO (Recovery Time Objective): 4 hours

---

## Related Documents

- [Technical Recommendations](./TECHNICAL_RECOMMENDATIONS.md) - Detection, sandbox, API decisions
- [Implementation Plan](./IMPLEMENTATION_PLAN.md) - Phased delivery with TDD
- [Test Strategy](./TEST_STRATEGY.md) - Testing approach and coverage
