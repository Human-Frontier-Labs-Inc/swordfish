# System Architecture Overview

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SWORDFISH                                       │
│                     AI-Powered Email Security Platform                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                         INTEGRATION LAYER                              │ │
│  │                                                                        │ │
│  │   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐              │ │
│  │   │   Microsoft  │   │    Google    │   │    Nango     │              │ │
│  │   │   Graph API  │   │   Gmail API  │   │   OAuth Hub  │              │ │
│  │   │              │   │              │   │              │              │ │
│  │   │  • O365 Mail │   │  • Gmail     │   │  • Token Mgmt│              │ │
│  │   │  • Webhooks  │   │  • Pub/Sub   │   │  • Refresh   │              │ │
│  │   └──────────────┘   └──────────────┘   └──────────────┘              │ │
│  │                                                                        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                    │                                         │
│                                    ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                         INGESTION LAYER                                │ │
│  │                                                                        │ │
│  │   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐              │ │
│  │   │   Webhook    │   │    Sync      │   │   Message    │              │ │
│  │   │   Handlers   │   │   Workers    │   │    Queue     │              │ │
│  │   │              │   │              │   │              │              │ │
│  │   │  • O365      │   │  • Gmail     │   │  • Priority  │              │ │
│  │   │  • Gmail     │   │  • O365      │   │  • Batching  │              │ │
│  │   └──────────────┘   └──────────────┘   └──────────────┘              │ │
│  │                                                                        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                    │                                         │
│                                    ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                         DETECTION LAYER                                │ │
│  │                                                                        │ │
│  │   ┌────────────────────────────────────────────────────────────────┐  │ │
│  │   │                    Detection Pipeline                          │  │ │
│  │   │                                                                │  │ │
│  │   │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐  │  │ │
│  │   │  │  Email  │ │  SPF/   │ │ Threat  │ │   BEC   │ │Behavior │  │  │ │
│  │   │  │  Auth   │ │  DKIM   │ │  Intel  │ │   NLP   │ │   AI    │  │  │ │
│  │   │  │         │ │  DMARC  │ │         │ │         │ │         │  │  │ │
│  │   │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘  │  │ │
│  │   │                                                                │  │ │
│  │   │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐  │  │ │
│  │   │  │  URL    │ │Lookalike│ │Attachmt │ │   ML    │ │  Risk   │  │  │ │
│  │   │  │ Rewrite │ │ Domain  │ │ Analysis│ │ Predict │ │ Scoring │  │  │ │
│  │   │  │         │ │         │ │         │ │         │ │         │  │  │ │
│  │   │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘  │  │ │
│  │   │                                                                │  │ │
│  │   └────────────────────────────────────────────────────────────────┘  │ │
│  │                                                                        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                    │                                         │
│                                    ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                        RESPONSE LAYER                                  │ │
│  │                                                                        │ │
│  │   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐              │ │
│  │   │   Policy     │   │ Remediation  │   │   Alerts     │              │ │
│  │   │   Engine     │   │   Actions    │   │   Dispatch   │              │ │
│  │   │              │   │              │   │              │              │ │
│  │   │  • Per-tenant│   │  • Quarantine│   │  • Slack     │              │ │
│  │   │  • Per-user  │   │  • Delete    │   │  • Teams     │              │ │
│  │   │  • Thresholds│   │  • Banner    │   │  • Email     │              │ │
│  │   └──────────────┘   └──────────────┘   └──────────────┘              │ │
│  │                                                                        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                    │                                         │
│                                    ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                          DATA LAYER                                    │ │
│  │                                                                        │ │
│  │   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐              │ │
│  │   │   Postgres   │   │    Redis     │   │   Threat     │              │ │
│  │   │   Database   │   │    Cache     │   │   Intel DB   │              │ │
│  │   │              │   │              │   │              │              │ │
│  │   │  • Tenants   │   │  • Sessions  │   │  • URLs      │              │ │
│  │   │  • Threats   │   │  • Rate Limit│   │  • Domains   │              │ │
│  │   │  • Audit Log │   │  • Cache     │   │  • IPs       │              │ │
│  │   └──────────────┘   └──────────────┘   └──────────────┘              │ │
│  │                                                                        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Descriptions

### Integration Layer
- **Microsoft Graph API**: O365 mailbox access, webhook subscriptions
- **Google Gmail API**: Gmail access, Pub/Sub notifications
- **Nango OAuth Hub**: Centralized OAuth token management and refresh

### Ingestion Layer
- **Webhook Handlers**: Real-time email event processing
- **Sync Workers**: Periodic mailbox synchronization
- **Message Queue**: Priority-based email processing queue

### Detection Layer
- **Email Authentication**: SPF, DKIM, DMARC validation
- **Threat Intelligence**: Multi-feed aggregation and lookup
- **BEC/NLP Detection**: Natural language threat analysis
- **Behavioral AI**: Communication graph and anomaly detection
- **URL Rewriting**: Click-time protection
- **Attachment Analysis**: Deep file inspection
- **ML Prediction**: Fast threat scoring
- **Risk Scoring**: Composite threat assessment

### Response Layer
- **Policy Engine**: Per-tenant/per-user policy evaluation
- **Remediation Actions**: Quarantine, delete, banner injection
- **Alert Dispatch**: Multi-channel notification delivery

### Data Layer
- **PostgreSQL**: Primary data store (multi-tenant)
- **Redis**: Caching and rate limiting
- **Threat Intel DB**: URL/domain/IP reputation data

## Technology Stack

| Component | Technology |
|-----------|------------|
| Framework | Next.js 14 (App Router) |
| Language | TypeScript |
| Database | PostgreSQL (Supabase) |
| Cache | Redis |
| Auth | Clerk |
| OAuth | Nango |
| Deployment | Vercel |
| Monitoring | Vercel Analytics |
| Testing | Vitest |

## Multi-Tenancy Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      MSP Platform                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  MSP Admin (msp_admin role)                                      │
│       │                                                          │
│       ├── Tenant A (Client Company)                              │
│       │   ├── Integrations (O365/Gmail)                          │
│       │   ├── Policies                                           │
│       │   ├── Threats                                            │
│       │   └── Users                                              │
│       │                                                          │
│       ├── Tenant B (Client Company)                              │
│       │   ├── Integrations                                       │
│       │   ├── Policies                                           │
│       │   ├── Threats                                            │
│       │   └── Users                                              │
│       │                                                          │
│       └── Tenant C (Client Company)                              │
│           ├── Integrations                                       │
│           ├── Policies                                           │
│           ├── Threats                                            │
│           └── Users                                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

Data Isolation:
- All tables include tenant_id column
- RLS (Row Level Security) enforced
- API validates tenant access
- No cross-tenant data leakage
```

## Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Controls                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Authentication                                                  │
│  ├── Clerk-managed user auth                                     │
│  ├── JWT validation on all API routes                            │
│  └── Session management                                          │
│                                                                  │
│  Authorization                                                   │
│  ├── Role-based access (msp_admin, admin, user)                  │
│  ├── Tenant isolation (tenant_id in all queries)                 │
│  └── Resource-level permissions                                  │
│                                                                  │
│  Data Protection                                                 │
│  ├── Encryption at rest (Supabase)                               │
│  ├── Encryption in transit (TLS 1.3)                             │
│  ├── Token encryption (AES-256-GCM)                              │
│  └── PII masking in logs                                         │
│                                                                  │
│  API Security                                                    │
│  ├── Rate limiting (per-tenant, per-endpoint)                    │
│  ├── Input validation (Zod schemas)                              │
│  ├── CORS configuration                                          │
│  └── Webhook signature verification                              │
│                                                                  │
│  Monitoring                                                      │
│  ├── Audit logging (all mutations)                               │
│  ├── Security event tracking                                     │
│  ├── Anomaly detection                                           │
│  └── Alert on suspicious activity                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Vercel Edge Network                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    CDN / Edge                            │    │
│  │  • Static assets                                         │    │
│  │  • Edge middleware                                       │    │
│  │  • Geo-routing                                           │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                 Serverless Functions                     │    │
│  │                                                          │    │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐           │    │
│  │  │  API      │  │  Webhooks │  │   Cron    │           │    │
│  │  │  Routes   │  │  Handlers │  │   Jobs    │           │    │
│  │  └───────────┘  └───────────┘  └───────────┘           │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                 External Services                        │    │
│  │                                                          │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    │    │
│  │  │Supabase │  │  Nango  │  │  Clerk  │  │  Redis  │    │    │
│  │  │Postgres │  │  OAuth  │  │  Auth   │  │  Cache  │    │    │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘    │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```
