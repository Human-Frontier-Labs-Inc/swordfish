# Component Diagram

## Core Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SWORDFISH COMPONENTS                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                              WEB LAYER                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  app/                                                                        │
│  ├── (dashboard)/              # Dashboard pages                             │
│  │   ├── page.tsx              # Main dashboard                              │
│  │   ├── threats/              # Threat management                           │
│  │   ├── integrations/         # O365/Gmail setup                            │
│  │   ├── policies/             # Policy configuration                        │
│  │   ├── reports/              # Analytics & reports                         │
│  │   └── settings/             # Tenant settings                             │
│  │                                                                           │
│  ├── api/                      # API routes                                  │
│  │   ├── v1/                   # Versioned API                               │
│  │   │   ├── threats/          # Threat CRUD                                 │
│  │   │   ├── policies/         # Policy CRUD                                 │
│  │   │   ├── integrations/     # Integration management                      │
│  │   │   ├── quarantine/       # Quarantine management                       │
│  │   │   ├── reports/          # Report generation                           │
│  │   │   └── click/            # URL click tracking                          │
│  │   │                                                                       │
│  │   ├── webhooks/             # Webhook handlers                            │
│  │   │   ├── gmail/            # Gmail Pub/Sub                               │
│  │   │   └── o365/             # O365 Graph subscriptions                    │
│  │   │                                                                       │
│  │   ├── cron/                 # Scheduled jobs                              │
│  │   │   ├── sync-emails/      # Periodic email sync                         │
│  │   │   └── refresh-feeds/    # Threat intel refresh                        │
│  │   │                                                                       │
│  │   └── admin/                # Admin endpoints                             │
│  │                                                                           │
│  └── warning/                  # URL warning page                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                             LIBRARY LAYER                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  lib/                                                                        │
│  │                                                                           │
│  ├── api/                      # API utilities                               │
│  │   ├── errors.ts             # Error handling                              │
│  │   ├── rate-limiter.ts       # Rate limiting                               │
│  │   ├── request-logger.ts     # Request logging                             │
│  │   ├── schemas.ts            # Zod validation schemas                      │
│  │   └── health.ts             # Health check utilities                      │
│  │                                                                           │
│  ├── auth/                     # Authentication                              │
│  │   └── tenant.ts             # Tenant context                              │
│  │                                                                           │
│  ├── db/                       # Database                                    │
│  │   ├── index.ts              # Database client                             │
│  │   └── migrations/           # SQL migrations                              │
│  │                                                                           │
│  ├── detection/                # Threat detection                            │
│  │   ├── pipeline.ts           # Main detection pipeline                     │
│  │   ├── bec.ts                # BEC detection                               │
│  │   ├── impersonation.ts      # Impersonation detection                     │
│  │   ├── lookalike.ts          # Lookalike domain detection                  │
│  │   ├── nlp-bec.ts            # NLP-based BEC                               │
│  │   └── attachment-analyzer.ts # Attachment analysis                        │
│  │                                                                           │
│  ├── email-auth/               # Email authentication                        │
│  │   ├── spf.ts                # SPF validation                              │
│  │   ├── dkim.ts               # DKIM verification                           │
│  │   ├── dmarc.ts              # DMARC policy                                │
│  │   └── analytics.ts          # Auth analytics                              │
│  │                                                                           │
│  ├── behavioral/               # Behavioral AI                               │
│  │   ├── contact-graph.ts      # Communication graph                         │
│  │   ├── baselines.ts          # User baselines                              │
│  │   ├── anomaly-engine.ts     # Anomaly detection                           │
│  │   └── first-contact.ts      # First contact detection                     │
│  │                                                                           │
│  ├── ato/                      # Account takeover                            │
│  │   ├── login-events.ts       # Login tracking                              │
│  │   ├── impossible-travel.ts  # Impossible travel detection                 │
│  │   ├── device-registry.ts    # Device management                           │
│  │   ├── activity-baseline.ts  # Activity baselines                          │
│  │   └── response-actions.ts   # ATO response                                │
│  │                                                                           │
│  ├── threat-intel/             # Threat intelligence                         │
│  │   ├── feeds/                # Feed integrations                           │
│  │   │   ├── index.ts          # Feed aggregator                             │
│  │   │   ├── phishtank.ts      # PhishTank                                   │
│  │   │   ├── urlhaus.ts        # URLhaus                                     │
│  │   │   ├── openphish.ts      # OpenPhish                                   │
│  │   │   ├── virustotal.ts     # VirusTotal                                  │
│  │   │   └── alienvault.ts     # AlienVault OTX                              │
│  │   ├── cache.ts              # Feed caching                                │
│  │   ├── domain-age.ts         # Domain age lookup                           │
│  │   └── ip-blocklists.ts      # IP blocklists                               │
│  │                                                                           │
│  ├── integrations/             # Email integrations                          │
│  │   ├── gmail/                # Gmail integration                           │
│  │   │   └── sync-worker.ts    # Gmail sync                                  │
│  │   └── o365/                 # O365 integration                            │
│  │       └── sync-worker.ts    # O365 sync                                   │
│  │                                                                           │
│  ├── protection/               # Protection features                         │
│  │   ├── url-rewriter.ts       # URL rewriting                               │
│  │   └── click-scanner.ts      # Click-time scanning                         │
│  │                                                                           │
│  ├── remediation/              # Remediation actions                         │
│  │   ├── quarantine.ts         # Quarantine management                       │
│  │   ├── banner.ts             # Warning banner injection                    │
│  │   └── actions.ts            # Remediation actions                         │
│  │                                                                           │
│  ├── ml/                       # Machine learning                            │
│  │   ├── predictor.ts          # Threat prediction                           │
│  │   ├── feature-extractor.ts  # Feature extraction                          │
│  │   ├── response-learner.ts   # Learning from feedback                      │
│  │   └── explainer.ts          # Explainable AI                              │
│  │                                                                           │
│  ├── monitoring/               # Monitoring & logging                        │
│  │   ├── metrics.ts            # Prometheus metrics                          │
│  │   ├── alerts.ts             # Alert management                            │
│  │   ├── audit.ts              # Audit logging                               │
│  │   └── events.ts             # Event tracking                              │
│  │                                                                           │
│  ├── alerts/                   # Alert channels                              │
│  │   ├── slack.ts              # Slack integration                           │
│  │   ├── teams.ts              # Teams integration                           │
│  │   ├── email.ts              # Email alerts                                │
│  │   └── dispatcher.ts         # Alert dispatch                              │
│  │                                                                           │
│  ├── reporting/                # Reporting                                   │
│  │   ├── phish-button.ts       # User report handling                        │
│  │   ├── executive-dashboard.ts # Executive reports                          │
│  │   └── pdf-generator.ts      # PDF export                                  │
│  │                                                                           │
│  ├── quarantine/               # Quarantine                                  │
│  │   └── manager.ts            # Quarantine management                       │
│  │                                                                           │
│  ├── security/                 # Security utilities                          │
│  │   ├── encryption.ts         # Token encryption                            │
│  │   ├── webhooks.ts           # Webhook verification                        │
│  │   └── secrets.ts            # Secrets management                          │
│  │                                                                           │
│  ├── resilience/               # Resilience patterns                         │
│  │   ├── circuit-breaker.ts    # Circuit breaker                             │
│  │   └── fallbacks.ts          # Fallback handlers                           │
│  │                                                                           │
│  ├── performance/              # Performance utilities                       │
│  │   ├── connection-pool.ts    # Connection pooling                          │
│  │   ├── query-cache.ts        # Query caching                               │
│  │   ├── compression.ts        # Response compression                        │
│  │   ├── retry.ts              # Retry utilities                             │
│  │   └── batch.ts              # Batch processing                            │
│  │                                                                           │
│  └── features/                 # Feature flags                               │
│      └── flags.ts              # Feature flag system                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                              TEST LAYER                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  tests/                                                                      │
│  ├── api/                      # API tests                                   │
│  ├── detection/                # Detection tests                             │
│  ├── email-auth/               # Email auth tests                            │
│  ├── behavioral/               # Behavioral AI tests                         │
│  ├── ato/                      # ATO tests                                   │
│  ├── threat-intel/             # Threat intel tests                          │
│  ├── integrations/             # Integration tests                           │
│  ├── protection/               # Protection tests                            │
│  ├── ml/                       # ML tests                                    │
│  ├── monitoring/               # Monitoring tests                            │
│  ├── alerts/                   # Alert tests                                 │
│  ├── reporting/                # Reporting tests                             │
│  ├── quarantine/               # Quarantine tests                            │
│  ├── security/                 # Security tests                              │
│  ├── resilience/               # Resilience tests                            │
│  ├── performance/              # Performance tests                           │
│  └── load/                     # Load tests                                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Dependencies

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        COMPONENT DEPENDENCY GRAPH                            │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────┐
                              │   Web Layer     │
                              │   (app/)        │
                              └────────┬────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
        ▼                              ▼                              ▼
┌───────────────┐            ┌───────────────┐            ┌───────────────┐
│     API       │            │   Detection   │            │   Behavioral  │
│   Utilities   │            │   Pipeline    │            │      AI       │
│               │            │               │            │               │
│ • errors      │            │ • pipeline    │            │ • graph       │
│ • rate-limit  │            │ • bec         │            │ • baselines   │
│ • schemas     │            │ • lookalike   │            │ • anomaly     │
└───────┬───────┘            └───────┬───────┘            └───────┬───────┘
        │                            │                            │
        │                    ┌───────┴───────┐                    │
        │                    │               │                    │
        │                    ▼               ▼                    │
        │          ┌───────────────┐ ┌───────────────┐           │
        │          │ Email Auth    │ │ Threat Intel  │           │
        │          │               │ │               │           │
        │          │ • spf         │ │ • feeds       │           │
        │          │ • dkim        │ │ • cache       │           │
        │          │ • dmarc       │ │ • domain-age  │           │
        │          └───────────────┘ └───────────────┘           │
        │                                                         │
        │          ┌───────────────┐ ┌───────────────┐           │
        │          │  Protection   │ │      ML       │           │
        │          │               │ │               │           │
        │          │ • url-rewrite │ │ • predictor   │           │
        │          │ • click-scan  │ │ • explainer   │           │
        │          └───────────────┘ └───────────────┘           │
        │                                                         │
        └────────────────────────┬────────────────────────────────┘
                                 │
        ┌────────────────────────┼────────────────────────────────┐
        │                        │                                │
        ▼                        ▼                                ▼
┌───────────────┐      ┌───────────────┐              ┌───────────────┐
│   Database    │      │   Security    │              │  Monitoring   │
│               │      │               │              │               │
│ • supabase    │      │ • encryption  │              │ • metrics     │
│ • migrations  │      │ • webhooks    │              │ • alerts      │
│               │      │ • secrets     │              │ • audit       │
└───────────────┘      └───────────────┘              └───────────────┘
        │                        │                                │
        └────────────────────────┼────────────────────────────────┘
                                 │
                        ┌────────▼────────┐
                        │   Performance   │
                        │                 │
                        │ • pool          │
                        │ • cache         │
                        │ • retry         │
                        │ • batch         │
                        └─────────────────┘
```

## External Service Dependencies

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        EXTERNAL SERVICE DEPENDENCIES                         │
└─────────────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────┐
│                        SWORDFISH                              │
└─────────────────────────────────┬─────────────────────────────┘
                                  │
       ┌──────────────────────────┼──────────────────────────┐
       │                          │                          │
       ▼                          ▼                          ▼
┌─────────────┐           ┌─────────────┐           ┌─────────────┐
│  SUPABASE   │           │    NANGO    │           │    CLERK    │
│             │           │             │           │             │
│ • Postgres  │           │ • OAuth     │           │ • Auth      │
│ • Storage   │           │ • Tokens    │           │ • Users     │
│ • Realtime  │           │ • Sync      │           │ • Sessions  │
└─────────────┘           └─────────────┘           └─────────────┘

       │                          │                          │
       ▼                          ▼                          ▼
┌─────────────┐           ┌─────────────┐           ┌─────────────┐
│  MICROSOFT  │           │   GOOGLE    │           │   VERCEL    │
│             │           │             │           │             │
│ • Graph API │           │ • Gmail API │           │ • Hosting   │
│ • Webhooks  │           │ • Pub/Sub   │           │ • Edge      │
│ • O365      │           │ • Workspace │           │ • Cron      │
└─────────────┘           └─────────────┘           └─────────────┘

       │                          │                          │
       ▼                          ▼                          ▼
┌─────────────┐           ┌─────────────┐           ┌─────────────┐
│  PHISHTANK  │           │  URLHAUS    │           │ VIRUSTOTAL  │
│             │           │             │           │             │
│ • Phishing  │           │ • Malware   │           │ • URL scan  │
│ • URLs      │           │ • URLs      │           │ • File scan │
└─────────────┘           └─────────────┘           └─────────────┘

       │                          │                          │
       ▼                          ▼                          ▼
┌─────────────┐           ┌─────────────┐           ┌─────────────┐
│  OPENPHISH  │           │ALIENVAULT   │           │  ABUSE.CH   │
│             │           │   OTX       │           │             │
│ • Phishing  │           │ • Pulses    │           │ • Malware   │
│ • Fresh     │           │ • IOCs      │           │ • Botnet    │
└─────────────┘           └─────────────┘           └─────────────┘
```
