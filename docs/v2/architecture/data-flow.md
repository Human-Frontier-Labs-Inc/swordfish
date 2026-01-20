# Data Flow Diagrams

## Email Processing Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        EMAIL PROCESSING PIPELINE                             │
└─────────────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────────────────────┐
                    │         EMAIL ARRIVES                │
                    │                                      │
                    │   Microsoft 365  │   Google Gmail    │
                    └──────────┬───────┴──────────┬────────┘
                               │                  │
                    ┌──────────▼──────────────────▼────────┐
                    │          WEBHOOK TRIGGER             │
                    │                                      │
                    │  O365: Graph API subscription        │
                    │  Gmail: Pub/Sub notification         │
                    └──────────────────┬───────────────────┘
                                       │
                    ┌──────────────────▼───────────────────┐
                    │         INGESTION LAYER              │
                    │                                      │
                    │  1. Validate webhook signature       │
                    │  2. Extract message metadata         │
                    │  3. Fetch full email content         │
                    │  4. Parse headers & body             │
                    └──────────────────┬───────────────────┘
                                       │
                    ┌──────────────────▼───────────────────┐
                    │        DETECTION PIPELINE            │
                    │                                      │
                    │  ┌─────────────────────────────┐    │
                    │  │    STAGE 1: Authentication  │    │
                    │  │                             │    │
                    │  │  • SPF validation           │    │
                    │  │  • DKIM verification        │    │
                    │  │  • DMARC policy check       │    │
                    │  └──────────────┬──────────────┘    │
                    │                 │                    │
                    │  ┌──────────────▼──────────────┐    │
                    │  │    STAGE 2: Threat Intel    │    │
                    │  │                             │    │
                    │  │  • URL reputation           │    │
                    │  │  • Domain reputation        │    │
                    │  │  • IP blocklist check       │    │
                    │  │  • Known phishing patterns  │    │
                    │  └──────────────┬──────────────┘    │
                    │                 │                    │
                    │  ┌──────────────▼──────────────┐    │
                    │  │    STAGE 3: Content Analysis│    │
                    │  │                             │    │
                    │  │  • BEC language detection   │    │
                    │  │  • Urgency signals          │    │
                    │  │  • Lookalike domains        │    │
                    │  │  • Attachment analysis      │    │
                    │  └──────────────┬──────────────┘    │
                    │                 │                    │
                    │  ┌──────────────▼──────────────┐    │
                    │  │    STAGE 4: Behavioral AI   │    │
                    │  │                             │    │
                    │  │  • Contact graph lookup     │    │
                    │  │  • Baseline comparison      │    │
                    │  │  • Anomaly scoring          │    │
                    │  │  • First contact detection  │    │
                    │  └──────────────┬──────────────┘    │
                    │                 │                    │
                    │  ┌──────────────▼──────────────┐    │
                    │  │    STAGE 5: ML Prediction   │    │
                    │  │                             │    │
                    │  │  • Feature extraction       │    │
                    │  │  • Model inference          │    │
                    │  │  • Confidence scoring       │    │
                    │  └──────────────┬──────────────┘    │
                    │                 │                    │
                    │  ┌──────────────▼──────────────┐    │
                    │  │    STAGE 6: Risk Scoring    │    │
                    │  │                             │    │
                    │  │  • Aggregate all signals    │    │
                    │  │  • Calculate final score    │    │
                    │  │  • Generate explanation     │    │
                    │  └─────────────────────────────┘    │
                    │                                      │
                    └──────────────────┬───────────────────┘
                                       │
                    ┌──────────────────▼───────────────────┐
                    │         POLICY ENGINE                │
                    │                                      │
                    │  • Load tenant policy                │
                    │  • Evaluate thresholds               │
                    │  • Determine action                  │
                    └──────────────────┬───────────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
              ▼                        ▼                        ▼
    ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
    │     ALLOW       │     │      WARN       │     │     BLOCK       │
    │                 │     │                 │     │                 │
    │  • Log event    │     │  • Inject banner│     │  • Quarantine   │
    │  • Update graph │     │  • Log event    │     │  • Delete       │
    │                 │     │  • Update graph │     │  • Alert admin  │
    │                 │     │                 │     │  • Log event    │
    └─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Account Takeover Detection Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     ACCOUNT TAKEOVER DETECTION FLOW                          │
└─────────────────────────────────────────────────────────────────────────────┘

         ┌───────────────────────────────────────────────────────┐
         │                    LOGIN EVENT                        │
         │                                                       │
         │  User authenticates via O365/Gmail                    │
         └─────────────────────────┬─────────────────────────────┘
                                   │
         ┌─────────────────────────▼─────────────────────────────┐
         │                 CAPTURE CONTEXT                       │
         │                                                       │
         │  • IP address                                         │
         │  • User agent                                         │
         │  • Timestamp                                          │
         │  • Device fingerprint                                 │
         └─────────────────────────┬─────────────────────────────┘
                                   │
         ┌─────────────────────────▼─────────────────────────────┐
         │               RESOLVE GEOLOCATION                     │
         │                                                       │
         │  IP → Country, City, Lat/Long                         │
         └─────────────────────────┬─────────────────────────────┘
                                   │
    ┌──────────────────────────────┼──────────────────────────────┐
    │                              │                              │
    ▼                              ▼                              ▼
┌────────────┐            ┌────────────────┐            ┌────────────────┐
│ IMPOSSIBLE │            │  NEW DEVICE    │            │   UNUSUAL      │
│  TRAVEL    │            │  DETECTION     │            │   ACTIVITY     │
│            │            │                │            │                │
│ Compare to │            │ Check device   │            │ Compare to     │
│ last login │            │ registry       │            │ baseline       │
│ location   │            │                │            │                │
│            │            │ New? → Alert   │            │ Anomalous?     │
│ >500mph?   │            │                │            │ → Alert        │
│ → Alert    │            │                │            │                │
└─────┬──────┘            └───────┬────────┘            └───────┬────────┘
      │                           │                             │
      └───────────────────────────┼─────────────────────────────┘
                                  │
         ┌────────────────────────▼────────────────────────────┐
         │                   RISK SCORING                      │
         │                                                     │
         │  Aggregate all ATO signals into composite score     │
         │                                                     │
         │  Score = w1*travel + w2*device + w3*activity        │
         └────────────────────────┬────────────────────────────┘
                                  │
         ┌────────────────────────▼────────────────────────────┐
         │                  RESPONSE DECISION                  │
         └────────────────────────┬────────────────────────────┘
                                  │
       ┌──────────────────────────┼──────────────────────────┐
       │                          │                          │
       ▼                          ▼                          ▼
 ┌───────────┐           ┌─────────────┐           ┌─────────────┐
 │   LOW     │           │   MEDIUM    │           │    HIGH     │
 │  50-70    │           │   70-85     │           │    85+      │
 │           │           │             │           │             │
 │ • Log     │           │ • Alert     │           │ • Lock acct │
 │           │           │ • Require   │           │ • End sess  │
 │           │           │   MFA       │           │ • Reset pwd │
 │           │           │             │           │ • Alert     │
 └───────────┘           └─────────────┘           └─────────────┘
```

## Threat Intelligence Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      THREAT INTELLIGENCE FLOW                                │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                          FEED SOURCES                                        │
│                                                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │PhishTank │ │ URLhaus  │ │OpenPhish │ │VirusTotal│ │  OTX     │          │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘          │
│       │            │            │            │            │                  │
│       └────────────┴────────────┴─────┬──────┴────────────┘                  │
│                                       │                                      │
└───────────────────────────────────────┼──────────────────────────────────────┘
                                        │
                     ┌──────────────────▼──────────────────┐
                     │           AGGREGATOR                │
                     │                                     │
                     │  • Normalize indicator format       │
                     │  • Deduplicate across sources       │
                     │  • Assign confidence scores         │
                     │  • Track source freshness           │
                     └──────────────────┬──────────────────┘
                                        │
                     ┌──────────────────▼──────────────────┐
                     │          THREAT INTEL DB            │
                     │                                     │
                     │  ┌─────────────────────────────┐   │
                     │  │  URLs     │ Domains │ IPs   │   │
                     │  │  (hash)   │ (hash)  │(range)│   │
                     │  └─────────────────────────────┘   │
                     │                                     │
                     │  • TTL-based expiration             │
                     │  • Confidence decay over time       │
                     └──────────────────┬──────────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────┐
              │                         │                         │
              ▼                         ▼                         ▼
    ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
    │   URL LOOKUP    │     │  DOMAIN LOOKUP  │     │   IP LOOKUP     │
    │                 │     │                 │     │                 │
    │  Input: URL     │     │  Input: domain  │     │  Input: IP      │
    │  Output:        │     │  Output:        │     │  Output:        │
    │  • is_malicious │     │  • is_malicious │     │  • is_malicious │
    │  • confidence   │     │  • confidence   │     │  • confidence   │
    │  • threat_type  │     │  • threat_type  │     │  • blocklist    │
    │  • sources      │     │  • sources      │     │  • sources      │
    └─────────────────┘     └─────────────────┘     └─────────────────┘


REFRESH CYCLE:
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐              │
│   │  Cron   │────▶│  Fetch  │────▶│  Parse  │────▶│  Store  │              │
│   │ (hourly)│     │  Feeds  │     │  IOCs   │     │  to DB  │              │
│   └─────────┘     └─────────┘     └─────────┘     └─────────┘              │
│                                                                              │
│   Metrics tracked:                                                           │
│   • Indicators per source                                                    │
│   • New indicators this cycle                                                │
│   • Expired indicators removed                                               │
│   • Source availability                                                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## User Reporting Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       USER PHISH REPORT FLOW                                 │
└─────────────────────────────────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────────────────────┐
    │                   USER INBOX                            │
    │                                                         │
    │  User sees suspicious email                             │
    │  Clicks "Report Phish" button                           │
    └───────────────────────────┬─────────────────────────────┘
                                │
    ┌───────────────────────────▼─────────────────────────────┐
    │                   ADD-IN/ADD-ON                         │
    │                                                         │
    │  • Capture email headers                                │
    │  • Capture email body                                   │
    │  • Capture attachments (hashes)                         │
    │  • Capture user context                                 │
    └───────────────────────────┬─────────────────────────────┘
                                │
    ┌───────────────────────────▼─────────────────────────────┐
    │              SWORDFISH REPORT API                       │
    │                                                         │
    │  POST /api/v1/report-phish                              │
    │                                                         │
    │  • Validate request                                     │
    │  • Queue for analysis                                   │
    │  • Acknowledge to user                                  │
    └───────────────────────────┬─────────────────────────────┘
                                │
                ┌───────────────┼───────────────┐
                │               │               │
                ▼               │               ▼
    ┌───────────────────┐      │      ┌───────────────────┐
    │  USER FEEDBACK    │      │      │  ANALYSIS QUEUE   │
    │                   │      │      │                   │
    │  "Thank you for   │      │      │  Background job   │
    │   reporting!"     │      │      │  picks up report  │
    └───────────────────┘      │      └─────────┬─────────┘
                               │                │
    ┌──────────────────────────▼────────────────▼──────────┐
    │                  THREAT ANALYSIS                     │
    │                                                      │
    │  Run full detection pipeline on reported email       │
    │                                                      │
    │  • All detection stages                              │
    │  • Compare to existing threats                       │
    │  • Calculate threat score                            │
    └──────────────────────────┬───────────────────────────┘
                               │
            ┌──────────────────┼──────────────────┐
            │                  │                  │
            ▼                  │                  ▼
    ┌──────────────┐          │          ┌──────────────┐
    │   THREAT     │          │          │  NOT THREAT  │
    │  CONFIRMED   │          │          │  (FP)        │
    │              │          │          │              │
    │ • Add to DB  │          │          │ • Log as FP  │
    │ • Check other│          │          │ • Improve    │
    │   mailboxes  │          │          │   model      │
    │ • Remediate  │          │          │              │
    └──────────────┘          │          └──────────────┘
                              │
    ┌─────────────────────────▼───────────────────────────┐
    │                 UPDATE USER STATS                    │
    │                                                      │
    │  • Increment report count                            │
    │  • Award badges if applicable                        │
    │  • Track accuracy rate                               │
    └─────────────────────────────────────────────────────┘
```
