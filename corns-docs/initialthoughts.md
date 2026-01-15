Excellent. Below are two real documents you could hand to engineers, investors, or partners today.

I’ve written them as V1 production documents, not marketing fluff.
They are scoped exactly to what you approved:

Hybrid (SMTP + O365 + Gmail)

Barracuda-parity or better

No AWS

Cloudflare + low-cost compute

Attachment detonation, link rewriting, sandboxing included in V1

SMB / Mid-market optimized (price + speed)

📄 PRODUCT REQUIREMENTS DOCUMENT (PRD)
Product: Hybrid Phishing & Email Threat Protection Platform (V1)
1. Purpose & Vision
Problem

SMB and mid-market organizations face increasing phishing, impersonation, and BEC attacks, but existing solutions (e.g., Barracuda, Proofpoint) are:

Expensive

Slow to deploy

Overbuilt for SMB needs

Poorly explainable when they block email

Vision

Deliver Barracuda-class hybrid email security with:

Faster onboarding (minutes, not days)

Lower cost per mailbox

Clear explanations and admin trust

Full parity: SMTP + O365 + Gmail + sandboxing + link rewriting

2. Target Customers
Primary

SMB & Mid-market (25–2,000 seats)

IT admins with limited security staff

MSPs managing multiple tenants

Secondary

Security-conscious startups

Finance-heavy orgs vulnerable to BEC

3. Key Differentiators
Area	Barracuda	Our V1
Deployment	Gateway-heavy	API-first + optional gateway
Onboarding	Hours–days	Minutes
Explainability	Limited	First-class
Cost Control	Opaque	Explicit gating
Sandbox	Always marketed	Policy-driven + visible
4. In-Scope for V1 (Non-Negotiable)
Integrations

SMTP Gateway (inline)

Microsoft 365 (Graph API)

Google Workspace (Gmail API)

Threat Coverage

Phishing

Credential harvesting

Executive impersonation

Vendor impersonation

BEC / wire fraud

Malicious attachments

Malicious URLs (pre- and click-time)

Core Capabilities

Deterministic detection

ML classification

LLM escalation (gated)

Attachment detonation

Behavioral sandboxing

URL rewriting + click-time protection

Retroactive purge/remediation

Admin dashboard + audit logs

5. Out of Scope (V1)

Full SOC tooling

Custom customer ML training

Long-term email archiving

DLP

6. Functional Requirements
6.1 Email Ingestion

Support three parallel ingestion paths:

SMTP inline (MX or smart host)

Microsoft 365 Graph API

Gmail API (Pub/Sub)

All ingestion paths normalize email into a common internal format.

6.2 Detection Pipeline (Shared Across All Paths)

Stage 1 – Deterministic (100% of mail)

SPF/DKIM/DMARC alignment

Header anomaly analysis

From / Reply-To mismatch

Display name impersonation

Domain similarity (homoglyphs, edit distance)

Domain age/reputation

URL lexical analysis

Attachment static analysis

QR-code phishing detection

Stage 2 – ML (Risk-Gated)

Phishing/BEC classifier

Sender anomaly detection

Thread/context anomalies

Stage 3 – LLM Escalation (≤5%)

Intent interpretation

Context summarization

Human-readable explanation

LLMs never make final decisions alone.

6.3 Attachment Handling

Hash reputation check

Static analysis

Policy-based gating

Sandbox detonation (V1 required)

IOC extraction + scoring

6.4 URL Handling

Rewrite URLs by default

Tenant allowlist exclusions

Click-time evaluation:

Redirect expansion

Reputation check

Optional headless inspection

Block, warn, or allow at click time

6.5 Actions
Risk	Action
High	Block / Quarantine
Medium	Deliver with warning
Confirmed malicious	Retroactive purge
User-reported	Re-evaluate + learn
7. Admin Dashboard (V1)
Required

Threat inbox

Per-email explanation

Quarantine management

Allowlist/blocklist

Tenant risk overview

Remediation history

Integration status (SMTP / O365 / Gmail)

MSP Mode

Multi-tenant switch

Per-tenant policy overrides

8. Non-Functional Requirements
Category	Requirement
Latency	<1s decision (non-sandbox)
Sandbox	Async, verdict cached
Availability	99.9%
Cost	Target < $1/user/month infra
Privacy	No long-term body retention
Security	Tenant isolation, audit logs
9. Success Metrics

<10 min onboarding

<0.5% false positive rate

<60s remediation latency

Competitive pricing vs Barracuda

🧱 TECHNICAL SPECIFICATION (V1)
1. Architecture Overview (No AWS)

Edge

Cloudflare Workers (URL rewrite + click-time)

Cloudflare WAF

Cloudflare R2 (artifacts/evidence)

Core Compute

Hetzner / OVH / Scaleway

k3s Kubernetes cluster

Sandbox Cluster

Separate node pool

KVM or Firecracker microVMs

Restricted egress

2. Services
2.1 control-plane-api

Tenant config

Policies

Users/RBAC

Billing hooks

Integration state

2.2 decision-engine

Feature extraction

Deterministic rules

ML inference

LLM escalation

Decision graph

2.3 smtp-gateway

Go-based SMTP server

Inline blocking/quarantine routing

Feature extraction

DKIM signing if modified

2.4 o365-worker

Graph subscriptions/polling

Quarantine

Purge

Banner management (strategy-based)

2.5 gmail-worker

Gmail watch + Pub/Sub

Label quarantine

Remove/purge

Gmail add-on ingestion

2.6 rewrite-service

Cloudflare Worker

Tokenized URLs

Click-time verdict fetch

2.7 sandbox-worker

Job consumer

VM lifecycle

Static + dynamic analysis

IOC extraction

3. Data Stores
Store	Purpose
Postgres	Tenants, policies, metadata, audit
Redis (Valkey)	Caching, dedupe, rate limits
NATS JetStream	Async jobs
R2 / B2	Artifacts & reports
4. Detection Flow (Unified)
Ingest → Normalize → Deterministic
     → ML (if gated)
     → LLM (if gated)
     → Decision
     → Action
     → Audit

5. Sandbox Design

One job = one VM

Ephemeral disk

Network capture

Auto-destroy

Hash-based verdict caching

6. URL Rewrite & Click-Time

Rewrite URLs → edge endpoint

Decode token

Fetch verdict (cached)

If unknown → async deep inspection

Return allow / warn / block

7. Security

Tenant isolation everywhere

Encrypted secrets

Signed rewrite tokens

Least-privilege API scopes

Immutable audit logs

8. Deployment & CI/CD

GitHub Actions

Docker everywhere

IaC (Terraform)

Blue/green deploys for APIs

Canary for gateway

9. Cost Controls (Explicit)

Deterministic gating first

Sandbox only on risky artifacts

LLM hard caps per tenant

Verdict caching

Storage TTLs