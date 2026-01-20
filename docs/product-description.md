# SwordPhish: Email Security Platform for SMBs and MSPs

## What is SwordPhish?

SwordPhish is a hybrid email security platform that protects organizations from phishing, business email compromise (BEC), credential harvesting, malicious attachments, and link-based attacks. Built specifically for SMB and mid-market organizations (25-2,000 seats), it delivers enterprise-grade protection with deployment speed and pricing that makes sense for smaller teams.

## The Problem

Current email security solutions like Barracuda and Proofpoint work, but they have significant drawbacks for SMBs:

- **Expensive**: Often $10-15+ per user per month
- **Slow to deploy**: Require days or weeks of vendor hand-holding
- **Over-engineered**: Built for enterprise, too complex for SMB IT teams
- **Poor explanations**: Block emails with cryptic technical jargon (SPF_FAIL, DKIM_FAIL) that non-security IT admins can't explain to users
- **MSP unfriendly**: Separate logins for each client, no bulk operations

## How SwordPhish Works

### Three Integration Paths

SwordPhish supports flexible deployment options:

1. **SMTP Gateway**: Drop-in inline protection (update MX records)
2. **Microsoft 365**: Graph API integration (no mail flow changes)
3. **Google Workspace**: Gmail API with Pub/Sub (no mail flow changes)

All three paths use the same detection pipeline, so you get consistent protection regardless of how you integrate.

### Multi-Layer Detection Pipeline

Every email goes through a staged analysis process:

**Stage 1: Deterministic Analysis (100% of email)**
- SPF/DKIM/DMARC authentication checks
- Header anomaly detection
- Display name vs. sender mismatch
- Domain similarity analysis (homoglyphs, typosquatting)
- Domain age and reputation checks
- URL lexical analysis
- Attachment static analysis
- QR code phishing detection

**Stage 2: Machine Learning (Risk-Gated)**
- Phishing classification
- BEC detection
- Sender behavior anomalies
- Thread and context analysis

**Stage 3: LLM Escalation (≤5%, Heavily Gated)**
- Natural language intent analysis
- Context interpretation
- Human-readable explanation generation

Cost-gating ensures expensive operations (ML inference, LLM analysis, sandbox detonation) only run on truly suspicious emails.

### Advanced Protection Features

**Attachment Security**
- Hash reputation checking
- Static file analysis
- Policy-based gating
- Sandbox detonation for high-risk files
- Indicator of compromise (IOC) extraction

**URL Protection**
- Automatic URL rewriting
- Click-time evaluation at the edge (Cloudflare)
- Redirect chain analysis
- Real-time reputation checking
- Headless browser inspection for suspicious links
- User warnings or blocks based on verdict

**Retroactive Remediation**
- Automatic purge of emails when threats are discovered post-delivery
- Works across all integration methods (SMTP, O365, Gmail)

## Key Benefits

### 1. Explainability First

Instead of technical jargon, SwordPhish provides plain-English explanations:

**Traditional tools say:**
> "SPF_FAIL, DKIM_FAIL, DMARC_QUARANTINE"

**SwordPhish says:**
> "This email claims to be from your bank but was sent from an unverified server. Attackers often impersonate banks to steal login credentials."

This means non-security IT admins can confidently explain blocks to executives and end users.

### 2. 10-Minute Deployment

Self-service onboarding with step-by-step guidance:
- Connect to Microsoft 365 or Gmail via OAuth (5 minutes)
- Or update MX records for SMTP gateway (10 minutes)
- Set basic policies (allowlists, default actions)
- Start protecting email immediately

No vendor calls or professional services required.

### 3. Built for MSPs

**Single Pane of Glass**
- Manage all clients from one dashboard
- Instant tenant switching (<1 second)
- Global search across all tenants

**Bulk Operations**
- Apply policies to multiple tenants at once
- Multi-select for quarantine actions
- Batch approvals and releases

**Policy Templates**
- Create once, apply to many
- Standardize security posture across clients

**White-Label Reports**
- PDF exports with your branding
- Client-ready formatting
- Automated weekly/monthly summaries

**Keyboard Shortcuts**
- Full keyboard navigation
- Command palette (Cmd/Ctrl+K)
- Designed for power users

### 4. Cost-Controlled Intelligence

Unlike competitors that run everything through expensive ML/LLM, SwordPhish uses intelligent gating:

1. Deterministic rules catch 70-80% of threats instantly (low cost)
2. ML only runs on emails that pass deterministic checks
3. LLM analysis only for the most ambiguous cases
4. Sandbox detonation only for high-risk attachments
5. All verdicts cached by hash to avoid redundant processing

This keeps pricing competitive while maintaining high detection accuracy.

### 5. Modern Architecture

- **No AWS**: Cloudflare edge + European compute (Hetzner)
- **Serverless databases**: Neon (PostgreSQL), Upstash (Redis + Kafka)
- **Fast**: <1 second decision latency for non-sandbox verdicts
- **Scalable**: Stateless services, horizontal scaling
- **Secure**: Full tenant isolation, encrypted credentials, audit logs

## What You Get

### Admin Dashboard
- Real-time threat feed with verdicts and explanations
- Quarantine management (review, release, delete)
- Policy configuration (allowlists, blocklists, custom rules)
- Integration status monitoring
- User management and RBAC
- Audit logs for compliance

### Email Protection
- Blocks high-confidence threats automatically
- Delivers medium-risk emails with warning banners
- Quarantines suspicious emails for admin review
- Allows safe emails through immediately

### Reporting & Analytics
- Weekly digest emails with key metrics
- Threat breakdown by type (phishing, BEC, malware, etc.)
- False positive tracking
- Response time metrics
- Executive-friendly summaries
- Exportable PDF reports

### Integration Support
- Microsoft 365 (all plans)
- Google Workspace (all plans)
- SMTP-based email systems
- Mix and match integration methods per tenant

## Who Should Use SwordPhish

### Perfect For:
- **SMB IT Admins**: Need email protection but aren't security specialists
- **MSPs**: Managing email security for 10-50+ clients
- **Mid-market companies**: 25-2,000 employees
- **Finance/healthcare**: Industries vulnerable to BEC and impersonation
- **Organizations upgrading from**: Basic spam filters, outdated Barracuda, expensive Proofpoint

### Not Ideal For (Yet):
- Enterprise with >2,000 seats (we'll get there)
- Organizations requiring on-premise deployment
- Companies with custom ML model requirements
- Environments with extreme compliance needs (we're working on SOC 2)

## Current Status

SwordPhish is in **active testing** with working deployments. We're maintaining whitelist-only access during this phase to ensure quality and gather feedback before wider launch.

### What's Working:
- All three integration paths (SMTP, O365, Gmail)
- Complete detection pipeline (deterministic → ML → LLM)
- Attachment sandbox analysis
- URL rewriting and click-time protection
- Admin dashboard and quarantine management
- Multi-tenant support for MSPs

### What We're Refining:
- False positive rates (currently targeting <0.5%)
- LLM explanation quality
- Onboarding flow polish
- Performance optimization

## Get Access

We're currently whitelisting email addresses for testing. If you'd like to try SwordPhish with your real email:

1. **Provide 2-5 email addresses** you want whitelisted
2. **We'll send onboarding instructions** (takes ~10 minutes to set up)
3. **Use it normally** for 2-4 weeks
4. **Give us feedback** on what works and what doesn't

No contracts, no payment required during testing. Just honest feedback from real-world usage.

**To request access:** [Contact Information]

---

## Technical Details

### Detection Capabilities
| Threat Type | Detection Method |
|-------------|------------------|
| Phishing | Domain analysis, ML classifier, intent analysis |
| Credential Harvesting | URL pattern matching, brand impersonation detection |
| BEC / Impersonation | Display name analysis, executive impersonation detection |
| Malware Attachments | Static analysis, sandbox detonation, IOC extraction |
| Malicious URLs | Reputation, click-time analysis, redirect inspection |
| QR Code Phishing | QR code extraction and URL analysis |

### Performance Targets
| Metric | Target |
|--------|--------|
| Detection latency | <1s (non-sandbox) |
| False positive rate | <0.5% |
| Availability | 99.9% |
| Setup time | <10 minutes |

### Security & Compliance
- Tenant isolation with row-level security
- TLS 1.3 encryption in transit
- AES-256 encryption at rest for sensitive data
- Audit logging for all actions
- OAuth 2.0 for Microsoft 365 and Gmail
- SOC 2 compliance planned for 2025

### Infrastructure
- **Edge**: Cloudflare (Workers, R2, WAF, DNS)
- **Compute**: Hetzner (k3s Kubernetes)
- **Database**: Neon (serverless PostgreSQL)
- **Cache/Queue**: Upstash (Redis + Kafka)
- **Sandbox**: Joe Sandbox API (V1), custom Firecracker VMs (V2)

---

## Questions?

**Website:** [Your Website]
**Email:** [Your Email]
**Technical Docs:** Available upon request

We're happy to provide architecture documentation, discuss integration details, or answer any questions about how SwordPhish works.
