# SwordPhish vs Sublime Security: Comprehensive Comparison

## Executive Summary

Both platforms represent modern approaches to email security, but target fundamentally different markets with different philosophies. **Sublime Security** is a well-funded ($243.8M raised, ~$926M valuation) enterprise-focused platform built around "detection-as-code" for security teams. **SwordPhish** is an SMB/MSP-focused platform built around explainability and operational simplicity for non-specialist IT admins.

---

## Company & Funding Comparison

| Metric | Sublime Security | SwordPhish |
|--------|------------------|------------|
| **Total Funding** | $243.8M | Bootstrapped/Early |
| **Latest Round** | $150M Series C (Oct 2024) | N/A |
| **Valuation** | ~$926M | N/A |
| **Investors** | IVP, Citi Ventures, Index Ventures, Decibel | N/A |
| **Founded** | 2019 | 2024 |
| **Team Size** | ~100+ employees | Small team |
| **Enterprise Customers** | Spotify, Snowflake, Brex, Anduril, SentinelOne | Testing phase |
| **Market Mindshare** | 1.7% (up from 1.0%) | Pre-launch |

**Analysis**: Sublime has significant financial runway and enterprise credibility. SwordPhish is early-stage but nimble. This funding gap means Sublime can outspend on R&D, sales, and marketing—but also means they're optimizing for enterprise needs, not SMB.

---

## Technical Approach Comparison

### Detection Philosophy

| Aspect | Sublime Security | SwordPhish |
|--------|------------------|------------|
| **Core Approach** | Detection-as-code (MQL) | Layered pipeline with cost-gating |
| **Rule Language** | MQL (Message Query Language) | Deterministic rules + ML + LLM |
| **Customization** | High (write your own queries) | Moderate (policy configuration) |
| **Learning Curve** | Steep (requires security expertise) | Low (designed for generalists) |
| **AI/ML** | Autonomous AI agents, ML classifiers | Gated ML → LLM escalation |
| **Open Source** | Rules published on GitHub | Proprietary |

### Sublime's MQL Approach

Sublime uses a custom query language (MQL) that lets security teams write detection rules like code:

```yaml
type.inbound
and sender.email.domain.domain not in $org_domains
and any(ml.nlu_classifier(body.current_thread.text).intents,
        .name == "cred_theft" and .confidence == "high")
```

**Pros**:
- Extremely flexible and customizable
- Transparent—you can see exactly why something was flagged
- Community-contributed rules on GitHub
- Security teams can write detections for novel attacks quickly

**Cons**:
- Requires security engineering expertise
- Steep learning curve for non-technical teams
- Time-intensive to maintain custom rules
- Overkill for organizations without dedicated security staff

### SwordPhish's Layered Approach

SwordPhish uses a cost-gated pipeline where expensive operations only run on suspicious emails:

```
Stage 1: Deterministic Analysis (100% of email)
  ├── SPF/DKIM/DMARC, header analysis, domain similarity
  └── Fast, cheap, catches 70-80% of obvious threats

Stage 2: Reputation APIs (~40% of email)
  ├── Domain age, URL reputation, attachment hashes
  └── External API calls, moderate cost

Stage 3: ML Classification (~20% of email)
  ├── Phishing classifiers, BEC detection, anomaly detection
  └── Inference cost, only on emails passing Stage 1-2

Stage 4: LLM Escalation (≤5% of email)
  ├── Natural language intent analysis, explanation generation
  └── High cost, only for truly ambiguous cases

Stage 5: Sandbox Detonation (attachments only)
  └── Joe Sandbox / Firecracker VMs for high-risk files
```

**Pros**:
- Cost-controlled (expensive ops only when needed)
- No security expertise required to operate
- Plain-English explanations for every verdict
- Consistent detection regardless of operator skill

**Cons**:
- Less customizable than MQL
- Can't write custom detection rules
- Dependent on vendor for new threat coverage

---

## Integration & Deployment

| Aspect | Sublime Security | SwordPhish |
|--------|------------------|------------|
| **Microsoft 365** | ✅ Graph API | ✅ Graph API |
| **Google Workspace** | ✅ Gmail API | ✅ Gmail API + Pub/Sub |
| **SMTP Gateway** | ❌ API-only | ✅ Inline MX gateway |
| **Setup Time** | Hours to days | <10 minutes |
| **Professional Services** | Often required | Self-service |
| **Self-Hosted Option** | ✅ Free tier | ❌ Cloud only |

**Key Difference**: Sublime is API-first (post-delivery analysis), while SwordPhish supports both API integration AND inline SMTP gateway for organizations that want traditional MX-based protection. This makes SwordPhish more flexible for legacy environments.

---

## Target Market Comparison

### Sublime's Target Market

- **Primary**: Enterprise (1,000+ seats)
- **Sweet Spot**: Security-mature organizations with dedicated security teams
- **Buyer**: CISO, Security Engineering Manager
- **Use Case**: Organizations that want to write custom detection rules and have the staff to maintain them

**Evidence**:
- Customers are large enterprises (Spotify, Snowflake, Brex)
- MQL requires security engineering expertise
- Pricing reportedly starts reasonable but scales up significantly
- Limited RBAC suggests single-team use, not multi-tenant MSP

### SwordPhish's Target Market

- **Primary**: SMB/Mid-market (25-2,000 seats)
- **Sweet Spot**: Organizations without dedicated security staff
- **Buyer**: IT Manager, IT Admin, MSP
- **Use Case**: Organizations that need protection but can't invest in security engineering

**Evidence**:
- Designed for IT generalists, not security specialists
- Plain-English explanations for non-technical stakeholders
- MSP features (multi-tenant, bulk operations, white-label)
- Target pricing <$1/user/month

---

## Pricing Comparison

### Sublime Security Pricing

| Tier | Price | Notes |
|------|-------|-------|
| **Self-Hosted** | Free | Full platform, you manage infrastructure |
| **Cloud (Free)** | $0 | Up to 100 mailboxes |
| **Cloud (Paid)** | Undisclosed | "Competitive" per user pricing |

**User Reports**:
- Free tier is genuinely useful (rare in enterprise security)
- Paid pricing reportedly ramps up significantly at scale
- Enterprise deals likely $15-25+/user/month based on market comparisons
- Sales-driven pricing (no public price list)

### SwordPhish Pricing

| Tier | Target Price | Notes |
|------|--------------|-------|
| **SMB** | <$1/user/month | Target based on unit economics |
| **MSP** | Volume discounts | Multi-tenant pricing |
| **Enterprise** | TBD | Not primary focus |

**Analysis**: Sublime's free tier is competitive for small deployments, but SwordPhish aims to be dramatically cheaper at scale. A 500-seat organization might pay:
- Sublime (estimated): $5,000-10,000+/month
- SwordPhish (target): $500/month or less

---

## Feature Comparison

### Detection Capabilities

| Threat Type | Sublime | SwordPhish |
|-------------|---------|------------|
| Phishing | ✅ MQL + ML | ✅ Layered detection |
| BEC/Impersonation | ✅ Strong | ✅ Display name analysis |
| Credential Harvesting | ✅ | ✅ URL + brand detection |
| Malicious Attachments | ✅ | ✅ Static + sandbox |
| Malicious URLs | ✅ | ✅ Click-time rewriting |
| QR Code Phishing | ✅ | ✅ QR extraction |
| Account Takeover | ✅ Behavioral | ⚠️ Planned |
| Supplier Compromise | ✅ | ⚠️ Basic |

### Operational Features

| Feature | Sublime | SwordPhish |
|---------|---------|------------|
| **Plain-English Explanations** | ⚠️ Technical | ✅ Core feature |
| **End-User Quarantine Access** | ❌ Admin only | ✅ User self-service |
| **Multi-Tenant (MSP)** | ⚠️ Limited | ✅ Built-in |
| **Bulk Operations** | ⚠️ Limited | ✅ Core feature |
| **White-Label Reports** | ❌ | ✅ MSP branding |
| **Custom Detection Rules** | ✅ MQL | ❌ |
| **Open Source Rules** | ✅ GitHub | ❌ |
| **Autonomous AI Agents** | ✅ | ❌ |
| **SIEM Integration** | ✅ Strong | ⚠️ Basic |
| **API Access** | ✅ Full | ⚠️ Limited |

---

## Where Each Platform Shines

### Where Sublime Shines

1. **Customization & Control**
   - MQL lets security teams write exactly the detection they need
   - Open-source rules mean community contribution and transparency
   - Security engineers can respond to novel threats immediately

2. **Enterprise Security Stack Integration**
   - Deep SIEM/SOAR integration
   - Fits into existing security operations workflows
   - API-first architecture for automation

3. **Detection Transparency**
   - Every rule is visible and auditable
   - No "black box" ML decisions
   - Compliance teams can review detection logic

4. **Autonomous AI Agents**
   - Can triage alerts and take actions automatically
   - Reduces SOC analyst workload
   - Sophisticated automation capabilities

5. **Free Self-Hosted Option**
   - Genuinely useful for small deployments
   - No vendor lock-in if you can manage infrastructure
   - Full feature parity with paid cloud

### Where SwordPhish Shines

1. **Explainability for Non-Experts**
   - "This email claims to be from your bank but was sent from an unverified server"
   - IT admins can explain blocks to executives without security expertise
   - Reduces help desk burden from confused users

2. **Deployment Speed**
   - <10 minute setup vs hours/days
   - Self-service onboarding without vendor calls
   - No security engineering required to operate

3. **MSP/Multi-Tenant Operations**
   - Single pane of glass for all clients
   - Sub-second tenant switching
   - Bulk operations across tenants
   - Policy templates for standardization
   - White-label reporting

4. **End-User Experience**
   - Users can see and manage their own quarantine
   - One-click release for false positives
   - Digest notifications (not per-email spam)

5. **Cost Efficiency**
   - Gated pipeline keeps costs low
   - Target <$1/user/month (10x cheaper than enterprise tools)
   - No hidden enterprise pricing tiers

6. **Flexible Integration**
   - SMTP gateway option for legacy environments
   - Not locked into API-only (post-delivery) model
   - Works with any email system via MX records

---

## Where Each Platform Has Weaknesses

### Sublime's Weaknesses

1. **Steep Learning Curve**
   - MQL requires training and expertise
   - Not suitable for generalist IT teams
   - Time investment to become proficient

2. **No End-User Quarantine Visibility**
   - End users can't see their own quarantined mail
   - All quarantine management goes through admins
   - Increases operational burden

3. **Limited RBAC**
   - User reviews mention RBAC as a gap
   - Challenging for MSP multi-tenant scenarios
   - Less suitable for delegated administration

4. **Pricing Opacity**
   - No public pricing
   - Enterprise sales motion
   - User reports of significant price increases at scale

5. **Post-Delivery Only**
   - API integration means emails are delivered, then analyzed
   - No option for inline (pre-delivery) blocking
   - Some organizations require gateway-style protection

### SwordPhish's Weaknesses

1. **Less Customizable**
   - Can't write custom detection rules
   - Dependent on vendor for new threat coverage
   - Security teams can't fine-tune detection logic

2. **Early Stage**
   - Still in testing phase
   - Smaller customer base
   - Less proven at scale

3. **No Self-Hosted Option**
   - Cloud-only deployment
   - Some organizations require on-premise
   - Data sovereignty concerns for some regions

4. **Limited Enterprise Features**
   - Less SIEM/SOAR integration
   - API not as comprehensive
   - Not designed for SOC workflows

5. **Funding Gap**
   - Can't match Sublime's R&D investment
   - Smaller team means slower feature development
   - Risk of being outpaced on detection capabilities

---

## Market Position Analysis

### Email Security Market Context

- **Total Market Size**: ~$5.23B (2025) → ~$9.55B (2030)
- **CAGR**: 12.78%
- **Growth Drivers**: AI-powered threats, regulatory compliance, remote work

### Market Segmentation

| Segment | Estimated Size | Key Players |
|---------|---------------|-------------|
| Enterprise (1000+) | ~60% of spend | Proofpoint, Mimecast, Microsoft, Sublime |
| Mid-Market (100-1000) | ~25% of spend | Barracuda, Abnormal, many |
| SMB (<100) | ~15% of spend | Microsoft Defender, basic spam filters |

### Competitive Positioning

**Sublime's Position**:
- Competing for enterprise deals against Proofpoint, Abnormal, Microsoft
- Differentiated by transparency (MQL) and AI agents
- 1.7% market mindshare—growing but still small
- Well-funded to pursue enterprise accounts

**SwordPhish's Position**:
- Targeting the underserved SMB/MSP segment
- Differentiated by explainability and operational simplicity
- No direct well-funded competitor in "simple + explainable" niche
- MSP channel can drive rapid adoption

---

## Market Share Capture Analysis

### Who Is Better Positioned to Capture Market Share?

**Short Answer**: Different markets, so both can succeed. But if forced to pick one:

**Sublime has advantages in capturing enterprise market share:**
- Massive funding enables sales/marketing investment
- Enterprise customers (Spotify, Snowflake) provide credibility
- MQL appeals to security-mature organizations
- Autonomous AI agents are compelling for SOC efficiency
- Network effects from open-source rules

**SwordPhish has advantages in capturing SMB/MSP market share:**
- Uncontested positioning in "simple + explainable" niche
- MSP channel can drive viral adoption (1 MSP = 20+ clients)
- Price point unlocks budget-constrained buyers
- No incumbent is focused on explainability
- SMTP gateway option serves legacy environments competitors ignore

### The Critical Question: Which Market Is Larger?

**Enterprise** is larger in total spend (~60%), but:
- Extremely competitive (Proofpoint, Microsoft, Abnormal, Sublime)
- Long sales cycles (6-12 months)
- High customer acquisition cost
- Winner-take-most dynamics

**SMB/MSP** is smaller in spend per customer, but:
- Vastly more organizations (millions vs thousands)
- Underserved by current solutions
- Faster sales cycles
- MSP multiplier effect (1 sale = many deployments)
- Less competitive

### Projection

| Metric | Sublime (3-year) | SwordPhish (3-year) |
|--------|-----------------|---------------------|
| **Target Customers** | 500-1,000 enterprise | 2,000-5,000 SMB/MSP |
| **Mailboxes Protected** | 2-5M | 500K-2M |
| **ARR Potential** | $50-100M+ | $5-20M |
| **Market Share** | 3-5% of enterprise | 5-10% of SMB |

---

## Strategic Recommendations for SwordPhish

### Double Down On

1. **Explainability** - This is your moat. Sublime can't easily pivot to "simple" without alienating enterprise buyers.

2. **MSP Channel** - Each MSP partner is a force multiplier. 50 MSPs with 20 clients each = 1,000 organizations.

3. **10-Minute Deployment** - This is a competitive weapon. Enterprise tools can't match it without rebuilding.

4. **End-User Self-Service** - Sublime explicitly doesn't offer this. It's a differentiator.

5. **SMTP Gateway** - Many SMBs still want traditional MX-based protection. Sublime doesn't offer this.

### Don't Try to Compete On

1. **Custom Detection Rules** - You can't out-MQL Sublime. Don't try.

2. **Enterprise SOC Integration** - Let them have this market. It's not your buyer.

3. **Open Source** - Your value is simplicity, not transparency of rules.

4. **AI Agent Automation** - Cool tech, but your buyer doesn't want to configure AI agents.

---

## Conclusion

**Sublime Security** is a well-funded, enterprise-focused platform optimized for security teams who want control and customization. They've raised $243.8M and have enterprise logos to prove their model works.

**SwordPhish** is positioning for the massive, underserved SMB/MSP market where simplicity and explainability matter more than customization. There's no well-funded competitor specifically targeting this niche.

**Who captures more market share?**

- In **enterprise**: Sublime is better positioned (funding, features, credibility)
- In **SMB/MSP**: SwordPhish is better positioned (simplicity, price, channel)

**Overall market dynamics favor SwordPhish's approach** for several reasons:

1. The SMB market is underserved while enterprise is hyper-competitive
2. MSP channel provides leverage Sublime doesn't have
3. AI-generated phishing will commoditize detection—explainability becomes the differentiator
4. Budget-conscious organizations are growing faster than enterprise security budgets

**Bottom Line**: Sublime will capture enterprise accounts and grow to a significant company. SwordPhish, if executed well, can capture a larger number of organizations (by count) and build a profitable business in the SMB/MSP segment that Sublime isn't designed to serve. They're not really competing—they're serving different buyers with different needs.

The email security market is large enough for both to succeed in their respective segments.
