# Swordfish User Personas

## Overview

This document defines the primary user personas for Swordfish Email Security Platform. These personas guide feature prioritization, UX design decisions, and help ensure we're building for real user needs.

---

## Primary Personas

### 1. Sarah Chen - IT Administrator (SMB)

**Demographics**
- Age: 34
- Role: IT Manager at a 150-person marketing agency
- Technical Level: Intermediate
- Industry: Professional Services

**Background**
Sarah manages all IT operations for her company, including security, infrastructure, and user support. She's responsible for 150 email accounts across Google Workspace. She has no dedicated security team and wears multiple hats.

**Goals**
- Protect employees from phishing and BEC attacks
- Minimize time spent on email security management
- Meet compliance requirements (SOC 2 for client contracts)
- Reduce false positives that interrupt employee productivity
- Get clear reporting for leadership

**Pain Points**
- Previous solutions were too complex for her limited time
- Enterprise tools (Proofpoint, Mimecast) are too expensive
- Google's built-in spam filtering misses sophisticated attacks
- No visibility into what threats are being blocked
- Spends hours weekly investigating suspicious emails reported by employees

**Technical Context**
- Google Workspace Business
- Basic SSO with Google
- No SIEM or dedicated security tools
- Limited PowerShell/CLI experience

**Behavioral Traits**
- Prefers GUI over command line
- Values clear documentation and onboarding
- Needs to justify ROI to CFO
- Checks dashboard 2-3 times per week
- Wants email alerts for critical threats only

**Success Metrics**
- Time to deployment: < 1 hour
- Threats blocked without intervention
- Zero business email compromise incidents
- Quarterly compliance reports generated automatically

**Quote**
> "I need something that works out of the box. I don't have time to tune rules or investigate every alert."

---

### 2. Marcus Thompson - Security Analyst (Enterprise)

**Demographics**
- Age: 28
- Role: SOC Analyst Level 2 at a 2,000-person financial services company
- Technical Level: Advanced
- Industry: Financial Services

**Background**
Marcus works in a 6-person SOC team, handling email security alongside other threat vectors. His company uses Microsoft 365 E5 and has dedicated security infrastructure. He's responsible for investigating alerts, tuning detection rules, and responding to incidents.

**Goals**
- Reduce email-based threat investigation time
- Integrate email security data with existing SIEM (Splunk)
- Create custom detection rules for industry-specific threats
- Get detailed forensic data for incident response
- Maintain compliance with SEC and FINRA regulations

**Pain Points**
- Microsoft Defender for O365 generates too many alerts
- Needs API access for automation and integration
- Current tools lack BEC detection capabilities
- Investigation workflows span multiple consoles
- Executives are prime targets for whaling attacks

**Technical Context**
- Microsoft 365 E5 with Defender
- Splunk SIEM
- CrowdStrike EDR
- Custom SOAR playbooks
- Strong PowerShell and API experience

**Behavioral Traits**
- Lives in SIEM dashboard
- Wants raw data and API access
- Writes custom detection rules
- Reviews email security daily
- Documents everything for compliance

**Success Metrics**
- Mean time to investigate (MTTI) < 5 minutes
- Custom rule deployment in minutes
- 100% SIEM integration coverage
- Detailed audit trails for compliance

**Quote**
> "Give me the API and the raw data. I'll build my own dashboards and workflows."

---

### 3. Jennifer Walsh - MSP Security Manager

**Demographics**
- Age: 42
- Role: Director of Security Services at a Managed Service Provider
- Technical Level: Expert
- Industry: MSP/MSSP serving 45 SMB clients

**Background**
Jennifer runs the security practice at an MSP that manages IT for 45 small businesses (2,500 total users). She needs to deploy and manage email security across all clients from a single console while maintaining per-client isolation and billing.

**Goals**
- Single pane of glass for all clients
- Per-client billing and usage tracking
- Standardized security policies with per-client customization
- White-label reporting for client presentations
- Automated onboarding for new clients

**Pain Points**
- Current tools require separate instances per client
- No consolidated threat view across all clients
- Manual billing reconciliation is time-consuming
- Client onboarding takes 2+ hours per client
- Difficult to demonstrate value to clients

**Technical Context**
- Mix of Google Workspace and Microsoft 365 clients
- PSA integration (ConnectWise, Autotask)
- RMM tools (Datto, Ninja)
- Basic SIEM for larger clients
- Extensive API/automation experience

**Behavioral Traits**
- Manages through automation
- Weekly client security reviews
- Monthly executive reports per client
- Needs to prove ROI to retain clients
- Values partner programs and margins

**Success Metrics**
- Client onboarding < 15 minutes
- Single dashboard for all clients
- Automated monthly reporting
- Per-client threat analytics
- 30%+ partner margins

**Quote**
> "I need to manage 45 clients like they're one, but report on them like they're 45 separate businesses."

---

### 4. David Park - Compliance Officer

**Demographics**
- Age: 51
- Role: Chief Compliance Officer at a healthcare organization
- Technical Level: Non-technical
- Industry: Healthcare (800 employees)

**Background**
David oversees regulatory compliance for a regional healthcare system. He's not technical but needs visibility into email security to satisfy HIPAA, HITECH, and state privacy law requirements. He relies on IT for implementation but owns the compliance outcomes.

**Goals**
- Demonstrate email security controls for audits
- Get executive-level reports without technical jargon
- Ensure PHI is protected in email
- Document incident response procedures
- Track security metrics over time

**Pain Points**
- Current security reports are too technical
- Can't demonstrate compliance controls to auditors
- No visibility into what emails contain PHI
- Incident response documentation is scattered
- Annual audits are stressful and time-consuming

**Technical Context**
- Microsoft 365 with basic licensing
- GRC platform (ServiceNow GRC)
- Limited technical knowledge
- Relies on IT for security operations

**Behavioral Traits**
- Quarterly board presentations on security posture
- Annual audit preparation
- Risk-focused rather than threat-focused
- Needs plain-English explanations
- Values certifications (SOC 2, HITRUST)

**Success Metrics**
- Audit-ready reports on demand
- Clear compliance dashboards
- Documented security controls
- Trend analysis for board reporting
- Incident documentation for regulators

**Quote**
> "I don't need to know how it works. I need to prove to auditors that it works."

---

### 5. Alex Rivera - End User (Knowledge Worker)

**Demographics**
- Age: 29
- Role: Account Executive at a SaaS company
- Technical Level: Low
- Industry: Technology (B2B Sales)

**Background**
Alex receives 100+ emails per day, many from unknown external contacts (prospects, partners). They're a high-value target for BEC and impersonation attacks because they handle contracts and payments. They need security that doesn't slow them down.

**Goals**
- Not get phished (professionally embarrassing and career-impacting)
- Minimal disruption to email workflow
- Clear guidance when something is suspicious
- Easy way to report suspicious emails
- Quick release of false positives from quarantine

**Pain Points**
- Previous security tools blocked legitimate prospect emails
- Warning banners are confusing and ignored
- Quarantine release process takes too long
- No training on what to look for
- Fear of clicking wrong link and causing breach

**Technical Context**
- Gmail in browser and mobile
- No security awareness training
- Uses email for contracts and payments
- External email is 60% of inbox

**Behavioral Traits**
- Processes email quickly
- Ignores most security warnings (banner blindness)
- Reports suspicious emails only if very obvious
- Will escalate to IT if blocked email is important
- Appreciates brief, actionable guidance

**Success Metrics**
- Zero legitimate emails blocked
- < 3 second added latency
- Clear, actionable warnings
- 1-click suspicious email reporting
- Self-service quarantine release for obvious false positives

**Quote**
> "Just don't block my prospects and don't make me think about security. That's IT's job."

---

## Secondary Personas

### 6. Chief Information Security Officer (CISO)

**Key Concerns**
- Board-level reporting
- Risk quantification
- Vendor security assessments
- Security program maturity
- Budget justification

**Interaction with Swordfish**
- Monthly executive dashboard review
- Quarterly business reviews with vendor
- Annual contract renewal decisions
- Incident escalation for major breaches

---

### 7. Help Desk Technician

**Key Concerns**
- User requests for quarantine release
- "Is this email safe?" questions
- Account compromise remediation
- New user onboarding

**Interaction with Swordfish**
- Daily quarantine management
- User lookup and email search
- Password reset after compromise
- Basic policy exceptions

---

## Persona Priority Matrix

| Persona | Priority | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
|---------|----------|---------|---------|---------|---------|
| Sarah (IT Admin SMB) | **P0** | Primary | Primary | Primary | Primary |
| Alex (End User) | **P0** | Primary | Primary | Primary | Primary |
| Marcus (SOC Analyst) | P1 | Basic | Full | Full | Full |
| Jennifer (MSP) | P1 | - | Basic | Full | Full |
| David (Compliance) | P2 | - | Basic | Full | Full |
| CISO | P2 | - | - | Basic | Full |
| Help Desk | P3 | Basic | Full | Full | Full |

---

## Persona-Feature Mapping

### Phase 1 Features → Primary Personas

| Feature | Sarah | Alex | Marcus |
|---------|-------|------|--------|
| Real-time email protection | Must have | Must have | Must have |
| Basic dashboard | Must have | - | Nice to have |
| Quarantine management | Must have | Self-service | Nice to have |
| Email warnings | Nice to have | Must have | - |
| Basic reporting | Must have | - | Must have |

### Phase 2 Features → Expanded Personas

| Feature | Sarah | Marcus | Jennifer |
|---------|-------|--------|----------|
| API access | Nice to have | Must have | Must have |
| Custom policies | Nice to have | Must have | Must have |
| Multi-tenant | - | - | Must have |
| SIEM integration | - | Must have | Nice to have |
| Threat intelligence | Nice to have | Must have | Nice to have |

---

## Jobs To Be Done (JTBD)

### Sarah (IT Admin)
1. **When** I'm setting up email security for my company, **I want** a simple wizard that connects to Google Workspace, **so that** I can protect my users without reading documentation.

2. **When** I receive a threat alert, **I want** a clear summary of what happened and what action was taken, **so that** I know if I need to do anything.

3. **When** a user reports a blocked email, **I want** to release it in one click after seeing why it was blocked, **so that** I don't delay business operations.

### Alex (End User)
1. **When** I receive an email from an unknown sender, **I want** a clear, brief warning if it's suspicious, **so that** I can make an informed decision without reading a wall of text.

2. **When** I accidentally click a suspicious link, **I want** to be protected automatically, **so that** I don't have to worry about making a mistake.

3. **When** a legitimate email is blocked, **I want** to request release quickly, **so that** I don't miss important business communications.

### Marcus (SOC Analyst)
1. **When** investigating a potential phishing campaign, **I want** to search all emails by sender domain across the organization, **so that** I can assess the scope of the attack.

2. **When** we identify a new threat pattern, **I want** to create a custom detection rule and deploy it immediately, **so that** I can protect users before the next variant arrives.

3. **When** our SIEM alerts on email-related IOCs, **I want** the data to flow automatically with full context, **so that** I don't have to pivot between consoles.

---

## Appendix: Persona Research Sources

- Customer interviews (12 SMB IT admins, 8 enterprise security teams)
- Support ticket analysis (500+ tickets categorized)
- Competitive analysis (Barracuda, Proofpoint, Mimecast user reviews)
- Industry reports (Gartner, Forrester email security)
- SANS Institute email security surveys
