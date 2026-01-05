# Swordfish User Stories

## Overview

This document contains comprehensive user stories organized by epic and mapped to personas, acceptance criteria, and implementation phases. All stories follow the format: **As a [persona], I want [goal], so that [benefit]**.

---

## Epic 1: Real-Time Email Protection

### E1.1 - Email Monitoring Setup

**US-001: Connect Google Workspace**
- **As** Sarah (IT Admin), **I want** to connect my Google Workspace with OAuth, **so that** Swordfish can monitor incoming emails in real-time.
- **Persona**: Sarah (IT Admin), Jennifer (MSP)
- **Phase**: 1
- **Priority**: P0
- **Story Points**: 8

**Acceptance Criteria:**
```gherkin
Given I am logged into Swordfish as an admin
When I click "Connect Google Workspace"
Then I should be redirected to Google OAuth consent
And I should see requested permissions clearly explained
When I approve the permissions
Then I should see "Connected" status within 30 seconds
And I should see email count starting to populate
```

**TDD Requirements:**
- [ ] Unit test: OAuth flow token exchange
- [ ] Unit test: Token storage encryption
- [ ] Integration test: Google Workspace connection
- [ ] E2E test: Full OAuth flow in Playwright

---

**US-002: Connect Microsoft 365**
- **As** Sarah (IT Admin), **I want** to connect my Microsoft 365 tenant, **so that** Swordfish can monitor incoming emails in real-time.
- **Persona**: Sarah (IT Admin), Marcus (SOC)
- **Phase**: 1
- **Priority**: P0
- **Story Points**: 8

**Acceptance Criteria:**
```gherkin
Given I am logged into Swordfish as an admin
When I click "Connect Microsoft 365"
Then I should be redirected to Microsoft OAuth consent
And I should see application permissions requested
When I grant admin consent
Then I should see "Connected" status within 30 seconds
And I should see Graph API subscription created
```

**TDD Requirements:**
- [ ] Unit test: Graph API token exchange
- [ ] Unit test: Webhook subscription creation
- [ ] Integration test: Microsoft 365 connection
- [ ] E2E test: Full OAuth flow with admin consent

---

**US-003: Real-Time Webhook Processing**
- **As** the system, **I need** to receive email notifications via webhooks, **so that** I can analyze emails within 5 seconds of delivery.
- **Persona**: System
- **Phase**: 1
- **Priority**: P0
- **Story Points**: 13

**Acceptance Criteria:**
```gherkin
Given an integration is connected with webhooks enabled
When a new email arrives at the user's inbox
Then I should receive a webhook notification within 3 seconds
And I should fetch the full email content
And I should complete analysis within 5 seconds
And I should apply the appropriate action (pass/warn/quarantine/block)
```

**TDD Requirements:**
- [ ] Unit test: Webhook signature validation
- [ ] Unit test: Email parsing for both providers
- [ ] Integration test: End-to-end webhook flow
- [ ] Load test: 100 concurrent webhooks
- [ ] E2E test: Simulated email delivery and detection

---

### E1.2 - Detection Engine

**US-004: Multi-Layer Detection Pipeline**
- **As** Sarah (IT Admin), **I want** emails to be analyzed through multiple detection layers, **so that** sophisticated threats are caught without excessive false positives.
- **Persona**: Sarah (IT Admin), Marcus (SOC)
- **Phase**: 1
- **Priority**: P0
- **Story Points**: 21

**Acceptance Criteria:**
```gherkin
Given an email is received for analysis
When the detection pipeline processes it
Then it should execute Policy Layer first (< 10ms)
Then it should execute Deterministic Layer (< 50ms)
Then it should execute Threat Intelligence Layer (< 100ms)
Then it should conditionally execute ML Layer based on confidence (< 200ms)
Then it should conditionally execute LLM Layer for ambiguous cases (< 2000ms)
And the total processing time should be < 5 seconds
And a comprehensive verdict should be returned
```

**TDD Requirements:**
- [ ] Unit test: Each detection layer independently
- [ ] Unit test: Layer gating logic
- [ ] Unit test: Score aggregation algorithm
- [ ] Integration test: Full pipeline with mock data
- [ ] Performance test: P95 < 5 seconds

---

**US-005: SPF/DKIM/DMARC Validation**
- **As** Sarah (IT Admin), **I want** email authentication to be validated automatically, **so that** spoofed emails are detected and blocked.
- **Persona**: Sarah (IT Admin), Marcus (SOC)
- **Phase**: 1
- **Priority**: P0
- **Story Points**: 5

**Acceptance Criteria:**
```gherkin
Given an email is received with authentication headers
When the deterministic layer processes it
Then SPF result should be parsed and validated
And DKIM signature should be verified
And DMARC policy should be evaluated
And appropriate signals should be generated for failures
```

**TDD Requirements:**
- [ ] Unit test: SPF header parsing
- [ ] Unit test: DKIM header parsing
- [ ] Unit test: DMARC header parsing
- [ ] Unit test: Signal generation for each failure type
- [ ] Integration test: Real email header samples

---

**US-006: Phishing URL Detection**
- **As** Alex (End User), **I want** malicious URLs to be detected and blocked, **so that** I don't accidentally click on phishing links.
- **Persona**: Alex (End User), Sarah (IT Admin)
- **Phase**: 1
- **Priority**: P0
- **Story Points**: 8

**Acceptance Criteria:**
```gherkin
Given an email contains URLs
When the detection pipeline processes it
Then each URL should be extracted from HTML and text
And shortened URLs should be expanded
And URLs should be checked against threat intelligence
And suspicious patterns should be detected (IP-based, homoglyph domains)
And malicious URLs should trigger quarantine action
```

**TDD Requirements:**
- [ ] Unit test: URL extraction from HTML
- [ ] Unit test: URL extraction from plain text
- [ ] Unit test: URL shortener expansion
- [ ] Unit test: Homoglyph detection
- [ ] Integration test: Known malicious URL detection

---

**US-007: Business Email Compromise Detection**
- **As** Sarah (IT Admin), **I want** BEC attacks to be detected, **so that** employees don't fall for impersonation scams.
- **Persona**: Sarah (IT Admin), Marcus (SOC)
- **Phase**: 2
- **Priority**: P1
- **Story Points**: 13

**Acceptance Criteria:**
```gherkin
Given an email is received
When it exhibits BEC patterns
Then executive impersonation should be detected
And payment/wire transfer requests should be flagged
And urgency language combined with financial requests should trigger alerts
And display name spoofing should be detected
And the email should be quarantined with BEC classification
```

**TDD Requirements:**
- [ ] Unit test: Executive name matching
- [ ] Unit test: Financial request pattern detection
- [ ] Unit test: Urgency language scoring
- [ ] Unit test: Display name vs email domain comparison
- [ ] E2E test: BEC email samples from dataset

---

### E1.3 - Actions and Responses

**US-008: Automatic Quarantine**
- **As** Sarah (IT Admin), **I want** malicious emails to be quarantined automatically, **so that** users never see dangerous messages.
- **Persona**: Sarah (IT Admin)
- **Phase**: 1
- **Priority**: P0
- **Story Points**: 8

**Acceptance Criteria:**
```gherkin
Given an email is classified as malicious (score > 70)
When the action engine processes the verdict
Then the email should be moved to quarantine
And the original should be removed from user's inbox
And a database record should be created
And an admin notification should be sent (if configured)
And the user should NOT receive the email
```

**TDD Requirements:**
- [ ] Unit test: Quarantine action logic
- [ ] Integration test: Gmail quarantine via API
- [ ] Integration test: Microsoft quarantine via Graph
- [ ] E2E test: Full quarantine flow

---

**US-009: Warning Banner Injection**
- **As** Alex (End User), **I want** to see clear warnings on suspicious emails, **so that** I can make informed decisions.
- **Persona**: Alex (End User)
- **Phase**: 1
- **Priority**: P1
- **Story Points**: 5

**Acceptance Criteria:**
```gherkin
Given an email is classified as suspicious (score 30-70)
When the action engine processes the verdict
Then a warning banner should be injected at the top of the email
And the banner should explain WHY it's suspicious in plain language
And the banner should provide a "Report as Safe" button
And the original email content should be preserved
```

**TDD Requirements:**
- [ ] Unit test: Banner HTML generation
- [ ] Unit test: Email body modification
- [ ] Integration test: Gmail message update
- [ ] Integration test: Microsoft message update

---

**US-010: Link Rewriting**
- **As** Alex (End User), **I want** suspicious links to be rewritten to pass through Swordfish, **so that** I'm protected even if I click.
- **Persona**: Alex (End User), Sarah (IT Admin)
- **Phase**: 2
- **Priority**: P1
- **Story Points**: 8

**Acceptance Criteria:**
```gherkin
Given an email contains suspicious URLs
When the action engine processes the verdict
Then URLs should be rewritten to route through Swordfish proxy
And the proxy should re-check URL reputation at click time
And the proxy should show a warning interstitial for suspicious URLs
And the proxy should block known malicious URLs
And original URL should be retrievable for legitimate access
```

**TDD Requirements:**
- [ ] Unit test: URL rewriting logic
- [ ] Unit test: Proxy URL generation
- [ ] Integration test: Click-time checking
- [ ] E2E test: Full link rewrite and click flow

---

## Epic 2: Dashboard and Visibility

### E2.1 - Threat Dashboard

**US-011: Threat Overview Dashboard**
- **As** Sarah (IT Admin), **I want** a dashboard showing threat statistics, **so that** I can understand my organization's email security posture.
- **Persona**: Sarah (IT Admin), David (Compliance)
- **Phase**: 1
- **Priority**: P0
- **Story Points**: 8

**Acceptance Criteria:**
```gherkin
Given I am logged into Swordfish
When I navigate to the Dashboard
Then I should see total emails processed (24h, 7d, 30d)
And I should see threats blocked by category (phishing, spam, malware, BEC)
And I should see threat trend chart
And I should see top targeted users
And I should see recent high-severity threats
And data should refresh every 60 seconds
```

**TDD Requirements:**
- [ ] Unit test: Statistics aggregation queries
- [ ] Unit test: Chart data formatting
- [ ] Component test: Dashboard widgets render
- [ ] E2E test: Dashboard loads with data

---

**US-012: Threat Detail View**
- **As** Marcus (SOC Analyst), **I want** to see detailed analysis of each threat, **so that** I can investigate and understand attack patterns.
- **Persona**: Marcus (SOC), Sarah (IT Admin)
- **Phase**: 1
- **Priority**: P1
- **Story Points**: 5

**Acceptance Criteria:**
```gherkin
Given I am viewing the threats list
When I click on a specific threat
Then I should see full email headers
And I should see detection signals with scores
And I should see URL analysis results
And I should see attachment analysis results
And I should see LLM explanation (if generated)
And I should see timeline of actions taken
And I should be able to release from quarantine
```

**TDD Requirements:**
- [ ] Unit test: Threat detail data assembly
- [ ] Component test: Detail view renders all sections
- [ ] E2E test: Navigate to threat detail and interact

---

### E2.2 - Quarantine Management

**US-013: Admin Quarantine View**
- **As** Sarah (IT Admin), **I want** to manage quarantined emails, **so that** I can release false positives and confirm threats.
- **Persona**: Sarah (IT Admin), Help Desk
- **Phase**: 1
- **Priority**: P0
- **Story Points**: 5

**Acceptance Criteria:**
```gherkin
Given I am logged in as an admin
When I navigate to Quarantine
Then I should see list of quarantined emails
And I should be able to filter by date, sender, recipient, threat type
And I should be able to search by subject or sender
And I should be able to release individual emails
And I should be able to bulk release/delete
And I should be able to add sender to allowlist
```

**TDD Requirements:**
- [ ] Unit test: Quarantine query with filters
- [ ] Unit test: Release action logic
- [ ] Unit test: Allowlist addition
- [ ] E2E test: Full quarantine management flow

---

**US-014: User Self-Service Quarantine**
- **As** Alex (End User), **I want** to see emails quarantined for me and request release, **so that** I don't miss important emails.
- **Persona**: Alex (End User)
- **Phase**: 2
- **Priority**: P2
- **Story Points**: 5

**Acceptance Criteria:**
```gherkin
Given I am logged in as a regular user
When I navigate to My Quarantine
Then I should see only emails addressed to me
And I should see why each email was quarantined
And I should be able to request release
And my request should notify the admin
And I should NOT be able to release directly (requires admin approval)
```

**TDD Requirements:**
- [ ] Unit test: User-scoped quarantine query
- [ ] Unit test: Release request creation
- [ ] Unit test: Admin notification trigger
- [ ] E2E test: User quarantine flow

---

### E2.3 - Reporting

**US-015: Scheduled Reports**
- **As** Sarah (IT Admin), **I want** to receive weekly email security reports, **so that** I can track trends without logging in.
- **Persona**: Sarah (IT Admin), David (Compliance)
- **Phase**: 2
- **Priority**: P2
- **Story Points**: 5

**Acceptance Criteria:**
```gherkin
Given I have configured scheduled reports
When the scheduled time arrives
Then a report should be generated with:
  - Emails processed
  - Threats blocked by category
  - Top threats
  - False positive rate
  - Trend vs previous period
And the report should be emailed as PDF
And the report should match my selected frequency (daily/weekly/monthly)
```

**TDD Requirements:**
- [ ] Unit test: Report data aggregation
- [ ] Unit test: PDF generation
- [ ] Unit test: Email delivery
- [ ] Integration test: Scheduled job execution

---

**US-016: Compliance Audit Report**
- **As** David (Compliance Officer), **I want** to generate audit-ready reports, **so that** I can demonstrate email security controls to auditors.
- **Persona**: David (Compliance)
- **Phase**: 3
- **Priority**: P2
- **Story Points**: 8

**Acceptance Criteria:**
```gherkin
Given I am logged in with compliance role
When I generate an audit report
Then it should include:
  - Policy configuration summary
  - Detection statistics
  - Incident timeline
  - User activity audit trail
  - System configuration changes
And it should be exportable as PDF
And it should be formatted for SOC 2 / HIPAA requirements
```

**TDD Requirements:**
- [ ] Unit test: Audit data collection
- [ ] Unit test: Compliance report formatting
- [ ] Unit test: PDF generation with compliance templates
- [ ] E2E test: Full report generation flow

---

## Epic 3: Policy Management

### E3.1 - Policy Configuration

**US-017: Create Detection Policy**
- **As** Sarah (IT Admin), **I want** to create custom detection policies, **so that** I can tune protection for my organization's needs.
- **Persona**: Sarah (IT Admin), Marcus (SOC)
- **Phase**: 1
- **Priority**: P1
- **Story Points**: 8

**Acceptance Criteria:**
```gherkin
Given I am logged in as an admin
When I create a new detection policy
Then I should be able to specify:
  - Policy name and description
  - Trigger conditions (sender, domain, content patterns)
  - Severity/priority level
  - Action (warn, quarantine, block)
  - Scope (all users, specific groups)
And the policy should be validated before saving
And the policy should take effect within 60 seconds
```

**TDD Requirements:**
- [ ] Unit test: Policy validation logic
- [ ] Unit test: Policy rule parsing
- [ ] Unit test: Policy scope evaluation
- [ ] Integration test: Policy enforcement in pipeline
- [ ] E2E test: Create and test policy

---

**US-018: Allowlist/Blocklist Management**
- **As** Sarah (IT Admin), **I want** to manage sender allowlists and blocklists, **so that** I can override detection for known senders.
- **Persona**: Sarah (IT Admin), Help Desk
- **Phase**: 1
- **Priority**: P0
- **Story Points**: 5

**Acceptance Criteria:**
```gherkin
Given I am logged in as an admin
When I manage allowlist/blocklist
Then I should be able to add/remove:
  - Email addresses
  - Domains
  - IP addresses
And allowlisted senders should bypass detection
And blocklisted senders should always be blocked
And I should see why each entry was added
And I should be able to import from CSV
```

**TDD Requirements:**
- [ ] Unit test: List entry validation
- [ ] Unit test: List lookup in detection pipeline
- [ ] Unit test: CSV import parsing
- [ ] E2E test: Add to list and verify behavior

---

**US-019: Policy Templates**
- **As** Sarah (IT Admin), **I want** to use pre-built policy templates, **so that** I can quickly enable best-practice protections.
- **Persona**: Sarah (IT Admin)
- **Phase**: 2
- **Priority**: P2
- **Story Points**: 5

**Acceptance Criteria:**
```gherkin
Given I am setting up policies
When I browse policy templates
Then I should see templates for:
  - Anti-phishing (basic, strict)
  - BEC protection
  - Malware protection
  - Compliance (HIPAA, PCI)
And I should be able to preview template rules
And I should be able to apply template with one click
And I should be able to customize after applying
```

**TDD Requirements:**
- [ ] Unit test: Template loading
- [ ] Unit test: Template application
- [ ] Unit test: Template customization
- [ ] E2E test: Apply template flow

---

## Epic 4: Multi-Tenant / MSP

### E4.1 - Tenant Management

**US-020: MSP Dashboard**
- **As** Jennifer (MSP), **I want** a consolidated dashboard for all my clients, **so that** I can monitor their security from one place.
- **Persona**: Jennifer (MSP)
- **Phase**: 2
- **Priority**: P1
- **Story Points**: 13

**Acceptance Criteria:**
```gherkin
Given I am logged in as an MSP admin
When I view the MSP dashboard
Then I should see all clients with:
  - Client name and status
  - Emails processed (24h)
  - Threats blocked (24h)
  - Health indicator (red/yellow/green)
And I should be able to click into any client
And I should be able to filter/sort clients
And I should see aggregate statistics across all clients
```

**TDD Requirements:**
- [ ] Unit test: Multi-tenant aggregation queries
- [ ] Unit test: Client health calculation
- [ ] Component test: MSP dashboard render
- [ ] E2E test: MSP dashboard with mock clients

---

**US-021: Client Onboarding**
- **As** Jennifer (MSP), **I want** to onboard new clients quickly, **so that** I can scale my business efficiently.
- **Persona**: Jennifer (MSP)
- **Phase**: 2
- **Priority**: P1
- **Story Points**: 8

**Acceptance Criteria:**
```gherkin
Given I am logged in as an MSP admin
When I add a new client
Then I should be able to:
  - Enter client name and contact
  - Select email platform (Google/Microsoft)
  - Initiate OAuth connection
  - Apply default policies from template
And onboarding should complete in < 15 minutes
And I should be able to track onboarding progress
```

**TDD Requirements:**
- [ ] Unit test: Client creation
- [ ] Unit test: Policy template application
- [ ] Integration test: OAuth delegation
- [ ] E2E test: Full onboarding flow

---

**US-022: Per-Client Billing**
- **As** Jennifer (MSP), **I want** to track usage per client, **so that** I can bill accurately.
- **Persona**: Jennifer (MSP)
- **Phase**: 3
- **Priority**: P2
- **Story Points**: 8

**Acceptance Criteria:**
```gherkin
Given I am viewing billing/usage
When I select a billing period
Then I should see per-client:
  - Emails processed
  - Users protected
  - Advanced features used
  - Calculated cost
And I should be able to export for invoicing
And I should see month-over-month comparison
```

**TDD Requirements:**
- [ ] Unit test: Usage tracking aggregation
- [ ] Unit test: Billing calculation
- [ ] Unit test: Export formatting
- [ ] E2E test: View and export billing data

---

## Epic 5: Integration and API

### E5.1 - API Access

**US-023: REST API Access**
- **As** Marcus (SOC Analyst), **I want** programmatic API access, **so that** I can integrate Swordfish with my security tools.
- **Persona**: Marcus (SOC), Jennifer (MSP)
- **Phase**: 2
- **Priority**: P1
- **Story Points**: 13

**Acceptance Criteria:**
```gherkin
Given I have API credentials
When I call the Swordfish API
Then I should be able to:
  - List and search threats
  - Get threat details
  - Manage quarantine
  - CRUD policies
  - Get statistics
And all endpoints should require authentication
And rate limiting should be enforced
And OpenAPI documentation should be available
```

**TDD Requirements:**
- [ ] Unit test: API authentication middleware
- [ ] Unit test: Each API endpoint
- [ ] Unit test: Rate limiting logic
- [ ] Integration test: Full API workflow
- [ ] Contract test: OpenAPI spec validation

---

**US-024: Webhook Notifications**
- **As** Marcus (SOC Analyst), **I want** to receive webhook notifications for threats, **so that** I can react immediately.
- **Persona**: Marcus (SOC)
- **Phase**: 2
- **Priority**: P2
- **Story Points**: 5

**Acceptance Criteria:**
```gherkin
Given I have configured a webhook endpoint
When a threat is detected
Then a webhook should be sent with:
  - Threat details
  - Verdict and score
  - Signals that triggered detection
  - Action taken
And webhooks should retry on failure
And I should be able to test webhooks
```

**TDD Requirements:**
- [ ] Unit test: Webhook payload generation
- [ ] Unit test: Webhook delivery with retry
- [ ] Integration test: Webhook to mock endpoint
- [ ] E2E test: Configure and receive webhook

---

### E5.2 - SIEM Integration

**US-025: Splunk Integration**
- **As** Marcus (SOC Analyst), **I want** Swordfish data in Splunk, **so that** I can correlate email threats with other security data.
- **Persona**: Marcus (SOC)
- **Phase**: 3
- **Priority**: P2
- **Story Points**: 8

**Acceptance Criteria:**
```gherkin
Given I have configured Splunk integration
When threats are detected
Then events should be sent to Splunk HEC
And events should include standard CEF/LEEF fields
And events should be searchable in Splunk
And I should be able to use Splunk dashboards
```

**TDD Requirements:**
- [ ] Unit test: CEF event formatting
- [ ] Unit test: HEC client
- [ ] Integration test: Event delivery to Splunk
- [ ] E2E test: Verify events in Splunk

---

## Epic 6: User Experience

### E6.1 - Onboarding

**US-026: First-Time Setup Wizard**
- **As** Sarah (IT Admin), **I want** a guided setup experience, **so that** I can get protected quickly.
- **Persona**: Sarah (IT Admin)
- **Phase**: 1
- **Priority**: P0
- **Story Points**: 8

**Acceptance Criteria:**
```gherkin
Given I am a new user
When I first log in
Then I should see a setup wizard that guides me through:
  1. Welcome and overview
  2. Connect email provider
  3. Configure basic policies
  4. Set notification preferences
  5. Review and complete
And I should be able to skip steps
And I should be able to return to wizard later
And progress should be saved between sessions
```

**TDD Requirements:**
- [ ] Unit test: Wizard state management
- [ ] Unit test: Step completion tracking
- [ ] Component test: Each wizard step
- [ ] E2E test: Complete wizard flow

---

### E6.2 - Notifications

**US-027: Threat Notifications**
- **As** Sarah (IT Admin), **I want** to receive notifications for critical threats, **so that** I can respond quickly.
- **Persona**: Sarah (IT Admin)
- **Phase**: 1
- **Priority**: P1
- **Story Points**: 5

**Acceptance Criteria:**
```gherkin
Given I have configured notifications
When a threat is detected matching my criteria
Then I should receive notification via configured channel (email/Slack)
And notification should include:
  - Threat summary
  - Affected user
  - Action taken
  - Link to details
And I should be able to configure:
  - Severity threshold
  - Notification channels
  - Quiet hours
```

**TDD Requirements:**
- [ ] Unit test: Notification matching rules
- [ ] Unit test: Notification formatting
- [ ] Integration test: Email notification delivery
- [ ] Integration test: Slack notification delivery

---

## Story Backlog Summary

### Phase 1 (Foundation) - 13 Stories, ~100 Points
| ID | Story | Points | Priority |
|----|-------|--------|----------|
| US-001 | Connect Google Workspace | 8 | P0 |
| US-002 | Connect Microsoft 365 | 8 | P0 |
| US-003 | Real-Time Webhook Processing | 13 | P0 |
| US-004 | Multi-Layer Detection Pipeline | 21 | P0 |
| US-005 | SPF/DKIM/DMARC Validation | 5 | P0 |
| US-006 | Phishing URL Detection | 8 | P0 |
| US-008 | Automatic Quarantine | 8 | P0 |
| US-009 | Warning Banner Injection | 5 | P1 |
| US-011 | Threat Overview Dashboard | 8 | P0 |
| US-012 | Threat Detail View | 5 | P1 |
| US-013 | Admin Quarantine View | 5 | P0 |
| US-017 | Create Detection Policy | 8 | P1 |
| US-018 | Allowlist/Blocklist Management | 5 | P0 |
| US-026 | First-Time Setup Wizard | 8 | P0 |
| US-027 | Threat Notifications | 5 | P1 |

### Phase 2 (Intelligence) - 10 Stories, ~75 Points
| ID | Story | Points | Priority |
|----|-------|--------|----------|
| US-007 | BEC Detection | 13 | P1 |
| US-010 | Link Rewriting | 8 | P1 |
| US-014 | User Self-Service Quarantine | 5 | P2 |
| US-015 | Scheduled Reports | 5 | P2 |
| US-019 | Policy Templates | 5 | P2 |
| US-020 | MSP Dashboard | 13 | P1 |
| US-021 | Client Onboarding | 8 | P1 |
| US-023 | REST API Access | 13 | P1 |
| US-024 | Webhook Notifications | 5 | P2 |

### Phase 3 (Advanced) - 4 Stories, ~32 Points
| ID | Story | Points | Priority |
|----|-------|--------|----------|
| US-016 | Compliance Audit Report | 8 | P2 |
| US-022 | Per-Client Billing | 8 | P2 |
| US-025 | Splunk Integration | 8 | P2 |
| Additional advanced stories | TBD | P3 |

---

## Appendix: Story Status Tracking

| Status | Count |
|--------|-------|
| Backlog | 27 |
| Ready | 0 |
| In Progress | 0 |
| Done | 0 |
| **Total** | **27** |
