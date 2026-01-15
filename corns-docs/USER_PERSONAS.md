# User Personas

## Overview

Three primary personas interact with Swordfish. Understanding their goals, frustrations, and behaviors drives every UX decision.

---

## Persona 1: IT Admin "Marcus"
**Direct Customer**

### Profile

| Attribute | Value |
|-----------|-------|
| Role | IT Administrator / IT Manager |
| Company Size | 50-200 employees |
| Tech Expertise | Generalist, not security specialist |
| Time for Security | 2-4 hours/week |
| Reports To | CFO or CEO (non-technical) |

### Context

Marcus manages all IT for a mid-sized company. He handles Office 365 or Google Workspace, endpoints, network, and now email security. Security is one of many responsibilities, not his specialty. He needs solutions that work without constant attention.

### Goals

1. **Protect the organization** from email threats without becoming a security expert
2. **Minimize help desk tickets** from false positives and confused users
3. **Demonstrate value** to leadership with clear metrics and reports
4. **Complete setup quickly** so he can focus on other priorities

### Frustrations

| Frustration | Impact | Design Implication |
|-------------|--------|-------------------|
| Complex products requiring security expertise | Avoids advanced features | Progressive disclosure, smart defaults |
| False positives generating tickets | Erodes trust in the system | Conservative blocking, clear explanations |
| Poor explanations when emails are blocked | Can't justify to execs | Human-readable verdicts |
| Slow onboarding requiring vendor calls | Delays deployment | Self-service <10 min setup |
| Dashboards requiring daily attention | Doesn't have time | Weekly digest, alerts only when needed |

### Behaviors

- Wants to complete setup in one session
- Checks dashboard weekly, not daily
- Needs to explain blocks to frustrated executives
- Values clear ROI metrics for budget justification
- Prefers email notifications over logging in

### Key Questions to Answer

1. Can Marcus complete setup in under 10 minutes without a call?
2. Can Marcus understand why an email was blocked without security expertise?
3. Can Marcus show his CEO a report proving the system is working?
4. Will Marcus get a ticket every time a legitimate email is blocked?

### Design Implications

| Requirement | Implementation |
|-------------|----------------|
| Fast onboarding | Step-by-step wizard, <10 min |
| Clear explanations | "This email pretends to be from your bank" |
| Weekly summary | Automated email with key metrics |
| Low false positive rate | Conservative defaults, easy release |
| Executive reports | One-click PDF export |

---

## Persona 2: MSP Admin "Dana"
**Managed Service Provider**

### Profile

| Attribute | Value |
|-----------|-------|
| Role | Senior Systems Engineer / Security Lead |
| Tenants Managed | 10-50 client companies |
| Tech Expertise | Deep, certified |
| Time per Tenant | 15-30 min/week average |
| Measured By | SLA compliance, incident response time |

### Context

Dana works for an MSP managing email security for dozens of clients. Every minute spent on one client is a minute not spent on another. She needs efficiency tools: bulk operations, templates, quick context switching. She's evaluated on metrics, not effort.

### Goals

1. **Minimize per-tenant management time** to handle more clients
2. **Standardize security posture** across clients with policy templates
3. **Demonstrate value** to clients with professional reports
4. **Respond quickly** to incidents across any tenant

### Frustrations

| Frustration | Impact | Design Implication |
|-------------|--------|-------------------|
| Logging into each tenant separately | Wastes 5+ min per tenant | Single pane of glass |
| No bulk operations | Manual repetition | Bulk select, bulk actions |
| Inconsistent policies across clients | Security gaps, audit failures | Policy templates |
| Poor client-facing reports | Hard to justify fees | White-label PDF reports |
| No keyboard shortcuts | Slower workflows | Full keyboard navigation |

### Behaviors

- Uses keyboard shortcuts whenever available
- Switches between tenants constantly
- Creates templates and reuses them
- Documents everything for compliance
- Prioritizes by urgency, not by tenant

### Key Questions to Answer

1. Can Dana switch between tenants in under 1 second?
2. Can Dana apply a policy to 10 tenants at once?
3. Can Dana generate a branded report for a client meeting?
4. Can Dana find "all tenants with >10 threats today" instantly?

### Design Implications

| Requirement | Implementation |
|-------------|----------------|
| Instant tenant switching | Cmd+K command palette, <200ms switch |
| Policy templates | Create once, apply to many |
| Bulk operations | Multi-select, batch actions |
| Global search | Search across all tenants |
| White-label reports | PDF with MSP branding |
| Keyboard-first | Full keyboard navigation, shortcuts |

### Keyboard Shortcuts (Proposed)

| Shortcut | Action |
|----------|--------|
| `Cmd/Ctrl + K` | Global search |
| `Cmd/Ctrl + 1-9` | Switch to pinned tenant |
| `Cmd/Ctrl + T` | Tenant switcher |
| `Cmd/Ctrl + R` | Generate report |
| `Cmd/Ctrl + Q` | Go to quarantine |
| `Esc` | Back to overview |
| `j/k` | Navigate list |
| `Enter` | Open selected |
| `x` | Select item |
| `Shift + x` | Select range |

---

## Persona 3: End User "Taylor"
**Email Recipient**

### Profile

| Attribute | Value |
|-----------|-------|
| Role | Any employee (sales, marketing, finance, etc.) |
| Tech Expertise | Low to moderate |
| Security Awareness | Minimal |
| Interaction Frequency | Only when email is blocked |
| Primary Concern | Getting their email |

### Context

Taylor just wants email to work. They don't care about security architecture or threat detection. When a legitimate email is blocked, they're frustrated. When they receive a phishing email, they might not recognize it. They need protection without friction.

### Goals

1. **Receive all legitimate email** without delays
2. **Understand** why something was blocked (in plain English)
3. **Release** false positives quickly and easily
4. **Not feel guilty** when clicking "release"

### Frustrations

| Frustration | Impact | Design Implication |
|-------------|--------|-------------------|
| Missing important emails | Panic, complaints to IT | Clear quarantine notification |
| Jargon-filled explanations | Confusion, ignores warnings | Plain English only |
| Multi-step release process | Abandons, contacts IT | One-click release |
| Per-email notifications | Notification fatigue | Daily/weekly digest |
| Feeling blamed for clicking | Defensive, hides mistakes | Reassuring tone |

### Behaviors

- Panics when important email is missing
- Forwards quarantine notifications to IT
- Doesn't read long explanations
- Wants one-click resolution
- Learns from clear, brief feedback

### Key Questions to Answer

1. Can Taylor understand why their email was blocked without IT?
2. Can Taylor release a false positive in one click?
3. Will Taylor feel confident (not guilty) releasing an email?
4. Will Taylor be annoyed by too many notifications?

### Design Implications

| Requirement | Implementation |
|-------------|----------------|
| Plain English explanations | "This email claimed to be from your bank but wasn't" |
| One-click release | Big button, no confirmation modal |
| Digest notifications | Daily summary, not per-email |
| Reassuring tone | "We blocked this for your safety" not "You received a threat" |
| Feedback loop | Thumbs up/down after release |

### Quarantine Notification Template

**Bad Example**:
```
SECURITY ALERT: Message Quarantined

Message ID: ABC123
Reason: SPF_FAIL, DKIM_FAIL, DMARC_QUARANTINE
From: invoice@acme-payments.net
Subject: Your invoice is ready

Action Required: Review and release or delete.
```

**Good Example**:
```
An email to you was held for review

From: invoice@acme-payments.net
Subject: Your invoice is ready

Why it was held:
This email claims to be from Acme Corp but was sent from
an unverified server. Attackers sometimes impersonate
vendors to steal payment information.

[View Details]     [It's Safe - Release]

Not sure? Forward this to your IT team.
```

---

## Persona Interaction Map

```
┌─────────────────────────────────────────────────────────────────┐
│                    INTERACTION FREQUENCY                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Daily                                                          │
│    │                                                            │
│    │        ┌─────────┐                                         │
│    │        │  Dana   │ (MSP - managing many tenants)           │
│    │        │  Admin  │                                         │
│    │        └─────────┘                                         │
│    │                                                            │
│  Weekly                                                         │
│    │   ┌─────────┐                                              │
│    │   │ Marcus  │ (IT Admin - checking dashboard)              │
│    │   │  Admin  │                                              │
│    │   └─────────┘                                              │
│    │                                                            │
│  Rare (event-driven)                                            │
│    │              ┌─────────┐                                   │
│    │              │ Taylor  │ (End user - only when blocked)    │
│    │              │  User   │                                   │
│    │              └─────────┘                                   │
│    │                                                            │
│    └──────────────────────────────────────────────────────────► │
│                        Engagement Depth                         │
│        Shallow                                    Deep          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Design Priorities by Persona

### Must Have (All Personas)

| Feature | Marcus | Dana | Taylor |
|---------|--------|------|--------|
| Clear explanations | Critical | Important | Critical |
| Fast performance | Important | Critical | Important |
| Mobile support | Nice to have | Important | Critical |

### Marcus (IT Admin) Priorities

1. Self-service onboarding
2. Weekly summary reports
3. Executive-friendly dashboard
4. Easy quarantine review
5. Integration status visibility

### Dana (MSP Admin) Priorities

1. Instant tenant switching
2. Bulk operations
3. Policy templates
4. White-label reports
5. Keyboard shortcuts
6. Global search

### Taylor (End User) Priorities

1. Plain English notifications
2. One-click release
3. Digest (not per-email) notifications
4. Reassuring (not blaming) tone
5. Mobile-friendly quarantine review

---

## Testing with Personas

When testing new features, walk through as each persona:

### Marcus Test Questions
- Can I complete this in under 5 minutes?
- Will this make sense to my CEO?
- Will this generate help desk tickets?

### Dana Test Questions
- Can I do this with keyboard only?
- Can I do this for multiple tenants at once?
- Is there a shortcut for this?

### Taylor Test Questions
- Do I understand what's happening?
- Can I fix this in one click?
- Am I being blamed for something?
