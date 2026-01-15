# User Journeys

## Overview

This document maps the key user journeys through Swordfish, including emotional states at each touchpoint. Use these maps to identify friction points and opportunities for delight.

---

## Journey 1: Direct Customer Onboarding (O365)

**Persona**: Marcus (IT Admin)
**Goal**: Connect O365 tenant and start protection in <10 minutes
**Success Criteria**: Protection active, first threat visible in dashboard

### Emotional Journey Graph

```
Emotion
   +3  |                                    *
   +2  |        *                       *      *
   +1  |    *       *   *           *
    0  |*
   -1  |                    *   *
   -2  |
       └──────────────────────────────────────────
        A   B   C   D   E   F   G   H   I   J   K

A: Landing page         G: Authorize Graph API
B: Sign up (Clerk)      H: Wait for sync
C: Choose plan          I: First threats detected
D: Select integration   J: Review dashboard
E: Enter tenant domain  K: Protection active!
F: Admin consent flow
```

### Detailed Journey Map

#### Stage 1: Awareness (Touchpoint A)
**Goal**: Understand what Swordfish does

| Aspect | Detail |
|--------|--------|
| **Touchpoint** | Landing page |
| **Action** | Read value proposition |
| **Emotion** | 0 (Neutral) - evaluating |
| **Thoughts** | "Is this better than what I have?" |
| **Pain Points** | Generic security claims, no proof |
| **Opportunities** | Show live threat counter, customer logos |

**Design Requirements**:
- Clear headline: "Email security that explains itself"
- Live metric: "X threats blocked today"
- Social proof: customer logos or testimonials
- One CTA: "Start Free Trial"

---

#### Stage 2: Sign Up (Touchpoint B)
**Goal**: Create account quickly

| Aspect | Detail |
|--------|--------|
| **Touchpoint** | Clerk sign-up |
| **Action** | Enter email, create password (or SSO) |
| **Emotion** | +1 (Hopeful) - taking action |
| **Thoughts** | "Hope this doesn't take forever" |
| **Pain Points** | Yet another account to manage |
| **Opportunities** | Microsoft/Google SSO (one-click) |

**Design Requirements**:
- Prominent "Sign in with Microsoft" button
- Prominent "Sign in with Google" button
- Email/password as fallback
- Progress indicator: "Step 1 of 4"

---

#### Stage 3: Plan Selection (Touchpoint C)
**Goal**: Choose appropriate tier

| Aspect | Detail |
|--------|--------|
| **Touchpoint** | Pricing page |
| **Action** | Review plans, select one |
| **Emotion** | +2 (Confident) - clear options |
| **Thoughts** | "This is straightforward" |
| **Pain Points** | Hidden costs, "contact sales" gates |
| **Opportunities** | Transparent pricing, feature comparison |

**Design Requirements**:
- 3 plans max (Starter, Pro, Enterprise)
- Clear feature comparison table
- No hidden fees
- "Start free, upgrade anytime"

---

#### Stage 4: Integration Selection (Touchpoint D)
**Goal**: Choose email provider to connect

| Aspect | Detail |
|--------|--------|
| **Touchpoint** | Integration picker |
| **Action** | Select O365, Gmail, or SMTP |
| **Emotion** | +1 (Progressing) - making progress |
| **Thoughts** | "Okay, here we go" |
| **Pain Points** | Fear of complexity |
| **Opportunities** | "Takes 3 minutes" reassurance |

**Design Requirements**:
- Large, clear icons for each provider
- Time estimate: "~3 minutes"
- "Not sure? We can help" chat option

---

#### Stage 5: Tenant Configuration (Touchpoint E)
**Goal**: Enter tenant details

| Aspect | Detail |
|--------|--------|
| **Touchpoint** | Tenant input form |
| **Action** | Enter domain or tenant ID |
| **Emotion** | +1 (Engaged) - inputting data |
| **Thoughts** | "What's my tenant ID again?" |
| **Pain Points** | Not knowing tenant ID |
| **Opportunities** | Auto-detect from SSO, helpful tooltip |

**Design Requirements**:
- Auto-detect tenant from Microsoft SSO if used
- Clear example: "e.g., contoso.com or contoso.onmicrosoft.com"
- "How to find your tenant ID" expandable help
- Validation as they type

---

#### Stage 6: Admin Consent (Touchpoint F-G)
**Goal**: Authorize API access
**CRITICAL MOMENT - Highest anxiety point**

| Aspect | Detail |
|--------|--------|
| **Touchpoint** | Microsoft consent screen |
| **Action** | Review permissions, click "Accept" |
| **Emotion** | -1 (Anxious) - scary permissions list |
| **Thoughts** | "What am I giving them access to?" |
| **Pain Points** | Microsoft's scary permission descriptions |
| **Opportunities** | Pre-explain each permission in plain English |

**Design Requirements**:

**Before redirect to Microsoft**:
```
┌─────────────────────────────────────────────────────────────────┐
│  We need permission to protect your email                       │
│                                                                 │
│  You'll be asked to approve these permissions:                  │
│                                                                 │
│  ✓ Read email                                                   │
│    So we can scan incoming messages for threats                 │
│                                                                 │
│  ✓ Move email to folders                                        │
│    So we can quarantine suspicious messages                     │
│                                                                 │
│  ✓ Delete email                                                 │
│    So we can remove confirmed malware (with your approval)      │
│                                                                 │
│  We never:                                                      │
│  ✗ Read email content after scanning                            │
│  ✗ Store email bodies long-term                                 │
│  ✗ Share data with third parties                                │
│                                                                 │
│  [Continue to Microsoft →]                                      │
│                                                                 │
│  Questions? Chat with us                                        │
└─────────────────────────────────────────────────────────────────┘
```

---

#### Stage 7: Sync Wait (Touchpoint H)
**Goal**: Wait for initial email scan
**Emotional dip - impatience risk**

| Aspect | Detail |
|--------|--------|
| **Touchpoint** | Sync progress screen |
| **Action** | Wait while emails are scanned |
| **Emotion** | -1 (Impatient) - waiting |
| **Thoughts** | "How long is this going to take?" |
| **Pain Points** | Unknown duration, nothing to do |
| **Opportunities** | Real-time progress, early value |

**Design Requirements**:
```
┌─────────────────────────────────────────────────────────────────┐
│  Scanning your mailboxes...                                     │
│                                                                 │
│  ████████████████░░░░░░░░░░░░░░ 45%                             │
│                                                                 │
│  📧 1,247 emails scanned                                        │
│  🛡️ 3 threats found so far                                     │
│  ⏱️ ~2 minutes remaining                                        │
│                                                                 │
│  ─────────────────────────────────────────────────────          │
│                                                                 │
│  While you wait:                                                │
│  [Set up your team] [Customize policies] [Read the guide]       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

#### Stage 8: First Threat (Touchpoint I)
**Goal**: See system working
**CRITICAL MOMENT - Trust builder or breaker**

| Aspect | Detail |
|--------|--------|
| **Touchpoint** | First threat notification |
| **Action** | Review detected threat |
| **Emotion** | +2 (Relieved) - system is working |
| **Thoughts** | "Good thing I set this up" |
| **Pain Points** | Might be false positive |
| **Opportunities** | Clear explanation, confidence indicator |

**Design Requirements**:
- Show threat with high confidence first
- Clear, jargon-free explanation
- "Why we blocked this" expandable section
- Don't show borderline cases first

---

#### Stage 9: Dashboard Review (Touchpoint J)
**Goal**: Explore the dashboard

| Aspect | Detail |
|--------|--------|
| **Touchpoint** | Main dashboard |
| **Action** | Explore features |
| **Emotion** | +3 (Delighted) - this looks good |
| **Thoughts** | "This is exactly what I needed" |
| **Pain Points** | Overwhelm from too many features |
| **Opportunities** | Progressive disclosure, guided tour |

**Design Requirements**:
- Start with overview, not detailed data
- Highlight key metrics: "3 threats blocked, 0 false positives"
- Optional guided tour (dismissible)
- Empty states with helpful CTAs

---

#### Stage 10: Protection Active (Touchpoint K)
**Goal**: Confirm setup is complete

| Aspect | Detail |
|--------|--------|
| **Touchpoint** | Success confirmation |
| **Action** | See "Protected" status |
| **Emotion** | +3 (Confident) - done! |
| **Thoughts** | "That was easier than expected" |
| **Pain Points** | Uncertainty if it's really working |
| **Opportunities** | Clear confirmation, next steps |

**Design Requirements**:
```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│              ✓ Your organization is protected                   │
│                                                                 │
│  Office 365 connected                         Active            │
│  47 mailboxes protected                                         │
│  3 threats blocked in initial scan                              │
│                                                                 │
│  What happens next:                                             │
│  • Incoming emails are now being scanned                        │
│  • Threats will be quarantined automatically                    │
│  • You'll get a weekly summary every Monday                     │
│                                                                 │
│  [Go to Dashboard]                                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Journey 2: MSP Multi-Tenant Management

**Persona**: Dana (MSP Admin)
**Goal**: Efficiently manage threats across multiple client tenants
**Success Criteria**: Handle 10 tenants in under 15 minutes

### Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  SWORDFISH                    [🔍 Cmd+K]         Dana @ MSP.io  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  TENANTS                    │  ACTIVE: Acme Corp               │
│  ─────────────────          │  ──────────────────────────────  │
│  ● Acme Corp      3 ⚠️      │                                   │
│  ○ Beta LLC                 │  Threats Today: 3                 │
│  ○ Gamma Inc      1 ⚠️      │  Quarantine: 2 pending            │
│  ○ Delta Co                 │  Status: All integrations OK      │
│  ○ Echo Ltd                 │                                   │
│                             │  ┌─────────────────────────────┐  │
│  [+ Add Tenant]             │  │ THREAT INBOX               │  │
│                             │  │                             │  │
│  ─────────────────          │  │ ☐ invoice@fake.com         │  │
│  QUICK ACTIONS              │  │   Phishing - 95% conf      │  │
│  [📊 Report]                │  │   "Wire transfer request"  │  │
│  [⚙️ Templates]             │  │                             │  │
│  [📋 Audit Log]             │  │ ☐ support@scam.net         │  │
│                             │  │   BEC - 87% conf           │  │
│                             │  │   "Update payment info"    │  │
│                             │  │                             │  │
│                             │  │ ☐ newsletter@legit.com     │  │
│                             │  │   Spam - 72% conf          │  │
│                             │  │   "Weekly digest"          │  │
│                             │  └─────────────────────────────┘  │
│                             │                                   │
│                             │  [Block Selected] [Release] [More]│
│                             │                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Key Interactions

#### Tenant Switching
**Speed requirement**: <200ms

| Action | Shortcut | Result |
|--------|----------|--------|
| Open switcher | `Cmd+T` | Tenant list with search |
| Quick switch | `Cmd+1` through `Cmd+9` | Jump to pinned tenant |
| Search tenants | `Cmd+K` then type | Filter all tenants |
| Return to overview | `Esc` | Back to multi-tenant view |

#### Bulk Operations

```
Select multiple threats:
1. Click first checkbox
2. Shift+click last checkbox (range select)
3. Or Cmd+click for individual selection

Bulk actions available:
• Block all selected
• Release all selected
• Add sender to blocklist
• Add sender to allowlist
• Export for report
```

#### Global Search (Cmd+K)

```
┌─────────────────────────────────────────────────────────────────┐
│  🔍  Search across all tenants...                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  RECENT                                                         │
│  └─ "wire transfer" in Acme Corp                                │
│  └─ invoice@suspicious.com                                      │
│                                                                 │
│  COMMANDS                                                       │
│  └─ Go to Acme Corp                                             │
│  └─ Generate report for all tenants                             │
│  └─ View audit log                                              │
│                                                                 │
│  QUICK FILTERS                                                  │
│  └─ All tenants with pending quarantine                         │
│  └─ All tenants with integration issues                         │
│  └─ All threats in last 24 hours                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Journey Stages

| Stage | Action | Emotion | Design Requirement |
|-------|--------|---------|-------------------|
| Login | Authenticate | +1 | Remember last context |
| Overview | See all tenants | +2 | Threat badges visible |
| Triage | Notice Acme has 3 threats | 0 | Red badge with count |
| Switch | Click Acme Corp | +1 | <200ms switch |
| Investigate | Review first threat | +2 | Full context visible |
| Action | Quarantine threat | +2 | One-click action |
| Bulk | Select remaining 2 | +1 | Shift+click range |
| Bulk Action | Block all selected | +2 | Single confirmation |
| Document | Add to report | +1 | One-click "Add to report" |
| Switch Back | Return to overview | +1 | Esc key |
| Report | Generate PDF | +2 | Client-ready in 1 click |

---

## Journey 3: End User Quarantine Release

**Persona**: Taylor (End User)
**Goal**: Understand why email was blocked and release if legitimate
**Success Criteria**: Release decision in <30 seconds, no IT ticket

### Notification Flow

#### Email Notification (Daily Digest)

```
┌─────────────────────────────────────────────────────────────────┐
│  Subject: Your daily email security summary - 2 items held      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  2 emails were held for your review                             │
│                                                                 │
│  ─────────────────────────────────────────────────────────────  │
│                                                                 │
│  1. From: invoice@acme-payments.net                             │
│     Subject: Your invoice is ready                              │
│     Held because: This email claims to be from Acme Corp        │
│     but was sent from an unverified server.                     │
│                                                                 │
│     [View] [Release - It's Safe]                                │
│                                                                 │
│  ─────────────────────────────────────────────────────────────  │
│                                                                 │
│  2. From: hr@company-benefits.com                               │
│     Subject: Update your benefits enrollment                    │
│     Held because: This sender has never emailed you before      │
│     and the link goes to an unusual website.                    │
│                                                                 │
│     [View] [Release - It's Safe]                                │
│                                                                 │
│  ─────────────────────────────────────────────────────────────  │
│                                                                 │
│  Questions? Reply to this email for help.                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Release Flow (Web Interface)

```
┌─────────────────────────────────────────────────────────────────┐
│  Email Details                                    [← Back]      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  From: invoice@acme-payments.net                                │
│  To: taylor@company.com                                         │
│  Subject: Your invoice is ready                                 │
│  Received: Today at 2:34 PM                                     │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  WHY THIS WAS HELD                                       │   │
│  │                                                          │   │
│  │  ⚠️ Unverified sender                                    │   │
│  │  This email claims to be from Acme Corp but was sent     │   │
│  │  from a server that isn't authorized to send on their    │   │
│  │  behalf.                                                 │   │
│  │                                                          │   │
│  │  What this could mean:                                   │   │
│  │  • Someone is pretending to be Acme Corp                 │   │
│  │  • Acme Corp's email isn't configured correctly          │   │
│  │                                                          │   │
│  │  If you're expecting an invoice from Acme Corp,          │   │
│  │  contact them directly to verify.                        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    EMAIL PREVIEW                         │   │
│  │  ─────────────────────────────────────────────────────   │   │
│  │  Hi Taylor,                                              │   │
│  │                                                          │   │
│  │  Your invoice #12345 is ready. Please click below        │   │
│  │  to view and pay:                                        │   │
│  │                                                          │   │
│  │  [View Invoice] ← Link goes to: acme-payments.net/inv... │   │
│  │                                                          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                                                          │   │
│  │  [Delete - Not Safe]        [Release - It's Safe]        │   │
│  │                                                          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Not sure? Ask your IT team or reply to this email.             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Post-Release Feedback

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  ✓ Email released                                               │
│                                                                 │
│  The email has been delivered to your inbox.                    │
│                                                                 │
│  Was this helpful?                                              │
│  [👍 Yes, good catch]  [👎 Shouldn't have been held]            │
│                                                                 │
│  [Close]                                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Journey Stages

| Stage | Action | Emotion | Design Requirement |
|-------|--------|---------|-------------------|
| Notification | Receive daily digest | -1 (Mild annoyance) | Batch, don't spam |
| Scan | Look for expected email | 0 (Neutral) | Bold sender names |
| Read | Understand why held | +1 (Informed) | Plain English |
| Preview | View email content | 0 (Evaluating) | Safe preview mode |
| Decide | Determine if legitimate | 0 (Thinking) | Clear guidance |
| Release | Click release button | +1 (Relieved) | One click, immediate |
| Confirm | See success message | +2 (Satisfied) | Clear confirmation |
| Feedback | Rate the experience | +1 (Helpful) | Optional, simple |

---

## Critical Moments Summary

### High-Impact Touchpoints

| Journey | Moment | Risk | Mitigation |
|---------|--------|------|------------|
| Onboarding | Admin consent | Abandonment (30%) | Pre-explain permissions |
| Onboarding | Wait for sync | Impatience | Real-time progress |
| Onboarding | First threat | Trust erosion if FP | Show high-confidence first |
| MSP | Tenant switch | Frustration | <200ms, keyboard |
| End User | Explanation | Confusion | Plain English only |
| End User | Release button | Hesitation | One click, no modal |

### Emotional Peaks to Engineer

1. **Onboarding**: "Protection Active" confirmation
2. **MSP**: First bulk action saving time
3. **End User**: Understanding why something was blocked

### Emotional Valleys to Fix

1. **Onboarding**: Microsoft consent screen
2. **Onboarding**: Waiting for sync
3. **End User**: Receiving too many notifications
