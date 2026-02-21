# Swordfish Email Processing - State Machine Diagram

## System Component Overview

```
+------------------+     +-------------------+     +------------------+
|   Gmail Inbox    |     |  Google Pub/Sub   |     |    Vercel App    |
|  (User's email)  |---->|   (Push notify)   |---->| (Webhook handler)|
+------------------+     +-------------------+     +------------------+
                                                           |
                                                           v
+------------------+     +-------------------+     +------------------+
|  Gmail API       |<----|   Remediation     |<----|  Detection       |
|  (Label modify)  |     |   Worker          |     |  Pipeline        |
+------------------+     +-------------------+     +------------------+
                                                           |
                                                           v
+------------------+     +-------------------+     +------------------+
| Swordfish/       |     |   threats         |     | email_verdicts   |
| Quarantine Label |     |   (DB table)      |     | (DB table)       |
+------------------+     +-------------------+     +------------------+
```

## Email State Machine

```
                            NEW EMAIL ARRIVES IN GMAIL
                                      |
                                      v
                    +----------------------------------+
                    |  Google Pub/Sub Push Notification |
                    |  POST /api/webhooks/gmail        |
                    +----------------------------------+
                                      |
                                      v
                    +----------------------------------+
                    |  1. Validate Pub/Sub signature    |
                    |  2. Decode notification           |
                    |  3. Find integration by email     |
                    +----------------------------------+
                                      |
                                      v
                    +----------------------------------+
                    |  Fetch Gmail History (new msgs)   |
                    |  getGmailHistory(historyId)       |
                    +----------------------------------+
                                      |
                              FOR EACH MESSAGE
                                      |
                                      v
                    +----------------------------------+
                    |  Fetch Full Message via Gmail API |
                    |  getGmailMessage(messageId)       |
                    +----------------------------------+
                                      |
                                      v
                    +----------------------------------+
                    |  Parse Email Content              |
                    |  parseGmailEmail(message)         |
                    +----------------------------------+
                                      |
                                      v
                +===========================================+
                |        DETECTION PIPELINE                 |
                |   analyzeEmail(email, tenantId)           |
                |                                           |
                |  PHASE A: Policy Check (EARLY EXIT)       |
                |  +---------------------------------+      |
                |  | evaluatePolicies(email, tenant) |      |
                |  |                                 |      |
                |  | Allowlist? --> PASS (score=0)  -----> SKIP ALL
                |  | Blocklist? --> BLOCK (score=100) ---> SKIP ALL
                |  | Custom policy? --> apply rule    |      |
                |  +---------------------------------+      |
                |                                           |
                |  PHASE B: Parallel Analysis               |
                |  +------------+ +----------+ +---------+  |
                |  |Deterministic| |Reputation| |  BEC    |  |
                |  |Rules (29%) | |Check(17%)| |Det(20%) |  |
                |  |SPF/DKIM/   | |Domain age| |Exec     |  |
                |  |DMARC,URLs  | |Trust scr | |imperson |  |
                |  |Homoglyph   | |Known bad | |Wire xfer|  |
                |  +------------+ +----------+ +---------+  |
                |                                           |
                |  PHASE C: Sequential Analysis             |
                |  +------------+ +----------+ +---------+  |
                |  |ML Classify | |Lookalike | |  LLM    |  |
                |  |(17%)       | |Domain    | |Analysis |  |
                |  |Phish/BEC/  | |Homoglyph | |(12%)    |  |
                |  |Malware/Spam| |Typosquat | |Context  |  |
                |  +------------+ +----------+ +---------+  |
                |                                           |
                |  PHASE D: Score Calculation                |
                |  +--------------------------------------+ |
                |  | Weighted avg of all layer scores     | |
                |  | + Critical signal boost (0-20 pts)   | |
                |  | + Warning signal boost (0-10 pts)    | |
                |  | + Synergy bonus (0-8 pts)            | |
                |  |                                      | |
                |  | DAMPENING MODIFIERS:                  | |
                |  | - Trusted sender: up to -50%         | |
                |  | - Marketing email: -30%              | |
                |  | - Institutional domain: -50%         | |
                |  | - Thread reply: -40%                 | |
                |  | - User feedback: -30%                | |
                |  +--------------------------------------+ |
                |                                           |
                |  PHASE E: Verdict Determination            |
                |  +--------------------------------------+ |
                |  |  Score >= 85  --> BLOCK              | |
                |  |  Score 55-84  --> QUARANTINE         | |
                |  |  Score 35-54  --> SUSPICIOUS         | |
                |  |  Score < 35   --> PASS               | |
                |  +--------------------------------------+ |
                +===========================================+
                                      |
                                      v
                    +----------------------------------+
                    |  Store verdict in email_verdicts  |
                    |  storeVerdict(tenant, msgId, ...)  |
                    +----------------------------------+
                                      |
                          +-----------+-----------+
                          |                       |
                    PASS/SUSPICIOUS         QUARANTINE/BLOCK
                          |                       |
                          v                       v
                +------------------+   +-------------------------+
                | NO ACTION        |   | autoRemediate()         |
                | Email stays in   |   |                         |
                | Gmail INBOX      |   | 1. Create threat record |
                | (as-is)          |   |    in threats table     |
                +------------------+   |                         |
                                       | 2. Send notification    |
                                       |                         |
                                       | 3. Gmail API call:      |
                                       |    - ADD label:         |
                                       |      Swordfish/Quarantine|
                                       |    - REMOVE label:      |
                                       |      INBOX              |
                                       +-------------------------+
                                                  |
                                                  v
                                       +-------------------------+
                                       |  Email now in           |
                                       |  Swordfish/Quarantine   |
                                       |  label (not in INBOX)   |
                                       +-------------------------+
                                                  |
                                    +-------------+-------------+
                                    |                           |
                              USER: RELEASE              USER: DELETE
                                    |                           |
                                    v                           v
                          +------------------+    +------------------+
                          | POST /api/threats|    | DELETE /api/     |
                          |  /{id}/release   |    | threats/{id}     |
                          +------------------+    +------------------+
                                    |                           |
                                    v                           v
                          +------------------+    +------------------+
                          | Gmail API:       |    | Gmail API:       |
                          | ADD: INBOX       |    | Permanently      |
                          | REMOVE: Quarantine|    | delete message   |
                          +------------------+    +------------------+
                                    |                           |
                                    v                           v
                          +------------------+    +------------------+
                          | threats.status = |    | threats.status = |
                          | 'released'       |    | 'deleted'        |
                          +------------------+    +------------------+
```

## Threat Record State Machine

```
                    +-------------------+
                    |     (no record)   |
                    +-------------------+
                              |
                    Email gets verdict
                    quarantine or block
                              |
                              v
                    +-------------------+
                    |   QUARANTINED     |
                    |                   |
                    | - In threats table|
                    | - Gmail: labeled  |
                    |   Swordfish/      |
                    |   Quarantine      |
                    | - Removed from    |
                    |   INBOX           |
                    +-------------------+
                         /         \
                   Release        Delete
                       /             \
                      v               v
          +-------------------+  +-------------------+
          |    RELEASED       |  |     DELETED       |
          |                   |  |                   |
          | - Gmail: back in  |  | - Gmail: message  |
          |   INBOX           |  |   permanently     |
          | - Quarantine label|  |   deleted          |
          |   removed         |  |                   |
          | - Optional: add   |  |                   |
          |   to allowlist    |  |                   |
          +-------------------+  +-------------------+
```

## Database Tables & Their Roles

```
+-------------------+     +-------------------+     +-------------------+
|  integrations     |     |  email_verdicts   |     |    threats        |
|                   |     |                   |     |                   |
| - tenant_id       |     | - tenant_id       |     | - tenant_id       |
| - type (gmail/o365)|    | - message_id      |     | - message_id      |
| - connected_email |     | - verdict         |     | - verdict         |
| - status          |     | - score           |     | - score           |
| - oauth tokens    |     | - signals[]       |     | - status          |
| - config (historyId)|   | - from/to/subject |     |   (quarantined/   |
|                   |     | - processing_time |     |    released/      |
| ONE PER MAILBOX   |     |                   |     |    deleted)       |
| Links tenant to   |     | ALL SCANNED EMAILS|     |                   |
| their Gmail       |     | (pass, suspicious,|     | ONLY QUARANTINED/ |
|                   |     |  quarantine, block)|    | BLOCKED EMAILS    |
+-------------------+     +-------------------+     +-------------------+
        |                         |                         |
        |   +-------------------+ |                         |
        +-->|   oauth_states    | |   +-------------------+ |
            | - CSRF protection | +-->|   list_entries    |<+
            | - PKCE codes      |     | - allowlist       |
            +-------------------+     | - blocklist       |
                                      +-------------------+
                                              |
                                      +-------------------+
                                      |    policies       |
                                      | - custom rules    |
                                      | - conditions      |
                                      | - actions         |
                                      +-------------------+
```

## Key Data Flow Paths

### Path 1: Safe Email (Score < 35)
```
Gmail --> Webhook --> Detection Pipeline --> verdict: PASS
  --> Store in email_verdicts (verdict='pass')
  --> NO remediation
  --> Email stays in Gmail INBOX
```

### Path 2: Suspicious Email (Score 35-54)
```
Gmail --> Webhook --> Detection Pipeline --> verdict: SUSPICIOUS
  --> Store in email_verdicts (verdict='suspicious')
  --> NO remediation (no Gmail label change)
  --> Email stays in Gmail INBOX
```

### Path 3: Quarantined Email (Score 55-84)
```
Gmail --> Webhook --> Detection Pipeline --> verdict: QUARANTINE
  --> Store in email_verdicts (verdict='quarantine')
  --> Create threats record (status='quarantined')
  --> autoRemediate() --> Gmail API: move to Swordfish/Quarantine label
  --> Email REMOVED from INBOX
```

### Path 4: Blocked Email (Score >= 85)
```
Gmail --> Webhook --> Detection Pipeline --> verdict: BLOCK
  --> Store in email_verdicts (verdict='block')
  --> Create threats record (status='quarantined')
  --> autoRemediate() --> Gmail API: move to Swordfish/Quarantine label
  --> Email REMOVED from INBOX
```

### Path 5: Allowlisted Sender
```
Gmail --> Webhook --> Detection Pipeline
  --> Policy check: sender in allowlist
  --> EARLY EXIT: verdict=PASS, score=0
  --> Store in email_verdicts
  --> NO remediation
  --> Email stays in INBOX
```

### Path 6: Blocklisted Sender
```
Gmail --> Webhook --> Detection Pipeline
  --> Policy check: sender in blocklist
  --> EARLY EXIT: verdict=BLOCK, score=100
  --> Store in email_verdicts + threats record
  --> autoRemediate() --> Gmail API: move to quarantine label
  --> Email REMOVED from INBOX
```

## Scoring Layer Weights

```
  Deterministic ████████████████████████████░ 29%  (SPF/DKIM/DMARC, URLs, headers)
  BEC Detection ████████████████████░░░░░░░░░ 20%  (Executive impersonation, wire xfer)
  Reputation    █████████████████░░░░░░░░░░░░ 17%  (Domain age, known bad, trust score)
  ML Classify   █████████████████░░░░░░░░░░░░ 17%  (Trained phishing/malware model)
  LLM Analysis  ████████████░░░░░░░░░░░░░░░░░ 12%  (AI contextual, only if uncertain)
  Sandbox       █████░░░░░░░░░░░░░░░░░░░░░░░░  5%  (Attachment behavior analysis)
```

## Known Issues

1. **Neon DB quota exceeded (HTTP 402)** - Webhooks fail silently, no emails processed
2. **Score boosting too aggressive** - criticalBoost adds 7-28 pts from normal email signals
3. **Dampening can stack** - trusted + institutional + thread = up to 85% reduction
4. **Sandbox weight too low** - Malware in attachment only contributes 5% to score
5. **No behavioral anomaly detection** - Known sender suddenly phishing gets trust dampening
