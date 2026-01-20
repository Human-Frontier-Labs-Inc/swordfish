# Phase 5: Advanced Threat Detection

## Overview

**Goal**: Enhanced detection capabilities beyond basic threat intel
**Duration**: 1.5 weeks
**Score Impact**:
- vs Barracuda: 58 → 64 (+6)
- Innovation: 56 → 64 (+8)
- Production Readiness: 94 → 96 (+2)

## Why This Matters

This phase adds the sophisticated detection that separates enterprise solutions from basic email security:
- **URL Rewriting**: Click-time protection, not just scan-time
- **Lookalike Detection**: Catch sophisticated impersonation
- **NLP-Based BEC**: Understand attacker intent
- **Attachment Analysis**: Deep file inspection
- **Expanded Intel**: More sources = better coverage

## Slices

### Slice 5.1: URL Rewriting & Click Protection

**Goal**: Protect users at click time, not just delivery time

**User Story**:
> As an email user, I need protection when I click links, even if the link became malicious after the email was delivered.

**Acceptance Criteria**:
- [ ] Rewrite URLs in email body to route through proxy
- [ ] Preserve original URL for user transparency
- [ ] Scan URL at click time
- [ ] Redirect to warning page if malicious
- [ ] Track click analytics
- [ ] Handle URL shorteners (expand and check)
- [ ] Bypass for whitelisted domains
- [ ] Handle deep links and parameters

**URL Rewrite Format**:
```
Original: https://suspicious-site.com/login
Rewritten: https://protect.swordfish.io/click?
  url=https%3A%2F%2Fsuspicious-site.com%2Flogin
  &tid=tenant-123
  &mid=message-456
  &ts=1234567890
  &sig=hmac_signature
```

**Click Flow**:
```
User clicks rewritten link
    │
    ▼
Swordfish click endpoint
    │
    ├─► Extract original URL
    ├─► Verify signature (prevent tampering)
    ├─► Check URL against threat intel
    ├─► Check URL reputation
    │
    ├─► SAFE: Redirect to original URL
    │
    └─► MALICIOUS: Show warning page
            │
            ├─► "This link is potentially dangerous"
            ├─► Show threat details
            ├─► Option to proceed anyway (logged)
            └─► Option to report false positive
```

**Tests**:
```typescript
// tests/protection/url-rewriting.test.ts
describe('URL Rewriting', () => {
  it('should rewrite http URLs')
  it('should rewrite https URLs')
  it('should preserve query parameters')
  it('should handle URL encoding')
  it('should not rewrite whitelisted domains')
  it('should include HMAC signature')
  it('should verify signature on click')
  it('should reject tampered URLs')
});

describe('Click Protection', () => {
  it('should scan URL at click time')
  it('should redirect safe URLs')
  it('should block malicious URLs')
  it('should show warning page')
  it('should track click analytics')
  it('should expand shortened URLs')
  it('should handle redirect chains')
});
```

**Implementation**:
- `lib/protection/url-rewriter.ts`
- `lib/protection/click-scanner.ts`
- `app/api/v1/click/route.ts`
- `app/warning/page.tsx`

---

### Slice 5.2: Lookalike Domain Detection

**Goal**: Catch sophisticated domain impersonation

**User Story**:
> As a security analyst, I need to detect when attackers use domains that look similar to legitimate ones so that I can protect users from impersonation attacks.

**Detection Techniques**:
```
1. Homoglyph substitution:
   - rn → m (payrnent.com vs payment.com)
   - l → I (paypaI.com vs paypal.com)
   - 0 → o (g00gle.com vs google.com)

2. Character insertion/deletion:
   - googgle.com (extra g)
   - gogle.com (missing o)

3. Character transposition:
   - goolge.com (swapped o and l)

4. TLD variations:
   - google.co (vs .com)
   - google.net
   - google.io

5. Subdomain tricks:
   - google.com.malicious.com
   - login-google.com
```

**Acceptance Criteria**:
- [ ] Detect homoglyph substitutions
- [ ] Calculate Levenshtein distance
- [ ] Detect keyboard proximity typos
- [ ] Detect TLD swapping
- [ ] Extract brand names from domains
- [ ] Maintain protected domain registry
- [ ] Calculate similarity score (0-100)
- [ ] Generate explanation of detection

**Tests**:
```typescript
// tests/detection/lookalike.test.ts
describe('Lookalike Domain Detection', () => {
  it('should detect homoglyph substitution')
  it('should detect character insertion')
  it('should detect character deletion')
  it('should detect character transposition')
  it('should detect TLD swap')
  it('should detect subdomain tricks')
  it('should calculate similarity score')
  it('should compare against protected domains')
  it('should explain detection reason')
});
```

**Implementation**:
- `lib/detection/lookalike.ts`
- `lib/detection/homoglyphs.ts`
- `lib/detection/levenshtein.ts`

---

### Slice 5.3: NLP-Based BEC Detection

**Goal**: Understand email intent using natural language processing

**User Story**:
> As a security analyst, I need to detect BEC attacks based on the language and intent of emails, not just technical indicators.

**BEC Patterns to Detect**:
```
1. Urgency signals:
   - "urgent", "immediately", "ASAP", "time-sensitive"
   - "before end of day", "within the hour"

2. Financial requests:
   - "wire transfer", "bank account", "payment"
   - "invoice attached", "update payment details"

3. Credential harvesting:
   - "verify your account", "confirm your password"
   - "click here to login", "security alert"

4. Authority impersonation:
   - "As per CEO", "at John's request"
   - "I'm in a meeting", "can't talk right now"

5. Pressure tactics:
   - "Don't tell anyone", "keep this confidential"
   - "I trust you to handle this"
```

**Acceptance Criteria**:
- [ ] Extract urgency signals
- [ ] Detect financial requests
- [ ] Detect credential requests
- [ ] Detect wire transfer requests
- [ ] Detect authority impersonation language
- [ ] Detect pressure tactics
- [ ] Calculate BEC confidence score
- [ ] Generate detailed explanation

**Tests**:
```typescript
// tests/detection/nlp-bec.test.ts
describe('NLP-Based BEC Detection', () => {
  it('should detect urgency language')
  it('should detect financial request')
  it('should detect credential request')
  it('should detect wire transfer request')
  it('should detect authority impersonation')
  it('should detect pressure tactics')
  it('should calculate confidence score')
  it('should handle multiple languages')
  it('should generate explanation')
});
```

**Implementation**:
- `lib/detection/nlp-bec.ts`
- `lib/detection/intent-classifier.ts`
- `lib/detection/patterns.ts`

---

### Slice 5.4: Attachment Analysis

**Goal**: Deep inspection of email attachments

**User Story**:
> As a security analyst, I need to analyze email attachments for malicious content beyond just virus signatures.

**Analysis Techniques**:
```
1. File type detection:
   - Magic byte analysis (don't trust extension)
   - Detect double extensions (.pdf.exe)

2. Document analysis:
   - Macro detection in Office docs
   - Embedded object detection
   - Hidden content extraction

3. URL extraction:
   - Links in documents
   - QR codes in images
   - Embedded URLs in PDFs

4. Archive inspection:
   - Recursive zip/rar extraction
   - Password-protected detection
   - Zip bombs detection

5. Executable detection:
   - PE headers
   - Script files (.js, .vbs, .ps1)
   - Batch files
```

**Acceptance Criteria**:
- [ ] Detect file type from magic bytes
- [ ] Detect macro-enabled documents
- [ ] Extract embedded URLs
- [ ] Detect password-protected archives
- [ ] Inspect archive contents recursively
- [ ] Detect executable content
- [ ] Calculate attachment risk score
- [ ] Handle large files efficiently

**Tests**:
```typescript
// tests/detection/attachment-analysis.test.ts
describe('Attachment Analysis', () => {
  it('should detect file type from magic bytes')
  it('should detect mismatched extension')
  it('should detect macros in docx')
  it('should detect macros in xlsx')
  it('should extract URLs from PDF')
  it('should detect password-protected zip')
  it('should inspect nested archives')
  it('should detect zip bombs')
  it('should detect executables')
  it('should calculate risk score')
});
```

**Implementation**:
- `lib/detection/attachment-analyzer.ts`
- `lib/detection/file-inspector.ts`
- `lib/detection/magic-bytes.ts`

---

### Slice 5.5: Threat Intel Expansion

**Goal**: More intelligence sources for better coverage

**User Story**:
> As a security analyst, I need comprehensive threat intelligence from multiple sources so that we catch threats other vendors might miss.

**Additional Sources**:
```
Current:
- PhishTank
- URLhaus
- OpenPhish

Adding:
- VirusTotal (URL/file reputation)
- AlienVault OTX (threat indicators)
- abuse.ch (malware feeds)
- Spamhaus (IP/domain blocklists)
```

**Acceptance Criteria**:
- [ ] VirusTotal URL lookup
- [ ] VirusTotal file hash lookup
- [ ] AlienVault OTX pulse search
- [ ] abuse.ch malware feeds
- [ ] Aggregate across all feeds
- [ ] Deduplicate indicators
- [ ] Track feed freshness
- [ ] Weight confidence by source

**Tests**:
```typescript
// tests/threat-intel/expanded-feeds.test.ts
describe('Expanded Threat Intel', () => {
  describe('VirusTotal', () => {
    it('should lookup URL reputation')
    it('should lookup file hash')
    it('should handle rate limiting')
    it('should cache results')
  });

  describe('AlienVault OTX', () => {
    it('should search pulses for indicator')
    it('should extract related indicators')
  });

  describe('abuse.ch', () => {
    it('should fetch malware URL list')
    it('should fetch file hash list')
  });

  describe('Aggregation', () => {
    it('should aggregate across sources')
    it('should deduplicate indicators')
    it('should weight by confidence')
  });
});
```

**Implementation**:
- `lib/threat-intel/virustotal.ts`
- `lib/threat-intel/alienvault.ts`
- `lib/threat-intel/abusech.ts`
- `lib/threat-intel/aggregator.ts`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                 Advanced Threat Detection Pipeline               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Email Received                                                 │
│        │                                                         │
│   ┌────┴────────────────────────────────────────┐               │
│   │                                              │               │
│   ▼                                              ▼               │
│ ┌──────────────┐                         ┌──────────────┐       │
│ │     URL      │                         │  Attachment  │       │
│ │  Processing  │                         │   Analysis   │       │
│ └──────┬───────┘                         └──────┬───────┘       │
│        │                                        │               │
│   ┌────┴────┐                            ┌─────┴─────┐          │
│   │         │                            │           │          │
│   ▼         ▼                            ▼           ▼          │
│ ┌─────┐ ┌────────┐                 ┌──────────┐ ┌────────┐     │
│ │Scan │ │Rewrite │                 │File Type │ │Content │     │
│ └──┬──┘ └────┬───┘                 │Detection │ │Analysis│     │
│    │         │                     └────┬─────┘ └────┬───┘     │
│    │         │                          │            │          │
│    │         │                     ┌────┴────────────┴────┐     │
│    │         │                     │    Macro/URL/Exec    │     │
│    │         │                     │      Detection       │     │
│    │         │                     └──────────┬───────────┘     │
│    │         │                                │                 │
│    └─────────┼────────────────────────────────┘                 │
│              │                                                   │
│         ┌────▼────┐                                             │
│         │Lookalike│                                             │
│         │Detection│                                             │
│         └────┬────┘                                             │
│              │                                                   │
│         ┌────▼────┐                                             │
│         │   NLP   │                                             │
│         │   BEC   │                                             │
│         └────┬────┘                                             │
│              │                                                   │
│         ┌────▼────┐     ┌─────────────────────────────────┐    │
│         │ Threat  │◄────│  VirusTotal | OTX | abuse.ch   │    │
│         │  Intel  │     │  PhishTank | URLhaus | OpenPhish│    │
│         └────┬────┘     └─────────────────────────────────┘    │
│              │                                                   │
│         ┌────▼────┐                                             │
│         │  Risk   │                                             │
│         │ Scoring │                                             │
│         └─────────┘                                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Success Metrics

| Metric | Before | After |
|--------|--------|-------|
| vs Barracuda | 58 | 64 |
| Innovation | 56 | 64 |
| Production Readiness | 94 | 96 |
| Test Count | 1,730 | 1,850 |
| Detection Techniques | Basic | Advanced (URL rewrite, NLP, attachment) |
