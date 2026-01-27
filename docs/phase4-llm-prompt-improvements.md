# Phase 4: LLM Prompt Improvements

**Date:** 2026-01-27
**Status:** 🚧 IN PROGRESS

## Overview

Enhance LLM analysis prompts to leverage Phase 1-3 improvements for better BEC detection, clearer explanations, and reduced false positives.

## Current State Analysis

### Strengths
- ✅ Good BEC pattern coverage (wire transfer, gift cards, executive impersonation)
- ✅ Prior signals from deterministic analysis
- ✅ Structured JSON response format
- ✅ Reasonable verdict-to-score mapping

### Identified Gaps

1. **Missing Phase 1-3 Context**
   - No sender reputation information
   - No URL classification results
   - No email classification context (marketing/transactional)
   - Not leveraging known sender data

2. **Generic Explanation Quality**
   - Current: "2-3 sentence summary" is too vague
   - Lacks specific threat indicators
   - Doesn't reference detected signals clearly
   - Missing actionable recommendations

3. **No Threat Calibration Guidance**
   - Prompt doesn't explain Phase 3 thresholds (35/55/73/85)
   - No guidance on severity levels
   - Doesn't align LLM scoring with pipeline expectations

4. **Limited False Positive Prevention**
   - Doesn't distinguish legitimate urgency (marketing) from malicious
   - Missing context about known trusted senders
   - No guidance on common false positive patterns

5. **BEC Detection Depth**
   - Missing: compound attack patterns (urgency + secrecy + financial)
   - Missing: context about known executives who CAN make urgent requests
   - Missing: legitimate business context (quarterly reports, deadlines)

## Phase 4 Improvements

### 1. Context-Aware Prompt Enhancement

**Add Sender Reputation Context:**
```typescript
interface SenderReputationContext {
  isKnownGood: boolean;
  trustScore: number;
  historicalActivity: string; // "Regular sender", "First contact", etc.
  knownCategories: string[]; // ["marketing", "transactional"]
}
```

**Add URL Classification Context:**
```typescript
interface URLContext {
  totalURLs: number;
  trackingURLs: number;
  maliciousURLs: number;
  suspiciousURLs: number;
  urlTrustLevel: 'high' | 'medium' | 'low' | 'untrusted';
}
```

**Add Email Classification Context:**
```typescript
interface EmailContext {
  emailType: 'marketing' | 'transactional' | 'automated' | 'personal' | 'unknown';
  isKnownSender: boolean;
  senderCategory?: string;
}
```

### 2. Enhanced System Prompt Structure

**New Prompt Sections:**

1. **Threat Calibration Guidance**
   - Explain pipeline thresholds: PASS (<35), SUSPICIOUS (55-72), QUARANTINE (73-84), BLOCK (85+)
   - Guide LLM on severity levels aligned with thresholds
   - Provide examples of each category

2. **False Positive Prevention**
   - Known sender patterns (marketing, transactional, automated)
   - Legitimate urgency vs malicious urgency
   - Common false positive triggers and how to avoid them
   - Phase 1-3 context interpretation

3. **BEC Sophistication Levels**
   - Basic: Display name spoofing
   - Intermediate: Domain lookalikes + urgency
   - Advanced: Compound attacks (urgency + secrecy + authority + financial)
   - Critical: Known executive impersonation with context manipulation

4. **Context-Aware Analysis**
   - "If sender is known good with high trust score, require stronger evidence"
   - "If email type is marketing, expect urgency language (not malicious)"
   - "If URLs are classified as tracking (high trust), don't penalize"
   - "If first contact + executive impersonation, critical threat"

### 3. Improved Explanation Format

**Current Format:**
```
"This email appears suspicious due to urgency language."
```

**Enhanced Format:**
```
"BEC ATTACK DETECTED (High Confidence): This email impersonates CEO John Smith from a free Gmail account
(john.smith.ceo@gmail.com vs legitimate @company.com). It requests an urgent wire transfer of $50,000
with secrecy instructions ('don't tell finance'). This combines 3 critical BEC patterns: executive
impersonation + financial request + secrecy manipulation."
```

**Explanation Structure:**
- **Verdict Prefix:** [THREAT TYPE] DETECTED (Confidence Level)
- **Primary Evidence:** What are the most damning indicators?
- **Supporting Evidence:** What secondary signals support the verdict?
- **Context:** How does Phase 1-3 analysis inform this?

### 4. Enhanced Recommendation Format

**Current Format:**
```
"Review this email carefully."
```

**Enhanced Format:**
```
"🚨 IMMEDIATE ACTION REQUIRED:
1. DO NOT comply with wire transfer request
2. Verify sender identity through known phone number (not email/text)
3. Forward to security@company.com
4. Report to IT security team immediately

Why: This is a sophisticated CEO impersonation attack designed to steal $50,000."
```

**Recommendation Tiers:**
- **BLOCK (85+):** Immediate actions, reporting procedures, what NOT to do
- **QUARANTINE (73-84):** Verification steps, caution guidance
- **SUSPICIOUS (55-72):** Manual review guidance, red flags to check
- **PASS (<35):** Brief note if any minor concerns

### 5. Threat Type Descriptions

**Add detailed threat taxonomy:**
- **BEC - Wire Transfer Fraud:** (patterns, risk, response)
- **BEC - Gift Card Scam:** (patterns, risk, response)
- **BEC - Invoice Fraud:** (patterns, risk, response)
- **BEC - Payroll Diversion:** (patterns, risk, response)
- **Phishing - Credential Harvesting:** (patterns, risk, response)
- **Phishing - Malware Delivery:** (patterns, risk, response)

## Implementation Plan

### Step 1: Update Interface Types
- Add context interfaces to llm.ts
- Update runLLMAnalysis signature to accept context
- Pass context from pipeline.ts

### Step 2: Enhance System Prompt
- Add threat calibration section
- Add false positive prevention guidance
- Add BEC sophistication levels
- Add context-aware analysis instructions

### Step 3: Update Email Formatting
- Include sender reputation in formatted email
- Include URL classification summary
- Include email classification context
- Add "Context Summary" section

### Step 4: Improve Explanation Parser
- Extract structured explanations
- Parse threat type descriptions
- Format actionable recommendations
- Add confidence level prefix

### Step 5: Create Test Suite
- Test BEC detection with context
- Test false positive prevention
- Test explanation quality
- Test recommendation actionability

### Step 6: Validate and Deploy
- Run comprehensive test suite
- Validate against Phase 1-3 test cases
- Commit and push to production
- Document achievements

## Success Metrics

**Primary Goals:**
- ✅ BEC detection accuracy: Maintain 100%
- ✅ False positive reduction: Additional 5-10%
- ✅ Explanation quality: Specific, actionable, context-aware
- ✅ Recommendation clarity: Clear next steps for each threat level

**Secondary Goals:**
- Better distinction between legitimate and malicious urgency
- Reduced need for manual review on edge cases
- Improved user confidence in verdicts
- Enhanced security awareness through explanations

## Expected Impact

### Detection Quality
- **BEC Attacks:** 100% → 100% (maintained with better explanations)
- **Phishing:** 100% → 100% (maintained)
- **False Positives:** 2.7% → 2.4% (-10% additional reduction)

### Explanation Quality
- **Before:** Generic 2-3 sentence summary
- **After:** Specific threat analysis with evidence and context

### User Experience
- **Before:** "Suspicious email, review carefully"
- **After:** "CEO impersonation + wire transfer + secrecy = BEC attack. DO NOT comply. Verify via known phone."

## Timeline

- [x] Phase 1: Sender Reputation (COMPLETE)
- [x] Phase 2: URL Classification (COMPLETE)
- [x] Phase 3: Threshold Tuning (COMPLETE)
- [ ] **Phase 4: LLM Prompt Improvements** (IN PROGRESS)
- [ ] Phase 5: User Feedback Loop (PENDING)

## Next Steps

1. Implement context interfaces
2. Update system prompt with all enhancements
3. Modify email formatting to include context
4. Create comprehensive test suite
5. Validate improvements
6. Deploy to production
7. Document achievements
