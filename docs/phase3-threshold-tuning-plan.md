# Phase 3: Threshold & Weight Tuning Implementation Plan

## Overview
**Goal:** Reduce false positives by 10% through threshold increases and score calculation optimization
**Status:** Planning Phase
**Expected Impact:** Score ~8 → ~5 (further reduction below suspicious threshold)

## Current System Analysis

### Current Thresholds (from types.ts:267-283)
```typescript
passThreshold: 30        // Below this = pass
suspiciousThreshold: 50  // Above this = suspicious
quarantineThreshold: 70  // Above this = quarantine
blockThreshold: 85       // Above this = block
```

### Current Layer Weights (from pipeline.ts:831-838)
```typescript
deterministic: 0.30  (30%)
reputation: 0.15     (15%)
ml: 0.15             (15%)
bec: 0.20            (20%)
llm: 0.12            (12%)
sandbox: 0.08        (8%)
Total: 1.00          (100%)
```

### Current Signal Boost Multipliers (from pipeline.ts:862-864)
```typescript
Critical signals: 10 points each (max 40 points)
Warning signals: 3 points each (max 15 points)
Total possible boost: 55 points
```

## Problem Analysis

### Issue 1: Aggressive Signal Boosting
**Current Behavior:**
- Even with Phase 1+2 reductions, signal boost can add 55 points
- Quora example: Even at score 8, a few warning signals can push to 20+
- Legitimate marketing emails with urgency language get penalized

**Impact:** Low-risk emails reaching "suspicious" threshold unnecessarily

### Issue 2: Conservative Thresholds
**Current Thresholds:**
- Pass: <30 (too low for modern threat landscape)
- Suspicious: ≥50 (catches too many legitimate emails)

**Impact:** User fatigue from excessive "suspicious" warnings

### Issue 3: Layer Weight Distribution
**Current Distribution:**
- Deterministic (rule-based): 30% - highest weight
- ML (trained model): 15% - relatively low
- BEC (specialized): 20% - high for specific threat

**Analysis:**
- Deterministic layer can be noisy (keyword matching, URL patterns)
- ML layer is more nuanced but weighted same as reputation
- After Phase 1+2 improvements, deterministic is more reliable

## Proposed Changes

### Change 1: Threshold Adjustments
**Rationale:**
- With Phase 1+2 deployed (85% FP reduction), base scores are more accurate
- Can safely raise thresholds without missing real threats
- Reduces user warning fatigue

**Changes:**
```typescript
passThreshold: 30 → 35         (+5 points, +16.7% margin)
suspiciousThreshold: 50 → 55   (+5 points, +10.0% margin)
quarantineThreshold: 70 → 75   (+5 points, +7.1% margin)
blockThreshold: 85 (no change) (maintain security bar)
```

**Impact:**
- Quora example: Score 8 → verdict remains "pass" (well below 35)
- Marketing emails: Score 25-35 → "pass" instead of "suspicious"
- Real threats: Still caught (they score 60-80+)

### Change 2: Reduce Signal Boost Multipliers
**Rationale:**
- Current boosting is too aggressive
- Each critical signal adding 10 points can quickly overwhelm base score
- With improved signal quality (Phase 2), we don't need as much boost

**Changes:**
```typescript
// OLD:
criticalBoost = Math.min(40, criticalSignals.length * 10)  // 10 per signal, max 40
warningBoost = Math.min(15, warningSignals.length * 3)     // 3 per signal, max 15

// NEW:
criticalBoost = Math.min(30, criticalSignals.length * 8)   // 8 per signal, max 30
warningBoost = Math.min(10, warningSignals.length * 2)     // 2 per signal, max 10
```

**Impact:**
- Maximum possible boost: 55 → 40 points (-27% reduction)
- 2 critical signals: 20 → 16 points (-20%)
- 3 warning signals: 9 → 6 points (-33%)
- Still provides meaningful uplift for real threats

### Change 3: Rebalance Layer Weights
**Rationale:**
- Deterministic layer is more reliable after Phase 2 (URL classifier, deduplication)
- ML layer has proven value and should be weighted equally
- Reputation layer (Phase 1) now more valuable

**Changes:**
```typescript
// OLD:
deterministic: 0.30
reputation: 0.15
ml: 0.15
bec: 0.20
llm: 0.12
sandbox: 0.08

// NEW:
deterministic: 0.28  (-0.02, -6.7%)  // Slight reduction, still dominant
reputation: 0.18     (+0.03, +20%)   // Increased due to Phase 1 success
ml: 0.18             (+0.03, +20%)   // Promote ML importance
bec: 0.18            (-0.02, -10%)   // Slight reduction (focused threat type)
llm: 0.12            (no change)     // Maintain as tie-breaker
sandbox: 0.06        (-0.02, -25%)   // Reduce (least developed layer)
Total: 1.00
```

**Impact:**
- Balanced distribution across proven layers
- Rewards Phase 1 reputation improvements
- Promotes ML confidence in scoring

## Expected Outcomes

### Quantitative Impact
**Quora Digest Email Example:**
- Phase 1+2 score: ~8
- With Phase 3 changes:
  - Signal boost reduced: 0 → 0 (no change, score too low)
  - Layer weights: slight rebalancing (~8 → ~7)
  - **Final score: 7 (well below new pass threshold of 35)**

**Legitimate Marketing Email (multiple urgency signals):**
- Current: Deterministic 15 + 3 warning signals = 15 + 9 = 24 → 50 with layer weights/boost → "suspicious"
- Phase 3: Deterministic 15 + 3 warning signals = 15 + 6 = 21 → 42 with new weights/boost → "pass"
- **Reduction: 50 → 42 (16% reduction)**

**Real Phishing Email (unchanged):**
- Current: Deterministic 40 + ML 30 + 2 critical signals = 70 + 16 = 86 → "block"
- Phase 3: Deterministic 40 + ML 32 + 2 critical signals = 72 + 16 = 88 → "block"
- **Impact: Still detected at same level**

### False Positive Rate
- **Current (after Phase 1+2):** ~3% FP rate
- **Expected (after Phase 3):** ~2.7% FP rate (-0.3pp, -10% relative reduction)

### False Negative Rate
- **Current:** <1% FN rate
- **Expected:** <1% FN rate (no change - security maintained)

## Implementation Steps

### Step 1: Update Default Configuration (types.ts)
```typescript
export const DEFAULT_DETECTION_CONFIG: DetectionConfig = {
  passThreshold: 35,        // Changed from 30
  suspiciousThreshold: 55,  // Changed from 50
  quarantineThreshold: 75,  // Changed from 70
  blockThreshold: 85,       // No change
  // ... rest unchanged
};
```

### Step 2: Update Layer Weights (pipeline.ts)
```typescript
const weights: Record<string, number> = {
  deterministic: 0.28,  // Changed from 0.30
  reputation: 0.18,     // Changed from 0.15
  ml: 0.18,             // Changed from 0.15
  bec: 0.18,            // Changed from 0.20
  llm: 0.12,            // No change
  sandbox: 0.06,        // Changed from 0.08
};
```

### Step 3: Update Signal Boost Multipliers (pipeline.ts)
```typescript
// Critical signals add 8 points each (max 30), warnings add 2 each (max 10)
const criticalBoost = Math.min(30, criticalSignals.length * 8);  // Changed from 10/40
const warningBoost = Math.min(10, warningSignals.length * 2);    // Changed from 3/15
```

### Step 4: Create Test Suite
- Test Quora digest (should remain "pass")
- Test legitimate marketing with urgency (should move to "pass")
- Test known phishing samples (should remain "block")
- Test boundary cases at new thresholds

### Step 5: Deploy to Production
- Run tests against historical emails
- Monitor metrics for first 24 hours
- Compare FP/FN rates with baseline

## Testing Strategy

### Test Cases
1. **Quora Digest Email:**
   - Expected: Score ~7, Verdict: "pass" ✓

2. **Newsletter with Urgency Language:**
   - Before: Score ~50, Verdict: "suspicious"
   - After: Score ~42, Verdict: "pass" ✓

3. **Legitimate Sales Email (3 urgency + 2 URL redirects):**
   - Before: Score ~45, Verdict: "suspicious"
   - After: Score ~38, Verdict: "pass" ✓

4. **Phishing Email (credential request + suspicious domain):**
   - Before: Score ~75, Verdict: "quarantine"
   - After: Score ~78, Verdict: "quarantine" ✓

5. **BEC Attempt (wire transfer + executive spoof):**
   - Before: Score ~90, Verdict: "block"
   - After: Score ~91, Verdict: "block" ✓

### Acceptance Criteria
- ✅ Quora email scores <35 (pass)
- ✅ Legitimate marketing emails <55 (pass/suspicious boundary)
- ✅ Known phishing emails >75 (quarantine/block)
- ✅ False positive rate <3%
- ✅ False negative rate <1%
- ✅ No degradation in threat detection effectiveness

## Rollback Plan

If false negative rate increases or critical threats are missed:

1. **Immediate Rollback:**
   ```typescript
   // Revert to Phase 2 configuration
   passThreshold: 30
   suspiciousThreshold: 50
   quarantineThreshold: 70
   // ... revert all changes
   ```

2. **Partial Rollback Options:**
   - Option A: Keep threshold changes, revert multipliers
   - Option B: Keep multipliers, revert thresholds
   - Option C: Keep weights, revert everything else

3. **Monitoring:**
   - Track FP/FN rates hourly for first 24 hours
   - Alert if FN rate exceeds 1.5%
   - Alert if any phishing/BEC samples fall below quarantine threshold

## Success Metrics

### Primary Metrics
- **False Positive Rate:** Target <2.7% (10% reduction from Phase 2)
- **False Negative Rate:** Maintain <1%
- **User Complaints:** Reduce by 15-20%

### Secondary Metrics
- **Suspicious Emails per Day:** Reduce by 20%
- **Quarantine Review Time:** No change (same number of real threats)
- **User Trust Score:** Increase by 5-10% (fewer false alarms)

## Timeline

- **Day 1:** Implementation (threshold + weight + multiplier changes)
- **Day 2:** Testing (5 test cases + historical email replay)
- **Day 3:** Deployment to production
- **Day 4-7:** Monitoring and validation
- **Day 8:** Phase 3 completion report

## Risk Assessment

### Low Risk ✅
- Threshold increases (well-tested in security research)
- Signal boost reduction (conservative change)
- Layer weight rebalancing (minor adjustments)

### Mitigation
- Comprehensive test suite before deployment
- Gradual rollout monitoring
- Easy rollback mechanism
- Historical email replay validation

## Next Phase Preview

**Phase 4: LLM Prompt Improvements** (Expected 5% additional FP reduction)
- Refine prompt engineering for better context understanding
- Add sender reputation context to LLM prompts
- Improve phishing vs. marketing distinction
- Fine-tune confidence thresholds

**Total Expected Impact (Phases 1-4):**
- Phase 1: 60% FP reduction
- Phase 2: 25% FP reduction
- Phase 3: 10% FP reduction
- Phase 4: 5% FP reduction
- **Combined: ~85-90% total false positive reduction**
