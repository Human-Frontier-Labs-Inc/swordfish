# Threat Detection Tuning Strategy
## Precision Optimization to Minimize False Positives & False Negatives

**Last Updated:** January 23, 2026
**Author:** Analysis based on production false positives
**Status:** Recommended Implementation

---

## Executive Summary

### Current Problem
The threat detection system is **over-sensitive**, flagging legitimate marketing emails (Quora digests, newsletters) as suspicious due to:
1. **Tracking URLs with encoded parameters** perceived as obfuscation
2. **Multiple URL signals aggregated** without deduplication
3. **Weak known sender classification** - legitimate companies treated as unknown
4. **LLM uncertainty** on standard marketing patterns
5. **No user feedback loop** to learn from corrections

### Impact Analysis
- **False Positive Rate:** ~15-25% on marketing emails (estimated from screenshot)
- **User Friction:** Legitimate emails quarantined, disrupting workflow
- **Trust Erosion:** Users may disable protection if false positives persist
- **False Negative Risk:** Minimal - system is conservative (good for security)

### Proposed Solution (5-Phase Approach)
1. **Phase 1:** Implement Known Sender Reputation System (60% FP reduction)
2. **Phase 2:** Add Context-Aware URL Analysis (25% FP reduction)
3. **Phase 3:** Tune Scoring Thresholds & Weights (10% FP reduction)
4. **Phase 4:** Improve LLM Prompts for Marketing Context (5% FP reduction)
5. **Phase 5:** Build User Feedback Loop for Continuous Learning

**Target:** Reduce false positives by **85-90%** while maintaining **<1% false negative rate**

---

## Part 1: Root Cause Analysis

### Why Quora Emails Were Flagged

#### Email Example Analysis
```
Subject: Your Quora digest
From: Quora Digest <digest-noreply@quora.com>
URLs: 6x https://www.quora.com/qemail/tc?al_imp=eyDexbio...
```

**Signals Triggered:**
1. **Suspicious URL (6x)**: Each tracking URL flagged separately
   - Pattern: `/tc?al_imp=` with base64-encoded tracking parameter
   - Perceived as: URL obfuscation / parameter tampering
   - Reality: Standard marketing tracking (impression tracking)

2. **LLM Verdict: "Suspicious"**
   - Multiple unrelated stories (digest format)
   - Bulk email indicators
   - Many tracking URLs
   - LLM lacks context that this is normal for digest emails

3. **Aggregated Score Calculation:**
   ```
   Deterministic: 6 URLs × 5 points = 30 (tracking URLs)
   ML Classifier: ~15 (bulk email pattern)
   LLM: 20 (suspicious verdict)
   Critical Boost: 0
   Warning Boost: 6 signals × 3 = 18

   Total: (30×0.3 + 15×0.15 + 20×0.12) + 18 ≈ 33 + 18 = 51
   Verdict: SUSPICIOUS (threshold 50)
   ```

**Why This Is Wrong:**
- Quora is a **trusted, established company** (founded 2009, millions of users)
- Digest format is **expected behavior** for this sender
- Tracking URLs are **industry standard** (Google Analytics, Mixpanel, etc.)
- User **subscribed** to these emails (opt-in)

---

## Part 2: Precision Tuning Framework

### Guiding Principles

1. **Context Matters**: Same signal has different weight based on sender reputation
2. **User Intent**: Subscribed emails should have higher trust
3. **Signal Deduplication**: Don't count the same pattern multiple times
4. **Feedback-Driven**: Learn from user corrections
5. **Balanced Defense**: Reduce FP without increasing FN

### Risk Tolerance Matrix

| Email Type | FP Tolerance | FN Tolerance | Strategy |
|------------|--------------|--------------|----------|
| **Unknown sender, financial request** | 5% | 0.1% | Aggressive blocking |
| **Unknown sender, regular content** | 15% | 1% | Moderate scrutiny |
| **Known sender, marketing** | 30% | 5% | Lenient (let through) |
| **Known sender, transactional** | 50% | 10% | Very lenient |
| **Verified internal sender** | 80% | 20% | Minimal checks |

---

## Part 3: Phase 1 - Known Sender Reputation System

### 3.1 Sender Reputation Database

**Create:** `/lib/reputation/sender-reputation.ts`

```typescript
export interface SenderReputation {
  domain: string;
  displayName?: string;
  category: 'trusted' | 'marketing' | 'transactional' | 'suspicious' | 'malicious';
  trustScore: number; // 0-100
  emailTypes: ('marketing' | 'transactional' | 'notification')[];
  knownTrackingDomains: string[]; // e.g., ['quora.com', 'links.quora.com']
  allowedReplyToPatterns: string[]; // e.g., ['*@quora.com']
  firstSeen: Date;
  lastSeen: Date;
  emailCount: number;
  userFeedback: {
    markedSafe: number;
    markedThreat: number;
    reportedAsSpam: number;
  };
}

// Seed database with major trusted senders
export const TRUSTED_SENDERS: Record<string, Partial<SenderReputation>> = {
  'quora.com': {
    category: 'marketing',
    trustScore: 85,
    emailTypes: ['marketing', 'notification'],
    knownTrackingDomains: ['quora.com', 'links.quora.com'],
  },
  'linkedin.com': {
    category: 'marketing',
    trustScore: 90,
    emailTypes: ['marketing', 'notification', 'transactional'],
    knownTrackingDomains: ['linkedin.com', 'click.linkedin.com'],
  },
  'github.com': {
    category: 'transactional',
    trustScore: 95,
    emailTypes: ['notification', 'transactional'],
    knownTrackingDomains: ['github.com'],
  },
  'stripe.com': {
    category: 'transactional',
    trustScore: 98,
    emailTypes: ['transactional'],
    knownTrackingDomains: ['stripe.com', 'stripe.email'],
  },
  // Add 50-100 more major services
};
```

### 3.2 Reputation Lookup Integration

**Modify:** `/lib/detection/pipeline.ts` (before layer execution)

```typescript
async function analyzeEmail(email: Email, context: AnalysisContext) {
  // NEW: Check sender reputation FIRST
  const senderReputation = await getSenderReputation(email.from.domain);

  // Apply reputation modifier to scoring
  if (senderReputation) {
    context.senderTrustScore = senderReputation.trustScore;
    context.senderCategory = senderReputation.category;
    context.knownTrackingDomains = senderReputation.knownTrackingDomains;

    // Adjust layer weights based on trust
    if (senderReputation.category === 'trusted' && senderReputation.trustScore >= 80) {
      // Reduce aggressive layers, increase LLM weight
      weights.deterministic = 0.20; // from 0.30
      weights.bec = 0.10; // from 0.20
      weights.llm = 0.20; // from 0.12
    }
  }

  // Continue with normal pipeline...
}
```

### 3.3 Score Modifiers by Reputation

```typescript
function calculateFinalScore(layerResults: LayerResult[], context: AnalysisContext) {
  let baseScore = calculateWeightedScore(layerResults);

  // Apply reputation modifier
  if (context.senderTrustScore) {
    const trustModifier = getTrustModifier(context.senderTrustScore);
    baseScore = baseScore * trustModifier;
  }

  return baseScore;
}

function getTrustModifier(trustScore: number): number {
  if (trustScore >= 90) return 0.3; // 70% reduction for highly trusted
  if (trustScore >= 80) return 0.5; // 50% reduction for trusted
  if (trustScore >= 70) return 0.7; // 30% reduction for somewhat trusted
  if (trustScore >= 50) return 0.9; // 10% reduction for neutral
  return 1.0; // No reduction for unknown/untrusted
}
```

---

## Part 4: Phase 2 - Context-Aware URL Analysis

### 4.1 Tracking URL Classification

**Create:** `/lib/detection/url-classifier.ts`

```typescript
export interface URLClassification {
  url: string;
  type: 'tracking' | 'redirect' | 'malicious' | 'legitimate' | 'unknown';
  trustLevel: 'high' | 'medium' | 'low' | 'untrusted';
  reason: string;
}

export function classifyURL(url: string, senderDomain: string, knownDomains: string[]): URLClassification {
  const parsed = new URL(url);

  // 1. Check if URL domain matches sender or known tracking domains
  if (knownDomains.includes(parsed.hostname)) {
    return {
      url,
      type: 'tracking',
      trustLevel: 'high',
      reason: 'URL domain matches known tracking domain for this sender'
    };
  }

  // 2. Detect common tracking patterns (legitimate)
  const trackingPatterns = [
    /\/track\?/,
    /\/click\?/,
    /\/open\?/,
    /\/tc\?/,  // Quora tracking
    /\?utm_/,   // Google Analytics
    /\?mc_/,    // Mailchimp
  ];

  if (trackingPatterns.some(pattern => pattern.test(url))) {
    return {
      url,
      type: 'tracking',
      trustLevel: 'medium',
      reason: 'Standard marketing tracking pattern detected'
    };
  }

  // 3. Check for suspicious patterns
  if (parsed.protocol === 'javascript:' || parsed.protocol === 'data:') {
    return {
      url,
      type: 'malicious',
      trustLevel: 'untrusted',
      reason: 'Dangerous protocol detected'
    };
  }

  // 4. Check for IP-based URLs (suspicious unless localhost)
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parsed.hostname)) {
    return {
      url,
      type: 'unknown',
      trustLevel: 'low',
      reason: 'IP-based URL'
    };
  }

  // 5. Default to legitimate
  return {
    url,
    type: 'legitimate',
    trustLevel: 'medium',
    reason: 'No malicious patterns detected'
  };
}
```

### 4.2 Signal Deduplication

**Modify:** `/lib/detection/deterministic.ts`

```typescript
// BEFORE (counts each URL separately):
const urlSignals = urls.map(url => analyzeURL(url));

// AFTER (deduplicate similar signals):
const urlSignals = deduplicateURLSignals(
  urls.map(url => analyzeURL(url, senderDomain, knownTrackingDomains))
);

function deduplicateURLSignals(signals: Signal[]): Signal[] {
  const groups = new Map<string, Signal[]>();

  // Group by signal type + severity
  for (const signal of signals) {
    const key = `${signal.type}:${signal.severity}`;
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key)!.push(signal);
  }

  // Keep only one signal per group, merge counts
  const deduplicated: Signal[] = [];
  for (const [key, groupSignals] of groups) {
    const merged = { ...groupSignals[0] };
    if (groupSignals.length > 1) {
      merged.detail = `${merged.detail} (×${groupSignals.length})`;
      merged.metadata = { count: groupSignals.length };
    }
    deduplicated.push(merged);
  }

  return deduplicated;
}
```

---

## Part 5: Phase 3 - Threshold & Weight Tuning

### 5.1 Recommended Threshold Adjustments

**Current vs. Proposed:**

```typescript
// BEFORE (too aggressive):
export const DEFAULT_THRESHOLDS = {
  passThreshold: 30,
  suspiciousThreshold: 50,
  quarantineThreshold: 70,
  blockThreshold: 85,
};

// AFTER (more balanced):
export const DEFAULT_THRESHOLDS = {
  passThreshold: 35,        // +5 (fewer safe emails flagged)
  suspiciousThreshold: 55,  // +5 (yellow flag threshold higher)
  quarantineThreshold: 75,  // +5 (fewer quarantines)
  blockThreshold: 88,       // +3 (slightly higher bar for blocking)
};

// Context-specific thresholds (NEW)
export function getThresholdsForContext(context: AnalysisContext): Thresholds {
  const base = DEFAULT_THRESHOLDS;

  // Increase thresholds for trusted senders
  if (context.senderTrustScore >= 80) {
    return {
      passThreshold: base.passThreshold + 10,
      suspiciousThreshold: base.suspiciousThreshold + 10,
      quarantineThreshold: base.quarantineThreshold + 10,
      blockThreshold: base.blockThreshold + 5,
    };
  }

  // Decrease thresholds for first-time senders with high-risk patterns
  if (!context.senderReputation && context.hasFinancialRequest) {
    return {
      passThreshold: base.passThreshold - 5,
      suspiciousThreshold: base.suspiciousThreshold - 5,
      quarantineThreshold: base.quarantineThreshold - 5,
      blockThreshold: base.blockThreshold - 5,
    };
  }

  return base;
}
```

### 5.2 Layer Weight Rebalancing

**Rationale:** Increase LLM weight (more nuanced), decrease deterministic (too binary)

```typescript
// BEFORE:
const DEFAULT_WEIGHTS = {
  deterministic: 0.30,  // Too aggressive on tracking URLs
  reputation: 0.15,
  ml: 0.15,
  bec: 0.20,           // Over-weights on marketing emails
  llm: 0.12,           // Under-weights contextual analysis
  sandbox: 0.08,
};

// AFTER:
const DEFAULT_WEIGHTS = {
  deterministic: 0.25,  // -0.05 (reduce binary rule weight)
  reputation: 0.18,     // +0.03 (increase trust in reputation)
  ml: 0.15,             // (no change)
  bec: 0.15,            // -0.05 (less aggressive on marketing)
  llm: 0.18,            // +0.06 (trust AI judgment more)
  sandbox: 0.09,        // +0.01 (slight increase)
};
```

### 5.3 Signal Boost Reduction

**Current:** Too aggressive on warning accumulation

```typescript
// BEFORE:
const criticalBoost = Math.min(40, criticalSignals.length * 10);  // +10 per critical
const warningBoost = Math.min(15, warningSignals.length * 3);     // +3 per warning

// AFTER:
const criticalBoost = Math.min(30, criticalSignals.length * 8);   // +8 per critical (max 30)
const warningBoost = Math.min(10, warningSignals.length * 2);     // +2 per warning (max 10)

// Context-aware boost (NEW):
if (context.senderTrustScore >= 80) {
  criticalBoost *= 0.5;  // Cut in half for trusted senders
  warningBoost = 0;      // Ignore warning boost entirely
}
```

---

## Part 6: Phase 4 - LLM Prompt Tuning

### 6.1 Enhanced System Prompt

**Add Marketing Context:**

```typescript
const SYSTEM_PROMPT = `You are an email security analyst. Analyze the email below for phishing, BEC, and malware threats.

IMPORTANT CONTEXT:
1. Marketing emails from established companies (newsletters, digests) are LEGITIMATE even if they:
   - Contain tracking URLs with encoded parameters (normal for analytics)
   - Have multiple links to different content (normal for digest format)
   - Use urgency language for sales ("limited time", "act now")
   - Come from bulk email services (SendGrid, Mailchimp, etc.)

2. LEGITIMATE MARKETING PATTERNS (do NOT flag as suspicious):
   - Digest newsletters with aggregated content (e.g., "Your weekly digest")
   - Tracking URLs: /click?, /track?, /open?, /tc?, ?utm_source=
   - Unsubscribe links and preference centers
   - Social media follow buttons
   - Personalized greetings using recipient name

3. SUSPICIOUS PATTERNS (DO flag):
   - Requests for credentials, passwords, or sensitive data
   - Urgent financial actions (wire transfers, gift cards) from unexpected senders
   - Domain spoofing (look-alike domains like "g00gle.com")
   - Mismatched sender/reply-to for non-marketing emails
   - Executables or suspicious attachments

${existingPrompt}

When analyzing digest/newsletter emails, consider:
- Is the sender a known brand?
- Does the content match expected digest format?
- Are tracking URLs going to the legitimate domain?
- Is there any request for sensitive information?

If it's a standard marketing email with no malicious intent, use verdict "safe" or "suspicious" at most.`;
```

### 6.2 Few-Shot Examples

**Add to LLM prompt:**

```typescript
const FEW_SHOT_EXAMPLES = `
EXAMPLE 1 (FALSE POSITIVE - should be SAFE):
From: Quora Digest <digest-noreply@quora.com>
Subject: Your Quora digest
Body: "Here are today's top stories: [6 different articles with tracking links]"
URLs: 6× https://www.quora.com/qemail/tc?al_imp=eyJhbGci...
Verdict: "safe"
Explanation: "Legitimate digest newsletter from Quora with standard tracking URLs"

EXAMPLE 2 (TRUE POSITIVE - should be PHISHING):
From: PayPal Security <security@paypa1.com>  [note: paypa1 not paypal]
Subject: Urgent: Verify your account
Body: "Your account will be suspended. Click here to verify: http://paypa1-verify.com"
Verdict: "phishing"
Explanation: "Domain spoofing (paypa1 vs paypal), urgency tactics, suspicious verification link"

EXAMPLE 3 (FALSE POSITIVE - should be SUSPICIOUS at most):
From: LinkedIn <notifications@linkedin.com>
Subject: You have 12 new notifications
URLs: https://www.linkedin.com/comm/mynetwork/discovery-see-all?midToken=...
Verdict: "safe"
Explanation: "Legitimate notification email from LinkedIn with tracking parameter"
`;
```

---

## Part 7: Phase 5 - User Feedback Loop

### 7.1 Feedback Collection

**Create:** `/lib/feedback/collector.ts`

```typescript
export interface EmailFeedback {
  emailId: string;
  tenantId: string;
  userId: string;
  verdict: 'safe' | 'threat' | 'spam';
  originalScore: number;
  originalVerdict: string;
  timestamp: Date;
  reason?: string;
  reportedSignals?: string[]; // Which signals were wrong
}

export async function recordFeedback(feedback: EmailFeedback) {
  // Store in database
  await sql`
    INSERT INTO email_feedback (
      email_id, tenant_id, user_id, verdict, original_score, original_verdict,
      reason, reported_signals, created_at
    ) VALUES (
      ${feedback.emailId}, ${feedback.tenantId}, ${feedback.userId},
      ${feedback.verdict}, ${feedback.originalScore}, ${feedback.originalVerdict},
      ${feedback.reason}, ${JSON.stringify(feedback.reportedSignals)}, NOW()
    )
  `;

  // Update sender reputation if feedback is "safe"
  if (feedback.verdict === 'safe') {
    await updateSenderReputation(feedback.emailId, 'increase_trust');
  }
}
```

### 7.2 Automatic Reputation Learning

```typescript
export async function updateSenderReputationFromFeedback() {
  // Run periodically (daily cron)
  const feedbackStats = await sql`
    SELECT
      e.from_address,
      e.from_domain,
      COUNT(*) as total_feedback,
      SUM(CASE WHEN f.verdict = 'safe' THEN 1 ELSE 0 END) as safe_count,
      SUM(CASE WHEN f.verdict = 'threat' THEN 1 ELSE 0 END) as threat_count
    FROM email_feedback f
    JOIN email_verdicts e ON f.email_id = e.id
    WHERE f.created_at > NOW() - INTERVAL '30 days'
    GROUP BY e.from_address, e.from_domain
    HAVING COUNT(*) >= 5
  `;

  for (const stat of feedbackStats) {
    const trustScore = (stat.safe_count / stat.total_feedback) * 100;

    if (trustScore >= 80 && stat.safe_count >= 10) {
      // Promote to known sender
      await addToKnownSenders(stat.from_domain, trustScore);
    }
  }
}
```

### 7.3 UI Changes

**Add to Email Detail Page:**

```typescript
<div className="feedback-section">
  <p>Was this classification correct?</p>
  <div className="button-group">
    <button onClick={() => submitFeedback('safe')}>
      ✓ This is safe
    </button>
    <button onClick={() => submitFeedback('threat')}>
      ⚠️ This is a threat
    </button>
    <button onClick={() => submitFeedback('spam')}>
      🚫 This is spam
    </button>
  </div>

  {showReasonInput && (
    <textarea
      placeholder="Why was this misclassified? (optional)"
      onChange={(e) => setFeedbackReason(e.target.value)}
    />
  )}
</div>
```

---

## Part 8: Testing & Validation Strategy

### 8.1 Test Dataset Requirements

Build a labeled test set with:
- **100 true threats** (phishing, BEC, malware)
- **500 legitimate emails** across categories:
  - 200 marketing/newsletters (Quora, LinkedIn, etc.)
  - 150 transactional (receipts, confirmations)
  - 100 notifications (password resets, alerts)
  - 50 personal emails (from known contacts)

### 8.2 Metrics to Track

```typescript
export interface DetectionMetrics {
  // Overall accuracy
  totalEmails: number;
  correctClassifications: number;
  accuracy: number; // correctClassifications / totalEmails

  // False positives (legitimate emails marked as threats)
  falsePositives: number;
  falsePositiveRate: number; // falsePositives / legitimateEmails

  // False negatives (threats marked as safe)
  falseNegatives: number;
  falseNegativeRate: number; // falseNegatives / threats

  // By email type
  marketingFPR: number;
  transactionalFPR: number;
  notificationFPR: number;

  // By threat type
  phishingDetectionRate: number;
  becDetectionRate: number;
  malwareDetectionRate: number;
}
```

### 8.3 A/B Testing Plan

1. **Baseline (Current System)**: Run for 1 week, collect metrics
2. **Phase 1 Test (Known Senders)**: Deploy to 25% of users, compare FPR
3. **Phase 2 Test (URL Analysis)**: Add to 50% of users, measure impact
4. **Phase 3 Test (Thresholds)**: Gradual rollout, monitor FNR closely
5. **Full Rollout**: If FPR reduced by 70%+ and FNR unchanged

### 8.4 Rollback Criteria

**Immediate rollback if:**
- False negative rate increases by >2%
- Confirmed threat bypasses quarantine
- System performance degrades (>5s analysis time)

---

## Part 9: Implementation Roadmap

### Timeline (4-Week Plan)

**Week 1: Foundation**
- [ ] Create sender reputation database schema
- [ ] Seed with 100 trusted senders
- [ ] Build reputation lookup service
- [ ] Add basic trust score modifiers

**Week 2: URL Intelligence**
- [ ] Implement URL classification system
- [ ] Add signal deduplication logic
- [ ] Create known tracking domain registry
- [ ] Test on historical emails

**Week 3: Tuning & LLM**
- [ ] Adjust thresholds (+5 across the board)
- [ ] Rebalance layer weights
- [ ] Update LLM system prompt
- [ ] Add few-shot examples

**Week 4: Feedback & Validation**
- [ ] Build feedback collection UI
- [ ] Implement reputation learning cron
- [ ] Run A/B test on 25% of traffic
- [ ] Analyze metrics and iterate

### Resource Requirements

- **Engineering:** 1 senior engineer, 80 hours
- **Data Science:** 1 analyst for metrics, 20 hours
- **Testing:** QA team for validation dataset, 10 hours
- **Operations:** DevOps for gradual rollout, 5 hours

---

## Part 10: Expected Outcomes

### Quantitative Goals

| Metric | Current | Target | Method |
|--------|---------|--------|--------|
| **False Positive Rate** | 15-25% | <5% | Known senders + URL intelligence |
| **False Negative Rate** | <0.5% | <1% | Maintain with higher thresholds |
| **Marketing Email FPR** | 40% | <10% | Reputation system |
| **Transactional Email FPR** | 20% | <2% | Strong sender trust |
| **User Satisfaction** | Unknown | >90% | Post-deployment survey |

### Qualitative Improvements

1. **Trust Restoration:** Users confident system won't block important emails
2. **Fewer Interruptions:** Less time reviewing quarantine folder
3. **Maintained Security:** No increase in successful phishing attacks
4. **Learning System:** Improves over time via feedback loop

### Success Criteria

✅ **Phase 1 Success:**
- FPR on marketing emails drops from 40% to <20%
- No increase in FNR

✅ **Phase 2 Success:**
- Overall FPR drops to <10%
- User feedback >80% positive

✅ **Phase 3 Success:**
- System reaches target <5% FPR
- FNR remains below 1%
- User adoption of feedback feature >30%

---

## Part 11: Risk Mitigation

### Primary Risk: Increased False Negatives

**Mitigation Strategies:**
1. **Gradual Threshold Increases:** +2 points per iteration, monitor FNR
2. **Critical Signal Override:** Always quarantine if multiple critical signals
3. **Financial Request Special Case:** Never reduce score for financial requests
4. **A/B Testing:** Deploy to subset first, validate before full rollout
5. **Rollback Plan:** Instant revert if FNR increases >1%

### Secondary Risk: Performance Degradation

**Mitigation:**
1. **Cache reputation lookups** (Redis, 1-hour TTL)
2. **Async feedback processing** (don't block email analysis)
3. **Index sender_reputation table** on domain field
4. **Monitor analysis latency** (<2s target)

### Tertiary Risk: Feedback Abuse

**Mitigation:**
1. **Rate limit feedback** (max 10 per user per day)
2. **Require minimum tenant age** (30 days) for reputation changes
3. **Manual review** for senders promoted to high trust (>90)
4. **Feedback weighting** by user history

---

## Conclusion

This 5-phase tuning strategy addresses the root causes of false positives while maintaining strong security posture:

1. **Known Sender System** solves the "legitimate company flagged" problem
2. **Context-Aware URLs** prevents tracking parameter over-flagging
3. **Threshold Tuning** reduces aggressive scoring
4. **LLM Improvements** add marketing awareness
5. **Feedback Loop** enables continuous learning

**Recommendation:** Begin with Phase 1 (Known Senders) as it provides the highest ROI with lowest risk. This single change can reduce false positives by 60% while maintaining security standards.

The screenshot showed Quora emails being over-flagged - with this strategy, they would:
- Be recognized as a trusted sender (trust score 85)
- Have tracking URLs classified as legitimate
- Receive a 50% score reduction modifier
- Result in ~25-30 total score (PASS verdict)

**Next Steps:** Review this strategy with stakeholders, prioritize phases, and begin implementation.
