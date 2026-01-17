# Phase 7: ML & Predictive Intelligence

## Overview

**Goal**: Machine learning for predictive threat detection
**Duration**: 1 week
**Score Impact**:
- vs Barracuda: 68 → 70 (+2)
- Innovation: 66 → 74 (+8)
- Production Readiness: 100 (maintained)

## Why This Matters

This is our innovation differentiator:
- **Predictive Scoring**: Score threats before full analysis
- **Autonomous Learning**: System improves from admin feedback
- **Explainable AI**: Users understand why emails are flagged

## Slices

### Slice 7.1: Threat Prediction Model

**Goal**: Fast initial threat scoring

**User Story**:
> As a security system, I need to quickly score incoming emails for threat likelihood so that I can prioritize which emails need deep analysis.

**Model Architecture**:
```
Input Features:
├── Sender features (domain age, reputation, first contact)
├── Content features (urgency, requests, links)
├── Recipient features (VIP status, role)
├── Historical features (similar emails, sender history)
└── Technical features (auth results, header anomalies)

Model:
├── Gradient Boosted Trees (fast inference)
└── Trained on labeled threat data

Output:
├── Threat probability (0-1)
├── Confidence score (0-1)
└── Top contributing features
```

**Acceptance Criteria**:
- [ ] Extract 50+ features from email
- [ ] Fast inference (<10ms per email)
- [ ] Calibrated probability output
- [ ] Feature importance extraction
- [ ] Model versioning and A/B testing
- [ ] Automatic retraining pipeline
- [ ] Rollback capability

**Tests**:
```typescript
// tests/ml/predictor.test.ts
describe('Threat Prediction Model', () => {
  it('should extract features from email')
  it('should score email within 10ms')
  it('should return calibrated probability')
  it('should return confidence score')
  it('should return top features')
  it('should handle missing features')
  it('should support model versions')
  it('should support A/B testing')
});
```

**Implementation**:
- `lib/ml/predictor.ts`
- `lib/ml/feature-extractor.ts`
- `lib/ml/model-manager.ts`

---

### Slice 7.2: Autonomous Response Learning

**Goal**: Learn from admin decisions

**User Story**:
> As a security system, I need to learn from administrator decisions so that I continuously improve my detection accuracy.

**Learning Signals**:
```
Positive signals (confirms threat):
├── Admin deletes reported email
├── Admin blocks sender
├── User confirms phishing attempt
└── Similar emails detected as threats

Negative signals (false positive):
├── Admin releases quarantined email
├── Admin whitelists sender
├── User reports as safe
└── Same sender, no action taken

Learning pipeline:
1. Collect decision events
2. Extract features from email
3. Create training sample
4. Add to training dataset
5. Retrain model periodically
6. Validate improvement
7. Deploy if better
```

**Acceptance Criteria**:
- [ ] Track admin decisions
- [ ] Identify patterns in overrides
- [ ] Suggest policy adjustments
- [ ] Auto-tune detection thresholds
- [ ] Incorporate feedback into training
- [ ] Detect model drift
- [ ] Alert on accuracy degradation

**Tests**:
```typescript
// tests/ml/response-learning.test.ts
describe('Autonomous Response Learning', () => {
  it('should track admin release decision')
  it('should track admin delete decision')
  it('should identify false positive patterns')
  it('should suggest threshold adjustments')
  it('should create training samples')
  it('should detect model drift')
  it('should alert on accuracy drop')
});
```

**Implementation**:
- `lib/ml/response-learner.ts`
- `lib/ml/policy-suggester.ts`
- `lib/ml/drift-detector.ts`

---

### Slice 7.3: Explainable AI

**Goal**: Human-understandable threat explanations

**User Story**:
> As an email user or admin, I need to understand why an email was flagged so that I can verify the decision and learn to identify threats myself.

**Explanation Format**:
```typescript
interface ThreatExplanation {
  summary: string;  // "This email appears to be a phishing attempt"

  confidence: {
    score: number;  // 0.87
    level: 'low' | 'medium' | 'high' | 'very_high';
  };

  reasons: Array<{
    factor: string;  // "Sender domain is new"
    impact: 'high' | 'medium' | 'low';
    detail: string;  // "Domain registered 3 days ago"
    evidence: string;  // "Domain age: 3 days"
  }>;

  similarThreats: Array<{
    id: string;
    similarity: number;
    summary: string;
  }>;

  recommendations: Array<{
    action: string;  // "Do not click any links"
    priority: 'required' | 'suggested';
  }>;
}
```

**Explanation Techniques**:
```
1. Feature attribution:
   - SHAP values for each feature
   - "Domain age contributed 30% to threat score"

2. Rule-based explanations:
   - Pattern matching
   - "Contains urgency language: 'act immediately'"

3. Similarity-based:
   - Find similar known threats
   - "Similar to confirmed phishing campaign XYZ"

4. Counterfactual:
   - What would make it safe?
   - "Would be safe if sender domain was older than 30 days"
```

**Acceptance Criteria**:
- [ ] Generate human-readable summary
- [ ] List top contributing factors
- [ ] Provide evidence for each factor
- [ ] Find similar known threats
- [ ] Generate actionable recommendations
- [ ] Support multiple explanation depths
- [ ] API for explanation retrieval

**Tests**:
```typescript
// tests/ml/explainability.test.ts
describe('Explainable AI', () => {
  it('should generate summary explanation')
  it('should list contributing factors')
  it('should rank factors by impact')
  it('should provide evidence')
  it('should find similar threats')
  it('should generate recommendations')
  it('should support brief explanation')
  it('should support detailed explanation')
});
```

**Implementation**:
- `lib/ml/explainer.ts`
- `lib/ml/evidence-linker.ts`
- `lib/ml/similarity-finder.ts`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    ML & Predictive Pipeline                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    Prediction Layer                      │   │
│   │                                                          │   │
│   │  Email → Feature Extraction → Model Inference → Score   │   │
│   │                                                          │   │
│   │  ┌──────────────┐   ┌──────────────┐   ┌────────────┐  │   │
│   │  │   Feature    │   │    Model     │   │   Score    │  │   │
│   │  │   Extractor  │──▶│   Predictor  │──▶│   Output   │  │   │
│   │  │   (50+ feat) │   │   (<10ms)    │   │   (0-1)    │  │   │
│   │  └──────────────┘   └──────────────┘   └────────────┘  │   │
│   │                                                          │   │
│   └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                   Explanation Layer                      │   │
│   │                                                          │   │
│   │  ┌──────────────┐   ┌──────────────┐   ┌────────────┐  │   │
│   │  │   Feature    │   │  Similarity  │   │   Human    │  │   │
│   │  │  Attribution │   │   Finder     │   │  Readable  │  │   │
│   │  │   (SHAP)     │   │              │   │  Summary   │  │   │
│   │  └──────────────┘   └──────────────┘   └────────────┘  │   │
│   │                                                          │   │
│   └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    Learning Layer                        │   │
│   │                                                          │   │
│   │  Admin Decision → Training Sample → Model Retrain       │   │
│   │                                                          │   │
│   │  ┌──────────────┐   ┌──────────────┐   ┌────────────┐  │   │
│   │  │   Decision   │   │   Training   │   │   Model    │  │   │
│   │  │   Collector  │──▶│   Pipeline   │──▶│  Deployer  │  │   │
│   │  └──────────────┘   └──────────────┘   └────────────┘  │   │
│   │                                                          │   │
│   │  ┌──────────────┐   ┌──────────────┐                    │   │
│   │  │    Drift     │   │   Policy     │                    │   │
│   │  │   Detector   │   │  Suggester   │                    │   │
│   │  └──────────────┘   └──────────────┘                    │   │
│   │                                                          │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Model Features

```typescript
interface EmailFeatures {
  // Sender features
  sender: {
    domainAge: number;
    domainReputation: number;
    isFirstContact: boolean;
    historicalThreatRate: number;
    spfResult: string;
    dkimResult: string;
    dmarcResult: string;
  };

  // Content features
  content: {
    urgencyScore: number;
    financialRequestScore: number;
    credentialRequestScore: number;
    linkCount: number;
    suspiciousLinkCount: number;
    attachmentCount: number;
    attachmentRisk: number;
    subjectLength: number;
    bodyLength: number;
  };

  // Recipient features
  recipient: {
    isVip: boolean;
    isExecutive: boolean;
    role: string;
    historicalTargetRate: number;
  };

  // Behavioral features
  behavioral: {
    anomalyScore: number;
    baselineDeviation: number;
    firstContactRisk: number;
    lookalikeDomainScore: number;
  };

  // Technical features
  technical: {
    headerAnomalyCount: number;
    replyToMismatch: boolean;
    returnPathMismatch: boolean;
    suspiciousEncodingUsed: boolean;
  };
}
```

## Success Metrics

| Metric | Before | After |
|--------|--------|-------|
| vs Barracuda | 68 | 70 |
| Innovation | 66 | 74 |
| Production Readiness | 100 | 100 |
| Test Count | 1,930 | 2,000 |
| ML Features | Basic | Predictive + Learning + Explainable |

## Final Project Status

After Phase 7, Swordfish achieves:

| Metric | Target | Achieved |
|--------|--------|----------|
| Production Readiness | 100 | ✅ 100 |
| vs Barracuda (50=parity) | 60+ | ✅ 70 |
| Innovation (50=innovative) | 60+ | ✅ 74 |
| Test Count | 2,000 | ✅ 2,000 |
