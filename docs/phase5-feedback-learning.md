# Phase 5: Feedback Learning System

## Overview

Phase 5 implements a continuous learning system that processes user feedback to automatically improve threat detection accuracy over time. This is the final phase of the 5-phase false positive reduction strategy.

**Expected Impact**: Additional 5-10% false positive reduction through learned patterns

## Architecture

### Core Components

1. **Feedback Learning Module** (`lib/feedback/feedback-learning.ts`)
   - Pattern extraction from user feedback
   - Rule creation from high-confidence patterns
   - Sender promotion/demotion based on feedback ratios
   - Comprehensive analytics

2. **Database Schema** (`lib/db/migrations/020_feedback_learning.sql`)
   - `feedback_patterns` - Stores extracted patterns from feedback
   - `learned_rules` - Detection rules created from patterns
   - `feedback_learning_log` - Audit trail for learning events

3. **API Integration**
   - Feedback API triggers learning (`app/api/threats/[id]/feedback/route.ts`)
   - Analytics API provides insights (`app/api/feedback/analytics/route.ts`)

4. **Detection Pipeline Integration** (`lib/detection/pipeline.ts`)
   - Applies learned rules during threat analysis
   - Adjusts scores based on accumulated feedback patterns

## How It Works

### 1. Feedback Processing Flow

```
User submits feedback → API receives feedback → processFeedback() triggered
                                                       ↓
                          ┌────────────────────────────┴────────────────────────────┐
                          ↓                            ↓                            ↓
                  Update Sender            Extract Patterns            Evaluate Sender
                  Reputation               (domain, URL, subject)      Promotion/Demotion
                          ↓                            ↓
                          └────────────────────────────┴─────→ Create Rules if
                                                               threshold met
```

### 2. Pattern Extraction

When a user submits feedback, the system extracts patterns:

| Pattern Type | Description | Example |
|-------------|-------------|---------|
| `domain` | Sender domain | `newsletter.company.com` |
| `url_pattern` | URL domains in email | `tracking.company.com` |
| `subject_pattern` | Common subject patterns | `newsletter`, `weekly.*update` |
| `content_pattern` | Content patterns | (Future) |

### 3. Rule Creation Thresholds

Rules are automatically created when patterns meet these criteria:
- **Minimum occurrences**: 5 feedback instances
- **Minimum confidence**: 70%
- **Unique**: No existing rule for the same pattern

### 4. Score Adjustment

During detection, learned rules adjust the threat score:

```typescript
// Rule adjustment formula
weightedAdjustment = score_adjustment * (confidence / 100)

// Total adjustment capped at ±30
totalAdjustment = Math.max(-30, Math.min(30, sum(weightedAdjustments)))
```

### 5. Sender Promotion/Demotion

Based on feedback ratios:

| Condition | Action | New Category |
|-----------|--------|--------------|
| ≥80% safe feedback, ≥5 safe confirmations | Promotion | `marketing` |
| ≥50% threat/spam feedback, ≥3 reports | Demotion | `suspicious` |

## Database Schema

### feedback_patterns

```sql
CREATE TABLE feedback_patterns (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(255) NOT NULL,
  pattern_type VARCHAR(50) NOT NULL,     -- domain, url_pattern, subject_pattern, content_pattern
  pattern_value TEXT NOT NULL,
  feedback_type VARCHAR(50) NOT NULL,    -- false_positive, false_negative, confirmed_threat
  confidence INTEGER DEFAULT 10,          -- 0-100
  occurrence_count INTEGER DEFAULT 1,
  first_seen TIMESTAMP WITH TIME ZONE,
  last_seen TIMESTAMP WITH TIME ZONE,
  is_active BOOLEAN DEFAULT true,
  UNIQUE(tenant_id, pattern_type, pattern_value, feedback_type)
);
```

### learned_rules

```sql
CREATE TABLE learned_rules (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(255) NOT NULL,
  rule_type VARCHAR(50) NOT NULL,         -- trust_boost, suspicion_boost, auto_pass, auto_flag
  condition_field VARCHAR(100) NOT NULL,
  condition_operator VARCHAR(50) DEFAULT 'equals',
  condition_value TEXT NOT NULL,
  score_adjustment INTEGER NOT NULL,      -- -50 to +50
  confidence INTEGER DEFAULT 70,
  source_feedback_count INTEGER DEFAULT 0,
  expires_at TIMESTAMP WITH TIME ZONE,    -- Rules expire after 90 days
  UNIQUE(tenant_id, condition_field, condition_value)
);
```

## API Endpoints

### Submit Feedback (existing, now triggers learning)

```
POST /api/threats/{id}/feedback
```

```json
{
  "feedbackType": "false_positive",
  "notes": "This is a legitimate marketing email",
  "correctedVerdict": "pass"
}
```

Response includes learning results:
```json
{
  "success": true,
  "feedbackId": "uuid",
  "message": "Thank you for reporting this as a false positive..."
}
```

### Get Feedback Analytics

```
GET /api/feedback/analytics
```

Response:
```json
{
  "success": true,
  "analytics": {
    "total_feedback": 156,
    "false_positives": 42,
    "false_negatives": 8,
    "confirmed_threats": 106,
    "accuracy_rate": 67.9,
    "top_fp_domains": [
      { "domain": "newsletter.company.com", "count": 12 },
      { "domain": "marketing.vendor.com", "count": 8 }
    ],
    "top_fn_senders": [
      { "sender": "spoofed@example.com", "count": 3 }
    ],
    "patterns_learned": 23,
    "senders_promoted": 5,
    "senders_demoted": 2,
    "trend_7d": {
      "fp_rate": 15.2,
      "fn_rate": 3.1,
      "accuracy": 81.7
    }
  }
}
```

## Rule Types

| Type | Score Adjustment | Use Case |
|------|------------------|----------|
| `trust_boost` | -15 (typical) | Reduce threat score for known safe patterns |
| `suspicion_boost` | +20 (typical) | Increase threat score for known bad patterns |
| `auto_pass` | -30 | Highly trusted patterns (future) |
| `auto_flag` | +30 | Known malicious patterns (future) |

## Confidence Decay

Patterns lose confidence over time if not reinforced:

```sql
-- Reduce confidence by 5% for patterns not seen in 30 days
UPDATE feedback_patterns
SET confidence = GREATEST(10, confidence - 5)
WHERE last_seen < NOW() - INTERVAL '30 days';

-- Deactivate patterns with very low confidence
UPDATE feedback_patterns
SET is_active = false
WHERE confidence < 20
  AND last_seen < NOW() - INTERVAL '60 days';
```

## Integration with Detection Pipeline

The pipeline applies learned rules in Phase 5 of detection:

```typescript
// Phase 5: Apply learned rules from user feedback
const appliedRules = await getApplicableRules({
  tenantId,
  senderDomain,
  urls,
  subject,
});

if (appliedRules.length > 0) {
  const { adjustment, appliedRules: ruleIds, explanation } = calculateRuleAdjustment(appliedRules);
  if (adjustment !== 0) {
    overallScore = Math.max(0, Math.min(100, overallScore + adjustment));

    allSignals.push({
      type: 'feedback_learning',
      severity: adjustment < 0 ? 'info' : 'warning',
      score: 0,
      detail: explanation,
      metadata: {
        originalScore,
        adjustedScore: overallScore,
        adjustment,
        rulesApplied: ruleIds.length,
      },
    });
  }
}
```

## Testing

Run Phase 5 tests:

```bash
npm test -- tests/feedback-learning.test.ts
```

Tests cover:
- Score adjustment calculation
- Rule type validation
- Confidence weighting
- Adjustment capping (±30)
- Integration scenarios (marketing emails, phishing detection)

## Monitoring & Maintenance

### Key Metrics to Track

1. **Accuracy Rate**: `(total - FP - FN) / total * 100`
2. **FP Rate**: `FP / total * 100` (target: <15%)
3. **FN Rate**: `FN / total * 100` (target: <5%)
4. **Patterns Learned**: Number of active patterns
5. **Senders Promoted/Demoted**: Trust changes from feedback

### Recommended Maintenance Tasks

1. **Weekly**: Run confidence decay function
2. **Monthly**: Review learned rules for accuracy
3. **Quarterly**: Audit top FP/FN domains and adjust thresholds

### Scheduled Functions

```sql
-- Run weekly to expire old rules
SELECT expire_old_learned_rules();

-- Run weekly to decay pattern confidence
SELECT decay_pattern_confidence();
```

## Security Considerations

1. **Tenant Isolation**: All patterns and rules are scoped to tenant_id
2. **Rate Limiting**: Implicit through feedback submission limits
3. **Rule Expiration**: Rules automatically expire after 90 days
4. **Score Caps**: Adjustments capped at ±30 to prevent manipulation
5. **Audit Trail**: All learning events logged in feedback_learning_log

## Future Enhancements

1. **Content Patterns**: Extract patterns from email body
2. **ML Pattern Detection**: Use ML to identify non-obvious patterns
3. **Cross-Tenant Learning**: Learn from anonymized cross-tenant patterns
4. **Automated Threshold Tuning**: Adjust detection thresholds based on feedback trends
5. **Feedback Quality Scoring**: Weight feedback by user reliability

## Dependencies

- Phase 1: Sender Reputation System (provides base reputation data)
- Phase 2: Context-Aware URL Classification (URL reputation context)
- Phase 3: Threshold Tuning (balanced threshold configuration)
- Phase 4: LLM Prompt Improvements (accurate initial classification)
