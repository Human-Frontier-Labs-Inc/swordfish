/**
 * Phase 5: Feedback Learning System
 *
 * This module implements continuous learning from user feedback to:
 * 1. Update sender reputation scores automatically
 * 2. Extract patterns from false positives/negatives
 * 3. Build learned pattern rules for future detection
 * 4. Provide feedback analytics for tuning
 *
 * Expected Impact: Additional 5-10% false positive reduction through learned patterns
 */

import { sql } from '../db';

// ============================================================================
// Types
// ============================================================================

export interface FeedbackPattern {
  id: string;
  pattern_type: 'domain' | 'url_pattern' | 'subject_pattern' | 'content_pattern';
  pattern_value: string;
  feedback_type: 'false_positive' | 'false_negative' | 'confirmed_threat';
  confidence: number; // 0-100
  occurrence_count: number;
  first_seen: Date;
  last_seen: Date;
  is_active: boolean;
  metadata: Record<string, unknown>;
}

export interface FeedbackAnalytics {
  total_feedback: number;
  false_positives: number;
  false_negatives: number;
  confirmed_threats: number;
  accuracy_rate: number;
  top_fp_domains: Array<{ domain: string; count: number }>;
  top_fn_senders: Array<{ sender: string; count: number }>;
  patterns_learned: number;
  senders_promoted: number;
  senders_demoted: number;
  trend_7d: {
    fp_rate: number;
    fn_rate: number;
    accuracy: number;
  };
}

export interface LearnedRule {
  rule_id: string;
  rule_type: 'trust_boost' | 'suspicion_boost' | 'auto_pass' | 'auto_flag';
  condition: {
    field: string;
    operator: 'equals' | 'contains' | 'matches' | 'starts_with' | 'ends_with';
    value: string;
  };
  score_adjustment: number;
  confidence: number;
  source_feedback_count: number;
  created_at: Date;
  expires_at: Date | null;
}

// ============================================================================
// Feedback Processing
// ============================================================================

/**
 * Process new feedback and trigger learning updates
 * Called after user submits feedback via API
 */
export async function processFeedback(params: {
  feedbackId: string;
  tenantId: string;
  messageId: string;
  senderDomain: string;
  senderEmail: string;
  feedbackType: string;
  originalVerdict: string;
  originalScore: number;
  subject?: string;
  urls?: string[];
}): Promise<{
  reputationUpdated: boolean;
  patternsExtracted: number;
  rulesCreated: number;
}> {
  const result = {
    reputationUpdated: false,
    patternsExtracted: 0,
    rulesCreated: 0,
  };

  try {
    // 1. Update sender reputation based on feedback
    result.reputationUpdated = await updateReputationFromFeedback(
      params.senderDomain,
      params.feedbackType
    );

    // 2. Extract patterns from the feedback
    const patterns = await extractPatternsFromFeedback(params);
    result.patternsExtracted = patterns.length;

    // 3. Check if any patterns meet threshold for rule creation
    const newRules = await createRulesFromPatterns(params.tenantId);
    result.rulesCreated = newRules.length;

    // 4. Check if sender qualifies for promotion/demotion
    await evaluateSenderPromotion(params.senderDomain);

    console.log(
      `📚 Feedback processed: reputation=${result.reputationUpdated}, ` +
        `patterns=${result.patternsExtracted}, rules=${result.rulesCreated}`
    );

    return result;
  } catch (error) {
    console.error('Failed to process feedback:', error);
    return result;
  }
}

/**
 * Update sender reputation based on feedback type
 */
async function updateReputationFromFeedback(
  domain: string,
  feedbackType: string
): Promise<boolean> {
  try {
    // Map feedback type to reputation field
    let field: string;
    switch (feedbackType) {
      case 'false_positive':
        field = 'safe';
        break;
      case 'false_negative':
      case 'phishing':
      case 'malware':
        field = 'threat';
        break;
      case 'spam':
        field = 'spam';
        break;
      case 'confirmed_threat':
        field = 'threat';
        break;
      default:
        return false;
    }

    // Update or create sender reputation
    await sql`
      INSERT INTO sender_reputation (
        domain,
        category,
        trust_score,
        email_count,
        user_feedback,
        last_seen
      ) VALUES (
        ${domain},
        'unknown',
        50,
        1,
        ${JSON.stringify({ safe: field === 'safe' ? 1 : 0, threat: field === 'threat' ? 1 : 0, spam: field === 'spam' ? 1 : 0 })}::jsonb,
        NOW()
      )
      ON CONFLICT (domain)
      DO UPDATE SET
        user_feedback = jsonb_set(
          sender_reputation.user_feedback,
          ${`{${field}}`},
          to_jsonb(COALESCE((sender_reputation.user_feedback->>${field})::int, 0) + 1)
        ),
        last_seen = NOW(),
        updated_at = NOW()
    `;

    return true;
  } catch (error) {
    console.error('Failed to update reputation from feedback:', error);
    return false;
  }
}

/**
 * Extract learnable patterns from feedback
 */
async function extractPatternsFromFeedback(params: {
  tenantId: string;
  senderDomain: string;
  feedbackType: string;
  subject?: string;
  urls?: string[];
}): Promise<FeedbackPattern[]> {
  const patterns: FeedbackPattern[] = [];
  const feedbackTypeNormalized = normalizeFeedbackType(params.feedbackType);

  try {
    // 1. Domain pattern (always extract)
    await upsertPattern({
      tenantId: params.tenantId,
      patternType: 'domain',
      patternValue: params.senderDomain,
      feedbackType: feedbackTypeNormalized,
    });
    patterns.push({
      id: '',
      pattern_type: 'domain',
      pattern_value: params.senderDomain,
      feedback_type: feedbackTypeNormalized,
      confidence: 0,
      occurrence_count: 1,
      first_seen: new Date(),
      last_seen: new Date(),
      is_active: true,
      metadata: {},
    });

    // 2. Subject patterns (for false positives)
    if (params.subject && feedbackTypeNormalized === 'false_positive') {
      const subjectPatterns = extractSubjectPatterns(params.subject);
      for (const pattern of subjectPatterns) {
        await upsertPattern({
          tenantId: params.tenantId,
          patternType: 'subject_pattern',
          patternValue: pattern,
          feedbackType: feedbackTypeNormalized,
        });
        patterns.push({
          id: '',
          pattern_type: 'subject_pattern',
          pattern_value: pattern,
          feedback_type: feedbackTypeNormalized,
          confidence: 0,
          occurrence_count: 1,
          first_seen: new Date(),
          last_seen: new Date(),
          is_active: true,
          metadata: {},
        });
      }
    }

    // 3. URL patterns (for both FP and FN)
    if (params.urls && params.urls.length > 0) {
      for (const url of params.urls) {
        const urlDomain = extractUrlDomain(url);
        if (urlDomain) {
          await upsertPattern({
            tenantId: params.tenantId,
            patternType: 'url_pattern',
            patternValue: urlDomain,
            feedbackType: feedbackTypeNormalized,
          });
          patterns.push({
            id: '',
            pattern_type: 'url_pattern',
            pattern_value: urlDomain,
            feedback_type: feedbackTypeNormalized,
            confidence: 0,
            occurrence_count: 1,
            first_seen: new Date(),
            last_seen: new Date(),
            is_active: true,
            metadata: {},
          });
        }
      }
    }

    return patterns;
  } catch (error) {
    console.error('Failed to extract patterns:', error);
    return patterns;
  }
}

/**
 * Upsert a pattern into the feedback_patterns table
 */
async function upsertPattern(params: {
  tenantId: string;
  patternType: string;
  patternValue: string;
  feedbackType: string;
}): Promise<void> {
  await sql`
    INSERT INTO feedback_patterns (
      tenant_id,
      pattern_type,
      pattern_value,
      feedback_type,
      confidence,
      occurrence_count,
      first_seen,
      last_seen,
      is_active,
      metadata
    ) VALUES (
      ${params.tenantId},
      ${params.patternType},
      ${params.patternValue},
      ${params.feedbackType},
      10,
      1,
      NOW(),
      NOW(),
      true,
      '{}'::jsonb
    )
    ON CONFLICT (tenant_id, pattern_type, pattern_value, feedback_type)
    DO UPDATE SET
      occurrence_count = feedback_patterns.occurrence_count + 1,
      last_seen = NOW(),
      confidence = LEAST(95, feedback_patterns.confidence + 5)
  `;
}

/**
 * Create detection rules from high-confidence patterns
 */
async function createRulesFromPatterns(tenantId: string): Promise<LearnedRule[]> {
  const rules: LearnedRule[] = [];

  try {
    // Find patterns with enough occurrences and confidence
    const highConfidencePatterns = await sql`
      SELECT
        id,
        pattern_type,
        pattern_value,
        feedback_type,
        confidence,
        occurrence_count
      FROM feedback_patterns
      WHERE tenant_id = ${tenantId}
      AND is_active = true
      AND occurrence_count >= 5
      AND confidence >= 70
      AND NOT EXISTS (
        SELECT 1 FROM learned_rules
        WHERE tenant_id = ${tenantId}
        AND condition_value = feedback_patterns.pattern_value
        AND condition_field = feedback_patterns.pattern_type
      )
    `;

    for (const pattern of highConfidencePatterns) {
      const rule = await createRuleFromPattern(tenantId, {
        pattern_type: pattern.pattern_type as string,
        pattern_value: pattern.pattern_value as string,
        feedback_type: pattern.feedback_type as string,
        confidence: pattern.confidence as number,
        occurrence_count: pattern.occurrence_count as number,
      });
      if (rule) {
        rules.push(rule);
      }
    }

    return rules;
  } catch (error) {
    console.error('Failed to create rules from patterns:', error);
    return rules;
  }
}

/**
 * Create a single rule from a high-confidence pattern
 */
async function createRuleFromPattern(
  tenantId: string,
  pattern: {
    pattern_type: string;
    pattern_value: string;
    feedback_type: string;
    confidence: number;
    occurrence_count: number;
  }
): Promise<LearnedRule | null> {
  try {
    // Determine rule type and score adjustment
    let ruleType: string;
    let scoreAdjustment: number;

    if (pattern.feedback_type === 'false_positive') {
      ruleType = 'trust_boost';
      scoreAdjustment = -15; // Reduce threat score
    } else if (pattern.feedback_type === 'false_negative') {
      ruleType = 'suspicion_boost';
      scoreAdjustment = 20; // Increase threat score
    } else {
      ruleType = 'suspicion_boost';
      scoreAdjustment = 10;
    }

    // Insert the rule
    const result = await sql`
      INSERT INTO learned_rules (
        tenant_id,
        rule_type,
        condition_field,
        condition_operator,
        condition_value,
        score_adjustment,
        confidence,
        source_feedback_count,
        created_at,
        expires_at
      ) VALUES (
        ${tenantId},
        ${ruleType},
        ${pattern.pattern_type},
        'equals',
        ${pattern.pattern_value},
        ${scoreAdjustment},
        ${pattern.confidence},
        ${pattern.occurrence_count},
        NOW(),
        NOW() + INTERVAL '90 days'
      )
      RETURNING id, created_at
    `;

    console.log(
      `📏 Created rule: ${ruleType} for ${pattern.pattern_type}=${pattern.pattern_value} (adj: ${scoreAdjustment})`
    );

    return {
      rule_id: result[0].id as string,
      rule_type: ruleType as LearnedRule['rule_type'],
      condition: {
        field: pattern.pattern_type,
        operator: 'equals',
        value: pattern.pattern_value,
      },
      score_adjustment: scoreAdjustment,
      confidence: pattern.confidence,
      source_feedback_count: pattern.occurrence_count,
      created_at: result[0].created_at as Date,
      expires_at: null,
    };
  } catch (error) {
    console.error('Failed to create rule from pattern:', error);
    return null;
  }
}

/**
 * Evaluate if sender should be promoted or demoted based on feedback
 */
async function evaluateSenderPromotion(domain: string): Promise<void> {
  try {
    const [sender] = await sql`
      SELECT
        category,
        trust_score,
        user_feedback
      FROM sender_reputation
      WHERE domain = ${domain}
    `;

    if (!sender) return;

    const feedback = sender.user_feedback as { safe: number; threat: number; spam: number };
    const total = feedback.safe + feedback.threat + feedback.spam;

    if (total < 5) return; // Not enough feedback

    const safeRatio = feedback.safe / total;
    const threatRatio = (feedback.threat + feedback.spam) / total;

    // Promotion: 80%+ safe feedback and at least 5 safe confirmations
    if (safeRatio >= 0.8 && feedback.safe >= 5 && sender.category === 'unknown') {
      const newTrustScore = Math.min(85, 50 + Math.round(safeRatio * 40));
      await sql`
        UPDATE sender_reputation
        SET
          category = 'marketing',
          trust_score = ${newTrustScore}
        WHERE domain = ${domain}
      `;
      console.log(`📈 Promoted ${domain} to marketing (trust: ${newTrustScore})`);
    }

    // Demotion: 50%+ threat/spam feedback
    if (threatRatio >= 0.5 && (feedback.threat + feedback.spam) >= 3) {
      const newTrustScore = Math.max(10, 50 - Math.round(threatRatio * 40));
      await sql`
        UPDATE sender_reputation
        SET
          category = 'suspicious',
          trust_score = ${newTrustScore}
        WHERE domain = ${domain}
      `;
      console.log(`📉 Demoted ${domain} to suspicious (trust: ${newTrustScore})`);
    }
  } catch (error) {
    console.error('Failed to evaluate sender promotion:', error);
  }
}

// ============================================================================
// Rule Application (for detection pipeline)
// ============================================================================

/**
 * Get applicable learned rules for an email
 * Called during detection to apply feedback-based adjustments
 */
export async function getApplicableRules(params: {
  tenantId: string;
  senderDomain: string;
  urls?: string[];
  subject?: string;
}): Promise<LearnedRule[]> {
  try {
    const rules = await sql`
      SELECT
        id as rule_id,
        rule_type,
        condition_field,
        condition_operator,
        condition_value,
        score_adjustment,
        confidence,
        source_feedback_count,
        created_at,
        expires_at
      FROM learned_rules
      WHERE tenant_id = ${params.tenantId}
      AND is_active = true
      AND (expires_at IS NULL OR expires_at > NOW())
      AND (
        (condition_field = 'domain' AND condition_value = ${params.senderDomain})
        OR (condition_field = 'url_pattern' AND condition_value = ANY(${params.urls || []}))
      )
      ORDER BY confidence DESC
      LIMIT 10
    `;

    return rules.map((r) => ({
      rule_id: r.rule_id as string,
      rule_type: r.rule_type as LearnedRule['rule_type'],
      condition: {
        field: r.condition_field as string,
        operator: r.condition_operator as 'equals',
        value: r.condition_value as string,
      },
      score_adjustment: r.score_adjustment as number,
      confidence: r.confidence as number,
      source_feedback_count: r.source_feedback_count as number,
      created_at: r.created_at as Date,
      expires_at: r.expires_at as Date | null,
    }));
  } catch (error) {
    console.error('Failed to get applicable rules:', error);
    return [];
  }
}

/**
 * Calculate total score adjustment from applicable rules
 */
export function calculateRuleAdjustment(rules: LearnedRule[]): {
  adjustment: number;
  appliedRules: string[];
  explanation: string;
} {
  if (rules.length === 0) {
    return { adjustment: 0, appliedRules: [], explanation: '' };
  }

  let totalAdjustment = 0;
  const appliedRules: string[] = [];
  const explanations: string[] = [];

  for (const rule of rules) {
    // Weight adjustment by confidence
    const weightedAdjustment = Math.round(rule.score_adjustment * (rule.confidence / 100));
    totalAdjustment += weightedAdjustment;
    appliedRules.push(rule.rule_id);

    const direction = weightedAdjustment < 0 ? 'reduced' : 'increased';
    explanations.push(
      `${rule.condition.field}="${rule.condition.value}" ${direction} score by ${Math.abs(weightedAdjustment)} (${rule.source_feedback_count} feedback samples)`
    );
  }

  // Cap total adjustment
  totalAdjustment = Math.max(-30, Math.min(30, totalAdjustment));

  return {
    adjustment: totalAdjustment,
    appliedRules,
    explanation: `Feedback learning: ${explanations.join('; ')}`,
  };
}

// ============================================================================
// Analytics
// ============================================================================

/**
 * Get comprehensive feedback analytics for a tenant
 */
export async function getFeedbackAnalytics(tenantId: string): Promise<FeedbackAnalytics> {
  try {
    // Total feedback counts
    const [totals] = await sql`
      SELECT
        COUNT(*)::int as total,
        COUNT(*) FILTER (WHERE feedback_type = 'false_positive')::int as false_positives,
        COUNT(*) FILTER (WHERE feedback_type = 'false_negative')::int as false_negatives,
        COUNT(*) FILTER (WHERE feedback_type = 'confirmed_threat')::int as confirmed
      FROM feedback
      WHERE tenant_id = ${tenantId}
    `;

    // Top false positive domains
    const topFPDomains = await sql`
      SELECT
        SUBSTRING(LOWER(t.sender_email) FROM '@(.+)$') as domain,
        COUNT(*)::int as count
      FROM feedback f
      JOIN threats t ON f.threat_id = t.id
      WHERE f.tenant_id = ${tenantId}
      AND f.feedback_type = 'false_positive'
      GROUP BY domain
      ORDER BY count DESC
      LIMIT 10
    `;

    // Top false negative senders
    const topFNSenders = await sql`
      SELECT
        t.sender_email as sender,
        COUNT(*)::int as count
      FROM feedback f
      JOIN threats t ON f.threat_id = t.id
      WHERE f.tenant_id = ${tenantId}
      AND f.feedback_type = 'false_negative'
      GROUP BY sender
      ORDER BY count DESC
      LIMIT 10
    `;

    // Patterns and rules counts
    const [patterns] = await sql`
      SELECT COUNT(*)::int as count
      FROM feedback_patterns
      WHERE tenant_id = ${tenantId}
      AND is_active = true
    `;

    // Sender promotions/demotions
    const [promotions] = await sql`
      SELECT
        COUNT(*) FILTER (WHERE category IN ('marketing', 'trusted', 'transactional'))::int as promoted,
        COUNT(*) FILTER (WHERE category = 'suspicious')::int as demoted
      FROM sender_reputation
      WHERE (user_feedback->>'safe')::int > 0
         OR (user_feedback->>'threat')::int > 0
         OR (user_feedback->>'spam')::int > 0
    `;

    // 7-day trend
    const [trend] = await sql`
      WITH recent AS (
        SELECT
          feedback_type,
          COUNT(*)::int as count
        FROM feedback
        WHERE tenant_id = ${tenantId}
        AND created_at >= NOW() - INTERVAL '7 days'
        GROUP BY feedback_type
      ),
      totals AS (
        SELECT
          COALESCE(SUM(count), 0)::int as total,
          COALESCE(SUM(count) FILTER (WHERE feedback_type = 'false_positive'), 0)::int as fp,
          COALESCE(SUM(count) FILTER (WHERE feedback_type = 'false_negative'), 0)::int as fn
        FROM recent
      )
      SELECT
        CASE WHEN total > 0 THEN ROUND((fp::numeric / total) * 100, 1) ELSE 0 END as fp_rate,
        CASE WHEN total > 0 THEN ROUND((fn::numeric / total) * 100, 1) ELSE 0 END as fn_rate,
        CASE WHEN total > 0 THEN ROUND(((total - fp - fn)::numeric / total) * 100, 1) ELSE 100 END as accuracy
      FROM totals
    `;

    // Calculate accuracy rate
    const total = totals.total || 0;
    const fp = totals.false_positives || 0;
    const fn = totals.false_negatives || 0;
    const accuracyRate = total > 0 ? ((total - fp - fn) / total) * 100 : 100;

    return {
      total_feedback: total,
      false_positives: fp,
      false_negatives: fn,
      confirmed_threats: totals.confirmed || 0,
      accuracy_rate: Math.round(accuracyRate * 10) / 10,
      top_fp_domains: topFPDomains.map((r) => ({
        domain: r.domain as string,
        count: r.count as number,
      })),
      top_fn_senders: topFNSenders.map((r) => ({
        sender: r.sender as string,
        count: r.count as number,
      })),
      patterns_learned: patterns?.count || 0,
      senders_promoted: promotions?.promoted || 0,
      senders_demoted: promotions?.demoted || 0,
      trend_7d: {
        fp_rate: parseFloat(trend?.fp_rate) || 0,
        fn_rate: parseFloat(trend?.fn_rate) || 0,
        accuracy: parseFloat(trend?.accuracy) || 100,
      },
    };
  } catch (error) {
    console.error('Failed to get feedback analytics:', error);
    return {
      total_feedback: 0,
      false_positives: 0,
      false_negatives: 0,
      confirmed_threats: 0,
      accuracy_rate: 0,
      top_fp_domains: [],
      top_fn_senders: [],
      patterns_learned: 0,
      senders_promoted: 0,
      senders_demoted: 0,
      trend_7d: { fp_rate: 0, fn_rate: 0, accuracy: 0 },
    };
  }
}

// ============================================================================
// Helpers
// ============================================================================

function normalizeFeedbackType(
  type: string
): 'false_positive' | 'false_negative' | 'confirmed_threat' {
  switch (type) {
    case 'false_positive':
      return 'false_positive';
    case 'false_negative':
    case 'phishing':
    case 'malware':
      return 'false_negative';
    default:
      return 'confirmed_threat';
  }
}

function extractSubjectPatterns(subject: string): string[] {
  const patterns: string[] = [];

  // Common marketing subject patterns
  const marketingPatterns = [
    /newsletter/i,
    /digest/i,
    /weekly.*update/i,
    /monthly.*report/i,
    /your.*subscription/i,
    /special.*offer/i,
    /limited.*time/i,
  ];

  for (const pattern of marketingPatterns) {
    if (pattern.test(subject)) {
      patterns.push(pattern.source);
    }
  }

  return patterns;
}

function extractUrlDomain(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

// Export for testing
export const __testing = {
  updateReputationFromFeedback,
  extractPatternsFromFeedback,
  createRulesFromPatterns,
  evaluateSenderPromotion,
};
