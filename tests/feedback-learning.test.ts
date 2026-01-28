/**
 * Phase 5: Feedback Learning System Tests
 *
 * Tests for the continuous learning from user feedback:
 * 1. Pattern extraction from feedback
 * 2. Rule creation from high-confidence patterns
 * 3. Score adjustment calculation
 * 4. Sender promotion/demotion
 * 5. Analytics aggregation
 */

import {
  calculateRuleAdjustment,
  type LearnedRule,
} from '../lib/feedback/feedback-learning';

describe('Phase 5: Feedback Learning System', () => {
  describe('calculateRuleAdjustment', () => {
    it('should return zero adjustment for empty rules', () => {
      const result = calculateRuleAdjustment([]);

      expect(result.adjustment).toBe(0);
      expect(result.appliedRules).toHaveLength(0);
      expect(result.explanation).toBe('');
    });

    it('should calculate weighted adjustment for single trust boost rule', () => {
      const rules: LearnedRule[] = [
        {
          rule_id: 'rule-1',
          rule_type: 'trust_boost',
          condition: {
            field: 'domain',
            operator: 'equals',
            value: 'trusted-domain.com',
          },
          score_adjustment: -15,
          confidence: 80,
          source_feedback_count: 10,
          created_at: new Date(),
          expires_at: null,
        },
      ];

      const result = calculateRuleAdjustment(rules);

      // -15 * (80/100) = -12
      expect(result.adjustment).toBe(-12);
      expect(result.appliedRules).toContain('rule-1');
      expect(result.explanation).toContain('trusted-domain.com');
      expect(result.explanation).toContain('reduced');
    });

    it('should calculate weighted adjustment for suspicion boost rule', () => {
      const rules: LearnedRule[] = [
        {
          rule_id: 'rule-2',
          rule_type: 'suspicion_boost',
          condition: {
            field: 'domain',
            operator: 'equals',
            value: 'suspicious-domain.com',
          },
          score_adjustment: 20,
          confidence: 90,
          source_feedback_count: 8,
          created_at: new Date(),
          expires_at: null,
        },
      ];

      const result = calculateRuleAdjustment(rules);

      // 20 * (90/100) = 18
      expect(result.adjustment).toBe(18);
      expect(result.appliedRules).toContain('rule-2');
      expect(result.explanation).toContain('suspicious-domain.com');
      expect(result.explanation).toContain('increased');
    });

    it('should combine multiple rules correctly', () => {
      const rules: LearnedRule[] = [
        {
          rule_id: 'rule-1',
          rule_type: 'trust_boost',
          condition: {
            field: 'domain',
            operator: 'equals',
            value: 'marketing.example.com',
          },
          score_adjustment: -15,
          confidence: 100,
          source_feedback_count: 20,
          created_at: new Date(),
          expires_at: null,
        },
        {
          rule_id: 'rule-2',
          rule_type: 'trust_boost',
          condition: {
            field: 'url_pattern',
            operator: 'equals',
            value: 'tracking.example.com',
          },
          score_adjustment: -10,
          confidence: 80,
          source_feedback_count: 15,
          created_at: new Date(),
          expires_at: null,
        },
      ];

      const result = calculateRuleAdjustment(rules);

      // -15 * (100/100) + -10 * (80/100) = -15 + -8 = -23
      expect(result.adjustment).toBe(-23);
      expect(result.appliedRules).toHaveLength(2);
    });

    it('should cap positive adjustment at +30', () => {
      const rules: LearnedRule[] = [
        {
          rule_id: 'rule-1',
          rule_type: 'suspicion_boost',
          condition: {
            field: 'domain',
            operator: 'equals',
            value: 'very-bad-domain.com',
          },
          score_adjustment: 50, // Will be capped
          confidence: 100,
          source_feedback_count: 50,
          created_at: new Date(),
          expires_at: null,
        },
      ];

      const result = calculateRuleAdjustment(rules);

      expect(result.adjustment).toBe(30); // Capped at +30
    });

    it('should cap negative adjustment at -30', () => {
      const rules: LearnedRule[] = [
        {
          rule_id: 'rule-1',
          rule_type: 'trust_boost',
          condition: {
            field: 'domain',
            operator: 'equals',
            value: 'very-trusted-domain.com',
          },
          score_adjustment: -20,
          confidence: 100,
          source_feedback_count: 100,
          created_at: new Date(),
          expires_at: null,
        },
        {
          rule_id: 'rule-2',
          rule_type: 'trust_boost',
          condition: {
            field: 'domain',
            operator: 'equals',
            value: 'another-trusted-domain.com',
          },
          score_adjustment: -20,
          confidence: 100,
          source_feedback_count: 100,
          created_at: new Date(),
          expires_at: null,
        },
      ];

      const result = calculateRuleAdjustment(rules);

      // Would be -40, but capped at -30
      expect(result.adjustment).toBe(-30);
    });

    it('should weight adjustment by confidence correctly', () => {
      const lowConfidenceRule: LearnedRule[] = [
        {
          rule_id: 'rule-1',
          rule_type: 'trust_boost',
          condition: {
            field: 'domain',
            operator: 'equals',
            value: 'uncertain-domain.com',
          },
          score_adjustment: -20,
          confidence: 50, // Low confidence
          source_feedback_count: 5,
          created_at: new Date(),
          expires_at: null,
        },
      ];

      const result = calculateRuleAdjustment(lowConfidenceRule);

      // -20 * (50/100) = -10
      expect(result.adjustment).toBe(-10);
    });

    it('should include feedback count in explanation', () => {
      const rules: LearnedRule[] = [
        {
          rule_id: 'rule-1',
          rule_type: 'trust_boost',
          condition: {
            field: 'domain',
            operator: 'equals',
            value: 'test-domain.com',
          },
          score_adjustment: -15,
          confidence: 80,
          source_feedback_count: 25,
          created_at: new Date(),
          expires_at: null,
        },
      ];

      const result = calculateRuleAdjustment(rules);

      expect(result.explanation).toContain('25 feedback samples');
    });
  });

  describe('LearnedRule Types', () => {
    it('should support trust_boost rule type', () => {
      const rule: LearnedRule = {
        rule_id: 'test-1',
        rule_type: 'trust_boost',
        condition: {
          field: 'domain',
          operator: 'equals',
          value: 'example.com',
        },
        score_adjustment: -15,
        confidence: 80,
        source_feedback_count: 10,
        created_at: new Date(),
        expires_at: null,
      };

      expect(rule.rule_type).toBe('trust_boost');
      expect(rule.score_adjustment).toBeLessThan(0);
    });

    it('should support suspicion_boost rule type', () => {
      const rule: LearnedRule = {
        rule_id: 'test-2',
        rule_type: 'suspicion_boost',
        condition: {
          field: 'domain',
          operator: 'equals',
          value: 'bad.com',
        },
        score_adjustment: 20,
        confidence: 90,
        source_feedback_count: 8,
        created_at: new Date(),
        expires_at: null,
      };

      expect(rule.rule_type).toBe('suspicion_boost');
      expect(rule.score_adjustment).toBeGreaterThan(0);
    });

    it('should support auto_pass rule type', () => {
      const rule: LearnedRule = {
        rule_id: 'test-3',
        rule_type: 'auto_pass',
        condition: {
          field: 'domain',
          operator: 'equals',
          value: 'very-trusted.com',
        },
        score_adjustment: -30,
        confidence: 95,
        source_feedback_count: 50,
        created_at: new Date(),
        expires_at: null,
      };

      expect(rule.rule_type).toBe('auto_pass');
    });

    it('should support auto_flag rule type', () => {
      const rule: LearnedRule = {
        rule_id: 'test-4',
        rule_type: 'auto_flag',
        condition: {
          field: 'domain',
          operator: 'equals',
          value: 'known-threat.com',
        },
        score_adjustment: 30,
        confidence: 95,
        source_feedback_count: 30,
        created_at: new Date(),
        expires_at: null,
      };

      expect(rule.rule_type).toBe('auto_flag');
    });
  });

  describe('Rule Condition Operators', () => {
    it('should support equals operator', () => {
      const rule: LearnedRule = {
        rule_id: 'test-1',
        rule_type: 'trust_boost',
        condition: {
          field: 'domain',
          operator: 'equals',
          value: 'exact-match.com',
        },
        score_adjustment: -10,
        confidence: 80,
        source_feedback_count: 10,
        created_at: new Date(),
        expires_at: null,
      };

      expect(rule.condition.operator).toBe('equals');
    });

    it('should support contains operator', () => {
      const rule: LearnedRule = {
        rule_id: 'test-2',
        rule_type: 'trust_boost',
        condition: {
          field: 'subject_pattern',
          operator: 'contains',
          value: 'newsletter',
        },
        score_adjustment: -10,
        confidence: 75,
        source_feedback_count: 15,
        created_at: new Date(),
        expires_at: null,
      };

      expect(rule.condition.operator).toBe('contains');
    });
  });

  describe('Rule Expiration', () => {
    it('should support null expires_at (no expiration)', () => {
      const rule: LearnedRule = {
        rule_id: 'test-1',
        rule_type: 'trust_boost',
        condition: {
          field: 'domain',
          operator: 'equals',
          value: 'permanent.com',
        },
        score_adjustment: -15,
        confidence: 90,
        source_feedback_count: 50,
        created_at: new Date(),
        expires_at: null,
      };

      expect(rule.expires_at).toBeNull();
    });

    it('should support specific expires_at date', () => {
      const expirationDate = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000); // 90 days
      const rule: LearnedRule = {
        rule_id: 'test-2',
        rule_type: 'trust_boost',
        condition: {
          field: 'domain',
          operator: 'equals',
          value: 'temporary.com',
        },
        score_adjustment: -10,
        confidence: 70,
        source_feedback_count: 5,
        created_at: new Date(),
        expires_at: expirationDate,
      };

      expect(rule.expires_at).toEqual(expirationDate);
      expect(rule.expires_at!.getTime()).toBeGreaterThan(Date.now());
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle marketing email false positive reduction', () => {
      // Scenario: User marks marketing emails as safe, system learns
      const marketingRules: LearnedRule[] = [
        {
          rule_id: 'marketing-1',
          rule_type: 'trust_boost',
          condition: {
            field: 'domain',
            operator: 'equals',
            value: 'newsletter.company.com',
          },
          score_adjustment: -15,
          confidence: 85,
          source_feedback_count: 12,
          created_at: new Date(),
          expires_at: null,
        },
        {
          rule_id: 'marketing-2',
          rule_type: 'trust_boost',
          condition: {
            field: 'url_pattern',
            operator: 'equals',
            value: 'tracking.company.com',
          },
          score_adjustment: -10,
          confidence: 80,
          source_feedback_count: 10,
          created_at: new Date(),
          expires_at: null,
        },
      ];

      const result = calculateRuleAdjustment(marketingRules);

      // Should reduce score significantly for learned marketing patterns
      expect(result.adjustment).toBeLessThan(0);
      expect(result.adjustment).toBeGreaterThanOrEqual(-30); // Capped
      expect(result.appliedRules).toHaveLength(2);
    });

    it('should handle phishing false negative detection improvement', () => {
      // Scenario: User reports missed phishing, system learns
      const phishingRules: LearnedRule[] = [
        {
          rule_id: 'phish-1',
          rule_type: 'suspicion_boost',
          condition: {
            field: 'domain',
            operator: 'equals',
            value: 'suspicious-sender.xyz',
          },
          score_adjustment: 20,
          confidence: 90,
          source_feedback_count: 5,
          created_at: new Date(),
          expires_at: null,
        },
      ];

      const result = calculateRuleAdjustment(phishingRules);

      // Should increase score for known bad patterns
      expect(result.adjustment).toBeGreaterThan(0);
      expect(result.explanation).toContain('increased');
    });

    it('should balance conflicting rules appropriately', () => {
      // Scenario: Both positive and negative signals for same email
      const mixedRules: LearnedRule[] = [
        {
          rule_id: 'trust-1',
          rule_type: 'trust_boost',
          condition: {
            field: 'domain',
            operator: 'equals',
            value: 'reputable-company.com',
          },
          score_adjustment: -15,
          confidence: 80,
          source_feedback_count: 10,
          created_at: new Date(),
          expires_at: null,
        },
        {
          rule_id: 'suspicion-1',
          rule_type: 'suspicion_boost',
          condition: {
            field: 'url_pattern',
            operator: 'equals',
            value: 'suspicious-link.xyz',
          },
          score_adjustment: 10,
          confidence: 70,
          source_feedback_count: 3,
          created_at: new Date(),
          expires_at: null,
        },
      ];

      const result = calculateRuleAdjustment(mixedRules);

      // Net effect: -15 * 0.80 + 10 * 0.70 = -12 + 7 = -5
      expect(result.adjustment).toBe(-5);
      expect(result.appliedRules).toHaveLength(2);
    });
  });
});
