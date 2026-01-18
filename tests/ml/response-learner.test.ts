/**
 * ML Response Learner Tests
 *
 * TDD tests for the Response Learner module that learns from admin decisions
 * to improve detection accuracy over time.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock uuid - use inline function, no external reference
vi.mock('uuid', () => ({
  v4: () => `mock-uuid-${Date.now()}-${Math.random().toString(36).substring(7)}`,
}));

// Mock database - use inline function
vi.mock('@/lib/db', () => ({
  sql: vi.fn().mockImplementation(() => Promise.resolve([])),
}));

// Import the sql mock to control it in tests
import { sql } from '@/lib/db';

import {
  ResponseLearner,
  AdminDecision,
  EmailFeatures,
  PolicySuggestion,
  ThresholdAdjustment,
  DriftReport,
  DecisionFilters,
  Pattern,
} from '@/lib/ml/response-learner';

// Cast sql to mock type for test control
const mockSql = sql as ReturnType<typeof vi.fn>;

// Helper to create mock email features
function createMockEmailFeatures(overrides: Partial<EmailFeatures> = {}): EmailFeatures {
  return {
    senderDomain: 'example.com',
    senderEmail: 'sender@example.com',
    displayName: 'Test Sender',
    isFreemailProvider: false,
    domainAge: 365,
    urgencyScore: 25,
    threatLanguageScore: 15,
    linkCount: 2,
    shortenerLinkCount: 0,
    attachmentCount: 0,
    attachmentTypes: [],
    spfResult: 'pass',
    dkimResult: 'pass',
    dmarcResult: 'pass',
    deterministicScore: 20,
    mlScore: 25,
    mlCategory: 'legitimate',
    hasExternalLinks: true,
    requestsPersonalInfo: false,
    requestsFinancialAction: false,
    isReplyChain: false,
    ...overrides,
  };
}

// Helper to create mock admin decision
function createMockDecision(overrides: Partial<AdminDecision> = {}): AdminDecision {
  return {
    id: `decision-${Date.now()}-${Math.random()}`,
    tenantId: 'tenant-1',
    verdictId: `verdict-${Date.now()}`,
    originalVerdict: 'quarantine',
    adminAction: 'release',
    adminId: 'admin-1',
    reason: 'Known sender',
    timestamp: new Date(),
    emailFeatures: createMockEmailFeatures(),
    ...overrides,
  };
}

// Helper to create multiple decisions with patterns
function createDecisionsWithDomainPattern(
  domain: string,
  count: number,
  action: AdminDecision['adminAction'] = 'release'
): AdminDecision[] {
  const decisions: AdminDecision[] = [];
  for (let i = 0; i < count; i++) {
    decisions.push(
      createMockDecision({
        id: `decision-${domain}-${i}`,
        adminAction: action,
        timestamp: new Date(Date.now() - i * 24 * 60 * 60 * 1000),
        emailFeatures: createMockEmailFeatures({
          senderDomain: domain,
          senderEmail: `user${i}@${domain}`,
        }),
      })
    );
  }
  return decisions;
}

// Helper to convert decisions to DB row format
function toDbRows(decisions: AdminDecision[]) {
  return decisions.map((d) => ({
    id: d.id,
    tenant_id: d.tenantId,
    verdict_id: d.verdictId,
    original_verdict: d.originalVerdict,
    admin_action: d.adminAction,
    admin_id: d.adminId,
    reason: d.reason,
    timestamp: d.timestamp.toISOString(),
    email_features: JSON.stringify(d.emailFeatures),
    subsequent_reported_as_phish: d.subsequentReportedAsPhish,
    reported_at: d.reportedAt?.toISOString(),
  }));
}

describe('ResponseLearner', () => {
  let learner: ResponseLearner;

  beforeEach(() => {
    vi.clearAllMocks();
    mockSql.mockReset();
    mockSql.mockImplementation(() => Promise.resolve([]));
    learner = new ResponseLearner();
  });

  describe('Recording Decisions', () => {
    it('should record an admin decision', async () => {
      const decision = await learner.recordDecision({
        tenantId: 'tenant-1',
        verdictId: 'verdict-1',
        originalVerdict: 'quarantine',
        adminAction: 'release',
        adminId: 'admin-1',
        reason: 'Known sender',
        emailFeatures: createMockEmailFeatures(),
      });

      expect(decision.id).toBeDefined();
      expect(decision.timestamp).toBeInstanceOf(Date);
      expect(decision.tenantId).toBe('tenant-1');
      expect(decision.adminAction).toBe('release');
    });

    it('should track all admin action types', async () => {
      const actions: AdminDecision['adminAction'][] = [
        'release',
        'delete',
        'block',
        'whitelist',
        'confirm',
      ];

      for (const action of actions) {
        const decision = await learner.recordDecision({
          tenantId: 'tenant-1',
          verdictId: `verdict-${action}`,
          originalVerdict: 'quarantine',
          adminAction: action,
          adminId: 'admin-1',
          emailFeatures: createMockEmailFeatures(),
        });

        expect(decision.adminAction).toBe(action);
      }
    });

    it('should store email features snapshot at decision time', async () => {
      const features = createMockEmailFeatures({
        urgencyScore: 85,
        threatLanguageScore: 70,
        senderDomain: 'suspicious.com',
      });

      const decision = await learner.recordDecision({
        tenantId: 'tenant-1',
        verdictId: 'verdict-1',
        originalVerdict: 'quarantine',
        adminAction: 'release',
        adminId: 'admin-1',
        emailFeatures: features,
      });

      expect(decision.emailFeatures.urgencyScore).toBe(85);
      expect(decision.emailFeatures.threatLanguageScore).toBe(70);
      expect(decision.emailFeatures.senderDomain).toBe('suspicious.com');
    });

    it('should handle decisions without reason', async () => {
      const decision = await learner.recordDecision({
        tenantId: 'tenant-1',
        verdictId: 'verdict-1',
        originalVerdict: 'quarantine',
        adminAction: 'confirm',
        adminId: 'admin-1',
        emailFeatures: createMockEmailFeatures(),
      });

      expect(decision.reason).toBeUndefined();
    });
  });

  describe('Pattern Analysis', () => {
    it('should calculate override rate', async () => {
      const decisions: AdminDecision[] = [
        ...createDecisionsWithDomainPattern('example.com', 7, 'release'),
        ...createDecisionsWithDomainPattern('other.com', 3, 'confirm'),
      ];

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const analysis = await learner.analyzePatterns('tenant-1');

      // 7 releases out of 10 decisions (confirm is not an override)
      expect(analysis.overrideRate).toBe(0.7);
    });

    it('should identify false positive patterns by domain', async () => {
      const decisions = [
        ...createDecisionsWithDomainPattern('partner.com', 5, 'release'),
        ...createDecisionsWithDomainPattern('vendor.com', 3, 'release'),
        ...createDecisionsWithDomainPattern('random.com', 2, 'confirm'),
      ];

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const analysis = await learner.analyzePatterns('tenant-1');

      expect(analysis.falsePositivePatterns.length).toBeGreaterThan(0);

      const partnerPattern = analysis.falsePositivePatterns.find(
        (p) => p.type === 'domain' && p.features.domain === 'partner.com'
      );
      expect(partnerPattern).toBeDefined();
      expect(partnerPattern?.occurrences).toBe(5);
    });

    it('should identify false positive patterns by sender', async () => {
      const decisions: AdminDecision[] = [];
      const senderEmail = 'ceo@trusted-company.com';

      // Create sender pattern decisions (4)
      for (let i = 0; i < 4; i++) {
        decisions.push(
          createMockDecision({
            id: `decision-sender-${i}`,
            adminAction: 'release',
            emailFeatures: createMockEmailFeatures({
              senderEmail,
              senderDomain: 'trusted-company.com',
            }),
          })
        );
      }
      // Add padding decisions to meet minSampleSize of 10
      for (let i = 0; i < 6; i++) {
        decisions.push(
          createMockDecision({
            id: `decision-padding-${i}`,
            adminAction: 'confirm',
            emailFeatures: createMockEmailFeatures({
              senderEmail: `other${i}@other.com`,
              senderDomain: 'other.com',
            }),
          })
        );
      }

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const analysis = await learner.analyzePatterns('tenant-1');

      const senderPattern = analysis.falsePositivePatterns.find(
        (p) => p.type === 'sender' && p.features.sender === senderEmail
      );
      expect(senderPattern).toBeDefined();
    });

    it('should identify false negative patterns', async () => {
      const decisions: AdminDecision[] = [];

      // Emails that passed but were blocked by admin (financial requests)
      for (let i = 0; i < 4; i++) {
        decisions.push(
          createMockDecision({
            id: `decision-fn-${i}`,
            originalVerdict: 'pass',
            adminAction: 'block',
            emailFeatures: createMockEmailFeatures({
              requestsFinancialAction: true,
              urgencyScore: 60 + i * 5,
            }),
          })
        );
      }
      // Add padding decisions to meet minSampleSize of 10
      for (let i = 0; i < 6; i++) {
        decisions.push(
          createMockDecision({
            id: `decision-padding-${i}`,
            adminAction: 'confirm',
          })
        );
      }

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const analysis = await learner.analyzePatterns('tenant-1');

      expect(analysis.falseNegativePatterns.length).toBeGreaterThan(0);

      const financialPattern = analysis.falseNegativePatterns.find(
        (p) => p.features.requestsFinancialAction === true
      );
      expect(financialPattern).toBeDefined();
    });

    it('should track common override reasons', async () => {
      const decisions = [
        createMockDecision({ id: 'r1', reason: 'Known sender' }),
        createMockDecision({ id: 'r2', reason: 'Known sender' }),
        createMockDecision({ id: 'r3', reason: 'Known sender' }),
        createMockDecision({ id: 'r4', reason: 'Internal communication' }),
        createMockDecision({ id: 'r5', reason: 'Internal communication' }),
        createMockDecision({ id: 'r6', reason: 'Marketing email' }),
        // Add padding to meet minSampleSize of 10
        createMockDecision({ id: 'r7', reason: 'Other reason' }),
        createMockDecision({ id: 'r8', reason: 'Other reason' }),
        createMockDecision({ id: 'r9', reason: 'Another reason' }),
        createMockDecision({ id: 'r10', reason: 'Another reason' }),
      ];

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const analysis = await learner.analyzePatterns('tenant-1');

      expect(analysis.commonOverrideReasons.length).toBeGreaterThan(0);
      expect(analysis.commonOverrideReasons[0].reason).toBe('known sender');
      expect(analysis.commonOverrideReasons[0].count).toBe(3);
    });

    it('should calculate time-based trends', async () => {
      const decisions: AdminDecision[] = [];

      // Create decisions over 4 weeks
      for (let week = 0; week < 4; week++) {
        for (let i = 0; i < 5; i++) {
          decisions.push(
            createMockDecision({
              id: `decision-w${week}-${i}`,
              timestamp: new Date(Date.now() - (week * 7 + i) * 24 * 60 * 60 * 1000),
              adminAction: i % 3 === 0 ? 'release' : 'confirm',
            })
          );
        }
      }

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const analysis = await learner.analyzePatterns('tenant-1');

      expect(analysis.timeBasedTrends.length).toBeGreaterThan(0);
      expect(analysis.timeBasedTrends[0].period).toMatch(/Week -\d/);
    });

    it('should handle insufficient data gracefully', async () => {
      mockSql.mockResolvedValueOnce([
        {
          id: 'decision-1',
          tenant_id: 'tenant-1',
          verdict_id: 'verdict-1',
          original_verdict: 'quarantine',
          admin_action: 'release',
          admin_id: 'admin-1',
          reason: 'Test',
          timestamp: new Date().toISOString(),
          email_features: JSON.stringify(createMockEmailFeatures()),
        },
      ]);

      const analysis = await learner.analyzePatterns('tenant-1');

      expect(analysis.overrideRate).toBe(0);
      expect(analysis.falsePositivePatterns).toHaveLength(0);
      expect(analysis.totalDecisions).toBe(1);
    });
  });

  describe('Policy Suggestions', () => {
    it('should suggest whitelisting frequently released domains', async () => {
      const decisions = createDecisionsWithDomainPattern('trusted-partner.com', 8, 'release');
      // Add padding decisions to meet minSampleSize of 10
      for (let i = 0; i < 3; i++) {
        decisions.push(createMockDecision({ id: `padding-${i}`, adminAction: 'confirm' }));
      }

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const suggestions = await learner.suggestPolicyAdjustments('tenant-1');

      const whitelistSuggestion = suggestions.find(
        (s) =>
          s.type === 'whitelist_domain' && s.suggestedValue === 'trusted-partner.com'
      );
      expect(whitelistSuggestion).toBeDefined();
      expect(whitelistSuggestion?.confidence).toBeGreaterThan(0.7);
    });

    it('should suggest whitelisting specific senders', async () => {
      const senderEmail = 'vip@important-client.com';
      const decisions: AdminDecision[] = [];

      for (let i = 0; i < 5; i++) {
        decisions.push(
          createMockDecision({
            id: `decision-vip-${i}`,
            adminAction: 'release',
            emailFeatures: createMockEmailFeatures({
              senderEmail,
              senderDomain: 'important-client.com',
            }),
          })
        );
      }
      // Add padding decisions to meet minSampleSize of 10
      for (let i = 0; i < 5; i++) {
        decisions.push(createMockDecision({ id: `padding-${i}`, adminAction: 'confirm' }));
      }

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const suggestions = await learner.suggestPolicyAdjustments('tenant-1');

      const senderSuggestion = suggestions.find(
        (s) => s.type === 'whitelist_sender' && s.suggestedValue === senderEmail
      );
      expect(senderSuggestion).toBeDefined();
    });

    it('should suggest threshold adjustments for high FP rate', async () => {
      const decisions: AdminDecision[] = [];

      // Create many releases (high FP rate)
      for (let i = 0; i < 15; i++) {
        decisions.push(
          createMockDecision({
            id: `decision-fp-${i}`,
            adminAction: i < 10 ? 'release' : 'confirm', // 67% release rate
          })
        );
      }

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const suggestions = await learner.suggestPolicyAdjustments('tenant-1');

      const thresholdSuggestion = suggestions.find(
        (s) => s.type === 'adjust_threshold'
      );
      expect(thresholdSuggestion).toBeDefined();
      expect(thresholdSuggestion?.description).toContain('threshold');
    });

    it('should include confidence scores for suggestions', async () => {
      const decisions = createDecisionsWithDomainPattern('high-confidence.com', 10, 'release');

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const suggestions = await learner.suggestPolicyAdjustments('tenant-1');

      for (const suggestion of suggestions) {
        expect(suggestion.confidence).toBeGreaterThanOrEqual(0);
        expect(suggestion.confidence).toBeLessThanOrEqual(1);
      }
    });

    it('should estimate impact of suggestions', async () => {
      const decisions = createDecisionsWithDomainPattern('impact-test.com', 6, 'release');

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const suggestions = await learner.suggestPolicyAdjustments('tenant-1');

      for (const suggestion of suggestions) {
        expect(suggestion.impact).toBeDefined();
        if (suggestion.impact.expectedFPReduction !== undefined) {
          expect(suggestion.impact.expectedFPReduction).toBeGreaterThanOrEqual(0);
        }
      }
    });

    it('should sort suggestions by confidence and impact', async () => {
      const decisions = [
        ...createDecisionsWithDomainPattern('high-priority.com', 10, 'release'),
        ...createDecisionsWithDomainPattern('medium-priority.com', 5, 'release'),
        ...createDecisionsWithDomainPattern('low-priority.com', 3, 'release'),
      ];

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const suggestions = await learner.suggestPolicyAdjustments('tenant-1');

      // Should be sorted by confidence * impact
      for (let i = 1; i < suggestions.length; i++) {
        const prevScore =
          suggestions[i - 1].confidence *
          (suggestions[i - 1].impact.expectedFPReduction || 0);
        const currScore =
          suggestions[i].confidence * (suggestions[i].impact.expectedFPReduction || 0);
        expect(prevScore).toBeGreaterThanOrEqual(currScore);
      }
    });
  });

  describe('Threshold Auto-Tuning', () => {
    it('should analyze score distributions for tuning', async () => {
      const decisions: AdminDecision[] = [];

      // Released emails with various scores
      for (let i = 0; i < 10; i++) {
        decisions.push(
          createMockDecision({
            id: `decision-release-${i}`,
            adminAction: 'release',
            emailFeatures: createMockEmailFeatures({
              deterministicScore: 30 + i * 2,
              mlScore: 35 + i * 2,
            }),
          })
        );
      }

      // Blocked emails with various scores
      for (let i = 0; i < 10; i++) {
        decisions.push(
          createMockDecision({
            id: `decision-block-${i}`,
            adminAction: 'block',
            emailFeatures: createMockEmailFeatures({
              deterministicScore: 60 + i * 3,
              mlScore: 65 + i * 3,
            }),
          })
        );
      }

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const adjustments = await learner.autoTuneThresholds('tenant-1');

      expect(adjustments.length).toBeGreaterThan(0);
      for (const adj of adjustments) {
        expect(adj.thresholdName).toBeDefined();
        expect(adj.currentValue).toBeDefined();
        expect(adj.suggestedValue).toBeDefined();
        expect(adj.direction).toMatch(/increase|decrease/);
      }
    });

    it('should provide evidence for threshold adjustments', async () => {
      const decisions: AdminDecision[] = [];

      // Create decisions with clear pattern
      for (let i = 0; i < 15; i++) {
        decisions.push(
          createMockDecision({
            id: `decision-${i}`,
            adminAction: i < 10 ? 'release' : 'block',
            emailFeatures: createMockEmailFeatures({
              deterministicScore: 25 + i * 3,
              mlScore: 30 + i * 3,
            }),
          })
        );
      }

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const adjustments = await learner.autoTuneThresholds('tenant-1');

      for (const adj of adjustments) {
        expect(adj.evidence).toBeDefined();
        expect(adj.evidence.sampleSize).toBeGreaterThan(0);
      }
    });

    it('should support rollback for auto-tuning', async () => {
      const decisions: AdminDecision[] = [];
      for (let i = 0; i < 20; i++) {
        decisions.push(
          createMockDecision({
            id: `decision-${i}`,
            adminAction: i % 2 === 0 ? 'release' : 'block',
            emailFeatures: createMockEmailFeatures({
              deterministicScore: 30 + i * 2,
              mlScore: 35 + i * 2,
            }),
          })
        );
      }

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const adjustments = await learner.autoTuneThresholds('tenant-1');

      for (const adj of adjustments) {
        expect(adj.rollbackAvailable).toBe(true);
      }
    });

    it('should not suggest adjustments with insufficient data', async () => {
      mockSql.mockResolvedValueOnce([
        {
          id: 'decision-1',
          tenant_id: 'tenant-1',
          verdict_id: 'verdict-1',
          original_verdict: 'quarantine',
          admin_action: 'release',
          admin_id: 'admin-1',
          reason: 'Test',
          timestamp: new Date().toISOString(),
          email_features: JSON.stringify(createMockEmailFeatures()),
        },
      ]);

      const adjustments = await learner.autoTuneThresholds('tenant-1');

      expect(adjustments).toHaveLength(0);
    });
  });

  describe('Feedback Incorporation', () => {
    it('should incorporate user feedback', async () => {
      mockSql
        .mockResolvedValueOnce([
          {
            id: 'feedback-1',
            verdict_id: 'verdict-1',
            feedback_type: 'false_positive',
            notes: 'This was a legitimate email',
          },
        ])
        .mockResolvedValue([]);

      await expect(learner.incorporateFeedback('feedback-1')).resolves.not.toThrow();
    });

    it('should update decision records with feedback outcomes', async () => {
      mockSql
        .mockResolvedValueOnce([
          {
            id: 'feedback-1',
            verdict_id: 'verdict-1',
            feedback_type: 'missed_threat',
            notes: 'This was actually phishing',
          },
        ])
        .mockResolvedValue([]);

      await learner.incorporateFeedback('feedback-1');

      // Verify SQL was called to update the decision
      expect(mockSql).toHaveBeenCalled();
    });

    it('should handle feedback not found', async () => {
      mockSql.mockResolvedValueOnce([]);

      await expect(learner.incorporateFeedback('nonexistent-feedback')).rejects.toThrow(
        'Feedback not found'
      );
    });

    it('should process false positive feedback', async () => {
      mockSql
        .mockResolvedValueOnce([
          {
            id: 'feedback-fp',
            verdict_id: 'verdict-1',
            feedback_type: 'false_positive',
            notes: 'Known sender',
          },
        ])
        .mockResolvedValue([]);

      await expect(learner.incorporateFeedback('feedback-fp')).resolves.not.toThrow();
    });

    it('should process missed threat feedback', async () => {
      mockSql
        .mockResolvedValueOnce([
          {
            id: 'feedback-fn',
            verdict_id: 'verdict-1',
            feedback_type: 'missed_threat',
            notes: 'Confirmed phishing',
          },
        ])
        .mockResolvedValue([]);

      await expect(learner.incorporateFeedback('feedback-fn')).resolves.not.toThrow();
    });
  });

  describe('Drift Detection', () => {
    it('should detect feature drift', async () => {
      const baselineDecisions: AdminDecision[] = [];
      const comparisonDecisions: AdminDecision[] = [];

      // Baseline: low urgency scores
      for (let i = 0; i < 20; i++) {
        baselineDecisions.push(
          createMockDecision({
            id: `baseline-${i}`,
            timestamp: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000 - i * 12 * 60 * 60 * 1000),
            emailFeatures: createMockEmailFeatures({
              urgencyScore: 20 + Math.random() * 10,
            }),
          })
        );
      }

      // Comparison: high urgency scores (drift)
      for (let i = 0; i < 20; i++) {
        comparisonDecisions.push(
          createMockDecision({
            id: `comparison-${i}`,
            timestamp: new Date(Date.now() - i * 12 * 60 * 60 * 1000),
            emailFeatures: createMockEmailFeatures({
              urgencyScore: 60 + Math.random() * 20,
            }),
          })
        );
      }

      // First call for baseline period
      mockSql.mockResolvedValueOnce(toDbRows(baselineDecisions));

      // Second call for comparison period
      mockSql.mockResolvedValueOnce(toDbRows(comparisonDecisions));

      const report = await learner.detectDrift('tenant-1');

      expect(report.hasDrift).toBeDefined();
      expect(report.driftScore).toBeGreaterThanOrEqual(0);
      expect(report.driftScore).toBeLessThanOrEqual(1);
      expect(report.driftType).toBeDefined();
    });

    it('should detect label drift (override rate changes)', async () => {
      const baselineDecisions: AdminDecision[] = [];
      const comparisonDecisions: AdminDecision[] = [];

      // Baseline: low override rate (20% releases)
      for (let i = 0; i < 20; i++) {
        baselineDecisions.push(
          createMockDecision({
            id: `baseline-${i}`,
            timestamp: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000 - i * 12 * 60 * 60 * 1000),
            adminAction: i < 4 ? 'release' : 'confirm',
          })
        );
      }

      // Comparison: high override rate (60% releases) - label drift
      for (let i = 0; i < 20; i++) {
        comparisonDecisions.push(
          createMockDecision({
            id: `comparison-${i}`,
            timestamp: new Date(Date.now() - i * 12 * 60 * 60 * 1000),
            adminAction: i < 12 ? 'release' : 'confirm',
          })
        );
      }

      mockSql.mockResolvedValueOnce(toDbRows(baselineDecisions));
      mockSql.mockResolvedValueOnce(toDbRows(comparisonDecisions));

      const report = await learner.detectDrift('tenant-1');

      expect(report.details.overrideRateChange).toBeDefined();
    });

    it('should provide drift recommendations', async () => {
      const decisions: AdminDecision[] = [];

      for (let i = 0; i < 40; i++) {
        decisions.push(
          createMockDecision({
            id: `decision-${i}`,
            timestamp: new Date(Date.now() - i * 24 * 60 * 60 * 1000),
            emailFeatures: createMockEmailFeatures({
              urgencyScore: 30 + i * 0.5, // Gradually increasing
            }),
          })
        );
      }

      mockSql.mockResolvedValueOnce(toDbRows(decisions.slice(0, 20)));
      mockSql.mockResolvedValueOnce(toDbRows(decisions.slice(20)));

      const report = await learner.detectDrift('tenant-1');

      expect(report.recommendation).toBeDefined();
      expect(typeof report.recommendation).toBe('string');
    });

    it('should report no drift with stable data', async () => {
      const decisions: AdminDecision[] = [];

      // Create stable decisions over time
      for (let i = 0; i < 40; i++) {
        decisions.push(
          createMockDecision({
            id: `decision-${i}`,
            timestamp: new Date(Date.now() - i * 24 * 60 * 60 * 1000),
            adminAction: i % 3 === 0 ? 'release' : 'confirm',
            emailFeatures: createMockEmailFeatures({
              urgencyScore: 30 + Math.random() * 5,
              mlScore: 35 + Math.random() * 5,
            }),
          })
        );
      }

      mockSql.mockResolvedValueOnce(toDbRows(decisions.slice(20)));
      mockSql.mockResolvedValueOnce(toDbRows(decisions.slice(0, 20)));

      const report = await learner.detectDrift('tenant-1');

      // With stable data, drift score should be low
      expect(report.driftScore).toBeLessThan(0.5);
    });

    it('should handle insufficient data for drift detection', async () => {
      mockSql.mockResolvedValueOnce([]);
      mockSql.mockResolvedValueOnce([]);

      const report = await learner.detectDrift('tenant-1');

      expect(report.hasDrift).toBe(false);
      expect(report.recommendation).toContain('Insufficient data');
    });
  });

  describe('Decision History Retrieval', () => {
    it('should retrieve decision history with filters', async () => {
      const decisions = [
        createMockDecision({ id: 'decision-1', adminAction: 'release' }),
        createMockDecision({ id: 'decision-2', adminAction: 'block' }),
        createMockDecision({ id: 'decision-3', adminAction: 'confirm' }),
      ];

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const history = await learner.getDecisionHistory('tenant-1', {});

      expect(history.length).toBe(3);
    });

    it('should filter by date range', async () => {
      const decisions = [
        createMockDecision({
          id: 'recent',
          timestamp: new Date(),
        }),
      ];

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const history = await learner.getDecisionHistory('tenant-1', {
        startDate: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
        endDate: new Date(),
      });

      expect(history.length).toBeGreaterThan(0);
    });

    it('should filter by admin action', async () => {
      const decisions = [
        createMockDecision({ id: 'decision-1', adminAction: 'release' }),
      ];

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const history = await learner.getDecisionHistory('tenant-1', {
        adminAction: ['release'],
      });

      expect(history.every((d) => d.adminAction === 'release')).toBe(true);
    });

    it('should paginate results', async () => {
      const decisions = Array.from({ length: 20 }, (_, i) =>
        createMockDecision({ id: `decision-${i}` })
      );

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const history = await learner.getDecisionHistory('tenant-1', {
        limit: 20,
        offset: 0,
      });

      expect(history.length).toBe(20);
    });

    it('should filter by sender domain', async () => {
      const decisions = [
        createMockDecision({
          id: 'decision-1',
          emailFeatures: createMockEmailFeatures({ senderDomain: 'specific.com' }),
        }),
      ];

      mockSql.mockResolvedValueOnce(toDbRows(decisions));

      const history = await learner.getDecisionHistory('tenant-1', {
        senderDomain: 'specific.com',
      });

      expect(
        history.every((d) => d.emailFeatures.senderDomain === 'specific.com')
      ).toBe(true);
    });
  });

  describe('A/B Testing', () => {
    it('should start an A/B test for a policy suggestion', async () => {
      const test = await learner.startABTest('tenant-1', 'suggestion-1', {
        name: 'Whitelist Domain Test',
        testGroupPercentage: 20,
      });

      expect(test.id).toBeDefined();
      expect(test.status).toBe('running');
      expect(test.testGroup).toContain('20%');
      expect(test.controlGroup).toContain('80%');
    });

    it('should evaluate A/B test results', async () => {
      const testDecisions = Array.from({ length: 40 }, (_, i) =>
        createMockDecision({
          id: `decision-${i}`,
          adminAction: i % 3 === 0 ? 'release' : 'confirm',
          subsequentReportedAsPhish: i % 10 === 0,
        })
      );

      mockSql
        .mockResolvedValueOnce([
          {
            id: 'test-1',
            tenant_id: 'tenant-1',
            suggestion_id: 'suggestion-1',
            name: 'Test',
            status: 'running',
            started_at: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
          },
        ])
        .mockResolvedValueOnce(toDbRows(testDecisions))
        .mockResolvedValue([]);

      const results = await learner.evaluateABTest('test-1');

      expect(results).toBeDefined();
      expect(results?.controlFPRate).toBeDefined();
      expect(results?.testFPRate).toBeDefined();
      expect(results?.statisticalSignificance).toBeDefined();
      expect(results?.recommendation).toMatch(/apply|reject|continue/);
    });

    it('should handle insufficient data for A/B test evaluation', async () => {
      mockSql
        .mockResolvedValueOnce([
          {
            id: 'test-1',
            tenant_id: 'tenant-1',
            suggestion_id: 'suggestion-1',
            name: 'Test',
            status: 'running',
            started_at: new Date().toISOString(),
          },
        ])
        .mockResolvedValueOnce([]); // No decisions yet

      const results = await learner.evaluateABTest('test-1');

      expect(results?.recommendation).toBe('continue');
    });
  });

  describe('Threshold Adjustment Application and Rollback', () => {
    it('should apply threshold adjustment', async () => {
      mockSql.mockResolvedValue([{ settings: {} }]);

      await expect(
        learner.applyThresholdAdjustment('adjustment-1', 'tenant-1')
      ).resolves.not.toThrow();
    });

    it('should rollback threshold adjustment', async () => {
      mockSql
        .mockResolvedValueOnce([
          { previous_settings: { threshold: 40 } },
        ])
        .mockResolvedValue([]);

      await expect(
        learner.rollbackThresholdAdjustment('adjustment-1', 'tenant-1')
      ).resolves.not.toThrow();
    });

    it('should handle rollback for non-existent adjustment', async () => {
      mockSql.mockResolvedValueOnce([]);

      await expect(
        learner.rollbackThresholdAdjustment('nonexistent', 'tenant-1')
      ).rejects.toThrow('Adjustment record not found');
    });
  });
});

describe('Type Exports', () => {
  it('should export all required types', () => {
    // These are compile-time checks - if the imports fail, the test fails
    const emailFeatures: EmailFeatures = createMockEmailFeatures();
    expect(emailFeatures).toBeDefined();

    const decision: AdminDecision = createMockDecision();
    expect(decision).toBeDefined();

    const pattern: Pattern = {
      id: 'pattern-1',
      type: 'domain',
      description: 'Test pattern',
      occurrences: 5,
      confidence: 0.8,
      examples: [],
      features: {},
      firstSeen: new Date(),
      lastSeen: new Date(),
    };
    expect(pattern).toBeDefined();

    const suggestion: PolicySuggestion = {
      id: 'suggestion-1',
      type: 'whitelist_domain',
      description: 'Test suggestion',
      confidence: 0.9,
      evidence: [],
      impact: {},
      createdAt: new Date(),
      status: 'pending',
    };
    expect(suggestion).toBeDefined();

    const adjustment: ThresholdAdjustment = {
      id: 'adjustment-1',
      thresholdName: 'test',
      currentValue: 40,
      suggestedValue: 45,
      direction: 'increase',
      reason: 'Test',
      evidence: {
        falsePositiveImpact: 10,
        falseNegativeRisk: 0.05,
        sampleSize: 100,
      },
      rollbackAvailable: true,
    };
    expect(adjustment).toBeDefined();

    const driftReport: DriftReport = {
      hasDrift: false,
      driftScore: 0.1,
      driftType: 'none',
      affectedFeatures: [],
      recommendation: 'No action needed',
      details: {
        baselinePeriod: { start: new Date(), end: new Date() },
        comparisonPeriod: { start: new Date(), end: new Date() },
        featureShifts: [],
        predictionDistributionShift: 0,
        overrideRateChange: 0,
      },
      detectedAt: new Date(),
    };
    expect(driftReport).toBeDefined();

    const filters: DecisionFilters = {
      startDate: new Date(),
      limit: 100,
    };
    expect(filters).toBeDefined();
  });
});
