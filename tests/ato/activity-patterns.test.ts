/**
 * Activity Patterns Detection Tests
 *
 * Tests for detecting anomalous email activity patterns that may indicate
 * account takeover, including sending spikes, unusual recipients, unusual
 * send times, mass forwarding rules, and inbox rule changes.
 */

import {
  ActivityPatternDetector,
  detectSendingSpike,
  detectUnusualRecipients,
  detectUnusualSendTime,
  detectMassForwardingRules,
  detectInboxRuleChanges,
  calculateCompositeAnomalyScore,
  getActivityBaseline,
  updateActivityBaseline,
  type ActivityEvent,
  type ActivityBaseline,
  type InboxRule,
  type AnomalyResult,
  type SendingPattern,
} from '@/lib/ato/activity-patterns';

describe('Activity Patterns Detection', () => {
  describe('Sending Spike Detection', () => {
    it('should detect sending spike vs baseline', async () => {
      const baseline: SendingPattern = {
        avgEmailsPerHour: 5,
        stdDevEmailsPerHour: 2,
        avgEmailsPerDay: 40,
        stdDevEmailsPerDay: 10,
        peakHours: [9, 10, 11, 14, 15, 16],
      };

      const currentActivity: ActivityEvent[] = Array.from({ length: 50 }, (_, i) => ({
        type: 'email_sent',
        timestamp: new Date(Date.now() - i * 60000), // 50 emails in 50 minutes
        userId: 'user123',
        metadata: { recipients: [`user${i}@example.com`] },
      }));

      const result = detectSendingSpike(currentActivity, baseline);

      expect(result.isAnomaly).toBe(true);
      expect(result.severity).toBe('high');
      expect(result.score).toBeGreaterThan(70);
    });

    it('should not flag normal sending volume', async () => {
      const baseline: SendingPattern = {
        avgEmailsPerHour: 5,
        stdDevEmailsPerHour: 2,
        avgEmailsPerDay: 40,
        stdDevEmailsPerDay: 10,
        peakHours: [9, 10, 11, 14, 15, 16],
      };

      const currentActivity: ActivityEvent[] = Array.from({ length: 5 }, (_, i) => ({
        type: 'email_sent',
        timestamp: new Date(Date.now() - i * 720000), // 5 emails per hour
        userId: 'user123',
        metadata: { recipients: [`user${i}@example.com`] },
      }));

      const result = detectSendingSpike(currentActivity, baseline);

      expect(result.isAnomaly).toBe(false);
    });

    it('should use z-score to measure deviation', async () => {
      const baseline: SendingPattern = {
        avgEmailsPerHour: 10,
        stdDevEmailsPerHour: 3,
        avgEmailsPerDay: 80,
        stdDevEmailsPerDay: 15,
        peakHours: [9, 10, 11, 14, 15, 16],
      };

      // 25 emails per hour (5 std devs above mean)
      const currentActivity: ActivityEvent[] = Array.from({ length: 25 }, (_, i) => ({
        type: 'email_sent',
        timestamp: new Date(Date.now() - i * 144000), // spread over 1 hour
        userId: 'user123',
        metadata: { recipients: [`user${i}@example.com`] },
      }));

      const result = detectSendingSpike(currentActivity, baseline);

      expect(result.isAnomaly).toBe(true);
      expect(result.details.zScore).toBeGreaterThan(4);
    });

    it('should handle users with no baseline (first-time analysis)', async () => {
      const baseline: SendingPattern | null = null;

      const currentActivity: ActivityEvent[] = Array.from({ length: 100 }, (_, i) => ({
        type: 'email_sent',
        timestamp: new Date(Date.now() - i * 36000), // 100 emails in 1 hour
        userId: 'newuser',
        metadata: { recipients: [`user${i}@example.com`] },
      }));

      const result = detectSendingSpike(currentActivity, baseline);

      // Should flag as anomaly using global defaults
      expect(result.isAnomaly).toBe(true);
      expect(result.details.usingDefaultBaseline).toBe(true);
    });
  });

  describe('Unusual Recipients Detection', () => {
    it('should detect external mass send', async () => {
      const baseline: ActivityBaseline = {
        knownRecipients: ['colleague1@company.com', 'colleague2@company.com'],
        internalDomains: ['company.com'],
        avgExternalRecipientsPerDay: 5,
      };

      const events: ActivityEvent[] = Array.from({ length: 50 }, (_, i) => ({
        type: 'email_sent',
        timestamp: new Date(Date.now() - i * 60000),
        userId: 'user123',
        metadata: { recipients: [`stranger${i}@external.com`] },
      }));

      const result = detectUnusualRecipients(events, baseline);

      expect(result.isAnomaly).toBe(true);
      expect(result.severity).toBe('high');
      expect(result.details.newExternalRecipients).toBeGreaterThan(40);
    });

    it('should not flag known recipients', async () => {
      const baseline: ActivityBaseline = {
        knownRecipients: ['colleague1@company.com', 'colleague2@company.com', 'partner@external.com'],
        internalDomains: ['company.com'],
        avgExternalRecipientsPerDay: 5,
      };

      const events: ActivityEvent[] = [
        {
          type: 'email_sent',
          timestamp: new Date(),
          userId: 'user123',
          metadata: { recipients: ['colleague1@company.com', 'partner@external.com'] },
        },
      ];

      const result = detectUnusualRecipients(events, baseline);

      expect(result.isAnomaly).toBe(false);
    });

    it('should flag bulk external recipients even with gradual sending', async () => {
      const baseline: ActivityBaseline = {
        knownRecipients: [],
        internalDomains: ['company.com'],
        avgExternalRecipientsPerDay: 2,
      };

      // 20 unique external recipients over 8 hours
      const events: ActivityEvent[] = Array.from({ length: 20 }, (_, i) => ({
        type: 'email_sent',
        timestamp: new Date(Date.now() - i * 1440000), // 24 min intervals
        userId: 'user123',
        metadata: { recipients: [`external${i}@outside.com`] },
      }));

      const result = detectUnusualRecipients(events, baseline);

      expect(result.isAnomaly).toBe(true);
      expect(result.details.uniqueNewRecipients).toBe(20);
    });

    it('should consider recipient domains in analysis', async () => {
      const baseline: ActivityBaseline = {
        knownRecipients: [],
        internalDomains: ['company.com', 'subsidiary.com'],
        avgExternalRecipientsPerDay: 10,
        knownExternalDomains: ['partner.com', 'vendor.com'],
      };

      const events: ActivityEvent[] = Array.from({ length: 30 }, (_, i) => ({
        type: 'email_sent',
        timestamp: new Date(Date.now() - i * 60000),
        userId: 'user123',
        metadata: { recipients: [`user${i}@suspicious-domain-${i % 5}.com`] },
      }));

      const result = detectUnusualRecipients(events, baseline);

      expect(result.isAnomaly).toBe(true);
      expect(result.details.newDomains).toBeGreaterThan(0);
    });
  });

  describe('Unusual Send Time Detection', () => {
    it('should detect sending during unusual hours', async () => {
      const baseline: ActivityBaseline = {
        typicalSendHours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17], // 8am-6pm
        typicalTimezone: 'America/New_York',
        weekendActivity: false,
      };

      // Sending at 3am
      const events: ActivityEvent[] = [
        {
          type: 'email_sent',
          timestamp: new Date('2024-01-15T03:00:00-05:00'), // 3am EST
          userId: 'user123',
          metadata: { recipients: ['someone@example.com'] },
        },
      ];

      const result = detectUnusualSendTime(events, baseline);

      expect(result.isAnomaly).toBe(true);
      expect(result.details.unusualHour).toBe(3);
    });

    it('should not flag activity during normal work hours', async () => {
      const baseline: ActivityBaseline = {
        typicalSendHours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
        typicalTimezone: 'America/New_York',
        weekendActivity: false,
      };

      const events: ActivityEvent[] = [
        {
          type: 'email_sent',
          timestamp: new Date('2024-01-15T10:00:00-05:00'), // 10am EST, Monday
          userId: 'user123',
          metadata: { recipients: ['someone@example.com'] },
        },
      ];

      const result = detectUnusualSendTime(events, baseline);

      expect(result.isAnomaly).toBe(false);
    });

    it('should detect weekend activity for non-weekend users', async () => {
      const baseline: ActivityBaseline = {
        typicalSendHours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
        typicalTimezone: 'America/New_York',
        weekendActivity: false,
      };

      // Saturday at normal hours
      const events: ActivityEvent[] = Array.from({ length: 10 }, (_, i) => ({
        type: 'email_sent',
        timestamp: new Date('2024-01-20T10:00:00-05:00'), // Saturday
        userId: 'user123',
        metadata: { recipients: [`user${i}@example.com`] },
      }));

      const result = detectUnusualSendTime(events, baseline);

      expect(result.isAnomaly).toBe(true);
      expect(result.details.isWeekend).toBe(true);
    });

    it('should handle timezone differences correctly', async () => {
      const baseline: ActivityBaseline = {
        typicalSendHours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
        typicalTimezone: 'America/Los_Angeles', // PST
        weekendActivity: false,
      };

      // 10am UTC = 2am PST (unusual for PST user)
      const events: ActivityEvent[] = [
        {
          type: 'email_sent',
          timestamp: new Date('2024-01-15T10:00:00Z'),
          userId: 'user123',
          metadata: { recipients: ['someone@example.com'] },
        },
      ];

      const result = detectUnusualSendTime(events, baseline, 'America/Los_Angeles');

      expect(result.isAnomaly).toBe(true);
    });
  });

  describe('Mass Forwarding Rules Detection', () => {
    it('should detect creation of forwarding rules to external addresses', async () => {
      const rules: InboxRule[] = [
        {
          id: 'rule1',
          name: 'Forward all',
          createdAt: new Date(),
          actions: [{ type: 'forward', destination: 'attacker@external.com' }],
          conditions: [{ field: 'all', operator: 'matches', value: '*' }],
          enabled: true,
        },
      ];

      const result = detectMassForwardingRules(rules, ['company.com']);

      expect(result.isAnomaly).toBe(true);
      expect(result.severity).toBe('critical');
      expect(result.details.forwardingToExternal).toBe(true);
    });

    it('should not flag internal forwarding rules', async () => {
      const rules: InboxRule[] = [
        {
          id: 'rule1',
          name: 'Forward to assistant',
          createdAt: new Date(),
          actions: [{ type: 'forward', destination: 'assistant@company.com' }],
          conditions: [{ field: 'subject', operator: 'contains', value: 'meeting' }],
          enabled: true,
        },
      ];

      const result = detectMassForwardingRules(rules, ['company.com']);

      expect(result.isAnomaly).toBe(false);
    });

    it('should detect suspicious forwarding rule patterns', async () => {
      const rules: InboxRule[] = [
        {
          id: 'rule1',
          name: 'xyzabc123', // Random name
          createdAt: new Date(),
          actions: [
            { type: 'forward', destination: 'external@gmail.com' },
            { type: 'markAsRead' },
            { type: 'moveToFolder', destination: 'Deleted Items' },
          ],
          conditions: [{ field: 'all', operator: 'matches', value: '*' }],
          enabled: true,
        },
      ];

      const result = detectMassForwardingRules(rules, ['company.com']);

      expect(result.isAnomaly).toBe(true);
      expect(result.details.hidesActivity).toBe(true);
    });

    it('should flag multiple forwarding rules created in short time', async () => {
      const now = new Date();
      const rules: InboxRule[] = Array.from({ length: 5 }, (_, i) => ({
        id: `rule${i}`,
        name: `Rule ${i}`,
        createdAt: new Date(now.getTime() - i * 60000), // Created within 5 minutes
        actions: [{ type: 'forward', destination: `external${i}@gmail.com` }],
        conditions: [{ field: 'subject', operator: 'contains', value: `keyword${i}` }],
        enabled: true,
      }));

      const result = detectMassForwardingRules(rules, ['company.com']);

      expect(result.isAnomaly).toBe(true);
      expect(result.details.rapidCreation).toBe(true);
    });
  });

  describe('Inbox Rule Changes Detection', () => {
    it('should detect deletion of security-related rules', async () => {
      const ruleChanges = [
        {
          type: 'delete' as const,
          ruleId: 'security-rule-1',
          ruleName: 'Block phishing',
          changedAt: new Date(),
          changedBy: 'user123',
        },
      ];

      const result = detectInboxRuleChanges(ruleChanges);

      expect(result.isAnomaly).toBe(true);
      expect(result.details.deletedSecurityRule).toBe(true);
    });

    it('should detect bulk rule modifications', async () => {
      const now = new Date();
      const ruleChanges = Array.from({ length: 10 }, (_, i) => ({
        type: 'modify' as const,
        ruleId: `rule-${i}`,
        ruleName: `Rule ${i}`,
        changedAt: new Date(now.getTime() - i * 30000), // 10 changes in 5 minutes
        changedBy: 'user123',
        changes: { actions: 'modified' },
      }));

      const result = detectInboxRuleChanges(ruleChanges);

      expect(result.isAnomaly).toBe(true);
      expect(result.details.bulkModification).toBe(true);
    });

    it('should not flag normal rule creation', async () => {
      const ruleChanges = [
        {
          type: 'create' as const,
          ruleId: 'new-rule-1',
          ruleName: 'Move newsletters',
          changedAt: new Date(),
          changedBy: 'user123',
        },
      ];

      const result = detectInboxRuleChanges(ruleChanges);

      expect(result.isAnomaly).toBe(false);
    });

    it('should detect disabling of multiple rules at once', async () => {
      const now = new Date();
      const ruleChanges = Array.from({ length: 5 }, (_, i) => ({
        type: 'modify' as const,
        ruleId: `rule-${i}`,
        ruleName: `Important Rule ${i}`,
        changedAt: new Date(now.getTime() - i * 1000),
        changedBy: 'user123',
        changes: { enabled: false },
      }));

      const result = detectInboxRuleChanges(ruleChanges);

      expect(result.isAnomaly).toBe(true);
      expect(result.details.massDisabled).toBe(true);
    });
  });

  describe('Composite Anomaly Score', () => {
    it('should calculate composite score from multiple detectors', async () => {
      const anomalyResults: AnomalyResult[] = [
        { type: 'sending_spike', isAnomaly: true, score: 80, severity: 'high', details: {} },
        { type: 'unusual_recipients', isAnomaly: true, score: 60, severity: 'medium', details: {} },
        { type: 'unusual_send_time', isAnomaly: false, score: 0, severity: 'low', details: {} },
      ];

      const composite = calculateCompositeAnomalyScore(anomalyResults);

      expect(composite.overallScore).toBeGreaterThan(50);
      expect(composite.isHighRisk).toBe(true);
      expect(composite.triggeredDetectors).toHaveLength(2);
    });

    it('should weight critical anomalies higher', async () => {
      const resultsWithCritical: AnomalyResult[] = [
        { type: 'mass_forwarding', isAnomaly: true, score: 95, severity: 'critical', details: {} },
        { type: 'sending_spike', isAnomaly: false, score: 0, severity: 'low', details: {} },
      ];

      const resultsWithoutCritical: AnomalyResult[] = [
        { type: 'unusual_recipients', isAnomaly: true, score: 50, severity: 'medium', details: {} },
        { type: 'unusual_send_time', isAnomaly: true, score: 40, severity: 'low', details: {} },
      ];

      const compositeCritical = calculateCompositeAnomalyScore(resultsWithCritical);
      const compositeNonCritical = calculateCompositeAnomalyScore(resultsWithoutCritical);

      expect(compositeCritical.overallScore).toBeGreaterThan(compositeNonCritical.overallScore);
    });

    it('should return low score when no anomalies detected', async () => {
      const anomalyResults: AnomalyResult[] = [
        { type: 'sending_spike', isAnomaly: false, score: 0, severity: 'low', details: {} },
        { type: 'unusual_recipients', isAnomaly: false, score: 10, severity: 'low', details: {} },
        { type: 'unusual_send_time', isAnomaly: false, score: 5, severity: 'low', details: {} },
      ];

      const composite = calculateCompositeAnomalyScore(anomalyResults);

      expect(composite.overallScore).toBeLessThan(20);
      expect(composite.isHighRisk).toBe(false);
    });

    it('should identify combination patterns', async () => {
      // Typical ATO pattern: unusual time + unusual recipients + sending spike
      const anomalyResults: AnomalyResult[] = [
        { type: 'sending_spike', isAnomaly: true, score: 70, severity: 'high', details: {} },
        { type: 'unusual_recipients', isAnomaly: true, score: 65, severity: 'high', details: {} },
        { type: 'unusual_send_time', isAnomaly: true, score: 50, severity: 'medium', details: {} },
      ];

      const composite = calculateCompositeAnomalyScore(anomalyResults);

      expect(composite.patternMatch).toBe('likely_ato');
      expect(composite.overallScore).toBeGreaterThan(80);
    });
  });

  describe('Activity Pattern Detector Class', () => {
    let detector: ActivityPatternDetector;

    beforeEach(() => {
      detector = new ActivityPatternDetector();
    });

    it('should analyze full activity stream and generate report', async () => {
      const userId = 'user123';

      // Set up baseline
      await detector.setBaseline(userId, {
        sending: {
          avgEmailsPerHour: 5,
          stdDevEmailsPerHour: 2,
          avgEmailsPerDay: 40,
          stdDevEmailsPerDay: 10,
          peakHours: [9, 10, 11, 14, 15, 16],
        },
        recipients: {
          knownRecipients: ['colleague@company.com'],
          internalDomains: ['company.com'],
          avgExternalRecipientsPerDay: 3,
        },
        timing: {
          typicalSendHours: [9, 10, 11, 12, 13, 14, 15, 16, 17],
          typicalTimezone: 'America/New_York',
          weekendActivity: false,
        },
      });

      // Simulate suspicious activity
      const events: ActivityEvent[] = Array.from({ length: 100 }, (_, i) => ({
        type: 'email_sent',
        timestamp: new Date(Date.now() - i * 36000), // 100 emails in 1 hour
        userId,
        metadata: { recipients: [`stranger${i}@external.com`] },
      }));

      const report = await detector.analyzeActivity(userId, events);

      expect(report.userId).toBe(userId);
      expect(report.anomalies.length).toBeGreaterThan(0);
      expect(report.riskLevel).toBeDefined();
      expect(report.recommendations).toBeDefined();
    });

    it('should track baseline updates over time', async () => {
      const userId = 'user123';

      const initialBaseline = await detector.getBaseline(userId);
      expect(initialBaseline).toBeNull();

      // Update baseline with new data
      const events: ActivityEvent[] = Array.from({ length: 50 }, (_, i) => ({
        type: 'email_sent',
        timestamp: new Date(Date.now() - i * 720000), // 50 emails over 10 hours
        userId,
        metadata: { recipients: ['regular@company.com'] },
      }));

      await detector.updateBaseline(userId, events);

      const updatedBaseline = await detector.getBaseline(userId);
      expect(updatedBaseline).toBeDefined();
      expect(updatedBaseline?.sending.avgEmailsPerHour).toBeCloseTo(5, 0);
    });
  });
});
