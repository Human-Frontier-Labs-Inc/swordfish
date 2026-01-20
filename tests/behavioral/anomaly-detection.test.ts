/**
 * Anomaly Detection Tests
 * Tests for behavioral anomaly detection including volume, time, recipient, and content anomalies
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  AnomalyDetector,
  type AnomalyResult,
  type AnomalyConfig,
  type EmailBehaviorData,
  type TenantBaseline,
} from '@/lib/behavioral/anomaly-engine';
import {
  generateAnomalyExplanation,
  type AnomalyExplanation,
} from '@/lib/behavioral/explainer';

// Mock database
vi.mock('@/lib/db', () => ({
  sql: vi.fn().mockImplementation(async () => []),
}));

describe('AnomalyDetector', () => {
  let detector: AnomalyDetector;
  const testTenantId = 'test-tenant-001';

  beforeEach(() => {
    detector = new AnomalyDetector();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  describe('Volume Anomaly Detection', () => {
    it('should detect volume anomaly when z-score exceeds threshold', async () => {
      // Baseline: 10 emails/day with stddev of 2
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 10, stdDev: 2 },
        hourlyDistribution: new Array(24).fill(0.0416), // Uniform distribution
        topRecipients: ['known@example.com'],
        topSenders: ['sender@company.com'],
        subjectPatterns: ['meeting', 'report', 'update'],
        calculatedAt: new Date(),
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['known@example.com'],
        subject: 'Regular meeting',
        sentAt: new Date(),
        dailyVolumeForSender: 20, // 5 stddev above mean
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.hasAnomaly).toBe(true);
      expect(result.volumeAnomaly).toBeDefined();
      expect(result.volumeAnomaly!.zScore).toBeGreaterThan(3);
      expect(result.volumeAnomaly!.severity).toBe('high');
    });

    it('should not flag normal volume as anomaly', async () => {
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 50, stdDev: 10 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: ['known@example.com'],
        topSenders: ['sender@company.com'],
        subjectPatterns: [],
        calculatedAt: new Date(),
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['known@example.com'],
        subject: 'Regular update',
        sentAt: new Date(),
        dailyVolumeForSender: 55, // Within 1 stddev
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.volumeAnomaly?.severity).not.toBe('high');
    });

    it('should calculate correct z-score for volume', async () => {
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 100, stdDev: 20 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: [],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['recipient@example.com'],
        subject: 'Test',
        sentAt: new Date(),
        dailyVolumeForSender: 160, // 3 stddev above
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.volumeAnomaly?.zScore).toBeCloseTo(3, 1);
    });
  });

  describe('Time Anomaly Detection', () => {
    it('should detect emails sent at unusual hours', async () => {
      // Set time to 3 AM
      vi.setSystemTime(new Date('2024-01-15T03:00:00'));

      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 50, stdDev: 10 },
        hourlyDistribution: [
          0.01, 0.005, 0.002, 0.001, 0.001, 0.01, // 00-05: very low
          0.03, 0.05, 0.08, 0.10, 0.10, 0.08,     // 06-11: ramping up
          0.05, 0.08, 0.10, 0.10, 0.08, 0.05,     // 12-17: high
          0.03, 0.02, 0.015, 0.01, 0.007, 0.005,  // 18-23: winding down
        ],
        topRecipients: [],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['recipient@example.com'],
        subject: 'Late night email',
        sentAt: new Date('2024-01-15T03:00:00'),
        dailyVolumeForSender: 50,
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.timeAnomaly).toBeDefined();
      expect(result.timeAnomaly!.isUnusualHour).toBe(true);
      expect(result.timeAnomaly!.hourProbability).toBeLessThan(0.02);
    });

    it('should not flag emails during business hours', async () => {
      vi.setSystemTime(new Date('2024-01-15T10:00:00'));

      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 50, stdDev: 10 },
        hourlyDistribution: [
          0.01, 0.005, 0.002, 0.001, 0.001, 0.01,
          0.03, 0.05, 0.08, 0.10, 0.10, 0.08,
          0.05, 0.08, 0.10, 0.10, 0.08, 0.05,
          0.03, 0.02, 0.015, 0.01, 0.007, 0.005,
        ],
        topRecipients: [],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['recipient@example.com'],
        subject: 'Normal business email',
        sentAt: new Date('2024-01-15T10:00:00'),
        dailyVolumeForSender: 50,
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.timeAnomaly?.isUnusualHour).toBeFalsy();
    });

    it('should consider weekend emails as potentially unusual', async () => {
      // Saturday at 9 AM
      vi.setSystemTime(new Date('2024-01-13T09:00:00'));

      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 50, stdDev: 10 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: [],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
        weekendActivity: 0.05, // Only 5% of emails on weekends
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['recipient@example.com'],
        subject: 'Weekend work',
        sentAt: new Date('2024-01-13T09:00:00'),
        dailyVolumeForSender: 50,
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.timeAnomaly?.isWeekend).toBe(true);
    });
  });

  describe('Recipient Anomaly Detection', () => {
    it('should detect never-before-seen external recipient', async () => {
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 50, stdDev: 10 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: ['colleague@company.com', 'client@known-partner.com'],
        topSenders: ['sender@company.com'],
        subjectPatterns: [],
        calculatedAt: new Date(),
        knownRecipientDomains: ['company.com', 'known-partner.com'],
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['unknown@suspicious-domain.xyz'],
        subject: 'First contact',
        sentAt: new Date(),
        dailyVolumeForSender: 50,
        isFirstContactWithRecipient: true,
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.recipientAnomaly).toBeDefined();
      expect(result.recipientAnomaly!.hasNewRecipient).toBe(true);
      expect(result.recipientAnomaly!.hasNewDomain).toBe(true);
    });

    it('should not flag known recipients', async () => {
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 50, stdDev: 10 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: ['colleague@company.com', 'client@partner.com'],
        topSenders: ['sender@company.com'],
        subjectPatterns: [],
        calculatedAt: new Date(),
        knownRecipientDomains: ['company.com', 'partner.com'],
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['colleague@company.com'],
        subject: 'Follow up',
        sentAt: new Date(),
        dailyVolumeForSender: 50,
        isFirstContactWithRecipient: false,
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.recipientAnomaly?.hasNewRecipient).toBeFalsy();
    });

    it('should flag multiple new recipients in single email', async () => {
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 50, stdDev: 10 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: ['known@company.com'],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
        knownRecipientDomains: ['company.com'],
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: [
          'new1@unknown.com',
          'new2@other-unknown.net',
          'new3@third-unknown.org',
        ],
        subject: 'Broadcast',
        sentAt: new Date(),
        dailyVolumeForSender: 50,
        isFirstContactWithRecipient: true,
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.recipientAnomaly?.newRecipientCount).toBe(3);
      expect(result.recipientAnomaly?.severity).toBe('high');
    });
  });

  describe('Content Anomaly Detection', () => {
    it('should detect unusual subject patterns', async () => {
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 50, stdDev: 10 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: [],
        topSenders: [],
        subjectPatterns: ['weekly report', 'meeting notes', 'project update'],
        calculatedAt: new Date(),
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['recipient@company.com'],
        subject: 'URGENT: Wire Transfer Needed Immediately!!!',
        sentAt: new Date(),
        dailyVolumeForSender: 50,
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.contentAnomaly).toBeDefined();
      expect(result.contentAnomaly!.hasUnusualSubject).toBe(true);
      expect(result.contentAnomaly!.urgencyScore).toBeGreaterThan(0.5);
    });

    it('should flag subjects with excessive punctuation', async () => {
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 50, stdDev: 10 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: [],
        topSenders: [],
        subjectPatterns: ['status update', 'team meeting'],
        calculatedAt: new Date(),
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['recipient@company.com'],
        subject: 'ACT NOW!!! IMPORTANT!!! DO NOT IGNORE!!!',
        sentAt: new Date(),
        dailyVolumeForSender: 50,
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.contentAnomaly?.excessivePunctuation).toBe(true);
    });

    it('should detect all-caps subjects', async () => {
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 50, stdDev: 10 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: [],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['recipient@company.com'],
        subject: 'PLEASE READ THIS IMPORTANT MESSAGE NOW',
        sentAt: new Date(),
        dailyVolumeForSender: 50,
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.contentAnomaly?.allCapsSubject).toBe(true);
    });
  });

  describe('Composite Anomaly Score Calculation', () => {
    it('should calculate composite score from multiple anomalies', async () => {
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 10, stdDev: 2 },
        hourlyDistribution: [
          0.01, 0.005, 0.002, 0.001, 0.001, 0.01,
          0.03, 0.05, 0.08, 0.10, 0.10, 0.08,
          0.05, 0.08, 0.10, 0.10, 0.08, 0.05,
          0.03, 0.02, 0.015, 0.01, 0.007, 0.005,
        ],
        topRecipients: ['known@company.com'],
        topSenders: [],
        subjectPatterns: ['normal pattern'],
        calculatedAt: new Date(),
        knownRecipientDomains: ['company.com'],
      };

      vi.setSystemTime(new Date('2024-01-15T03:00:00'));

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['unknown@suspicious.xyz'],
        subject: 'URGENT!!! Wire Transfer!!!',
        sentAt: new Date('2024-01-15T03:00:00'),
        dailyVolumeForSender: 100, // High volume
        isFirstContactWithRecipient: true,
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.compositeScore).toBeGreaterThan(70);
      expect(result.hasAnomaly).toBe(true);
      expect(result.anomalyTypes).toContain('volume');
      expect(result.anomalyTypes).toContain('time');
      expect(result.anomalyTypes).toContain('recipient');
      expect(result.anomalyTypes).toContain('content');
    });

    it('should weight anomalies appropriately', async () => {
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 50, stdDev: 10 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: [],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
      };

      // Single low-severity anomaly
      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['recipient@company.com'],
        subject: 'Slightly unusual email',
        sentAt: new Date(),
        dailyVolumeForSender: 70, // 2 stddev above mean
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      // Single anomaly should not push score too high
      expect(result.compositeScore).toBeLessThan(50);
    });

    it('should return zero score for completely normal email', async () => {
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 50, stdDev: 10 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: ['colleague@company.com'],
        topSenders: ['sender@company.com'],
        subjectPatterns: ['status update'],
        calculatedAt: new Date(),
        knownRecipientDomains: ['company.com'],
      };

      vi.setSystemTime(new Date('2024-01-15T10:00:00'));

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['colleague@company.com'],
        subject: 'Status update for Monday',
        sentAt: new Date('2024-01-15T10:00:00'),
        dailyVolumeForSender: 50,
        isFirstContactWithRecipient: false,
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.compositeScore).toBeLessThan(20);
      expect(result.hasAnomaly).toBe(false);
    });
  });

  describe('Anomaly Explanation Generation', () => {
    it('should generate human-readable explanation for volume anomaly', () => {
      const anomalyResult: AnomalyResult = {
        tenantId: testTenantId,
        emailId: 'email-001',
        hasAnomaly: true,
        compositeScore: 75,
        anomalyTypes: ['volume'],
        volumeAnomaly: {
          zScore: 4.5,
          severity: 'high',
          actualVolume: 100,
          expectedVolume: 10,
        },
        detectedAt: new Date(),
      };

      const explanation = generateAnomalyExplanation(anomalyResult);

      expect(explanation.summary).toContain('volume');
      expect(explanation.details.length).toBeGreaterThan(0);
      expect(explanation.riskLevel).toBe('high');
    });

    it('should generate explanation for multiple anomalies', () => {
      const anomalyResult: AnomalyResult = {
        tenantId: testTenantId,
        emailId: 'email-002',
        hasAnomaly: true,
        compositeScore: 85,
        anomalyTypes: ['volume', 'time', 'recipient', 'content'],
        volumeAnomaly: {
          zScore: 3.5,
          severity: 'high',
          actualVolume: 80,
          expectedVolume: 20,
        },
        timeAnomaly: {
          isUnusualHour: true,
          hourProbability: 0.01,
          hour: 3,
          severity: 'medium',
        },
        recipientAnomaly: {
          hasNewRecipient: true,
          hasNewDomain: true,
          newRecipientCount: 2,
          severity: 'high',
        },
        contentAnomaly: {
          hasUnusualSubject: true,
          urgencyScore: 0.8,
          allCapsSubject: true,
          severity: 'medium',
        },
        detectedAt: new Date(),
      };

      const explanation = generateAnomalyExplanation(anomalyResult);

      expect(explanation.details.length).toBe(4);
      expect(explanation.actionRecommendations.length).toBeGreaterThan(0);
    });

    it('should provide actionable recommendations', () => {
      const anomalyResult: AnomalyResult = {
        tenantId: testTenantId,
        emailId: 'email-003',
        hasAnomaly: true,
        compositeScore: 60,
        anomalyTypes: ['recipient'],
        recipientAnomaly: {
          hasNewRecipient: true,
          hasNewDomain: true,
          newRecipientCount: 1,
          newDomains: ['suspicious.xyz'],
          severity: 'medium',
        },
        detectedAt: new Date(),
      };

      const explanation = generateAnomalyExplanation(anomalyResult);

      expect(explanation.actionRecommendations.some(r => /verify|review|check/i.test(r))).toBe(true);
    });
  });

  describe('False Positive Feedback Incorporation', () => {
    it('should record false positive feedback', async () => {
      await detector.recordFeedback({
        tenantId: testTenantId,
        emailId: 'email-fp-001',
        feedbackType: 'false_positive',
        anomalyTypes: ['volume'],
        providedBy: 'user-001',
      });

      // Should not throw
      expect(true).toBe(true);
    });

    it('should adjust scoring based on feedback history', async () => {
      // Record multiple false positives for volume anomaly
      for (let i = 0; i < 5; i++) {
        await detector.recordFeedback({
          tenantId: testTenantId,
          emailId: `email-fp-${i}`,
          feedbackType: 'false_positive',
          anomalyTypes: ['volume'],
          providedBy: 'user-001',
        });
      }

      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 10, stdDev: 2 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: [],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['recipient@company.com'],
        subject: 'Test',
        sentAt: new Date(),
        dailyVolumeForSender: 20,
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      // Score should be adjusted down due to feedback
      expect(result.feedbackAdjustment).toBeDefined();
    });

    it('should confirm true positive feedback', async () => {
      await detector.recordFeedback({
        tenantId: testTenantId,
        emailId: 'email-tp-001',
        feedbackType: 'true_positive',
        anomalyTypes: ['recipient', 'content'],
        providedBy: 'user-001',
      });

      expect(true).toBe(true);
    });
  });

  describe('Threshold Configuration Per Tenant', () => {
    it('should apply custom thresholds for tenant', async () => {
      const customConfig: AnomalyConfig = {
        tenantId: testTenantId,
        volumeZScoreThreshold: 4.0, // More lenient than default 3.0
        unusualHourThreshold: 0.005, // Stricter than default 0.02
        contentUrgencyThreshold: 0.9, // Very strict
        enableVolumeDetection: true,
        enableTimeDetection: true,
        enableRecipientDetection: true,
        enableContentDetection: true,
      };

      const configuredDetector = new AnomalyDetector(customConfig);

      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 10, stdDev: 2 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: [],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['recipient@company.com'],
        subject: 'Test',
        sentAt: new Date(),
        dailyVolumeForSender: 17, // 3.5 stddev - would flag with default but not custom
      };

      const result = await configuredDetector.detectAnomalies(emailData, baseline);

      expect(result.volumeAnomaly?.severity).not.toBe('high');
    });

    it('should disable specific anomaly types via config', async () => {
      const config: AnomalyConfig = {
        tenantId: testTenantId,
        enableVolumeDetection: false,
        enableTimeDetection: true,
        enableRecipientDetection: true,
        enableContentDetection: false,
      };

      const configuredDetector = new AnomalyDetector(config);

      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 10, stdDev: 2 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: [],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['recipient@company.com'],
        subject: 'URGENT!!!',
        sentAt: new Date(),
        dailyVolumeForSender: 100, // Would trigger volume anomaly
      };

      const result = await configuredDetector.detectAnomalies(emailData, baseline);

      expect(result.volumeAnomaly).toBeUndefined();
      expect(result.contentAnomaly).toBeUndefined();
    });

    it('should merge tenant config with defaults', async () => {
      const partialConfig: Partial<AnomalyConfig> = {
        tenantId: testTenantId,
        volumeZScoreThreshold: 2.5,
        // Other values should use defaults
      };

      const detector = new AnomalyDetector(partialConfig as AnomalyConfig);

      expect(detector.getConfig().enableTimeDetection).toBe(true);
      expect(detector.getConfig().volumeZScoreThreshold).toBe(2.5);
    });
  });

  describe('Alert Generation for High Anomaly Scores', () => {
    it('should generate alert for high-severity anomaly', async () => {
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 10, stdDev: 2 },
        hourlyDistribution: [
          0.01, 0.005, 0.002, 0.001, 0.001, 0.01,
          0.03, 0.05, 0.08, 0.10, 0.10, 0.08,
          0.05, 0.08, 0.10, 0.10, 0.08, 0.05,
          0.03, 0.02, 0.015, 0.01, 0.007, 0.005,
        ],
        topRecipients: [],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
      };

      vi.setSystemTime(new Date('2024-01-15T03:00:00'));

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['unknown@suspicious.xyz'],
        subject: 'URGENT WIRE TRANSFER!!!',
        sentAt: new Date('2024-01-15T03:00:00'),
        dailyVolumeForSender: 100,
        isFirstContactWithRecipient: true,
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.shouldAlert).toBe(true);
      expect(result.alertSeverity).toBe('critical');
    });

    it('should not alert for low-severity anomalies', async () => {
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 50, stdDev: 10 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: [],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'sender@company.com',
        recipientEmails: ['recipient@company.com'],
        subject: 'Slightly urgent request',
        sentAt: new Date(),
        dailyVolumeForSender: 65, // Mild elevation
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      expect(result.shouldAlert).toBe(false);
    });

    it('should include alert metadata for integration', async () => {
      const baseline: TenantBaseline = {
        tenantId: testTenantId,
        dailyEmailVolume: { mean: 10, stdDev: 2 },
        hourlyDistribution: new Array(24).fill(0.0416),
        topRecipients: [],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
      };

      const emailData: EmailBehaviorData = {
        tenantId: testTenantId,
        senderEmail: 'attacker@malicious.com',
        recipientEmails: ['target@company.com'],
        subject: 'URGENT: Wire $50,000 now!',
        sentAt: new Date(),
        dailyVolumeForSender: 100,
        isFirstContactWithRecipient: true,
      };

      const result = await detector.detectAnomalies(emailData, baseline);

      if (result.shouldAlert) {
        expect(result.alertMetadata).toBeDefined();
        expect(result.alertMetadata!.emailId).toBeDefined();
        expect(result.alertMetadata!.senderEmail).toBe('attacker@malicious.com');
        expect(result.alertMetadata!.anomalyTypes.length).toBeGreaterThan(0);
      }
    });
  });
});

describe('Baseline Calculation', () => {
  it('should calculate baseline from historical data', async () => {
    const detector = new AnomalyDetector();

    const historicalData = [
      { sentAt: new Date('2024-01-10T09:00:00'), volume: 50 },
      { sentAt: new Date('2024-01-11T10:00:00'), volume: 45 },
      { sentAt: new Date('2024-01-12T11:00:00'), volume: 55 },
      { sentAt: new Date('2024-01-13T09:30:00'), volume: 48 },
      { sentAt: new Date('2024-01-14T10:30:00'), volume: 52 },
    ];

    const baseline = await detector.calculateBaseline('test-tenant', historicalData);

    expect(baseline.dailyEmailVolume.mean).toBeCloseTo(50, 0);
    expect(baseline.dailyEmailVolume.stdDev).toBeGreaterThan(0);
  });
});
