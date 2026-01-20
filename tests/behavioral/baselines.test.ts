/**
 * Communication Baselines Tests
 * Phase 4.2: User behavior baseline tracking
 * TDD: 25 tests for baseline functionality
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  BaselineService,
  UserBaseline,
  BaselineDeviation,
  SendTimeDistribution,
  BaselineConfig,
} from '@/lib/behavioral/baselines';
import {
  calculateMean,
  calculateStdDev,
  exponentialMovingAverage,
  calculatePercentile,
  normalizeDistribution,
} from '@/lib/behavioral/statistics';

// Mock database
vi.mock('@/lib/db', () => ({
  sql: vi.fn().mockImplementation(() => Promise.resolve([])),
}));

describe('Baseline Service', () => {
  let baselineService: BaselineService;
  const testTenantId = 'tenant_123';

  beforeEach(() => {
    vi.clearAllMocks();
    baselineService = new BaselineService(testTenantId);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Calculate typical send volume per user', () => {
    it('should calculate daily send volume baseline', async () => {
      const userEmail = 'user@company.com';

      // Simulate 7 days of email data
      const emailHistory = [
        { date: '2024-01-15', count: 10 },
        { date: '2024-01-16', count: 12 },
        { date: '2024-01-17', count: 8 },
        { date: '2024-01-18', count: 15 },
        { date: '2024-01-19', count: 11 },
        { date: '2024-01-20', count: 9 },
        { date: '2024-01-21', count: 13 },
      ];

      await baselineService.updateSendVolumeBaseline(userEmail, emailHistory);
      const baseline = baselineService.getBaseline(userEmail);

      expect(baseline?.dailySendVolume.mean).toBeCloseTo(11.14, 1);
      expect(baseline?.dailySendVolume.stdDev).toBeGreaterThan(0);
    });

    it('should calculate weekly send volume baseline', async () => {
      const userEmail = 'user@company.com';

      // Simulate 4 weeks of email data
      const weeklyHistory = [
        { week: '2024-W01', count: 55 },
        { week: '2024-W02', count: 62 },
        { week: '2024-W03', count: 48 },
        { week: '2024-W04', count: 58 },
      ];

      await baselineService.updateWeeklySendVolumeBaseline(userEmail, weeklyHistory);
      const baseline = baselineService.getBaseline(userEmail);

      expect(baseline?.weeklySendVolume.mean).toBeCloseTo(55.75, 1);
    });

    it('should track send volume trends over time', async () => {
      const userEmail = 'user@company.com';

      // Process emails over multiple days
      for (let day = 0; day < 14; day++) {
        const count = 10 + Math.floor(day / 2); // Gradually increasing
        await baselineService.recordDailySendCount(userEmail, count, new Date(2024, 0, 15 + day));
      }

      const baseline = baselineService.getBaseline(userEmail);
      expect(baseline?.volumeTrend).toBeDefined();
    });
  });

  describe('Calculate typical send times', () => {
    it('should build hour distribution from email history', async () => {
      const userEmail = 'user@company.com';

      // Simulate emails throughout the day
      const sendTimes = [
        9, 9, 10, 10, 10, 11, 14, 14, 15, 16, // Working hours
        22, // Late night outlier
      ];

      for (const hour of sendTimes) {
        await baselineService.recordSendTime(userEmail, new Date(2024, 0, 15, hour, 0, 0));
      }

      const baseline = baselineService.getBaseline(userEmail);
      const distribution = baseline?.sendTimeDistribution;

      expect(distribution).toBeDefined();
      expect(distribution?.hourCounts[10]).toBe(3); // Peak hour
    });

    it('should identify peak sending hours', async () => {
      const userEmail = 'user@company.com';

      // Concentrated activity in morning
      const sendTimes = [9, 9, 9, 10, 10, 10, 10, 11, 11, 14, 15];

      for (const hour of sendTimes) {
        await baselineService.recordSendTime(userEmail, new Date(2024, 0, 15, hour, 0, 0));
      }

      const baseline = baselineService.getBaseline(userEmail);
      const peakHours = baseline?.peakSendingHours;

      expect(peakHours).toContain(10);
    });

    it('should normalize time distribution to percentages', async () => {
      const userEmail = 'user@company.com';

      const sendTimes = [9, 9, 10, 10, 10, 10, 11, 11, 11, 11]; // 10 total emails

      for (const hour of sendTimes) {
        await baselineService.recordSendTime(userEmail, new Date(2024, 0, 15, hour, 0, 0));
      }

      const baseline = baselineService.getBaseline(userEmail);
      const distribution = baseline?.sendTimeDistribution;

      expect(distribution?.hourPercentages[9]).toBeCloseTo(20, 1);
      expect(distribution?.hourPercentages[10]).toBeCloseTo(40, 1);
      expect(distribution?.hourPercentages[11]).toBeCloseTo(40, 1);
    });
  });

  describe('Calculate typical recipients list', () => {
    it('should track frequent recipients', async () => {
      const userEmail = 'sender@company.com';

      const recipients = [
        'bob@company.com',
        'bob@company.com',
        'bob@company.com',
        'alice@company.com',
        'alice@company.com',
        'charlie@company.com',
      ];

      for (const recipient of recipients) {
        await baselineService.recordRecipient(userEmail, recipient);
      }

      const baseline = baselineService.getBaseline(userEmail);
      const topRecipients = baseline?.typicalRecipients;

      expect(topRecipients?.[0]).toBe('bob@company.com');
      expect(topRecipients?.length).toBeLessThanOrEqual(10); // Top 10 only
    });

    it('should calculate recipient frequency scores', async () => {
      const userEmail = 'sender@company.com';

      // Send 5 emails to bob, 2 to alice
      for (let i = 0; i < 5; i++) {
        await baselineService.recordRecipient(userEmail, 'bob@company.com');
      }
      for (let i = 0; i < 2; i++) {
        await baselineService.recordRecipient(userEmail, 'alice@company.com');
      }

      const baseline = baselineService.getBaseline(userEmail);

      expect(baseline?.recipientFrequency['bob@company.com']).toBe(5);
      expect(baseline?.recipientFrequency['alice@company.com']).toBe(2);
    });

    it('should identify new vs established recipients', async () => {
      const userEmail = 'sender@company.com';

      // Establish baseline with bob
      for (let i = 0; i < 10; i++) {
        await baselineService.recordRecipient(userEmail, 'bob@company.com');
      }

      const isNewRecipient = baselineService.isNewRecipient(userEmail, 'new@external.com');
      const isEstablished = baselineService.isNewRecipient(userEmail, 'bob@company.com');

      expect(isNewRecipient).toBe(true);
      expect(isEstablished).toBe(false);
    });
  });

  describe('Calculate typical subject line patterns', () => {
    it('should track common subject prefixes', async () => {
      const userEmail = 'user@company.com';

      const subjects = [
        'Re: Weekly Report',
        'Re: Project Update',
        'Re: Meeting Tomorrow',
        'Fwd: Important Document',
        'Weekly Report',
        'RE: Budget Review',
      ];

      for (const subject of subjects) {
        await baselineService.recordSubjectPattern(userEmail, subject);
      }

      const baseline = baselineService.getBaseline(userEmail);

      expect(baseline?.subjectPatterns.replyPercentage).toBeGreaterThan(0);
      expect(baseline?.subjectPatterns.forwardPercentage).toBeGreaterThan(0);
    });

    it('should calculate average subject length', async () => {
      const userEmail = 'user@company.com';

      const subjects = [
        'Short',
        'Medium subject line',
        'This is a longer subject line for testing',
      ];

      for (const subject of subjects) {
        await baselineService.recordSubjectPattern(userEmail, subject);
      }

      const baseline = baselineService.getBaseline(userEmail);

      expect(baseline?.subjectPatterns.averageLength).toBeGreaterThan(0);
    });

    it('should detect unusual subject patterns', async () => {
      const userEmail = 'user@company.com';

      // Establish baseline with normal subjects
      for (let i = 0; i < 20; i++) {
        await baselineService.recordSubjectPattern(userEmail, 'Normal subject line');
      }

      const isUnusual = baselineService.isUnusualSubjectPattern(
        userEmail,
        'URGENT!!! WIRE TRANSFER NEEDED IMMEDIATELY!!!'
      );

      expect(isUnusual).toBe(true);
    });
  });

  describe('Rolling baseline updates (EMA)', () => {
    it('should use exponential moving average for updates', async () => {
      const userEmail = 'user@company.com';
      const alpha = 0.2; // EMA smoothing factor

      // Record daily volumes
      const volumes = [10, 12, 8, 15, 11, 9, 13];

      for (let i = 0; i < volumes.length; i++) {
        await baselineService.recordDailySendCount(
          userEmail,
          volumes[i],
          new Date(2024, 0, 15 + i)
        );
      }

      const baseline = baselineService.getBaseline(userEmail);

      // EMA should weight recent values more heavily
      expect(baseline?.dailySendVolume.ema).toBeDefined();
    });

    it('should update baseline incrementally', async () => {
      const userEmail = 'user@company.com';

      // Initial baseline
      await baselineService.recordDailySendCount(userEmail, 10, new Date(2024, 0, 15));
      const initialBaseline = baselineService.getBaseline(userEmail);

      // Update with new data
      await baselineService.recordDailySendCount(userEmail, 20, new Date(2024, 0, 16));
      const updatedBaseline = baselineService.getBaseline(userEmail);

      expect(updatedBaseline?.dailySendVolume.ema).not.toBe(initialBaseline?.dailySendVolume.ema);
    });

    it('should preserve historical context in rolling updates', async () => {
      const userEmail = 'user@company.com';

      // Record 30 days of data
      for (let i = 0; i < 30; i++) {
        await baselineService.recordDailySendCount(userEmail, 10 + i, new Date(2024, 0, i + 1));
      }

      const baseline = baselineService.getBaseline(userEmail);

      // Historical data should still influence the baseline
      expect(baseline?.dailySendVolume.dataPoints).toBe(30);
    });
  });

  describe('Baseline confidence scoring', () => {
    it('should have low confidence with little data', async () => {
      const userEmail = 'user@company.com';

      // Only 3 data points
      for (let i = 0; i < 3; i++) {
        await baselineService.recordDailySendCount(userEmail, 10, new Date(2024, 0, 15 + i));
      }

      const baseline = baselineService.getBaseline(userEmail);

      expect(baseline?.confidence).toBeLessThan(0.5);
    });

    it('should have high confidence with sufficient data', async () => {
      const userEmail = 'user@company.com';

      // 30+ data points
      for (let i = 0; i < 30; i++) {
        await baselineService.recordDailySendCount(userEmail, 10 + (i % 5), new Date(2024, 0, i + 1));
      }

      const baseline = baselineService.getBaseline(userEmail);

      expect(baseline?.confidence).toBeGreaterThan(0.7);
    });

    it('should factor in data recency for confidence', async () => {
      const userEmail = 'user@company.com';

      // Old data (60 days ago)
      for (let i = 0; i < 20; i++) {
        const date = new Date();
        date.setDate(date.getDate() - 60 + i);
        await baselineService.recordDailySendCount(userEmail, 10, date);
      }

      const baseline = baselineService.getBaseline(userEmail);

      // Confidence should be lower due to stale data
      expect(baseline?.dataRecency).toBe('stale');
    });

    it('should calculate confidence based on multiple factors', async () => {
      const userEmail = 'user@company.com';

      // Add comprehensive data
      for (let i = 0; i < 30; i++) {
        const date = new Date(2024, 0, i + 1);
        await baselineService.recordDailySendCount(userEmail, 10 + (i % 5), date);
        await baselineService.recordSendTime(userEmail, new Date(2024, 0, i + 1, 10, 0, 0));
        await baselineService.recordRecipient(userEmail, 'recipient@company.com');
      }

      const baseline = baselineService.getBaseline(userEmail);

      expect(baseline?.confidence).toBeGreaterThan(0.8);
      expect(baseline?.confidenceFactors.dataPoints).toBeGreaterThan(0.7);
      expect(baseline?.confidenceFactors.recency).toBeGreaterThan(0.7);
      expect(baseline?.confidenceFactors.consistency).toBeGreaterThan(0.5);
    });
  });

  describe('New user baseline bootstrapping', () => {
    it('should use org defaults for new users', async () => {
      const newUserEmail = 'newuser@company.com';

      // Set org defaults
      baselineService.setOrgDefaults({
        dailySendVolume: { mean: 15, stdDev: 5 },
        peakHours: [9, 10, 11, 14, 15, 16],
        typicalSubjectLength: 30,
      });

      const baseline = baselineService.getBaseline(newUserEmail);

      expect(baseline?.isBootstrapped).toBe(true);
      expect(baseline?.dailySendVolume.mean).toBe(15);
    });

    it('should transition from org defaults to user-specific baseline', async () => {
      const newUserEmail = 'newuser@company.com';

      // Set org defaults
      baselineService.setOrgDefaults({
        dailySendVolume: { mean: 15, stdDev: 5 },
        peakHours: [9, 10, 11, 14, 15, 16],
        typicalSubjectLength: 30,
      });

      // User starts sending emails
      for (let i = 0; i < 10; i++) {
        await baselineService.recordDailySendCount(newUserEmail, 25, new Date(2024, 0, 15 + i));
      }

      const baseline = baselineService.getBaseline(newUserEmail);

      // Should blend org defaults with user data
      expect(baseline?.dailySendVolume.mean).toBeGreaterThan(15);
      expect(baseline?.isBootstrapped).toBe(false);
    });

    it('should weight user data more as it accumulates', async () => {
      const newUserEmail = 'newuser@company.com';

      baselineService.setOrgDefaults({
        dailySendVolume: { mean: 10, stdDev: 3 },
        peakHours: [9, 10, 11],
        typicalSubjectLength: 25,
      });

      // User consistently sends 30 emails/day
      for (let i = 0; i < 20; i++) {
        await baselineService.recordDailySendCount(newUserEmail, 30, new Date(2024, 0, i + 1));
      }

      const baseline = baselineService.getBaseline(newUserEmail);

      // User's actual behavior should dominate
      expect(baseline?.dailySendVolume.mean).toBeCloseTo(30, 5);
    });
  });

  describe('Detect deviation from baseline', () => {
    it('should detect volume spike deviation', async () => {
      const userEmail = 'user@company.com';

      // Establish baseline (10 emails/day)
      for (let i = 0; i < 30; i++) {
        await baselineService.recordDailySendCount(userEmail, 10, new Date(2024, 0, i + 1));
      }

      // Check for deviation with 50 emails
      const deviation = baselineService.detectDeviation(userEmail, {
        dailySendCount: 50,
        sendTime: new Date(2024, 0, 31, 10, 0, 0),
        recipients: ['regular@company.com'],
      });

      expect(deviation.hasDeviation).toBe(true);
      expect(deviation.deviations).toContainEqual(
        expect.objectContaining({ type: 'volume_spike' })
      );
    });

    it('should detect unusual send time deviation', async () => {
      const userEmail = 'user@company.com';

      // Establish baseline (sends during work hours 9-17)
      for (let i = 0; i < 30; i++) {
        const hour = 9 + (i % 8);
        await baselineService.recordSendTime(userEmail, new Date(2024, 0, i + 1, hour, 0, 0));
      }

      // Check for deviation with 3 AM send
      const deviation = baselineService.detectDeviation(userEmail, {
        dailySendCount: 10,
        sendTime: new Date(2024, 1, 1, 3, 0, 0), // 3 AM
        recipients: ['regular@company.com'],
      });

      expect(deviation.hasDeviation).toBe(true);
      expect(deviation.deviations).toContainEqual(
        expect.objectContaining({ type: 'unusual_time' })
      );
    });

    it('should detect new recipient deviation', async () => {
      const userEmail = 'user@company.com';

      // Establish baseline with regular recipients
      for (let i = 0; i < 20; i++) {
        await baselineService.recordRecipient(userEmail, 'regular@company.com');
      }

      // Check for deviation with new external recipient
      const deviation = baselineService.detectDeviation(userEmail, {
        dailySendCount: 10,
        sendTime: new Date(2024, 0, 31, 10, 0, 0),
        recipients: ['unknown@external.com'],
      });

      expect(deviation.hasDeviation).toBe(true);
      expect(deviation.deviations).toContainEqual(
        expect.objectContaining({ type: 'new_recipient' })
      );
    });

    it('should calculate deviation severity score', async () => {
      const userEmail = 'user@company.com';

      // Establish baseline
      for (let i = 0; i < 30; i++) {
        await baselineService.recordDailySendCount(userEmail, 10, new Date(2024, 0, i + 1));
        await baselineService.recordSendTime(userEmail, new Date(2024, 0, i + 1, 10, 0, 0));
        await baselineService.recordRecipient(userEmail, 'regular@company.com');
      }

      // Mild deviation
      const mildDeviation = baselineService.detectDeviation(userEmail, {
        dailySendCount: 15, // 50% increase
        sendTime: new Date(2024, 0, 31, 10, 0, 0),
        recipients: ['regular@company.com'],
      });

      // Severe deviation
      const severeDeviation = baselineService.detectDeviation(userEmail, {
        dailySendCount: 100, // 10x increase
        sendTime: new Date(2024, 0, 31, 3, 0, 0), // 3 AM
        recipients: ['unknown@external.com'],
      });

      expect(severeDeviation.severity).toBeGreaterThan(mildDeviation.severity);
    });

    it('should return no deviation for normal behavior', async () => {
      const userEmail = 'user@company.com';

      // Establish baseline
      for (let i = 0; i < 30; i++) {
        await baselineService.recordDailySendCount(userEmail, 10, new Date(2024, 0, i + 1));
        await baselineService.recordSendTime(userEmail, new Date(2024, 0, i + 1, 10, 0, 0));
        await baselineService.recordRecipient(userEmail, 'regular@company.com');
      }

      // Check normal behavior
      const deviation = baselineService.detectDeviation(userEmail, {
        dailySendCount: 11, // Within normal range
        sendTime: new Date(2024, 0, 31, 10, 0, 0), // Normal hour
        recipients: ['regular@company.com'], // Known recipient
      });

      expect(deviation.hasDeviation).toBe(false);
    });
  });
});

describe('Statistical Helpers', () => {
  describe('calculateMean', () => {
    it('should calculate mean correctly', () => {
      const values = [10, 20, 30, 40, 50];
      expect(calculateMean(values)).toBe(30);
    });

    it('should return 0 for empty array', () => {
      expect(calculateMean([])).toBe(0);
    });
  });

  describe('calculateStdDev', () => {
    it('should calculate standard deviation correctly', () => {
      const values = [2, 4, 4, 4, 5, 5, 7, 9];
      expect(calculateStdDev(values)).toBeCloseTo(2, 0);
    });

    it('should return 0 for single value', () => {
      expect(calculateStdDev([5])).toBe(0);
    });
  });

  describe('exponentialMovingAverage', () => {
    it('should calculate EMA correctly', () => {
      const values = [10, 12, 11, 13, 12, 14, 13];
      const ema = exponentialMovingAverage(values, 0.2);

      expect(ema).toBeGreaterThan(10);
      expect(ema).toBeLessThan(14);
    });

    it('should weight recent values more heavily', () => {
      const lowThenHigh = [10, 10, 10, 20, 20, 20];
      const highThenLow = [20, 20, 20, 10, 10, 10];

      const emaLowHigh = exponentialMovingAverage(lowThenHigh, 0.3);
      const emaHighLow = exponentialMovingAverage(highThenLow, 0.3);

      expect(emaLowHigh).toBeGreaterThan(emaHighLow);
    });
  });

  describe('calculatePercentile', () => {
    it('should calculate percentile correctly', () => {
      const values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

      expect(calculatePercentile(values, 50)).toBe(5.5);
      expect(calculatePercentile(values, 90)).toBeCloseTo(9.1, 1);
    });
  });

  describe('normalizeDistribution', () => {
    it('should normalize values to percentages', () => {
      const counts = { a: 10, b: 20, c: 30 };
      const normalized = normalizeDistribution(counts);

      expect(normalized.a).toBeCloseTo(16.67, 1);
      expect(normalized.b).toBeCloseTo(33.33, 1);
      expect(normalized.c).toBe(50);
    });
  });
});
