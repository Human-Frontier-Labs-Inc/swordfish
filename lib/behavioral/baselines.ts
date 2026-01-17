/**
 * Baseline Service Module
 * Phase 4.2: Communication behavior baselines and deviation detection
 */

import { sql } from '@/lib/db';
import {
  calculateMean,
  calculateStdDev,
  exponentialMovingAverage,
  calculateZScore,
  normalizeDistribution,
} from './statistics';

export interface VolumeStats {
  mean: number;
  stdDev: number;
  ema: number;
  dataPoints: number;
}

export interface SendTimeDistribution {
  hourCounts: Record<number, number>;
  hourPercentages: Record<number, number>;
  totalEmails: number;
}

export interface SubjectPatterns {
  replyPercentage: number;
  forwardPercentage: number;
  averageLength: number;
  commonPrefixes: string[];
  totalSubjects: number;
}

export interface ConfidenceFactors {
  dataPoints: number;
  recency: number;
  consistency: number;
}

export interface UserBaseline {
  userEmail: string;
  tenantId: string;
  dailySendVolume: VolumeStats;
  weeklySendVolume: VolumeStats;
  sendTimeDistribution: SendTimeDistribution;
  peakSendingHours: number[];
  typicalRecipients: string[];
  recipientFrequency: Record<string, number>;
  subjectPatterns: SubjectPatterns;
  volumeTrend: 'increasing' | 'decreasing' | 'stable';
  confidence: number;
  confidenceFactors: ConfidenceFactors;
  dataRecency: 'fresh' | 'moderate' | 'stale';
  isBootstrapped: boolean;
  lastUpdated: Date;
}

export interface DeviationCheck {
  dailySendCount: number;
  sendTime: Date;
  recipients: string[];
  subject?: string;
}

export interface Deviation {
  type: 'volume_spike' | 'unusual_time' | 'new_recipient' | 'unusual_subject';
  description: string;
  severity: number; // 0-1
  actual: string | number;
  expected: string | number;
}

export interface BaselineDeviation {
  hasDeviation: boolean;
  deviations: Deviation[];
  severity: number; // 0-1 overall severity
}

export interface OrgDefaults {
  dailySendVolume: { mean: number; stdDev: number };
  peakHours: number[];
  typicalSubjectLength: number;
}

export interface BaselineConfig {
  emaAlpha: number;
  minDataPointsForConfidence: number;
  volumeDeviationThreshold: number; // Z-score threshold
  timeDeviationThreshold: number;
  staleDataDays: number;
  moderateDataDays: number;
}

const DEFAULT_CONFIG: BaselineConfig = {
  emaAlpha: 0.2,
  minDataPointsForConfidence: 30,
  volumeDeviationThreshold: 2.0,
  timeDeviationThreshold: 0.01,
  staleDataDays: 30,
  moderateDataDays: 7,
};

/**
 * BaselineService for tracking and analyzing user communication patterns
 */
export class BaselineService {
  private tenantId: string;
  private config: BaselineConfig;
  private baselines: Map<string, UserBaseline> = new Map();
  private orgDefaults: OrgDefaults | null = null;

  // In-memory data stores
  private dailyVolumes: Map<string, number[]> = new Map();
  private weeklyVolumes: Map<string, number[]> = new Map();
  private sendTimes: Map<string, Date[]> = new Map();
  private recipients: Map<string, Map<string, number>> = new Map();
  private subjects: Map<string, string[]> = new Map();
  private lastRecordDates: Map<string, Date> = new Map();

  constructor(tenantId: string, config?: Partial<BaselineConfig>) {
    this.tenantId = tenantId;
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Set organization-wide defaults for bootstrapping new users
   */
  setOrgDefaults(defaults: OrgDefaults): void {
    this.orgDefaults = defaults;
  }

  /**
   * Get baseline for a user
   */
  getBaseline(userEmail: string): UserBaseline | null {
    const normalized = userEmail.toLowerCase();

    // Return cached baseline if exists
    const cached = this.baselines.get(normalized);
    if (cached) return cached;

    // Create bootstrapped baseline for new users
    if (this.orgDefaults) {
      const bootstrapped = this.createBootstrappedBaseline(normalized);
      this.baselines.set(normalized, bootstrapped);
      return bootstrapped;
    }

    // Check if we have any data
    const volumes = this.dailyVolumes.get(normalized);
    if (!volumes || volumes.length === 0) return null;

    // Generate baseline from collected data
    const baseline = this.generateBaseline(normalized);
    this.baselines.set(normalized, baseline);
    return baseline;
  }

  /**
   * Create a bootstrapped baseline from org defaults
   */
  private createBootstrappedBaseline(userEmail: string): UserBaseline {
    const defaults = this.orgDefaults!;

    return {
      userEmail,
      tenantId: this.tenantId,
      dailySendVolume: {
        mean: defaults.dailySendVolume.mean,
        stdDev: defaults.dailySendVolume.stdDev,
        ema: defaults.dailySendVolume.mean,
        dataPoints: 0,
      },
      weeklySendVolume: {
        mean: defaults.dailySendVolume.mean * 5,
        stdDev: defaults.dailySendVolume.stdDev * 5,
        ema: defaults.dailySendVolume.mean * 5,
        dataPoints: 0,
      },
      sendTimeDistribution: this.createDefaultTimeDistribution(defaults.peakHours),
      peakSendingHours: defaults.peakHours,
      typicalRecipients: [],
      recipientFrequency: {},
      subjectPatterns: {
        replyPercentage: 50,
        forwardPercentage: 10,
        averageLength: defaults.typicalSubjectLength,
        commonPrefixes: ['Re:', 'Fwd:'],
        totalSubjects: 0,
      },
      volumeTrend: 'stable',
      confidence: 0.1, // Low confidence for bootstrapped
      confidenceFactors: {
        dataPoints: 0,
        recency: 0,
        consistency: 0.5,
      },
      dataRecency: 'stale',
      isBootstrapped: true,
      lastUpdated: new Date(),
    };
  }

  /**
   * Create default time distribution from peak hours
   */
  private createDefaultTimeDistribution(peakHours: number[]): SendTimeDistribution {
    const hourCounts: Record<number, number> = {};
    const hourPercentages: Record<number, number> = {};

    for (let h = 0; h < 24; h++) {
      hourCounts[h] = peakHours.includes(h) ? 10 : 1;
    }

    const total = Object.values(hourCounts).reduce((a, b) => a + b, 0);
    for (let h = 0; h < 24; h++) {
      hourPercentages[h] = (hourCounts[h] / total) * 100;
    }

    return { hourCounts, hourPercentages, totalEmails: 0 };
  }

  /**
   * Generate baseline from collected data
   */
  private generateBaseline(userEmail: string): UserBaseline {
    const volumes = this.dailyVolumes.get(userEmail) || [];
    const weeklyVols = this.weeklyVolumes.get(userEmail) || [];
    const times = this.sendTimes.get(userEmail) || [];
    const recipientMap = this.recipients.get(userEmail) || new Map();
    const subjectList = this.subjects.get(userEmail) || [];

    const dailyStats = this.calculateVolumeStats(volumes);
    const weeklyStats = this.calculateVolumeStats(weeklyVols);
    const timeDistribution = this.calculateTimeDistribution(times);
    const peakHours = this.identifyPeakHours(timeDistribution);
    const recipientFreq = Object.fromEntries(recipientMap);
    const topRecipients = this.getTopRecipients(recipientMap, 10);
    const subjectPatterns = this.analyzeSubjectPatterns(subjectList);
    const trend = this.calculateVolumeTrend(volumes);
    const confidence = this.calculateConfidence(userEmail);
    const recency = this.calculateDataRecency(userEmail);

    // Blend with org defaults if bootstrapped
    const baseline = this.baselines.get(userEmail);
    if (baseline?.isBootstrapped && this.orgDefaults && volumes.length < 10) {
      // Gradually shift from org defaults to user-specific data
      const weight = Math.min(volumes.length / 10, 1);
      dailyStats.mean = dailyStats.mean * weight + this.orgDefaults.dailySendVolume.mean * (1 - weight);
    }

    return {
      userEmail,
      tenantId: this.tenantId,
      dailySendVolume: dailyStats,
      weeklySendVolume: weeklyStats,
      sendTimeDistribution: timeDistribution,
      peakSendingHours: peakHours,
      typicalRecipients: topRecipients,
      recipientFrequency: recipientFreq,
      subjectPatterns,
      volumeTrend: trend,
      confidence: confidence.overall,
      confidenceFactors: {
        dataPoints: confidence.dataPoints,
        recency: confidence.recency,
        consistency: confidence.consistency,
      },
      dataRecency: recency,
      isBootstrapped: false,
      lastUpdated: new Date(),
    };
  }

  /**
   * Calculate volume statistics
   */
  private calculateVolumeStats(volumes: number[]): VolumeStats {
    if (volumes.length === 0) {
      return { mean: 0, stdDev: 0, ema: 0, dataPoints: 0 };
    }

    return {
      mean: calculateMean(volumes),
      stdDev: calculateStdDev(volumes),
      ema: exponentialMovingAverage(volumes, this.config.emaAlpha),
      dataPoints: volumes.length,
    };
  }

  /**
   * Calculate time distribution from send times
   */
  private calculateTimeDistribution(times: Date[]): SendTimeDistribution {
    const hourCounts: Record<number, number> = {};
    for (let h = 0; h < 24; h++) {
      hourCounts[h] = 0;
    }

    for (const time of times) {
      const hour = time.getHours();
      hourCounts[hour]++;
    }

    const hourPercentages = normalizeDistribution(hourCounts);

    return {
      hourCounts,
      hourPercentages: hourPercentages as Record<number, number>,
      totalEmails: times.length,
    };
  }

  /**
   * Identify peak sending hours (top 3)
   */
  private identifyPeakHours(distribution: SendTimeDistribution): number[] {
    const entries = Object.entries(distribution.hourCounts)
      .map(([hour, count]) => ({ hour: parseInt(hour), count }))
      .sort((a, b) => b.count - a.count);

    return entries.slice(0, 3).map(e => e.hour);
  }

  /**
   * Get top N recipients by frequency
   */
  private getTopRecipients(recipientMap: Map<string, number>, n: number): string[] {
    return Array.from(recipientMap.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([email]) => email);
  }

  /**
   * Analyze subject line patterns
   */
  private analyzeSubjectPatterns(subjects: string[]): SubjectPatterns {
    if (subjects.length === 0) {
      return {
        replyPercentage: 0,
        forwardPercentage: 0,
        averageLength: 0,
        commonPrefixes: [],
        totalSubjects: 0,
      };
    }

    const replyCount = subjects.filter(s => /^re:/i.test(s)).length;
    const forwardCount = subjects.filter(s => /^fwd?:/i.test(s)).length;
    const totalLength = subjects.reduce((sum, s) => sum + s.length, 0);

    return {
      replyPercentage: (replyCount / subjects.length) * 100,
      forwardPercentage: (forwardCount / subjects.length) * 100,
      averageLength: totalLength / subjects.length,
      commonPrefixes: this.extractCommonPrefixes(subjects),
      totalSubjects: subjects.length,
    };
  }

  /**
   * Extract common subject prefixes
   */
  private extractCommonPrefixes(subjects: string[]): string[] {
    const prefixCounts: Record<string, number> = {};

    for (const subject of subjects) {
      const match = subject.match(/^([A-Za-z]+:)/);
      if (match) {
        const prefix = match[1];
        prefixCounts[prefix] = (prefixCounts[prefix] || 0) + 1;
      }
    }

    return Object.entries(prefixCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([prefix]) => prefix);
  }

  /**
   * Calculate volume trend
   */
  private calculateVolumeTrend(volumes: number[]): 'increasing' | 'decreasing' | 'stable' {
    if (volumes.length < 7) return 'stable';

    const recentWeek = volumes.slice(-7);
    const previousWeek = volumes.slice(-14, -7);

    if (previousWeek.length === 0) return 'stable';

    const recentMean = calculateMean(recentWeek);
    const previousMean = calculateMean(previousWeek);
    const change = (recentMean - previousMean) / (previousMean || 1);

    if (change > 0.2) return 'increasing';
    if (change < -0.2) return 'decreasing';
    return 'stable';
  }

  /**
   * Calculate confidence score
   */
  private calculateConfidence(userEmail: string): {
    overall: number;
    dataPoints: number;
    recency: number;
    consistency: number;
  } {
    const volumes = this.dailyVolumes.get(userEmail) || [];
    const times = this.sendTimes.get(userEmail) || [];
    const lastRecord = this.lastRecordDates.get(userEmail);

    // Data points factor
    const dataPointsScore = Math.min(volumes.length / this.config.minDataPointsForConfidence, 1);

    // Recency factor
    let recencyScore = 0;
    if (lastRecord) {
      const daysSinceRecord = (Date.now() - lastRecord.getTime()) / (1000 * 60 * 60 * 24);
      if (daysSinceRecord < 1) recencyScore = 1;
      else if (daysSinceRecord < 7) recencyScore = 0.8;
      else if (daysSinceRecord < 30) recencyScore = 0.5;
      else recencyScore = 0.2;
    }

    // Consistency factor (lower CV = higher consistency)
    let consistencyScore = 0.5;
    if (volumes.length > 5) {
      const cv = calculateStdDev(volumes) / (calculateMean(volumes) || 1);
      consistencyScore = Math.max(0, 1 - cv / 2);
    }

    // Weight data points more heavily - having little data should result in low confidence
    const overall = (dataPointsScore * 0.6 + recencyScore * 0.2 + consistencyScore * 0.2);

    return {
      overall,
      dataPoints: dataPointsScore,
      recency: recencyScore,
      consistency: consistencyScore,
    };
  }

  /**
   * Calculate data recency
   */
  private calculateDataRecency(userEmail: string): 'fresh' | 'moderate' | 'stale' {
    const lastRecord = this.lastRecordDates.get(userEmail);
    if (!lastRecord) return 'stale';

    const daysSinceRecord = (Date.now() - lastRecord.getTime()) / (1000 * 60 * 60 * 24);

    if (daysSinceRecord < this.config.moderateDataDays) return 'fresh';
    if (daysSinceRecord < this.config.staleDataDays) return 'moderate';
    return 'stale';
  }

  /**
   * Update send volume baseline from daily history
   */
  async updateSendVolumeBaseline(userEmail: string, history: { date: string; count: number }[]): Promise<void> {
    const normalized = userEmail.toLowerCase();
    const volumes = history.map(h => h.count);

    this.dailyVolumes.set(normalized, volumes);
    this.updateLastRecord(normalized);
    this.refreshBaseline(normalized);
  }

  /**
   * Update weekly send volume baseline
   */
  async updateWeeklySendVolumeBaseline(userEmail: string, history: { week: string; count: number }[]): Promise<void> {
    const normalized = userEmail.toLowerCase();
    const volumes = history.map(h => h.count);

    this.weeklyVolumes.set(normalized, volumes);
    this.updateLastRecord(normalized);
    this.refreshBaseline(normalized);
  }

  /**
   * Record a daily send count
   */
  async recordDailySendCount(userEmail: string, count: number, date: Date): Promise<void> {
    const normalized = userEmail.toLowerCase();

    if (!this.dailyVolumes.has(normalized)) {
      this.dailyVolumes.set(normalized, []);
    }

    this.dailyVolumes.get(normalized)!.push(count);
    this.updateLastRecord(normalized, date);
    this.refreshBaseline(normalized);
  }

  /**
   * Record a send time
   */
  async recordSendTime(userEmail: string, time: Date): Promise<void> {
    const normalized = userEmail.toLowerCase();

    if (!this.sendTimes.has(normalized)) {
      this.sendTimes.set(normalized, []);
    }

    this.sendTimes.get(normalized)!.push(time);
    this.updateLastRecord(normalized);
    this.refreshBaseline(normalized);
  }

  /**
   * Record a recipient
   */
  async recordRecipient(userEmail: string, recipientEmail: string): Promise<void> {
    const normalized = userEmail.toLowerCase();
    const normalizedRecipient = recipientEmail.toLowerCase();

    if (!this.recipients.has(normalized)) {
      this.recipients.set(normalized, new Map());
    }

    const recipientMap = this.recipients.get(normalized)!;
    recipientMap.set(normalizedRecipient, (recipientMap.get(normalizedRecipient) || 0) + 1);

    this.updateLastRecord(normalized);
    this.refreshBaseline(normalized);
  }

  /**
   * Record a subject line pattern
   */
  async recordSubjectPattern(userEmail: string, subject: string): Promise<void> {
    const normalized = userEmail.toLowerCase();

    if (!this.subjects.has(normalized)) {
      this.subjects.set(normalized, []);
    }

    this.subjects.get(normalized)!.push(subject);
    this.updateLastRecord(normalized);
    this.refreshBaseline(normalized);
  }

  /**
   * Check if a recipient is new for this user
   */
  isNewRecipient(userEmail: string, recipientEmail: string): boolean {
    const normalized = userEmail.toLowerCase();
    const normalizedRecipient = recipientEmail.toLowerCase();

    const recipientMap = this.recipients.get(normalized);
    if (!recipientMap) return true;

    return !recipientMap.has(normalizedRecipient);
  }

  /**
   * Check if a subject pattern is unusual
   */
  isUnusualSubjectPattern(userEmail: string, subject: string): boolean {
    const baseline = this.getBaseline(userEmail);
    if (!baseline) return false;

    // Check for excessive punctuation/caps
    const capsRatio = (subject.match(/[A-Z]/g)?.length || 0) / subject.length;
    const exclaimCount = (subject.match(/!/g)?.length || 0);

    if (capsRatio > 0.5 && subject.length > 10) return true;
    if (exclaimCount > 2) return true;

    // Check length deviation
    const avgLength = baseline.subjectPatterns.averageLength;
    if (avgLength > 0 && Math.abs(subject.length - avgLength) > avgLength * 2) {
      return true;
    }

    return false;
  }

  /**
   * Detect deviations from baseline
   */
  detectDeviation(userEmail: string, check: DeviationCheck): BaselineDeviation {
    const baseline = this.getBaseline(userEmail);

    if (!baseline) {
      return { hasDeviation: false, deviations: [], severity: 0 };
    }

    const deviations: Deviation[] = [];

    // Check volume deviation
    const volumeDeviation = this.checkVolumeDeviation(baseline, check.dailySendCount);
    if (volumeDeviation) deviations.push(volumeDeviation);

    // Check time deviation
    const timeDeviation = this.checkTimeDeviation(baseline, check.sendTime);
    if (timeDeviation) deviations.push(timeDeviation);

    // Check recipient deviations
    for (const recipient of check.recipients) {
      if (this.isNewRecipient(userEmail, recipient)) {
        deviations.push({
          type: 'new_recipient',
          description: `Email to new recipient: ${recipient}`,
          severity: 0.4,
          actual: recipient,
          expected: 'known recipient',
        });
      }
    }

    // Check subject deviation
    if (check.subject && this.isUnusualSubjectPattern(userEmail, check.subject)) {
      deviations.push({
        type: 'unusual_subject',
        description: 'Subject line has unusual pattern',
        severity: 0.3,
        actual: check.subject,
        expected: 'typical subject pattern',
      });
    }

    const overallSeverity = deviations.length > 0
      ? Math.min(deviations.reduce((sum, d) => sum + d.severity, 0), 1)
      : 0;

    return {
      hasDeviation: deviations.length > 0,
      deviations,
      severity: overallSeverity,
    };
  }

  /**
   * Check for volume deviation
   */
  private checkVolumeDeviation(baseline: UserBaseline, currentCount: number): Deviation | null {
    const { mean, stdDev } = baseline.dailySendVolume;

    if (mean === 0) return null;

    // If stdDev is 0 (all values identical), use percentage-based detection
    if (stdDev === 0) {
      const percentChange = Math.abs(currentCount - mean) / mean;
      if (percentChange > 1.0) { // More than 100% change
        const severity = Math.min(percentChange / 5, 1);
        return {
          type: 'volume_spike',
          description: `Send volume ${currentCount > mean ? 'spike' : 'drop'}: ${currentCount} vs typical ${mean.toFixed(1)}`,
          severity,
          actual: currentCount,
          expected: mean,
        };
      }
      return null;
    }

    const zScore = calculateZScore(currentCount, mean, stdDev);

    if (Math.abs(zScore) > this.config.volumeDeviationThreshold) {
      const severity = Math.min(Math.abs(zScore) / 5, 1);
      return {
        type: 'volume_spike',
        description: `Send volume ${zScore > 0 ? 'spike' : 'drop'}: ${currentCount} vs typical ${mean.toFixed(1)}`,
        severity,
        actual: currentCount,
        expected: mean,
      };
    }

    return null;
  }

  /**
   * Check for unusual send time
   */
  private checkTimeDeviation(baseline: UserBaseline, sendTime: Date): Deviation | null {
    const hour = sendTime.getHours();
    const hourPercentage = baseline.sendTimeDistribution.hourPercentages[hour] || 0;

    // If this hour is rarely used (< 1% of sends), flag it
    if (hourPercentage < this.config.timeDeviationThreshold * 100) {
      return {
        type: 'unusual_time',
        description: `Email sent at unusual time: ${hour}:00 (${hourPercentage.toFixed(1)}% typical)`,
        severity: 0.5,
        actual: `${hour}:00`,
        expected: `peak hours: ${baseline.peakSendingHours.join(', ')}`,
      };
    }

    return null;
  }

  /**
   * Update last record timestamp
   */
  private updateLastRecord(userEmail: string, date?: Date): void {
    const recordDate = date || new Date();
    const existing = this.lastRecordDates.get(userEmail);
    // Keep the most recent date
    if (!existing || recordDate > existing) {
      this.lastRecordDates.set(userEmail, recordDate);
    }
  }

  /**
   * Refresh baseline from current data
   */
  private refreshBaseline(userEmail: string): void {
    const existingBaseline = this.baselines.get(userEmail);
    const newBaseline = this.generateBaseline(userEmail);

    // If transitioning from bootstrapped, preserve the flag until sufficient data
    if (existingBaseline?.isBootstrapped) {
      const volumes = this.dailyVolumes.get(userEmail) || [];
      newBaseline.isBootstrapped = volumes.length < 10;
    }

    this.baselines.set(userEmail, newBaseline);
  }

  /**
   * Clear baseline for a user
   */
  clearBaseline(userEmail: string): void {
    const normalized = userEmail.toLowerCase();
    this.baselines.delete(normalized);
    this.dailyVolumes.delete(normalized);
    this.weeklyVolumes.delete(normalized);
    this.sendTimes.delete(normalized);
    this.recipients.delete(normalized);
    this.subjects.delete(normalized);
    this.lastRecordDates.delete(normalized);
  }
}
