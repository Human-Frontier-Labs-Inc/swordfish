/**
 * Anomaly Detection Engine
 * Detects behavioral anomalies in email patterns including volume, timing, recipients, and content
 */

export interface TenantBaseline {
  tenantId: string;
  dailyEmailVolume: { mean: number; stdDev: number };
  hourlyDistribution: number[]; // 24 elements, probabilities for each hour
  topRecipients: string[];
  topSenders: string[];
  subjectPatterns: string[];
  calculatedAt: Date;
  knownRecipientDomains?: string[];
  weekendActivity?: number; // Proportion of emails on weekends (0-1)
}

export interface EmailBehaviorData {
  tenantId: string;
  senderEmail: string;
  recipientEmails: string[];
  subject: string;
  sentAt: Date;
  dailyVolumeForSender: number;
  isFirstContactWithRecipient?: boolean;
}

export interface VolumeAnomaly {
  zScore: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  actualVolume: number;
  expectedVolume: number;
}

export interface TimeAnomaly {
  isUnusualHour: boolean;
  hourProbability: number;
  hour: number;
  severity: 'low' | 'medium' | 'high';
  isWeekend?: boolean;
}

export interface RecipientAnomaly {
  hasNewRecipient: boolean;
  hasNewDomain: boolean;
  newRecipientCount: number;
  newDomains?: string[];
  severity: 'low' | 'medium' | 'high';
}

export interface ContentAnomaly {
  hasUnusualSubject: boolean;
  urgencyScore: number;
  allCapsSubject: boolean;
  excessivePunctuation?: boolean;
  severity: 'low' | 'medium' | 'high';
}

export interface AlertMetadata {
  emailId: string;
  senderEmail: string;
  anomalyTypes: string[];
  compositeScore: number;
  timestamp: Date;
}

export interface AnomalyResult {
  tenantId: string;
  emailId: string;
  hasAnomaly: boolean;
  compositeScore: number;
  anomalyTypes: string[];
  volumeAnomaly?: VolumeAnomaly;
  timeAnomaly?: TimeAnomaly;
  recipientAnomaly?: RecipientAnomaly;
  contentAnomaly?: ContentAnomaly;
  detectedAt: Date;
  feedbackAdjustment?: number;
  shouldAlert?: boolean;
  alertSeverity?: 'low' | 'medium' | 'high' | 'critical';
  alertMetadata?: AlertMetadata;
}

export interface AnomalyConfig {
  tenantId: string;
  volumeZScoreThreshold?: number;
  unusualHourThreshold?: number;
  contentUrgencyThreshold?: number;
  enableVolumeDetection?: boolean;
  enableTimeDetection?: boolean;
  enableRecipientDetection?: boolean;
  enableContentDetection?: boolean;
  alertThreshold?: number;
}

export interface AnomalyFeedback {
  tenantId: string;
  emailId: string;
  feedbackType: 'false_positive' | 'true_positive';
  anomalyTypes: string[];
  providedBy: string;
}

interface FeedbackHistory {
  tenantId: string;
  anomalyType: string;
  falsePositiveCount: number;
  truePositiveCount: number;
}

const DEFAULT_CONFIG: AnomalyConfig = {
  tenantId: '',
  volumeZScoreThreshold: 3.0,
  unusualHourThreshold: 0.02,
  contentUrgencyThreshold: 0.7,
  enableVolumeDetection: true,
  enableTimeDetection: true,
  enableRecipientDetection: true,
  enableContentDetection: true,
  alertThreshold: 70,
};

// Urgency keywords for content analysis
const URGENCY_KEYWORDS = [
  'urgent', 'asap', 'immediately', 'now', 'critical', 'emergency',
  'deadline', 'expire', 'suspend', 'terminate', 'action required',
  'final warning', 'last chance', 'time sensitive', 'respond immediately',
];

export class AnomalyDetector {
  private config: AnomalyConfig;
  private feedbackHistory: Map<string, FeedbackHistory> = new Map();
  private contactHistory: Map<string, Set<string>> = new Map();

  constructor(config?: Partial<AnomalyConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  getConfig(): AnomalyConfig {
    return { ...this.config };
  }

  async detectAnomalies(
    emailData: EmailBehaviorData,
    baseline: TenantBaseline
  ): Promise<AnomalyResult> {
    const anomalyTypes: string[] = [];
    let volumeAnomaly: VolumeAnomaly | undefined;
    let timeAnomaly: TimeAnomaly | undefined;
    let recipientAnomaly: RecipientAnomaly | undefined;
    let contentAnomaly: ContentAnomaly | undefined;

    // Volume anomaly detection
    if (this.config.enableVolumeDetection) {
      volumeAnomaly = this.detectVolumeAnomaly(emailData, baseline);
      if (volumeAnomaly && volumeAnomaly.severity !== 'low') {
        anomalyTypes.push('volume');
      }
    }

    // Time anomaly detection
    if (this.config.enableTimeDetection) {
      timeAnomaly = this.detectTimeAnomaly(emailData, baseline);
      if (timeAnomaly && timeAnomaly.isUnusualHour) {
        anomalyTypes.push('time');
      }
    }

    // Recipient anomaly detection
    if (this.config.enableRecipientDetection) {
      recipientAnomaly = this.detectRecipientAnomaly(emailData, baseline);
      if (recipientAnomaly && recipientAnomaly.hasNewRecipient) {
        anomalyTypes.push('recipient');
      }
    }

    // Content anomaly detection
    if (this.config.enableContentDetection) {
      contentAnomaly = this.detectContentAnomaly(emailData, baseline);
      if (contentAnomaly && contentAnomaly.hasUnusualSubject) {
        anomalyTypes.push('content');
      }
    }

    // Calculate composite score
    const compositeScore = this.calculateCompositeScore(
      volumeAnomaly,
      timeAnomaly,
      recipientAnomaly,
      contentAnomaly
    );

    // Apply feedback adjustment
    const adjustedScore = this.applyFeedbackAdjustment(
      compositeScore,
      anomalyTypes,
      emailData.tenantId
    );

    const hasAnomaly = adjustedScore >= 30 || anomalyTypes.length > 0;

    // Determine alerting
    const { shouldAlert, alertSeverity } = this.determineAlertStatus(
      adjustedScore,
      anomalyTypes
    );

    const result: AnomalyResult = {
      tenantId: emailData.tenantId,
      emailId: `email-${Date.now()}`,
      hasAnomaly,
      compositeScore: adjustedScore,
      anomalyTypes,
      volumeAnomaly,
      timeAnomaly,
      recipientAnomaly,
      contentAnomaly,
      detectedAt: new Date(),
      feedbackAdjustment: adjustedScore !== compositeScore ? compositeScore - adjustedScore : undefined,
      shouldAlert,
      alertSeverity,
    };

    // Add alert metadata if alerting
    if (shouldAlert) {
      result.alertMetadata = {
        emailId: result.emailId,
        senderEmail: emailData.senderEmail,
        anomalyTypes,
        compositeScore: adjustedScore,
        timestamp: new Date(),
      };
    }

    return result;
  }

  private detectVolumeAnomaly(
    emailData: EmailBehaviorData,
    baseline: TenantBaseline
  ): VolumeAnomaly | undefined {
    const { mean, stdDev } = baseline.dailyEmailVolume;

    if (stdDev === 0) {
      return undefined;
    }

    const zScore = (emailData.dailyVolumeForSender - mean) / stdDev;
    const threshold = this.config.volumeZScoreThreshold || 3.0;

    let severity: VolumeAnomaly['severity'] = 'low';
    if (zScore >= threshold + 5) {
      severity = 'critical';
    } else if (zScore >= threshold + 1) {
      severity = 'high';
    } else if (zScore >= threshold) {
      severity = 'medium';
    }

    return {
      zScore,
      severity,
      actualVolume: emailData.dailyVolumeForSender,
      expectedVolume: mean,
    };
  }

  private detectTimeAnomaly(
    emailData: EmailBehaviorData,
    baseline: TenantBaseline
  ): TimeAnomaly | undefined {
    const hour = emailData.sentAt.getHours();
    const dayOfWeek = emailData.sentAt.getDay();
    const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;

    const hourProbability = baseline.hourlyDistribution[hour] || 0.0416;
    const threshold = this.config.unusualHourThreshold || 0.02;
    const isUnusualHour = hourProbability < threshold;

    let severity: TimeAnomaly['severity'] = 'low';
    if (hourProbability < 0.005) {
      severity = 'high';
    } else if (hourProbability < 0.01) {
      severity = 'medium';
    }

    return {
      isUnusualHour,
      hourProbability,
      hour,
      severity,
      isWeekend,
    };
  }

  private detectRecipientAnomaly(
    emailData: EmailBehaviorData,
    baseline: TenantBaseline
  ): RecipientAnomaly | undefined {
    const knownRecipients = new Set(baseline.topRecipients);
    const knownDomains = new Set(baseline.knownRecipientDomains || []);

    let newRecipientCount = 0;
    const newDomains: string[] = [];

    for (const recipient of emailData.recipientEmails) {
      if (!knownRecipients.has(recipient)) {
        newRecipientCount++;
      }

      const domain = recipient.split('@')[1]?.toLowerCase();
      if (domain && !knownDomains.has(domain)) {
        if (!newDomains.includes(domain)) {
          newDomains.push(domain);
        }
      }
    }

    const hasNewRecipient = newRecipientCount > 0 || emailData.isFirstContactWithRecipient === true;
    const hasNewDomain = newDomains.length > 0;

    let severity: RecipientAnomaly['severity'] = 'low';
    if (newRecipientCount >= 3 || (hasNewDomain && newDomains.length >= 2)) {
      severity = 'high';
    } else if (newRecipientCount >= 2 || hasNewDomain) {
      severity = 'medium';
    }

    return {
      hasNewRecipient,
      hasNewDomain,
      newRecipientCount,
      newDomains,
      severity,
    };
  }

  private detectContentAnomaly(
    emailData: EmailBehaviorData,
    baseline: TenantBaseline
  ): ContentAnomaly | undefined {
    const subject = emailData.subject || '';
    const lowerSubject = subject.toLowerCase();

    // Check urgency score
    let urgencyCount = 0;
    for (const keyword of URGENCY_KEYWORDS) {
      if (lowerSubject.includes(keyword)) {
        urgencyCount++;
      }
    }
    const urgencyScore = Math.min(urgencyCount / 3, 1);

    // Check all caps
    const alphaChars = subject.replace(/[^a-zA-Z]/g, '');
    const allCapsSubject = alphaChars.length > 5 && alphaChars === alphaChars.toUpperCase();

    // Check excessive punctuation
    const punctuationCount = (subject.match(/[!?]{2,}/g) || []).length;
    const excessivePunctuation = punctuationCount > 0;

    // Check if subject matches known patterns
    const matchesKnownPattern = baseline.subjectPatterns.some(pattern =>
      lowerSubject.includes(pattern.toLowerCase())
    );

    const hasUnusualSubject =
      urgencyScore >= (this.config.contentUrgencyThreshold || 0.7) ||
      allCapsSubject ||
      excessivePunctuation ||
      !matchesKnownPattern && baseline.subjectPatterns.length > 0;

    let severity: ContentAnomaly['severity'] = 'low';
    if (urgencyScore >= 0.8 || (allCapsSubject && excessivePunctuation)) {
      severity = 'high';
    } else if (urgencyScore >= 0.5 || allCapsSubject || excessivePunctuation) {
      severity = 'medium';
    }

    return {
      hasUnusualSubject,
      urgencyScore,
      allCapsSubject,
      excessivePunctuation,
      severity,
    };
  }

  private calculateCompositeScore(
    volumeAnomaly?: VolumeAnomaly,
    timeAnomaly?: TimeAnomaly,
    recipientAnomaly?: RecipientAnomaly,
    contentAnomaly?: ContentAnomaly
  ): number {
    const weights = {
      volume: 0.35,
      time: 0.15,
      recipient: 0.30,
      content: 0.20,
    };

    let score = 0;

    if (volumeAnomaly) {
      const severityScores: Record<string, number> = {
        low: 15,
        medium: 40,
        high: 70,
        critical: 95,
      };
      score += severityScores[volumeAnomaly.severity] * weights.volume;
    }

    if (timeAnomaly && timeAnomaly.isUnusualHour) {
      const severityScores: Record<string, number> = {
        low: 20,
        medium: 50,
        high: 80,
      };
      score += severityScores[timeAnomaly.severity] * weights.time;
    }

    if (recipientAnomaly && recipientAnomaly.hasNewRecipient) {
      const severityScores: Record<string, number> = {
        low: 20,
        medium: 50,
        high: 80,
      };
      score += severityScores[recipientAnomaly.severity] * weights.recipient;
    }

    if (contentAnomaly && contentAnomaly.hasUnusualSubject) {
      const severityScores: Record<string, number> = {
        low: 20,
        medium: 55,
        high: 85,
      };
      score += severityScores[contentAnomaly.severity] * weights.content;
    }

    return Math.min(100, Math.round(score));
  }

  private applyFeedbackAdjustment(
    score: number,
    anomalyTypes: string[],
    tenantId: string
  ): number {
    let adjustment = 0;

    for (const anomalyType of anomalyTypes) {
      const key = `${tenantId}:${anomalyType}`;
      const feedback = this.feedbackHistory.get(key);

      if (feedback) {
        const total = feedback.falsePositiveCount + feedback.truePositiveCount;
        if (total >= 3) {
          const falsePositiveRate = feedback.falsePositiveCount / total;
          // Reduce score by up to 20% if high false positive rate
          adjustment -= score * (falsePositiveRate * 0.2);
        }
      }
    }

    return Math.max(0, Math.round(score + adjustment));
  }

  private determineAlertStatus(
    score: number,
    anomalyTypes: string[]
  ): { shouldAlert: boolean; alertSeverity?: 'low' | 'medium' | 'high' | 'critical' } {
    const threshold = this.config.alertThreshold || 70;

    if (score < threshold && anomalyTypes.length < 3) {
      return { shouldAlert: false };
    }

    let alertSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';
    if (score >= 85 || anomalyTypes.length >= 4) {
      alertSeverity = 'critical';
    } else if (score >= 70 || anomalyTypes.length >= 3) {
      alertSeverity = 'high';
    } else if (score >= 50) {
      alertSeverity = 'medium';
    }

    return { shouldAlert: true, alertSeverity };
  }

  async recordFeedback(feedback: AnomalyFeedback): Promise<void> {
    for (const anomalyType of feedback.anomalyTypes) {
      const key = `${feedback.tenantId}:${anomalyType}`;
      let history = this.feedbackHistory.get(key);

      if (!history) {
        history = {
          tenantId: feedback.tenantId,
          anomalyType,
          falsePositiveCount: 0,
          truePositiveCount: 0,
        };
        this.feedbackHistory.set(key, history);
      }

      if (feedback.feedbackType === 'false_positive') {
        history.falsePositiveCount++;
      } else {
        history.truePositiveCount++;
      }
    }
  }

  async calculateBaseline(
    tenantId: string,
    historicalData: Array<{ sentAt: Date; volume: number }>
  ): Promise<TenantBaseline> {
    // Calculate mean and standard deviation
    const volumes = historicalData.map(d => d.volume);
    const mean = volumes.reduce((sum, v) => sum + v, 0) / volumes.length;
    const variance = volumes.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / volumes.length;
    const stdDev = Math.sqrt(variance);

    // Calculate hourly distribution
    const hourCounts = new Array(24).fill(0);
    for (const data of historicalData) {
      const hour = data.sentAt.getHours();
      hourCounts[hour]++;
    }
    const totalEmails = historicalData.length;
    const hourlyDistribution = hourCounts.map(count =>
      totalEmails > 0 ? count / totalEmails : 0.0416
    );

    return {
      tenantId,
      dailyEmailVolume: { mean, stdDev },
      hourlyDistribution,
      topRecipients: [],
      topSenders: [],
      subjectPatterns: [],
      calculatedAt: new Date(),
    };
  }
}
