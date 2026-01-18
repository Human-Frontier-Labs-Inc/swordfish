/**
 * ML Response Learner
 *
 * Learns from admin decisions to improve detection accuracy over time.
 * Tracks overrides, identifies patterns, suggests policy adjustments,
 * and detects model drift.
 *
 * Features:
 * - Learn from admin corrections (release from quarantine = false positive)
 * - Track model drift over time
 * - Suggest threshold adjustments
 * - Generate retraining datasets
 * - Feedback quality scoring
 * - Cross-tenant aggregated learning (privacy-preserving)
 */

import { sql } from '../db';
import { randomUUID } from 'crypto';

// Alias for uuid generation
const uuidv4 = () => randomUUID();

// ============================================================================
// Types
// ============================================================================

/**
 * Email features snapshot at decision time
 */
export interface EmailFeatures {
  // Sender features
  senderDomain: string;
  senderEmail: string;
  displayName?: string;
  isFreemailProvider: boolean;
  domainAge?: number;

  // Content features
  urgencyScore: number;
  threatLanguageScore: number;
  linkCount: number;
  shortenerLinkCount: number;
  attachmentCount: number;
  attachmentTypes: string[];

  // Detection features
  spfResult?: 'pass' | 'fail' | 'softfail' | 'none';
  dkimResult?: 'pass' | 'fail' | 'none';
  dmarcResult?: 'pass' | 'fail' | 'none';
  deterministicScore: number;
  mlScore: number;
  mlCategory?: string;

  // Contextual features
  hasExternalLinks: boolean;
  requestsPersonalInfo: boolean;
  requestsFinancialAction: boolean;
  isReplyChain: boolean;
}

/**
 * Admin action record - matches the user's requested interface
 */
export interface AdminAction {
  actionId: string;
  tenantId: string;
  adminId: string;
  verdictId: string;
  originalVerdict: string;
  newVerdict: string;
  action: 'release' | 'quarantine' | 'block' | 'delete' | 'mark_safe' | 'mark_threat';
  reason?: string;
  timestamp: Date;
}

/**
 * Learning signal derived from admin actions
 */
export interface LearningSignal {
  emailFeatures: EmailFeatures;
  originalPrediction: PredictionResult;
  adminAction: AdminAction;
  signalType: 'false_positive' | 'false_negative' | 'correct';
  weight: number;
}

/**
 * Prediction result structure (used for learning signals)
 */
export interface PredictionResult {
  threatScore: number;
  confidence: number;
  threatType: 'phishing' | 'bec' | 'malware' | 'spam' | 'clean';
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'safe';
  modelVersion: string;
}

/**
 * Admin decision record (backward compatible)
 */
export interface AdminDecision {
  id: string;
  tenantId: string;
  verdictId: string;
  originalVerdict: 'pass' | 'quarantine' | 'block' | 'review';
  adminAction: 'release' | 'delete' | 'block' | 'whitelist' | 'confirm';
  adminId: string;
  reason?: string;
  timestamp: Date;
  emailFeatures: EmailFeatures;
  // Outcome tracking
  subsequentReportedAsPhish?: boolean;
  reportedAt?: Date;
}

/**
 * Pattern identified in admin overrides
 */
export interface Pattern {
  id: string;
  type: 'domain' | 'sender' | 'feature' | 'time' | 'combination';
  description: string;
  occurrences: number;
  confidence: number;
  examples: string[]; // Decision IDs
  features: Record<string, unknown>;
  firstSeen: Date;
  lastSeen: Date;
}

/**
 * Analysis of admin override patterns
 */
export interface PatternAnalysis {
  overrideRate: number;
  falsePositivePatterns: Pattern[];
  falseNegativePatterns: Pattern[];
  commonOverrideReasons: { reason: string; count: number }[];
  timeBasedTrends: TrendData[];
  totalDecisions: number;
  analysisTimestamp: Date;
}

/**
 * Time-based trend data
 */
export interface TrendData {
  period: string;
  timestamp: Date;
  overrideCount: number;
  releaseCount: number;
  blockCount: number;
  falsePositiveRate: number;
}

/**
 * Policy adjustment suggestion
 */
export interface PolicySuggestion {
  id: string;
  type: 'whitelist_domain' | 'whitelist_sender' | 'adjust_threshold' | 'add_rule' | 'remove_rule' | 'modify_rule';
  description: string;
  confidence: number;
  evidence: string[];
  impact: {
    expectedFPReduction?: number;
    expectedFNRisk?: number;
    affectedEmailCount?: number;
  };
  suggestedValue?: unknown;
  createdAt: Date;
  status: 'pending' | 'applied' | 'rejected' | 'testing';
}

/**
 * Threshold adjustment recommendation (backward compatible)
 */
export interface ThresholdAdjustment {
  id: string;
  thresholdName: string;
  currentValue: number;
  suggestedValue: number;
  direction: 'increase' | 'decrease';
  reason: string;
  evidence: {
    falsePositiveImpact: number;
    falseNegativeRisk: number;
    sampleSize: number;
  };
  appliedAt?: Date;
  rollbackAvailable: boolean;
}

/**
 * Threshold suggestion (matches user's requested interface)
 */
export interface ThresholdSuggestion {
  category: string;
  currentThreshold: number;
  suggestedThreshold: number;
  expectedFPReduction: number;
  expectedFNIncrease: number;
  confidence: number;
}

/**
 * Drift detection report (backward compatible)
 */
export interface DriftReport {
  hasDrift: boolean;
  driftScore: number;
  driftType: 'feature' | 'label' | 'concept' | 'none';
  affectedFeatures: string[];
  recommendation: string;
  details: {
    baselinePeriod: { start: Date; end: Date };
    comparisonPeriod: { start: Date; end: Date };
    featureShifts: Array<{
      feature: string;
      baselineMean: number;
      currentMean: number;
      shift: number;
    }>;
    predictionDistributionShift: number;
    overrideRateChange: number;
  };
  detectedAt: Date;
}

/**
 * Drift metrics (matches user's requested interface)
 */
export interface DriftMetrics {
  overallDrift: number; // 0-1, higher = more drift
  fpRateTrend: 'increasing' | 'stable' | 'decreasing';
  fnRateTrend: 'increasing' | 'stable' | 'decreasing';
  recommendsRetrain: boolean;
  driftByCategory: Record<string, number>;
}

/**
 * False positive metrics
 */
export interface FPMetrics {
  overallRate: number;
  byCategory: Record<string, number>;
  recentTrend: 'increasing' | 'stable' | 'decreasing';
  sampleSize: number;
  confidenceInterval: { lower: number; upper: number };
}

/**
 * False negative metrics
 */
export interface FNMetrics {
  overallRate: number;
  byThreatType: Record<string, number>;
  recentTrend: 'increasing' | 'stable' | 'decreasing';
  sampleSize: number;
  confidenceInterval: { lower: number; upper: number };
}

/**
 * Training data options
 */
export interface TrainingDataOptions {
  startDate?: Date;
  endDate?: Date;
  includeFeatures?: string[];
  excludeCategories?: string[];
  balanceClasses?: boolean;
  maxSamples?: number;
}

/**
 * Training dataset
 */
export interface TrainingDataset {
  samples: Array<{
    features: EmailFeatures;
    label: 'threat' | 'safe';
    weight: number;
    source: 'admin_correction' | 'user_report' | 'confirmed';
  }>;
  metadata: {
    generatedAt: Date;
    sampleCount: number;
    threatCount: number;
    safeCount: number;
    dateRange: { start: Date; end: Date };
    tenantId: string;
  };
}

/**
 * Admin action patterns
 */
export interface ActionPatterns {
  adminId?: string;
  totalActions: number;
  actionBreakdown: Record<string, number>;
  avgTimeToAction: number; // milliseconds
  peakHours: number[];
  consistencyScore: number; // 0-1, how consistent are this admin's decisions
  outlierActions: Array<{
    actionId: string;
    reason: string;
    deviation: number;
  }>;
}

/**
 * Feedback quality metrics
 */
export interface FeedbackQualityMetrics {
  totalFeedback: number;
  verifiedFeedback: number;
  feedbackAccuracy: number;
  avgResponseTime: number;
  feedbackByType: Record<string, number>;
  qualityScore: number; // 0-100
  recommendations: string[];
}

/**
 * Aggregation options
 */
export interface AggregationOptions {
  minTenantCount?: number;
  anonymize?: boolean;
  categories?: string[];
  timeWindow?: number; // days
}

/**
 * Aggregated learning results
 */
export interface AggregatedLearning {
  tenantCount: number;
  totalSamples: number;
  commonPatterns: Pattern[];
  globalThresholdSuggestions: ThresholdSuggestion[];
  emergingThreats: Array<{
    pattern: string;
    frequency: number;
    firstSeen: Date;
    affectedTenants: number;
  }>;
  aggregatedAt: Date;
}

/**
 * Filters for retrieving decisions
 */
export interface DecisionFilters {
  startDate?: Date;
  endDate?: Date;
  adminAction?: AdminDecision['adminAction'][];
  originalVerdict?: AdminDecision['originalVerdict'][];
  adminId?: string;
  senderDomain?: string;
  limit?: number;
  offset?: number;
}

/**
 * A/B test configuration
 */
export interface ABTest {
  id: string;
  tenantId: string;
  suggestionId: string;
  name: string;
  status: 'running' | 'completed' | 'cancelled';
  controlGroup: string[]; // Percentage or user IDs
  testGroup: string[];
  startedAt: Date;
  endedAt?: Date;
  results?: {
    controlFPRate: number;
    testFPRate: number;
    controlFNRate: number;
    testFNRate: number;
    statisticalSignificance: number;
    recommendation: 'apply' | 'reject' | 'continue';
  };
}

// ============================================================================
// Response Learner Class
// ============================================================================

/**
 * ResponseLearner - Learns from admin decisions to improve detection
 */
export class ResponseLearner {
  private readonly minSampleSize = 10;
  private readonly patternConfidenceThreshold = 0.7;
  private readonly driftThreshold = 0.15;

  // ============================================================================
  // New Interface Methods (User's Requested Interface)
  // ============================================================================

  /**
   * Record admin action for learning
   */
  async recordAction(action: AdminAction): Promise<void> {
    try {
      await sql`
        INSERT INTO admin_actions (
          action_id, tenant_id, admin_id, verdict_id,
          original_verdict, new_verdict, action_type,
          reason, timestamp
        ) VALUES (
          ${action.actionId},
          ${action.tenantId},
          ${action.adminId},
          ${action.verdictId},
          ${action.originalVerdict},
          ${action.newVerdict},
          ${action.action},
          ${action.reason || null},
          ${action.timestamp.toISOString()}
        )
        ON CONFLICT (action_id) DO UPDATE SET
          new_verdict = ${action.newVerdict},
          action_type = ${action.action},
          reason = ${action.reason || null}
      `;

      // Log for audit trail
      await this.logActionForAudit(action);

      // Check for emerging patterns
      await this.checkForEmergingActionPatterns(action);
    } catch (error) {
      console.error('[ResponseLearner] Error recording action:', error);
      throw new Error('Failed to record admin action');
    }
  }

  /**
   * Get learning signals from recent actions
   */
  async getLearningSignals(tenantId: string, since?: Date): Promise<LearningSignal[]> {
    try {
      const sinceDate = since || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

      const actions = await sql`
        SELECT
          aa.action_id, aa.tenant_id, aa.admin_id, aa.verdict_id,
          aa.original_verdict, aa.new_verdict, aa.action_type, aa.reason, aa.timestamp,
          ev.signals, ev.deterministic_score, ev.ml_classification, ev.ml_confidence,
          ev.from_address, ev.subject
        FROM admin_actions aa
        LEFT JOIN email_verdicts ev ON aa.verdict_id = ev.id::text
        WHERE aa.tenant_id = ${tenantId}
          AND aa.timestamp >= ${sinceDate.toISOString()}
        ORDER BY aa.timestamp DESC
        LIMIT 1000
      `;

      return actions.map((row: Record<string, unknown>) => {
        const adminAction: AdminAction = {
          actionId: row.action_id as string,
          tenantId: row.tenant_id as string,
          adminId: row.admin_id as string,
          verdictId: row.verdict_id as string,
          originalVerdict: row.original_verdict as string,
          newVerdict: row.new_verdict as string,
          action: row.action_type as AdminAction['action'],
          reason: row.reason as string | undefined,
          timestamp: new Date(row.timestamp as string),
        };

        const signalType = this.determineSignalType(adminAction);
        const weight = this.calculateSignalWeight(adminAction, signalType);

        return {
          emailFeatures: this.extractFeaturesFromRow(row),
          originalPrediction: this.extractPredictionFromRow(row),
          adminAction,
          signalType,
          weight,
        };
      });
    } catch (error) {
      console.error('[ResponseLearner] Error getting learning signals:', error);
      return [];
    }
  }

  /**
   * Calculate model drift metrics
   */
  async calculateDrift(tenantId: string): Promise<DriftMetrics> {
    const report = await this.detectDrift(tenantId);

    // Calculate FP/FN rate trends
    const fpTrend = this.calculateRateTrend(tenantId, 'false_positive');
    const fnTrend = this.calculateRateTrend(tenantId, 'false_negative');

    // Calculate drift by category
    const driftByCategory: Record<string, number> = {};
    for (const shift of report.details.featureShifts) {
      const category = this.featureToCategory(shift.feature);
      driftByCategory[category] = Math.max(
        driftByCategory[category] || 0,
        shift.shift
      );
    }

    return {
      overallDrift: report.driftScore,
      fpRateTrend: await fpTrend,
      fnRateTrend: await fnTrend,
      recommendsRetrain: report.driftScore > 0.3 || report.hasDrift,
      driftByCategory,
    };
  }

  /**
   * Get false positive rate by category
   */
  async getFalsePositiveRate(tenantId: string, category?: string): Promise<FPMetrics> {
    try {
      const decisions = await this.getDecisionHistory(tenantId, {
        startDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        adminAction: ['release'],
      });

      const total = decisions.length;
      const byCategory: Record<string, number> = {};

      for (const decision of decisions) {
        const cat = decision.emailFeatures.mlCategory || 'unknown';
        byCategory[cat] = (byCategory[cat] || 0) + 1;
      }

      // Calculate rates
      const allDecisions = await this.getDecisionHistory(tenantId, {
        startDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
      });

      const overallRate = allDecisions.length > 0 ? total / allDecisions.length : 0;

      // Calculate trend
      const recentTrend = await this.calculateRateTrend(tenantId, 'false_positive');

      // Calculate confidence interval (Wilson score)
      const ci = this.wilsonConfidenceInterval(total, allDecisions.length);

      return {
        overallRate,
        byCategory: Object.fromEntries(
          Object.entries(byCategory).map(([k, v]) => [k, v / total])
        ),
        recentTrend,
        sampleSize: allDecisions.length,
        confidenceInterval: ci,
      };
    } catch (error) {
      console.error('[ResponseLearner] Error getting FP rate:', error);
      return {
        overallRate: 0,
        byCategory: {},
        recentTrend: 'stable',
        sampleSize: 0,
        confidenceInterval: { lower: 0, upper: 0 },
      };
    }
  }

  /**
   * Get false negative rate by threat type
   */
  async getFalseNegativeRate(tenantId: string, threatType?: string): Promise<FNMetrics> {
    try {
      // Get emails that passed but were later reported/blocked
      const fnDecisions = await this.getDecisionHistory(tenantId, {
        startDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        originalVerdict: ['pass'],
        adminAction: ['block', 'delete'],
      });

      // Also include reported as phish
      const reportedDecisions = await sql`
        SELECT COUNT(*) as count FROM admin_decisions
        WHERE tenant_id = ${tenantId}
          AND subsequent_reported_as_phish = true
          AND timestamp > ${new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()}
      `;

      const total = fnDecisions.length + parseInt(reportedDecisions[0]?.count || '0', 10);

      const byThreatType: Record<string, number> = {};
      for (const decision of fnDecisions) {
        const type = decision.emailFeatures.mlCategory || 'unknown';
        byThreatType[type] = (byThreatType[type] || 0) + 1;
      }

      // Get total passed emails
      const passedCount = await sql`
        SELECT COUNT(*) as count FROM email_verdicts
        WHERE tenant_id = ${tenantId}
          AND verdict = 'pass'
          AND created_at > ${new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()}
      `;

      const passedTotal = parseInt(passedCount[0]?.count || '0', 10);
      const overallRate = passedTotal > 0 ? total / passedTotal : 0;

      const recentTrend = await this.calculateRateTrend(tenantId, 'false_negative');
      const ci = this.wilsonConfidenceInterval(total, passedTotal);

      return {
        overallRate,
        byThreatType: Object.fromEntries(
          Object.entries(byThreatType).map(([k, v]) => [k, v / Math.max(1, total)])
        ),
        recentTrend,
        sampleSize: passedTotal,
        confidenceInterval: ci,
      };
    } catch (error) {
      console.error('[ResponseLearner] Error getting FN rate:', error);
      return {
        overallRate: 0,
        byThreatType: {},
        recentTrend: 'stable',
        sampleSize: 0,
        confidenceInterval: { lower: 0, upper: 0 },
      };
    }
  }

  /**
   * Suggest threshold adjustments based on feedback
   */
  async suggestThresholds(tenantId: string): Promise<ThresholdSuggestion[]> {
    const adjustments = await this.autoTuneThresholds(tenantId);

    return adjustments.map(adj => ({
      category: this.thresholdNameToCategory(adj.thresholdName),
      currentThreshold: adj.currentValue,
      suggestedThreshold: adj.suggestedValue,
      expectedFPReduction: adj.evidence.falsePositiveImpact,
      expectedFNIncrease: adj.evidence.falseNegativeRisk,
      confidence: Math.min(0.95, adj.evidence.sampleSize / 100),
    }));
  }

  /**
   * Generate retraining dataset from feedback
   */
  async generateTrainingData(
    tenantId: string,
    options?: TrainingDataOptions
  ): Promise<TrainingDataset> {
    const startDate = options?.startDate || new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
    const endDate = options?.endDate || new Date();

    try {
      // Get admin corrections
      const corrections = await this.getDecisionHistory(tenantId, {
        startDate,
        endDate,
        limit: options?.maxSamples || 10000,
      });

      const samples: TrainingDataset['samples'] = [];

      for (const correction of corrections) {
        // Determine label based on admin action
        let label: 'threat' | 'safe';
        let source: 'admin_correction' | 'user_report' | 'confirmed';

        if (correction.adminAction === 'release') {
          label = 'safe';
          source = 'admin_correction';
        } else if (correction.adminAction === 'block' || correction.adminAction === 'delete') {
          label = 'threat';
          source = 'admin_correction';
        } else if (correction.adminAction === 'confirm') {
          label = correction.originalVerdict === 'pass' ? 'safe' : 'threat';
          source = 'confirmed';
        } else {
          continue;
        }

        // Skip excluded categories
        if (options?.excludeCategories?.includes(correction.emailFeatures.mlCategory || '')) {
          continue;
        }

        // Calculate weight based on decision recency and admin confidence
        const ageWeight = 1 - (Date.now() - correction.timestamp.getTime()) / (90 * 24 * 60 * 60 * 1000);
        const weight = Math.max(0.1, ageWeight);

        samples.push({
          features: correction.emailFeatures,
          label,
          weight,
          source,
        });
      }

      // Balance classes if requested
      if (options?.balanceClasses) {
        const threats = samples.filter(s => s.label === 'threat');
        const safe = samples.filter(s => s.label === 'safe');
        const minCount = Math.min(threats.length, safe.length);

        const balancedSamples = [
          ...threats.slice(0, minCount),
          ...safe.slice(0, minCount),
        ];
        samples.length = 0;
        samples.push(...balancedSamples);
      }

      return {
        samples,
        metadata: {
          generatedAt: new Date(),
          sampleCount: samples.length,
          threatCount: samples.filter(s => s.label === 'threat').length,
          safeCount: samples.filter(s => s.label === 'safe').length,
          dateRange: { start: startDate, end: endDate },
          tenantId,
        },
      };
    } catch (error) {
      console.error('[ResponseLearner] Error generating training data:', error);
      return {
        samples: [],
        metadata: {
          generatedAt: new Date(),
          sampleCount: 0,
          threatCount: 0,
          safeCount: 0,
          dateRange: { start: startDate, end: endDate },
          tenantId,
        },
      };
    }
  }

  /**
   * Get admin action patterns (for detecting unusual admin behavior)
   */
  async getActionPatterns(tenantId: string, adminId?: string): Promise<ActionPatterns> {
    try {
      const whereClause = adminId
        ? sql`WHERE tenant_id = ${tenantId} AND admin_id = ${adminId}`
        : sql`WHERE tenant_id = ${tenantId}`;

      const actions = await sql`
        SELECT
          admin_action, admin_id, timestamp, reason,
          EXTRACT(HOUR FROM timestamp) as hour
        FROM admin_decisions
        ${whereClause}
          AND timestamp > ${new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()}
        ORDER BY timestamp DESC
        LIMIT 5000
      `;

      const actionBreakdown: Record<string, number> = {};
      const hourCounts: Record<number, number> = {};
      let totalTimeToAction = 0;
      let timeToActionCount = 0;

      for (const action of actions) {
        const actionType = action.admin_action as string;
        actionBreakdown[actionType] = (actionBreakdown[actionType] || 0) + 1;

        const hour = parseInt(action.hour as string, 10);
        hourCounts[hour] = (hourCounts[hour] || 0) + 1;
      }

      // Find peak hours (top 3)
      const peakHours = Object.entries(hourCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([hour]) => parseInt(hour, 10));

      // Calculate consistency score
      const consistencyScore = this.calculateAdminConsistency(actions);

      // Find outlier actions
      const outlierActions = this.findOutlierActions(actions);

      return {
        adminId,
        totalActions: actions.length,
        actionBreakdown,
        avgTimeToAction: timeToActionCount > 0 ? totalTimeToAction / timeToActionCount : 0,
        peakHours,
        consistencyScore,
        outlierActions,
      };
    } catch (error) {
      console.error('[ResponseLearner] Error getting action patterns:', error);
      return {
        adminId,
        totalActions: 0,
        actionBreakdown: {},
        avgTimeToAction: 0,
        peakHours: [],
        consistencyScore: 0,
        outlierActions: [],
      };
    }
  }

  /**
   * Calculate feedback quality score
   */
  async getFeedbackQuality(tenantId: string): Promise<FeedbackQualityMetrics> {
    try {
      const feedback = await sql`
        SELECT
          feedback_type,
          created_at,
          processed,
          processed_at
        FROM user_feedback
        WHERE tenant_id = ${tenantId}
          AND created_at > ${new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()}
      `;

      const totalFeedback = feedback.length;
      const verifiedFeedback = feedback.filter((f: Record<string, unknown>) => f.processed).length;

      const feedbackByType: Record<string, number> = {};
      let totalResponseTime = 0;
      let responseTimeCount = 0;

      for (const f of feedback) {
        const type = f.feedback_type as string;
        feedbackByType[type] = (feedbackByType[type] || 0) + 1;

        if (f.processed_at && f.created_at) {
          const responseTime = new Date(f.processed_at as string).getTime() -
                              new Date(f.created_at as string).getTime();
          totalResponseTime += responseTime;
          responseTimeCount++;
        }
      }

      const avgResponseTime = responseTimeCount > 0 ? totalResponseTime / responseTimeCount : 0;

      // Calculate quality score
      const verificationRate = totalFeedback > 0 ? verifiedFeedback / totalFeedback : 0;
      const responseTimeScore = avgResponseTime > 0
        ? Math.max(0, 1 - avgResponseTime / (24 * 60 * 60 * 1000)) // 24 hours baseline
        : 0.5;

      const qualityScore = Math.round((verificationRate * 0.6 + responseTimeScore * 0.4) * 100);

      const recommendations: string[] = [];
      if (verificationRate < 0.5) {
        recommendations.push('Increase feedback verification rate');
      }
      if (avgResponseTime > 12 * 60 * 60 * 1000) {
        recommendations.push('Reduce feedback response time');
      }
      if (totalFeedback < 50) {
        recommendations.push('Encourage more user feedback');
      }

      return {
        totalFeedback,
        verifiedFeedback,
        feedbackAccuracy: verificationRate,
        avgResponseTime,
        feedbackByType,
        qualityScore,
        recommendations,
      };
    } catch (error) {
      console.error('[ResponseLearner] Error getting feedback quality:', error);
      return {
        totalFeedback: 0,
        verifiedFeedback: 0,
        feedbackAccuracy: 0,
        avgResponseTime: 0,
        feedbackByType: {},
        qualityScore: 0,
        recommendations: ['Unable to calculate feedback quality'],
      };
    }
  }

  /**
   * Aggregate learning across tenants (anonymized)
   */
  async aggregateLearning(options?: AggregationOptions): Promise<AggregatedLearning> {
    const minTenants = options?.minTenantCount || 3;
    const timeWindow = options?.timeWindow || 30;

    try {
      // Get anonymized patterns across tenants
      const patterns = await sql`
        SELECT
          email_features->>'senderDomain' as domain,
          admin_action,
          COUNT(*) as count,
          COUNT(DISTINCT tenant_id) as tenant_count
        FROM admin_decisions
        WHERE timestamp > ${new Date(Date.now() - timeWindow * 24 * 60 * 60 * 1000).toISOString()}
        GROUP BY email_features->>'senderDomain', admin_action
        HAVING COUNT(DISTINCT tenant_id) >= ${minTenants}
        ORDER BY count DESC
        LIMIT 100
      `;

      const commonPatterns: Pattern[] = patterns
        .filter((p: Record<string, unknown>) => p.admin_action === 'release')
        .map((p: Record<string, unknown>) => ({
          id: uuidv4(),
          type: 'domain' as const,
          description: `Domain ${p.domain} frequently released across tenants`,
          occurrences: parseInt(p.count as string, 10),
          confidence: Math.min(0.95, parseInt(p.tenant_count as string, 10) / 10),
          examples: [],
          features: { domain: p.domain },
          firstSeen: new Date(Date.now() - timeWindow * 24 * 60 * 60 * 1000),
          lastSeen: new Date(),
        }));

      // Get tenant count
      const tenantResult = await sql`
        SELECT COUNT(DISTINCT tenant_id) as count FROM admin_decisions
        WHERE timestamp > ${new Date(Date.now() - timeWindow * 24 * 60 * 60 * 1000).toISOString()}
      `;

      const tenantCount = parseInt(tenantResult[0]?.count || '0', 10);

      // Get total samples
      const sampleResult = await sql`
        SELECT COUNT(*) as count FROM admin_decisions
        WHERE timestamp > ${new Date(Date.now() - timeWindow * 24 * 60 * 60 * 1000).toISOString()}
      `;

      const totalSamples = parseInt(sampleResult[0]?.count || '0', 10);

      // Detect emerging threats
      const emergingThreats = await this.detectEmergingThreats(timeWindow);

      return {
        tenantCount,
        totalSamples,
        commonPatterns,
        globalThresholdSuggestions: [],
        emergingThreats,
        aggregatedAt: new Date(),
      };
    } catch (error) {
      console.error('[ResponseLearner] Error aggregating learning:', error);
      return {
        tenantCount: 0,
        totalSamples: 0,
        commonPatterns: [],
        globalThresholdSuggestions: [],
        emergingThreats: [],
        aggregatedAt: new Date(),
      };
    }
  }

  // ============================================================================
  // Backward Compatible Methods
  // ============================================================================

  /**
   * Record an admin decision for learning (backward compatible)
   */
  async recordDecision(decision: Omit<AdminDecision, 'id' | 'timestamp'>): Promise<AdminDecision> {
    const id = uuidv4();
    const timestamp = new Date();

    const fullDecision: AdminDecision = {
      ...decision,
      id,
      timestamp,
    };

    try {
      await sql`
        INSERT INTO admin_decisions (
          id, tenant_id, verdict_id, original_verdict, admin_action,
          admin_id, reason, timestamp, email_features,
          subsequent_reported_as_phish, reported_at
        ) VALUES (
          ${id},
          ${decision.tenantId},
          ${decision.verdictId},
          ${decision.originalVerdict},
          ${decision.adminAction},
          ${decision.adminId},
          ${decision.reason || null},
          ${timestamp.toISOString()},
          ${JSON.stringify(decision.emailFeatures)},
          ${decision.subsequentReportedAsPhish || null},
          ${decision.reportedAt?.toISOString() || null}
        )
      `;

      // Also log for audit trail
      await this.logDecisionForAudit(fullDecision);

      // Check if this creates a pattern worth noting
      await this.checkForEmergingPatterns(fullDecision);

      return fullDecision;
    } catch (error) {
      console.error('[ResponseLearner] Error recording decision:', error);
      throw new Error('Failed to record admin decision');
    }
  }

  /**
   * Analyze patterns in admin overrides
   */
  async analyzePatterns(tenantId: string): Promise<PatternAnalysis> {
    const decisions = await this.getDecisionHistory(tenantId, {
      startDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // Last 30 days
    });

    if (decisions.length < this.minSampleSize) {
      return {
        overrideRate: 0,
        falsePositivePatterns: [],
        falseNegativePatterns: [],
        commonOverrideReasons: [],
        timeBasedTrends: [],
        totalDecisions: decisions.length,
        analysisTimestamp: new Date(),
      };
    }

    // Calculate override rate
    const overrides = decisions.filter(
      d => d.adminAction !== 'confirm' && d.originalVerdict !== 'pass'
    );
    const overrideRate = overrides.length / decisions.length;

    // Identify false positive patterns (releases from quarantine/block)
    const falsePositivePatterns = await this.identifyFalsePositivePatterns(
      decisions.filter(d => d.adminAction === 'release')
    );

    // Identify false negative patterns (blocks/deletes after pass)
    const falseNegativePatterns = await this.identifyFalseNegativePatterns(
      decisions.filter(d => d.adminAction === 'block' && d.originalVerdict === 'pass')
    );

    // Analyze common reasons
    const reasonCounts = new Map<string, number>();
    for (const d of decisions) {
      if (d.reason) {
        const normalized = d.reason.toLowerCase().trim();
        reasonCounts.set(normalized, (reasonCounts.get(normalized) || 0) + 1);
      }
    }
    const commonOverrideReasons = Array.from(reasonCounts.entries())
      .map(([reason, count]) => ({ reason, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Calculate time-based trends
    const timeBasedTrends = this.calculateTimeBasedTrends(decisions);

    return {
      overrideRate,
      falsePositivePatterns,
      falseNegativePatterns,
      commonOverrideReasons,
      timeBasedTrends,
      totalDecisions: decisions.length,
      analysisTimestamp: new Date(),
    };
  }

  /**
   * Suggest policy adjustments based on patterns
   */
  async suggestPolicyAdjustments(tenantId: string): Promise<PolicySuggestion[]> {
    const analysis = await this.analyzePatterns(tenantId);
    const suggestions: PolicySuggestion[] = [];

    // Suggest whitelisting frequently released domains
    for (const pattern of analysis.falsePositivePatterns) {
      if (pattern.type === 'domain' && pattern.confidence >= this.patternConfidenceThreshold) {
        const domain = pattern.features.domain as string;
        suggestions.push({
          id: uuidv4(),
          type: 'whitelist_domain',
          description: `Whitelist domain "${domain}" - frequently released from quarantine`,
          confidence: pattern.confidence,
          evidence: pattern.examples,
          impact: {
            expectedFPReduction: pattern.occurrences,
            expectedFNRisk: 0.05, // Small risk estimate
            affectedEmailCount: pattern.occurrences,
          },
          suggestedValue: domain,
          createdAt: new Date(),
          status: 'pending',
        });
      }

      if (pattern.type === 'sender' && pattern.confidence >= this.patternConfidenceThreshold) {
        const sender = pattern.features.sender as string;
        suggestions.push({
          id: uuidv4(),
          type: 'whitelist_sender',
          description: `Whitelist sender "${sender}" - consistently marked as false positive`,
          confidence: pattern.confidence,
          evidence: pattern.examples,
          impact: {
            expectedFPReduction: pattern.occurrences,
            expectedFNRisk: 0.02,
            affectedEmailCount: pattern.occurrences,
          },
          suggestedValue: sender,
          createdAt: new Date(),
          status: 'pending',
        });
      }
    }

    // Suggest threshold adjustments based on override patterns
    if (analysis.overrideRate > 0.3) {
      // High false positive rate
      suggestions.push({
        id: uuidv4(),
        type: 'adjust_threshold',
        description: 'Consider increasing quarantine threshold - high false positive rate detected',
        confidence: Math.min(0.9, analysis.overrideRate),
        evidence: [`Override rate: ${(analysis.overrideRate * 100).toFixed(1)}%`],
        impact: {
          expectedFPReduction: Math.round(analysis.totalDecisions * analysis.overrideRate * 0.3),
          expectedFNRisk: 0.1,
        },
        suggestedValue: { threshold: 'increase', amount: 5 },
        createdAt: new Date(),
        status: 'pending',
      });
    }

    // Suggest rules based on feature patterns
    for (const pattern of analysis.falsePositivePatterns) {
      if (pattern.type === 'feature' && pattern.confidence >= 0.8) {
        suggestions.push({
          id: uuidv4(),
          type: 'add_rule',
          description: `Add exception rule for: ${pattern.description}`,
          confidence: pattern.confidence,
          evidence: pattern.examples,
          impact: {
            expectedFPReduction: pattern.occurrences,
            expectedFNRisk: 0.05,
          },
          suggestedValue: pattern.features,
          createdAt: new Date(),
          status: 'pending',
        });
      }
    }

    // Sort by confidence and potential impact
    return suggestions.sort((a, b) => {
      const aScore = a.confidence * (a.impact.expectedFPReduction || 0);
      const bScore = b.confidence * (b.impact.expectedFPReduction || 0);
      return bScore - aScore;
    });
  }

  /**
   * Auto-tune detection thresholds based on feedback
   */
  async autoTuneThresholds(tenantId: string): Promise<ThresholdAdjustment[]> {
    const decisions = await this.getDecisionHistory(tenantId, {
      startDate: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000), // Last 14 days
    });

    if (decisions.length < this.minSampleSize * 2) {
      return []; // Not enough data to tune
    }

    const adjustments: ThresholdAdjustment[] = [];

    // Analyze score distributions for released vs blocked emails
    const released = decisions.filter(d => d.adminAction === 'release');
    const blocked = decisions.filter(d => d.adminAction === 'block' || d.adminAction === 'delete');

    // Deterministic score threshold analysis
    const deterministicAnalysis = this.analyzeScoreDistribution(
      released.map(d => d.emailFeatures.deterministicScore),
      blocked.map(d => d.emailFeatures.deterministicScore)
    );

    if (deterministicAnalysis.suggestedAdjustment !== 0) {
      adjustments.push({
        id: uuidv4(),
        thresholdName: 'deterministicQuarantineThreshold',
        currentValue: 40, // Default threshold
        suggestedValue: 40 + deterministicAnalysis.suggestedAdjustment,
        direction: deterministicAnalysis.suggestedAdjustment > 0 ? 'increase' : 'decrease',
        reason: deterministicAnalysis.reason,
        evidence: {
          falsePositiveImpact: deterministicAnalysis.falsePositiveImpact,
          falseNegativeRisk: deterministicAnalysis.falseNegativeRisk,
          sampleSize: decisions.length,
        },
        rollbackAvailable: true,
      });
    }

    // ML score threshold analysis
    const mlAnalysis = this.analyzeScoreDistribution(
      released.map(d => d.emailFeatures.mlScore),
      blocked.map(d => d.emailFeatures.mlScore)
    );

    if (mlAnalysis.suggestedAdjustment !== 0) {
      adjustments.push({
        id: uuidv4(),
        thresholdName: 'mlQuarantineThreshold',
        currentValue: 50, // Default threshold
        suggestedValue: 50 + mlAnalysis.suggestedAdjustment,
        direction: mlAnalysis.suggestedAdjustment > 0 ? 'increase' : 'decrease',
        reason: mlAnalysis.reason,
        evidence: {
          falsePositiveImpact: mlAnalysis.falsePositiveImpact,
          falseNegativeRisk: mlAnalysis.falseNegativeRisk,
          sampleSize: decisions.length,
        },
        rollbackAvailable: true,
      });
    }

    // Urgency score threshold
    const urgencyAnalysis = this.analyzeScoreDistribution(
      released.map(d => d.emailFeatures.urgencyScore),
      blocked.map(d => d.emailFeatures.urgencyScore)
    );

    if (urgencyAnalysis.suggestedAdjustment !== 0) {
      adjustments.push({
        id: uuidv4(),
        thresholdName: 'urgencyScoreThreshold',
        currentValue: 30, // Default
        suggestedValue: 30 + urgencyAnalysis.suggestedAdjustment,
        direction: urgencyAnalysis.suggestedAdjustment > 0 ? 'increase' : 'decrease',
        reason: urgencyAnalysis.reason,
        evidence: {
          falsePositiveImpact: urgencyAnalysis.falsePositiveImpact,
          falseNegativeRisk: urgencyAnalysis.falseNegativeRisk,
          sampleSize: decisions.length,
        },
        rollbackAvailable: true,
      });
    }

    return adjustments;
  }

  /**
   * Incorporate user feedback into learning
   */
  async incorporateFeedback(feedbackId: string): Promise<void> {
    try {
      // Retrieve the feedback record
      const feedbackResult = await sql`
        SELECT * FROM user_feedback WHERE id = ${feedbackId}
      `;

      if (feedbackResult.length === 0) {
        throw new Error(`Feedback not found: ${feedbackId}`);
      }

      const feedback = feedbackResult[0];

      // Update the corresponding decision record if it exists
      if (feedback.verdict_id) {
        await sql`
          UPDATE admin_decisions
          SET subsequent_reported_as_phish = ${feedback.feedback_type === 'missed_threat'},
              reported_at = ${new Date().toISOString()}
          WHERE verdict_id = ${feedback.verdict_id}
        `;
      }

      // If the feedback indicates a false negative, create a learning record
      if (feedback.feedback_type === 'missed_threat') {
        await this.recordFalseNegative(feedback);
      }

      // If feedback indicates false positive, strengthen the pattern
      if (feedback.feedback_type === 'false_positive') {
        await this.strengthenFalsePositivePattern(feedback);
      }

      // Mark feedback as processed
      await sql`
        UPDATE user_feedback
        SET processed = true, processed_at = ${new Date().toISOString()}
        WHERE id = ${feedbackId}
      `;
    } catch (error) {
      console.error('[ResponseLearner] Error incorporating feedback:', error);
      if (error instanceof Error && error.message.startsWith('Feedback not found')) {
        throw new Error('Feedback not found');
      }
      throw new Error('Failed to incorporate feedback');
    }
  }

  /**
   * Detect model or policy drift
   */
  async detectDrift(tenantId: string): Promise<DriftReport> {
    const now = new Date();
    const baselineStart = new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000); // 60 days ago
    const baselineEnd = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000); // 30 days ago
    const comparisonStart = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000); // 30 days ago
    const comparisonEnd = now;

    // Get decisions for both periods
    const baselineDecisions = await this.getDecisionHistory(tenantId, {
      startDate: baselineStart,
      endDate: baselineEnd,
    });

    const comparisonDecisions = await this.getDecisionHistory(tenantId, {
      startDate: comparisonStart,
      endDate: comparisonEnd,
    });

    if (baselineDecisions.length < this.minSampleSize || comparisonDecisions.length < this.minSampleSize) {
      return {
        hasDrift: false,
        driftScore: 0,
        driftType: 'none',
        affectedFeatures: [],
        recommendation: 'Insufficient data for drift detection. Continue collecting decisions.',
        details: {
          baselinePeriod: { start: baselineStart, end: baselineEnd },
          comparisonPeriod: { start: comparisonStart, end: comparisonEnd },
          featureShifts: [],
          predictionDistributionShift: 0,
          overrideRateChange: 0,
        },
        detectedAt: now,
      };
    }

    // Calculate feature shifts
    const featureShifts = this.calculateFeatureShifts(baselineDecisions, comparisonDecisions);

    // Calculate prediction distribution shift
    const baselineOverrideRate = this.calculateOverrideRate(baselineDecisions);
    const comparisonOverrideRate = this.calculateOverrideRate(comparisonDecisions);
    const overrideRateChange = comparisonOverrideRate - baselineOverrideRate;

    // Calculate overall drift score
    const maxFeatureShift = Math.max(...featureShifts.map(f => Math.abs(f.shift)), 0);
    const driftScore = Math.min(1, (maxFeatureShift + Math.abs(overrideRateChange)) / 2);

    // Determine drift type
    let driftType: DriftReport['driftType'] = 'none';
    const affectedFeatures: string[] = [];

    if (driftScore >= this.driftThreshold) {
      // Check for feature drift (input distribution changed)
      const significantFeatureShifts = featureShifts.filter(f => Math.abs(f.shift) > 0.2);
      if (significantFeatureShifts.length > 0) {
        driftType = 'feature';
        affectedFeatures.push(...significantFeatureShifts.map(f => f.feature));
      }

      // Check for label drift (outcome distribution changed)
      if (Math.abs(overrideRateChange) > 0.15) {
        driftType = driftType === 'feature' ? 'concept' : 'label';
      }
    }

    // Generate recommendation
    let recommendation = 'No significant drift detected. Continue monitoring.';
    if (driftType === 'feature') {
      recommendation = `Feature drift detected in: ${affectedFeatures.join(', ')}. Consider retraining the model with recent data.`;
    } else if (driftType === 'label') {
      recommendation = 'Label distribution drift detected. Review recent policy changes and admin decisions for consistency.';
    } else if (driftType === 'concept') {
      recommendation = 'Concept drift detected - both features and outcomes are shifting. Recommend comprehensive model review and retraining.';
    }

    return {
      hasDrift: driftScore >= this.driftThreshold,
      driftScore,
      driftType,
      affectedFeatures,
      recommendation,
      details: {
        baselinePeriod: { start: baselineStart, end: baselineEnd },
        comparisonPeriod: { start: comparisonStart, end: comparisonEnd },
        featureShifts,
        predictionDistributionShift: overrideRateChange,
        overrideRateChange,
      },
      detectedAt: now,
    };
  }

  /**
   * Get decision history with filters
   */
  async getDecisionHistory(tenantId: string, filters: DecisionFilters): Promise<AdminDecision[]> {
    try {
      const limit = Math.min(filters.limit || 1000, 5000);
      const offset = filters.offset || 0;
      const startDate = filters.startDate?.toISOString() || '1970-01-01T00:00:00.000Z';
      const endDate = filters.endDate?.toISOString() || '2100-01-01T00:00:00.000Z';

      // Use simple query without nested sql templates for better testability
      const result = await sql`
        SELECT * FROM admin_decisions
        WHERE tenant_id = ${tenantId}
          AND timestamp >= ${startDate}
          AND timestamp <= ${endDate}
        ORDER BY timestamp DESC
        LIMIT ${limit}
        OFFSET ${offset}
      `;

      return result.map((row: Record<string, unknown>) => ({
        id: row.id as string,
        tenantId: row.tenant_id as string,
        verdictId: row.verdict_id as string,
        originalVerdict: row.original_verdict as AdminDecision['originalVerdict'],
        adminAction: row.admin_action as AdminDecision['adminAction'],
        adminId: row.admin_id as string,
        reason: row.reason as string | undefined,
        timestamp: new Date(row.timestamp as string),
        emailFeatures: typeof row.email_features === 'string'
          ? JSON.parse(row.email_features)
          : row.email_features as EmailFeatures,
        subsequentReportedAsPhish: row.subsequent_reported_as_phish as boolean | undefined,
        reportedAt: row.reported_at ? new Date(row.reported_at as string) : undefined,
      }));
    } catch (error) {
      console.error('[ResponseLearner] Error getting decision history:', error);
      return [];
    }
  }

  /**
   * Apply a threshold adjustment with rollback capability
   */
  async applyThresholdAdjustment(adjustmentId: string, tenantId: string): Promise<void> {
    try {
      // Store the current threshold for rollback
      const currentSettings = await sql`
        SELECT settings FROM tenants WHERE id = ${tenantId}
      `;

      const settings = currentSettings[0]?.settings || {};

      // Record the adjustment application
      await sql`
        INSERT INTO threshold_adjustments (
          id, tenant_id, adjustment_data, previous_settings, applied_at
        ) VALUES (
          ${adjustmentId},
          ${tenantId},
          ${JSON.stringify({ adjustmentId })},
          ${JSON.stringify(settings)},
          ${new Date().toISOString()}
        )
      `;

      console.log(`[ResponseLearner] Applied threshold adjustment ${adjustmentId} for tenant ${tenantId}`);
    } catch (error) {
      console.error('[ResponseLearner] Error applying threshold adjustment:', error);
      throw new Error('Failed to apply threshold adjustment');
    }
  }

  /**
   * Rollback a threshold adjustment
   */
  async rollbackThresholdAdjustment(adjustmentId: string, tenantId: string): Promise<void> {
    try {
      const adjustmentRecord = await sql`
        SELECT previous_settings FROM threshold_adjustments
        WHERE id = ${adjustmentId} AND tenant_id = ${tenantId}
      `;

      if (adjustmentRecord.length === 0) {
        throw new Error('Adjustment record not found');
      }

      const previousSettings = adjustmentRecord[0].previous_settings;

      // Restore previous settings
      await sql`
        UPDATE tenants
        SET settings = ${JSON.stringify(previousSettings)},
            updated_at = ${new Date().toISOString()}
        WHERE id = ${tenantId}
      `;

      // Mark adjustment as rolled back
      await sql`
        UPDATE threshold_adjustments
        SET rolled_back_at = ${new Date().toISOString()}
        WHERE id = ${adjustmentId}
      `;

      console.log(`[ResponseLearner] Rolled back threshold adjustment ${adjustmentId} for tenant ${tenantId}`);
    } catch (error) {
      console.error('[ResponseLearner] Error rolling back threshold adjustment:', error);
      if (error instanceof Error && error.message === 'Adjustment record not found') {
        throw error;
      }
      throw new Error('Failed to rollback threshold adjustment');
    }
  }

  /**
   * Start an A/B test for a suggested policy change
   */
  async startABTest(
    tenantId: string,
    suggestionId: string,
    testConfig: { name: string; testGroupPercentage: number }
  ): Promise<ABTest> {
    const test: ABTest = {
      id: uuidv4(),
      tenantId,
      suggestionId,
      name: testConfig.name,
      status: 'running',
      controlGroup: [`${100 - testConfig.testGroupPercentage}%`],
      testGroup: [`${testConfig.testGroupPercentage}%`],
      startedAt: new Date(),
    };

    await sql`
      INSERT INTO ab_tests (
        id, tenant_id, suggestion_id, name, status,
        control_group, test_group, started_at
      ) VALUES (
        ${test.id},
        ${tenantId},
        ${suggestionId},
        ${testConfig.name},
        ${test.status},
        ${JSON.stringify(test.controlGroup)},
        ${JSON.stringify(test.testGroup)},
        ${test.startedAt.toISOString()}
      )
    `;

    // Update suggestion status
    await sql`
      UPDATE policy_suggestions
      SET status = 'testing'
      WHERE id = ${suggestionId}
    `;

    return test;
  }

  /**
   * Evaluate A/B test results
   */
  async evaluateABTest(testId: string): Promise<ABTest['results']> {
    const testRecord = await sql`
      SELECT * FROM ab_tests WHERE id = ${testId}
    `;

    if (testRecord.length === 0) {
      throw new Error('A/B test not found');
    }

    const test = testRecord[0];
    const tenantId = test.tenant_id as string;
    const startedAt = new Date(test.started_at as string);

    // Get decisions since test started
    const decisions = await this.getDecisionHistory(tenantId, {
      startDate: startedAt,
    });

    if (decisions.length < this.minSampleSize * 2) {
      return {
        controlFPRate: 0,
        testFPRate: 0,
        controlFNRate: 0,
        testFNRate: 0,
        statisticalSignificance: 0,
        recommendation: 'continue',
      };
    }

    // For simplicity, split decisions by hash (in production, would use actual group assignment)
    const controlDecisions = decisions.filter((_, i) => i % 2 === 0);
    const testDecisions = decisions.filter((_, i) => i % 2 === 1);

    const controlFPRate = controlDecisions.filter(d => d.adminAction === 'release').length / controlDecisions.length;
    const testFPRate = testDecisions.filter(d => d.adminAction === 'release').length / testDecisions.length;

    const controlFNRate = controlDecisions.filter(d => d.subsequentReportedAsPhish).length / controlDecisions.length;
    const testFNRate = testDecisions.filter(d => d.subsequentReportedAsPhish).length / testDecisions.length;

    // Simple significance calculation (would use proper statistical test in production)
    const fpDiff = Math.abs(controlFPRate - testFPRate);
    const statisticalSignificance = Math.min(1, fpDiff * Math.sqrt(decisions.length) / 2);

    let recommendation: 'apply' | 'reject' | 'continue' = 'continue';
    if (statisticalSignificance > 0.95) {
      if (testFPRate < controlFPRate && testFNRate <= controlFNRate * 1.1) {
        recommendation = 'apply';
      } else if (testFPRate >= controlFPRate || testFNRate > controlFNRate * 1.2) {
        recommendation = 'reject';
      }
    }

    const results = {
      controlFPRate,
      testFPRate,
      controlFNRate,
      testFNRate,
      statisticalSignificance,
      recommendation,
    };

    // Update test record
    await sql`
      UPDATE ab_tests
      SET results = ${JSON.stringify(results)}
      WHERE id = ${testId}
    `;

    return results;
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  private async logDecisionForAudit(decision: AdminDecision): Promise<void> {
    try {
      await sql`
        INSERT INTO audit_logs (
          id, tenant_id, actor_id, action, resource_type, resource_id,
          after_state, created_at
        ) VALUES (
          ${uuidv4()},
          ${decision.tenantId},
          ${decision.adminId},
          ${decision.adminAction},
          'email_verdict',
          ${decision.verdictId},
          ${JSON.stringify({
            originalVerdict: decision.originalVerdict,
            adminAction: decision.adminAction,
            reason: decision.reason,
          })},
          ${decision.timestamp.toISOString()}
        )
      `;
    } catch (error) {
      console.error('[ResponseLearner] Error logging for audit:', error);
    }
  }

  private async logActionForAudit(action: AdminAction): Promise<void> {
    try {
      await sql`
        INSERT INTO audit_logs (
          id, tenant_id, actor_id, action, resource_type, resource_id,
          after_state, created_at
        ) VALUES (
          ${uuidv4()},
          ${action.tenantId},
          ${action.adminId},
          ${action.action},
          'email_verdict',
          ${action.verdictId},
          ${JSON.stringify({
            originalVerdict: action.originalVerdict,
            newVerdict: action.newVerdict,
            action: action.action,
            reason: action.reason,
          })},
          ${action.timestamp.toISOString()}
        )
      `;
    } catch (error) {
      console.error('[ResponseLearner] Error logging action for audit:', error);
    }
  }

  private async checkForEmergingPatterns(decision: AdminDecision): Promise<void> {
    // Quick check for domain patterns
    const recentDomainDecisions = await sql`
      SELECT COUNT(*) as count FROM admin_decisions
      WHERE tenant_id = ${decision.tenantId}
        AND email_features->>'senderDomain' = ${decision.emailFeatures.senderDomain}
        AND admin_action = ${decision.adminAction}
        AND timestamp > ${new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()}
    `;

    const count = parseInt(recentDomainDecisions[0]?.count || '0', 10);

    if (count >= 5 && decision.adminAction === 'release') {
      console.log(
        `[ResponseLearner] Emerging pattern detected: Domain ${decision.emailFeatures.senderDomain} ` +
        `has been released ${count} times in the last 7 days. Consider whitelisting.`
      );
    }
  }

  private async checkForEmergingActionPatterns(action: AdminAction): Promise<void> {
    // Check for unusual action patterns
    const recentActions = await sql`
      SELECT COUNT(*) as count FROM admin_actions
      WHERE tenant_id = ${action.tenantId}
        AND action_type = ${action.action}
        AND timestamp > ${new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()}
    `;

    const count = parseInt(recentActions[0]?.count || '0', 10);

    if (count >= 20) {
      console.log(
        `[ResponseLearner] High action volume: ${count} "${action.action}" actions in the last 24 hours`
      );
    }
  }

  private async identifyFalsePositivePatterns(decisions: AdminDecision[]): Promise<Pattern[]> {
    const patterns: Pattern[] = [];

    // Group by domain
    const domainGroups = this.groupBy(decisions, d => d.emailFeatures.senderDomain);
    for (const [domain, domainDecisions] of Object.entries(domainGroups)) {
      if (domainDecisions.length >= 3) {
        patterns.push({
          id: uuidv4(),
          type: 'domain',
          description: `Emails from ${domain} are frequently released`,
          occurrences: domainDecisions.length,
          confidence: Math.min(0.95, 0.5 + domainDecisions.length * 0.1),
          examples: domainDecisions.slice(0, 5).map(d => d.id),
          features: { domain },
          firstSeen: new Date(Math.min(...domainDecisions.map(d => d.timestamp.getTime()))),
          lastSeen: new Date(Math.max(...domainDecisions.map(d => d.timestamp.getTime()))),
        });
      }
    }

    // Group by sender
    const senderGroups = this.groupBy(decisions, d => d.emailFeatures.senderEmail);
    for (const [sender, senderDecisions] of Object.entries(senderGroups)) {
      if (senderDecisions.length >= 2) {
        patterns.push({
          id: uuidv4(),
          type: 'sender',
          description: `Emails from ${sender} are frequently released`,
          occurrences: senderDecisions.length,
          confidence: Math.min(0.95, 0.6 + senderDecisions.length * 0.15),
          examples: senderDecisions.slice(0, 5).map(d => d.id),
          features: { sender },
          firstSeen: new Date(Math.min(...senderDecisions.map(d => d.timestamp.getTime()))),
          lastSeen: new Date(Math.max(...senderDecisions.map(d => d.timestamp.getTime()))),
        });
      }
    }

    // Identify feature-based patterns (low threat score releases)
    const lowScoreReleases = decisions.filter(d =>
      d.emailFeatures.deterministicScore < 30 && d.emailFeatures.mlScore < 40
    );

    if (lowScoreReleases.length >= 3) {
      patterns.push({
        id: uuidv4(),
        type: 'feature',
        description: 'Low-scoring emails being quarantined unnecessarily',
        occurrences: lowScoreReleases.length,
        confidence: 0.75,
        examples: lowScoreReleases.slice(0, 5).map(d => d.id),
        features: {
          maxDeterministicScore: 30,
          maxMlScore: 40,
        },
        firstSeen: new Date(Math.min(...lowScoreReleases.map(d => d.timestamp.getTime()))),
        lastSeen: new Date(Math.max(...lowScoreReleases.map(d => d.timestamp.getTime()))),
      });
    }

    return patterns.sort((a, b) => b.confidence - a.confidence);
  }

  private async identifyFalseNegativePatterns(decisions: AdminDecision[]): Promise<Pattern[]> {
    const patterns: Pattern[] = [];

    // Group by common features in blocked emails that passed initially
    const highUrgency = decisions.filter(d => d.emailFeatures.urgencyScore > 50);
    if (highUrgency.length >= 2) {
      patterns.push({
        id: uuidv4(),
        type: 'feature',
        description: 'High urgency emails passing detection but being blocked manually',
        occurrences: highUrgency.length,
        confidence: 0.7,
        examples: highUrgency.slice(0, 5).map(d => d.id),
        features: { minUrgencyScore: 50 },
        firstSeen: new Date(Math.min(...highUrgency.map(d => d.timestamp.getTime()))),
        lastSeen: new Date(Math.max(...highUrgency.map(d => d.timestamp.getTime()))),
      });
    }

    const financialRequests = decisions.filter(d => d.emailFeatures.requestsFinancialAction);
    if (financialRequests.length >= 2) {
      patterns.push({
        id: uuidv4(),
        type: 'feature',
        description: 'Financial request emails passing detection but being blocked manually',
        occurrences: financialRequests.length,
        confidence: 0.8,
        examples: financialRequests.slice(0, 5).map(d => d.id),
        features: { requestsFinancialAction: true },
        firstSeen: new Date(Math.min(...financialRequests.map(d => d.timestamp.getTime()))),
        lastSeen: new Date(Math.max(...financialRequests.map(d => d.timestamp.getTime()))),
      });
    }

    return patterns.sort((a, b) => b.confidence - a.confidence);
  }

  private calculateTimeBasedTrends(decisions: AdminDecision[]): TrendData[] {
    const trends: TrendData[] = [];
    const now = new Date();

    // Weekly trends for last 4 weeks
    for (let week = 0; week < 4; week++) {
      const weekStart = new Date(now.getTime() - (week + 1) * 7 * 24 * 60 * 60 * 1000);
      const weekEnd = new Date(now.getTime() - week * 7 * 24 * 60 * 60 * 1000);

      const weekDecisions = decisions.filter(d =>
        d.timestamp >= weekStart && d.timestamp < weekEnd
      );

      if (weekDecisions.length === 0) continue;

      const releases = weekDecisions.filter(d => d.adminAction === 'release').length;
      const blocks = weekDecisions.filter(d => d.adminAction === 'block').length;
      const overrides = weekDecisions.filter(d => d.adminAction !== 'confirm').length;

      trends.push({
        period: `Week -${week + 1}`,
        timestamp: weekStart,
        overrideCount: overrides,
        releaseCount: releases,
        blockCount: blocks,
        falsePositiveRate: releases / weekDecisions.length,
      });
    }

    return trends.reverse();
  }

  private analyzeScoreDistribution(
    releasedScores: number[],
    blockedScores: number[]
  ): {
    suggestedAdjustment: number;
    reason: string;
    falsePositiveImpact: number;
    falseNegativeRisk: number;
  } {
    if (releasedScores.length === 0 || blockedScores.length === 0) {
      return {
        suggestedAdjustment: 0,
        reason: 'Insufficient data for analysis',
        falsePositiveImpact: 0,
        falseNegativeRisk: 0,
      };
    }

    const releasedMean = this.mean(releasedScores);
    const blockedMean = this.mean(blockedScores);

    // If released emails have higher scores than expected, threshold might be too low
    if (releasedMean > 35 && releasedScores.length > 5) {
      return {
        suggestedAdjustment: 5,
        reason: `Released emails have high average score (${releasedMean.toFixed(1)}). Consider raising threshold.`,
        falsePositiveImpact: releasedScores.filter(s => s < releasedMean + 5).length,
        falseNegativeRisk: 0.1,
      };
    }

    // If blocked emails have lower scores, threshold might be too high
    if (blockedMean < 50 && blockedScores.length > 5) {
      return {
        suggestedAdjustment: -5,
        reason: `Manually blocked emails have low average score (${blockedMean.toFixed(1)}). Consider lowering threshold.`,
        falsePositiveImpact: 0,
        falseNegativeRisk: blockedScores.filter(s => s > blockedMean - 5).length / blockedScores.length,
      };
    }

    return {
      suggestedAdjustment: 0,
      reason: 'Current thresholds appear well-calibrated',
      falsePositiveImpact: 0,
      falseNegativeRisk: 0,
    };
  }

  private calculateFeatureShifts(
    baseline: AdminDecision[],
    comparison: AdminDecision[]
  ): Array<{ feature: string; baselineMean: number; currentMean: number; shift: number }> {
    const features: Array<keyof EmailFeatures> = [
      'urgencyScore',
      'threatLanguageScore',
      'linkCount',
      'shortenerLinkCount',
      'deterministicScore',
      'mlScore',
    ];

    return features.map(feature => {
      const baselineValues = baseline
        .map(d => d.emailFeatures[feature] as number)
        .filter(v => typeof v === 'number');
      const comparisonValues = comparison
        .map(d => d.emailFeatures[feature] as number)
        .filter(v => typeof v === 'number');

      const baselineMean = this.mean(baselineValues);
      const currentMean = this.mean(comparisonValues);

      // Normalize shift to 0-1 range
      const maxValue = Math.max(baselineMean, currentMean, 1);
      const shift = Math.abs(currentMean - baselineMean) / maxValue;

      return {
        feature,
        baselineMean,
        currentMean,
        shift,
      };
    });
  }

  private calculateOverrideRate(decisions: AdminDecision[]): number {
    if (decisions.length === 0) return 0;
    const overrides = decisions.filter(d => d.adminAction !== 'confirm');
    return overrides.length / decisions.length;
  }

  private async recordFalseNegative(feedback: Record<string, unknown>): Promise<void> {
    console.log('[ResponseLearner] Recording false negative for learning:', feedback);
    // This would be used to weight training data or adjust models
  }

  private async strengthenFalsePositivePattern(feedback: Record<string, unknown>): Promise<void> {
    console.log('[ResponseLearner] Strengthening false positive pattern:', feedback);
    // This would increase confidence in existing FP patterns
  }

  private determineSignalType(action: AdminAction): LearningSignal['signalType'] {
    // Release from quarantine/block = false positive
    if (action.action === 'release' || action.action === 'mark_safe') {
      return 'false_positive';
    }

    // Block/delete after pass = false negative
    if (
      (action.action === 'block' || action.action === 'delete' || action.action === 'mark_threat') &&
      action.originalVerdict === 'pass'
    ) {
      return 'false_negative';
    }

    return 'correct';
  }

  private calculateSignalWeight(action: AdminAction, signalType: LearningSignal['signalType']): number {
    // Base weight
    let weight = 1.0;

    // False negatives are more important (missed threats)
    if (signalType === 'false_negative') {
      weight = 2.0;
    }

    // Recent actions are more relevant
    const ageInDays = (Date.now() - action.timestamp.getTime()) / (24 * 60 * 60 * 1000);
    const ageWeight = Math.max(0.5, 1 - ageInDays / 30);
    weight *= ageWeight;

    // Actions with reasons are more reliable
    if (action.reason) {
      weight *= 1.2;
    }

    return Math.min(3.0, weight);
  }

  private extractFeaturesFromRow(row: Record<string, unknown>): EmailFeatures {
    return {
      senderDomain: (row.from_address as string)?.split('@')[1] || 'unknown',
      senderEmail: row.from_address as string || 'unknown',
      displayName: undefined,
      isFreemailProvider: false,
      domainAge: undefined,
      urgencyScore: 0,
      threatLanguageScore: 0,
      linkCount: 0,
      shortenerLinkCount: 0,
      attachmentCount: 0,
      attachmentTypes: [],
      deterministicScore: row.deterministic_score as number || 0,
      mlScore: (row.ml_confidence as number || 0) * 100,
      mlCategory: row.ml_classification as string,
      hasExternalLinks: false,
      requestsPersonalInfo: false,
      requestsFinancialAction: false,
      isReplyChain: false,
    };
  }

  private extractPredictionFromRow(row: Record<string, unknown>): PredictionResult {
    return {
      threatScore: row.deterministic_score as number || 0,
      confidence: row.ml_confidence as number || 0,
      threatType: (row.ml_classification as PredictionResult['threatType']) || 'clean',
      riskLevel: 'medium',
      modelVersion: '1.0.0',
    };
  }

  private async calculateRateTrend(
    tenantId: string,
    rateType: 'false_positive' | 'false_negative'
  ): Promise<'increasing' | 'stable' | 'decreasing'> {
    try {
      // Get weekly rates for last 4 weeks
      const rates: number[] = [];

      for (let week = 0; week < 4; week++) {
        const weekStart = new Date(Date.now() - (week + 1) * 7 * 24 * 60 * 60 * 1000);
        const weekEnd = new Date(Date.now() - week * 7 * 24 * 60 * 60 * 1000);

        const decisions = await this.getDecisionHistory(tenantId, {
          startDate: weekStart,
          endDate: weekEnd,
        });

        if (decisions.length === 0) {
          rates.push(0);
          continue;
        }

        if (rateType === 'false_positive') {
          const fpCount = decisions.filter(d => d.adminAction === 'release').length;
          rates.push(fpCount / decisions.length);
        } else {
          const fnCount = decisions.filter(d =>
            d.adminAction === 'block' && d.originalVerdict === 'pass'
          ).length;
          rates.push(fnCount / decisions.length);
        }
      }

      // Calculate trend
      if (rates.length < 2) return 'stable';

      const recentAvg = (rates[0] + rates[1]) / 2;
      const olderAvg = (rates[2] + rates[3]) / 2;
      const change = recentAvg - olderAvg;

      if (change > 0.1) return 'increasing';
      if (change < -0.1) return 'decreasing';
      return 'stable';
    } catch {
      return 'stable';
    }
  }

  private featureToCategory(feature: string): string {
    const mapping: Record<string, string> = {
      urgencyScore: 'content',
      threatLanguageScore: 'content',
      linkCount: 'url',
      shortenerLinkCount: 'url',
      deterministicScore: 'detection',
      mlScore: 'detection',
    };
    return mapping[feature] || 'other';
  }

  private thresholdNameToCategory(name: string): string {
    if (name.includes('deterministic')) return 'deterministic';
    if (name.includes('ml')) return 'ml';
    if (name.includes('urgency')) return 'content';
    return 'general';
  }

  private wilsonConfidenceInterval(
    successes: number,
    total: number,
    confidence: number = 0.95
  ): { lower: number; upper: number } {
    if (total === 0) return { lower: 0, upper: 0 };

    const z = 1.96; // 95% confidence
    const p = successes / total;
    const n = total;

    const denominator = 1 + z * z / n;
    const center = (p + z * z / (2 * n)) / denominator;
    const margin = (z / denominator) * Math.sqrt((p * (1 - p) + z * z / (4 * n)) / n);

    return {
      lower: Math.max(0, center - margin),
      upper: Math.min(1, center + margin),
    };
  }

  private calculateAdminConsistency(actions: Record<string, unknown>[]): number {
    if (actions.length < 5) return 1.0;

    // Check for consistent decision patterns
    const actionCounts: Record<string, number> = {};
    for (const action of actions) {
      const type = action.admin_action as string;
      actionCounts[type] = (actionCounts[type] || 0) + 1;
    }

    // Calculate entropy
    const total = actions.length;
    let entropy = 0;
    for (const count of Object.values(actionCounts)) {
      const p = count / total;
      if (p > 0) {
        entropy -= p * Math.log2(p);
      }
    }

    // Normalize to 0-1 (lower entropy = higher consistency)
    const maxEntropy = Math.log2(Object.keys(actionCounts).length);
    return maxEntropy > 0 ? 1 - entropy / maxEntropy : 1;
  }

  private findOutlierActions(actions: Record<string, unknown>[]): ActionPatterns['outlierActions'] {
    // Simple outlier detection based on action frequency
    const actionCounts: Record<string, number> = {};
    for (const action of actions) {
      const type = action.admin_action as string;
      actionCounts[type] = (actionCounts[type] || 0) + 1;
    }

    const total = actions.length;
    const threshold = 0.05; // Actions that occur less than 5% of the time

    return actions
      .filter(a => {
        const type = a.admin_action as string;
        return actionCounts[type] / total < threshold;
      })
      .slice(0, 10)
      .map(a => ({
        actionId: a.id as string || uuidv4(),
        reason: a.reason as string || 'No reason provided',
        deviation: 1 - (actionCounts[a.admin_action as string] || 0) / total,
      }));
  }

  private async detectEmergingThreats(timeWindowDays: number): Promise<AggregatedLearning['emergingThreats']> {
    try {
      const result = await sql`
        SELECT
          email_features->>'mlCategory' as pattern,
          COUNT(*) as frequency,
          MIN(timestamp) as first_seen,
          COUNT(DISTINCT tenant_id) as affected_tenants
        FROM admin_decisions
        WHERE admin_action IN ('block', 'delete')
          AND original_verdict = 'pass'
          AND timestamp > ${new Date(Date.now() - timeWindowDays * 24 * 60 * 60 * 1000).toISOString()}
        GROUP BY email_features->>'mlCategory'
        HAVING COUNT(*) >= 5
        ORDER BY frequency DESC
        LIMIT 10
      `;

      return result.map((r: Record<string, unknown>) => ({
        pattern: r.pattern as string || 'unknown',
        frequency: parseInt(r.frequency as string, 10),
        firstSeen: new Date(r.first_seen as string),
        affectedTenants: parseInt(r.affected_tenants as string, 10),
      }));
    } catch {
      return [];
    }
  }

  private groupBy<T>(items: T[], keyFn: (item: T) => string): Record<string, T[]> {
    return items.reduce((groups, item) => {
      const key = keyFn(item);
      if (!groups[key]) {
        groups[key] = [];
      }
      groups[key].push(item);
      return groups;
    }, {} as Record<string, T[]>);
  }

  private mean(values: number[]): number {
    if (values.length === 0) return 0;
    return values.reduce((sum, v) => sum + v, 0) / values.length;
  }
}

// ============================================================================
// Database Schema SQL (for reference/migration)
// ============================================================================

/**
 * SQL to create required tables:
 *
 * -- Admin decisions table (existing)
 * CREATE TABLE admin_decisions (
 *   id UUID PRIMARY KEY,
 *   tenant_id TEXT NOT NULL REFERENCES tenants(id),
 *   verdict_id UUID NOT NULL REFERENCES email_verdicts(id),
 *   original_verdict TEXT NOT NULL,
 *   admin_action TEXT NOT NULL,
 *   admin_id TEXT NOT NULL,
 *   reason TEXT,
 *   timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
 *   email_features JSONB NOT NULL,
 *   subsequent_reported_as_phish BOOLEAN,
 *   reported_at TIMESTAMP WITH TIME ZONE,
 *   created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
 * );
 *
 * CREATE INDEX idx_admin_decisions_tenant ON admin_decisions(tenant_id);
 * CREATE INDEX idx_admin_decisions_timestamp ON admin_decisions(timestamp);
 * CREATE INDEX idx_admin_decisions_action ON admin_decisions(admin_action);
 * CREATE INDEX idx_admin_decisions_sender_domain ON admin_decisions((email_features->>'senderDomain'));
 *
 * -- Admin actions table (new, for recordAction interface)
 * CREATE TABLE admin_actions (
 *   action_id UUID PRIMARY KEY,
 *   tenant_id TEXT NOT NULL REFERENCES tenants(id),
 *   admin_id TEXT NOT NULL,
 *   verdict_id TEXT NOT NULL,
 *   original_verdict TEXT NOT NULL,
 *   new_verdict TEXT NOT NULL,
 *   action_type TEXT NOT NULL,
 *   reason TEXT,
 *   timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
 *   created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
 * );
 *
 * CREATE INDEX idx_admin_actions_tenant ON admin_actions(tenant_id);
 * CREATE INDEX idx_admin_actions_timestamp ON admin_actions(timestamp);
 * CREATE INDEX idx_admin_actions_admin ON admin_actions(admin_id);
 *
 * -- Threshold adjustments table
 * CREATE TABLE threshold_adjustments (
 *   id UUID PRIMARY KEY,
 *   tenant_id TEXT NOT NULL REFERENCES tenants(id),
 *   adjustment_data JSONB NOT NULL,
 *   previous_settings JSONB NOT NULL,
 *   applied_at TIMESTAMP WITH TIME ZONE NOT NULL,
 *   rolled_back_at TIMESTAMP WITH TIME ZONE,
 *   created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
 * );
 *
 * -- A/B tests table
 * CREATE TABLE ab_tests (
 *   id UUID PRIMARY KEY,
 *   tenant_id TEXT NOT NULL REFERENCES tenants(id),
 *   suggestion_id UUID NOT NULL,
 *   name TEXT NOT NULL,
 *   status TEXT NOT NULL,
 *   control_group JSONB NOT NULL,
 *   test_group JSONB NOT NULL,
 *   started_at TIMESTAMP WITH TIME ZONE NOT NULL,
 *   ended_at TIMESTAMP WITH TIME ZONE,
 *   results JSONB,
 *   created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
 * );
 *
 * -- Policy suggestions table
 * CREATE TABLE policy_suggestions (
 *   id UUID PRIMARY KEY,
 *   tenant_id TEXT NOT NULL REFERENCES tenants(id),
 *   type TEXT NOT NULL,
 *   description TEXT NOT NULL,
 *   confidence DECIMAL NOT NULL,
 *   evidence JSONB NOT NULL,
 *   impact JSONB NOT NULL,
 *   suggested_value JSONB,
 *   status TEXT NOT NULL DEFAULT 'pending',
 *   created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
 *   applied_at TIMESTAMP WITH TIME ZONE,
 *   rejected_at TIMESTAMP WITH TIME ZONE
 * );
 *
 * -- User feedback table
 * CREATE TABLE user_feedback (
 *   id UUID PRIMARY KEY,
 *   tenant_id TEXT NOT NULL REFERENCES tenants(id),
 *   verdict_id UUID REFERENCES email_verdicts(id),
 *   feedback_type TEXT NOT NULL,
 *   notes TEXT,
 *   processed BOOLEAN DEFAULT FALSE,
 *   processed_at TIMESTAMP WITH TIME ZONE,
 *   created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
 * );
 */

// Export singleton instance
export const responseLearner = new ResponseLearner();
