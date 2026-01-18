/**
 * ML Threat Explainer Module
 *
 * Provides Explainable AI (XAI) capabilities for threat detection verdicts.
 * Generates human-readable explanations tailored to different audiences:
 * - End users: Brief, actionable summaries
 * - Analysts: Detailed technical breakdown
 * - Admins: Full technical details with thresholds
 * - Executives: High-level summary for reporting
 *
 * Features:
 * - Multi-audience explanation generation
 * - Risk breakdown by category
 * - Counterfactual explanations ("what would make this safe?")
 * - Detection timeline reconstruction
 * - Similar threat matching
 * - Executive summary generation
 */

import { sql } from '@/lib/db';
import type { Signal, LayerResult } from '@/lib/detection/types';
import type {
  EmailFeatures,
  HeaderFeatures,
  ContentFeatures,
  SenderFeatures,
  UrlFeatures,
  AttachmentFeatures,
  BehavioralFeatures,
} from './feature-extractor';
import type { PredictionResult, FeatureImportance } from './predictor';

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Request for generating an explanation
 */
export interface ExplanationRequest {
  /** Verdict ID to explain */
  verdictId: string;
  /** Email features used for prediction */
  emailFeatures?: EmailFeatures;
  /** Prediction result from ML model */
  predictionResult?: PredictionResult;
  /** Target audience for the explanation */
  audience: 'end_user' | 'analyst' | 'admin' | 'executive';
  /** Level of detail in the explanation */
  verbosity: 'brief' | 'detailed' | 'technical';
}

/**
 * Complete explanation for a threat verdict
 */
export interface Explanation {
  /** Human-readable summary */
  summary: string;
  /** Confidence level description */
  confidence: string;
  /** Top contributing factors */
  topFactors: ExplanationFactor[];
  /** Risk breakdown by category */
  riskBreakdown: RiskBreakdown;
  /** Actionable recommendations */
  recommendations: string[];
  /** Technical details (only for admin/analyst) */
  technicalDetails?: TechnicalDetails;
  /** Verdict metadata */
  metadata: {
    verdictId: string;
    generatedAt: Date;
    audience: string;
    verbosity: string;
    modelVersion?: string;
  };
}

/**
 * Individual factor contributing to the verdict
 */
export interface ExplanationFactor {
  /** Factor name (e.g., "Suspicious sender domain") */
  factor: string;
  /** Detailed description of the factor */
  description: string;
  /** Impact level on the verdict */
  impact: 'critical' | 'high' | 'medium' | 'low';
  /** Category of the factor */
  category: 'sender' | 'content' | 'url' | 'attachment' | 'behavioral' | 'authentication';
  /** Specific evidence for this factor */
  evidence?: string;
  /** Numeric contribution to risk score (-1 to 1) */
  contribution?: number;
}

/**
 * Risk breakdown by category
 */
export interface RiskBreakdown {
  /** Overall risk score (0-100) */
  overall: number;
  /** Risk scores by category */
  categories: {
    sender: number;
    content: number;
    urls: number;
    attachments: number;
    behavioral: number;
    authentication: number;
  };
  /** Data for visualization */
  chartData: ChartDataPoint[];
}

/**
 * Data point for risk visualization charts
 */
export interface ChartDataPoint {
  /** Category name */
  category: string;
  /** Risk score (0-100) */
  score: number;
  /** Display color for the category */
  color: string;
  /** Whether this category triggered detection */
  triggered: boolean;
}

/**
 * Technical details for admin/analyst audiences
 */
export interface TechnicalDetails {
  /** Feature importance scores */
  featureImportance: FeatureImportanceDetail[];
  /** Threshold values used */
  thresholds: ThresholdInfo[];
  /** Model information */
  modelInfo: {
    version: string;
    layersUsed: string[];
    processingTimeMs: number;
    calibrationApplied: boolean;
  };
  /** Raw scores from each detection layer */
  layerScores: LayerScoreDetail[];
  /** Signals that triggered detection */
  triggeredSignals: Signal[];
}

/**
 * Detailed feature importance information
 */
export interface FeatureImportanceDetail {
  /** Feature name */
  feature: string;
  /** Importance score (0-1) */
  importance: number;
  /** Feature value */
  value: string | number | boolean;
  /** Direction of impact */
  direction: 'increases_risk' | 'decreases_risk';
  /** Category of the feature */
  category: string;
}

/**
 * Threshold information for technical details
 */
export interface ThresholdInfo {
  /** Threshold name */
  name: string;
  /** Threshold value */
  value: number;
  /** Actual score compared against threshold */
  actualScore: number;
  /** Whether threshold was exceeded */
  exceeded: boolean;
}

/**
 * Detection layer score details
 */
export interface LayerScoreDetail {
  /** Layer name */
  layer: string;
  /** Layer score */
  score: number;
  /** Layer confidence */
  confidence: number;
  /** Layer weight in ensemble */
  weight: number;
  /** Whether layer was skipped */
  skipped: boolean;
  /** Reason for skipping (if applicable) */
  skipReason?: string;
}

/**
 * Comparative explanation between threat and safe email
 */
export interface ComparativeExplanation {
  /** ID of the threat email */
  threatVerdictId: string;
  /** ID of the safe comparison email */
  safeVerdictId?: string;
  /** Key differences between the emails */
  differences: ComparisonDifference[];
  /** Summary of comparison */
  summary: string;
}

/**
 * Single difference in comparative explanation
 */
export interface ComparisonDifference {
  /** Aspect being compared */
  aspect: string;
  /** Value in threat email */
  threatValue: string;
  /** Value in safe email */
  safeValue: string;
  /** Impact of this difference */
  impact: 'critical' | 'high' | 'medium' | 'low';
}

/**
 * Detection timeline entry
 */
export interface DetectionTimelineEntry {
  /** Timestamp of the event */
  timestamp: Date;
  /** Detection layer */
  layer: string;
  /** Event description */
  event: string;
  /** Score at this point */
  score?: number;
  /** Signals detected at this point */
  signals?: string[];
}

/**
 * Complete detection timeline
 */
export interface DetectionTimeline {
  /** Verdict ID */
  verdictId: string;
  /** Timeline entries in chronological order */
  entries: DetectionTimelineEntry[];
  /** Total processing time */
  totalTimeMs: number;
  /** Summary of detection flow */
  summary: string;
}

/**
 * Similar threat from historical data
 */
export interface SimilarThreat {
  /** Verdict ID */
  verdictId: string;
  /** Email subject */
  subject: string;
  /** Sender address */
  sender: string;
  /** Threat type classification */
  threatType: string;
  /** Similarity score (0-1) */
  similarity: number;
  /** When the threat was detected */
  detectedAt: Date;
  /** Outcome of the threat */
  outcome?: 'confirmed_threat' | 'false_positive' | 'pending';
}

/**
 * Counterfactual explanation
 */
export interface CounterfactualExplanation {
  /** Current verdict */
  currentVerdict: string;
  /** What the verdict would be with changes */
  hypotheticalVerdict: string;
  /** Changes required to flip the verdict */
  changesRequired: CounterfactualChange[];
  /** Summary of the counterfactual */
  summary: string;
}

/**
 * Single change in counterfactual explanation
 */
export interface CounterfactualChange {
  /** Factor to change */
  factor: string;
  /** Current value */
  currentValue: string;
  /** Required value for different verdict */
  requiredValue: string;
  /** How feasible is this change */
  feasibility: 'impossible' | 'unlikely' | 'possible';
  /** Explanation of why this matters */
  explanation: string;
}

/**
 * Executive summary for reporting
 */
export interface ExecutiveSummary {
  /** Tenant ID */
  tenantId: string;
  /** Reporting period */
  period: {
    start: Date;
    end: Date;
  };
  /** Summary statistics */
  statistics: {
    totalEmails: number;
    threatsBlocked: number;
    threatsQuarantined: number;
    falsePositives: number;
    accuracy: number;
  };
  /** Top threat categories */
  topThreatCategories: Array<{
    category: string;
    count: number;
    percentage: number;
  }>;
  /** Trend information */
  trends: {
    threatVolumeChange: number;
    topTargetedDepartments: string[];
    emergingThreatPatterns: string[];
  };
  /** Key highlights for executives */
  highlights: string[];
  /** Generated narrative summary */
  narrative: string;
}

// ============================================================================
// Constants and Mappings
// ============================================================================

const CATEGORY_COLORS: Record<string, string> = {
  sender: '#ef4444',      // red
  content: '#f97316',     // orange
  urls: '#eab308',        // yellow
  attachments: '#8b5cf6', // purple
  behavioral: '#3b82f6',  // blue
  authentication: '#10b981', // green
};

const CONFIDENCE_DESCRIPTIONS: Record<string, string> = {
  very_high: 'Very high confidence - Strong detection signals across multiple indicators',
  high: 'High confidence - Clear threat indicators detected',
  moderate: 'Moderate confidence - Some suspicious indicators present',
  low: 'Low confidence - Minor concerns detected',
  very_low: 'Very low confidence - Minimal risk indicators',
};

const AUDIENCE_TEMPLATES = {
  end_user: {
    brief: {
      phishing: 'This email appears to be a phishing attempt trying to steal your information.',
      bec: 'This email appears to impersonate someone in your organization to request money or information.',
      malware: 'This email contains suspicious attachments that may harm your computer.',
      spam: 'This email appears to be spam or unwanted marketing.',
      clean: 'This email appears to be safe.',
    },
    detailed: {
      prefix: 'Our security system has flagged this email because',
      suffix: 'If you are unsure, please contact your IT department before taking any action.',
    },
  },
  analyst: {
    prefix: 'Detection triggered by the following factors:',
    suffix: 'Review the full signal analysis for detailed investigation.',
  },
  admin: {
    prefix: 'Technical Analysis Summary:',
    suffix: 'Full feature importance and threshold details available below.',
  },
  executive: {
    prefix: 'Security Alert Summary:',
    suffix: 'Contact security team for detailed investigation.',
  },
};

const FACTOR_DESCRIPTIONS: Record<string, Record<string, string>> = {
  sender: {
    lookalike_domain: 'The sender domain closely resembles a legitimate domain',
    new_domain: 'The sender domain was recently registered',
    free_email: 'The sender is using a free email provider',
    disposable_email: 'The sender is using a disposable email address',
    first_contact: 'This is the first email from this sender',
    vip_impersonation: 'The sender appears to impersonate an executive',
    low_reputation: 'The sender has a poor reputation score',
  },
  content: {
    urgency: 'The email uses urgent or pressuring language',
    credential_request: 'The email asks for login credentials',
    financial_request: 'The email requests a financial transaction',
    threat_language: 'The email contains threatening language',
    grammar_errors: 'The email contains unusual grammar patterns',
  },
  url: {
    malicious_url: 'The email contains links to known malicious sites',
    shortened_url: 'The email uses URL shortening services',
    ip_url: 'The email contains links with IP addresses instead of domains',
    redirect_chain: 'The email contains links with multiple redirects',
  },
  attachment: {
    executable: 'The email contains executable files',
    macro_enabled: 'The email contains documents with macros',
    password_protected: 'The email contains password-protected archives',
    double_extension: 'The email contains files with suspicious double extensions',
  },
  behavioral: {
    unusual_time: 'The email was sent at an unusual time',
    volume_spike: 'Unusual email volume detected from this sender',
    new_recipient: 'Email sent to new recipients',
  },
  authentication: {
    spf_fail: 'SPF authentication failed',
    dkim_fail: 'DKIM signature verification failed',
    dmarc_fail: 'DMARC policy check failed',
    reply_to_mismatch: 'Reply-To address differs from sender',
  },
};

// ============================================================================
// ThreatExplainer Class
// ============================================================================

/**
 * Generates human-readable explanations for threat detection verdicts
 */
export class ThreatExplainer {
  private modelVersion: string = '1.0.0';

  /**
   * Generate a complete explanation for a verdict
   */
  async explain(request: ExplanationRequest): Promise<Explanation> {
    const { verdictId, audience, verbosity } = request;

    // Fetch verdict data if not provided
    let predictionResult = request.predictionResult;
    let emailFeatures = request.emailFeatures;

    // Only fetch from database if we don't have the prediction result
    if (!predictionResult) {
      const verdictData = await this.fetchVerdictWithFeatures(verdictId);
      if (!verdictData) {
        throw new Error(`Verdict not found: ${verdictId}`);
      }
      predictionResult = verdictData.predictionResult;
      emailFeatures = emailFeatures || verdictData.emailFeatures;
    }

    // Generate explanation components
    const topFactors = this.extractTopFactors(predictionResult, emailFeatures, audience);
    const riskBreakdown = this.calculateRiskBreakdown(predictionResult, emailFeatures);
    const summary = this.generateSummary(predictionResult, topFactors, audience, verbosity);
    const confidence = this.describeConfidence(predictionResult.confidence);
    const recommendations = this.generateRecommendations(predictionResult, topFactors, audience);

    // Build explanation
    const explanation: Explanation = {
      summary,
      confidence,
      topFactors,
      riskBreakdown,
      recommendations,
      metadata: {
        verdictId,
        generatedAt: new Date(),
        audience,
        verbosity,
        modelVersion: predictionResult.modelVersion || this.modelVersion,
      },
    };

    // Add technical details for admin/analyst
    if (audience === 'admin' || audience === 'analyst') {
      explanation.technicalDetails = await this.generateTechnicalDetails(
        verdictId,
        predictionResult,
        emailFeatures
      );
    }

    return explanation;
  }

  /**
   * Generate a brief summary for notifications/alerts
   */
  async summarize(verdictId: string): Promise<string> {
    const explanation = await this.explain({
      verdictId,
      audience: 'end_user',
      verbosity: 'brief',
    });
    return explanation.summary;
  }

  /**
   * Get the top factors that contributed to the verdict
   */
  async getFactors(verdictId: string): Promise<ExplanationFactor[]> {
    const explanation = await this.explain({
      verdictId,
      audience: 'analyst',
      verbosity: 'detailed',
    });
    return explanation.topFactors;
  }

  /**
   * Get the risk breakdown by category
   */
  async getRiskBreakdown(verdictId: string): Promise<RiskBreakdown> {
    const explanation = await this.explain({
      verdictId,
      audience: 'analyst',
      verbosity: 'detailed',
    });
    return explanation.riskBreakdown;
  }

  /**
   * Generate a comparative explanation with a similar safe email
   */
  async compareWithSafe(verdictId: string): Promise<ComparativeExplanation> {
    // Fetch the threat verdict
    const threatData = await this.fetchVerdictWithFeatures(verdictId);
    if (!threatData) {
      throw new Error(`Verdict not found: ${verdictId}`);
    }

    // Find a similar safe email for comparison
    const safeComparison = await this.findSimilarSafeEmail(
      threatData.tenantId,
      threatData.predictionResult
    );

    const differences: ComparisonDifference[] = [];

    // Compare authentication
    if (threatData.emailFeatures && safeComparison?.emailFeatures) {
      const threatAuth = threatData.emailFeatures.header;
      const safeAuth = safeComparison.emailFeatures.header;

      if (threatAuth.spfPassed !== safeAuth.spfPassed) {
        differences.push({
          aspect: 'SPF Authentication',
          threatValue: threatAuth.spfPassed ? 'Pass' : 'Fail',
          safeValue: safeAuth.spfPassed ? 'Pass' : 'Fail',
          impact: 'high',
        });
      }

      if (threatAuth.dkimPassed !== safeAuth.dkimPassed) {
        differences.push({
          aspect: 'DKIM Authentication',
          threatValue: threatAuth.dkimPassed ? 'Pass' : 'Fail',
          safeValue: safeAuth.dkimPassed ? 'Pass' : 'Fail',
          impact: 'high',
        });
      }

      // Compare sender features
      const threatSender = threatData.emailFeatures.sender;
      const safeSender = safeComparison.emailFeatures.sender;

      if (threatSender.isFirstContact !== safeSender.isFirstContact) {
        differences.push({
          aspect: 'Sender History',
          threatValue: threatSender.isFirstContact ? 'First contact' : 'Known sender',
          safeValue: safeSender.isFirstContact ? 'First contact' : 'Known sender',
          impact: 'medium',
        });
      }

      if (threatSender.isLookalikeDomain !== safeSender.isLookalikeDomain) {
        differences.push({
          aspect: 'Domain Authenticity',
          threatValue: threatSender.isLookalikeDomain ? 'Lookalike domain' : 'Authentic domain',
          safeValue: safeSender.isLookalikeDomain ? 'Lookalike domain' : 'Authentic domain',
          impact: 'critical',
        });
      }

      // Compare content features
      const threatContent = threatData.emailFeatures.content;
      const safeContent = safeComparison.emailFeatures.content;

      if (threatContent.hasCredentialRequest !== safeContent.hasCredentialRequest) {
        differences.push({
          aspect: 'Credential Requests',
          threatValue: threatContent.hasCredentialRequest ? 'Requests credentials' : 'No credential requests',
          safeValue: safeContent.hasCredentialRequest ? 'Requests credentials' : 'No credential requests',
          impact: 'critical',
        });
      }

      if (threatContent.hasUrgencyIndicator !== safeContent.hasUrgencyIndicator) {
        differences.push({
          aspect: 'Urgency Language',
          threatValue: threatContent.hasUrgencyIndicator ? 'Uses urgency tactics' : 'Normal tone',
          safeValue: safeContent.hasUrgencyIndicator ? 'Uses urgency tactics' : 'Normal tone',
          impact: 'high',
        });
      }
    }

    // Generate summary
    const criticalDiffs = differences.filter(d => d.impact === 'critical').length;
    const highDiffs = differences.filter(d => d.impact === 'high').length;

    let summary = `This email differs from safe emails in ${differences.length} key aspects. `;
    if (criticalDiffs > 0) {
      summary += `${criticalDiffs} critical difference(s) were detected. `;
    }
    if (highDiffs > 0) {
      summary += `${highDiffs} high-impact difference(s) were found. `;
    }

    return {
      threatVerdictId: verdictId,
      safeVerdictId: safeComparison?.verdictId,
      differences,
      summary,
    };
  }

  /**
   * Get the detection timeline for a verdict
   */
  async getDetectionTimeline(verdictId: string): Promise<DetectionTimeline> {
    const verdictData = await this.fetchVerdictWithFeatures(verdictId);
    if (!verdictData) {
      throw new Error(`Verdict not found: ${verdictId}`);
    }

    const entries: DetectionTimelineEntry[] = [];
    let totalTimeMs = 0;

    // Reconstruct timeline from layer results
    const layerResults = verdictData.layerResults || [];
    let baseTime = verdictData.analyzedAt || new Date();

    // Email received
    entries.push({
      timestamp: new Date(baseTime.getTime() - totalTimeMs),
      layer: 'intake',
      event: 'Email received for analysis',
    });

    for (const layer of layerResults) {
      if (layer.skipped) {
        entries.push({
          timestamp: new Date(baseTime.getTime() - totalTimeMs + 10),
          layer: layer.layer,
          event: `${layer.layer} layer skipped: ${layer.skipReason || 'Score threshold'}`,
        });
      } else {
        entries.push({
          timestamp: new Date(baseTime.getTime() - totalTimeMs + layer.processingTimeMs / 2),
          layer: layer.layer,
          event: `${layer.layer} analysis started`,
        });

        totalTimeMs += layer.processingTimeMs;

        entries.push({
          timestamp: new Date(baseTime.getTime()),
          layer: layer.layer,
          event: `${layer.layer} analysis completed`,
          score: layer.score,
          signals: layer.signals.map(s => s.type),
        });

        baseTime = new Date(baseTime.getTime() + layer.processingTimeMs);
      }
    }

    // Final verdict
    entries.push({
      timestamp: baseTime,
      layer: 'verdict',
      event: `Final verdict: ${verdictData.predictionResult.riskLevel}`,
      score: verdictData.predictionResult.threatScore * 100,
    });

    // Sort by timestamp
    entries.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    // Generate summary
    const triggeredLayers = layerResults.filter(l => !l.skipped && l.signals.length > 0);
    const summary = triggeredLayers.length > 0
      ? `Detection triggered across ${triggeredLayers.length} analysis layer(s) in ${totalTimeMs}ms`
      : `No threats detected across all layers in ${totalTimeMs}ms`;

    return {
      verdictId,
      entries,
      totalTimeMs,
      summary,
    };
  }

  /**
   * Get similar threats from historical data
   */
  async getSimilarThreats(verdictId: string, limit: number = 5): Promise<SimilarThreat[]> {
    try {
      const verdictData = await this.fetchVerdictWithFeatures(verdictId);
      if (!verdictData) return [];

      const signals = verdictData.predictionResult.featureImportance || [];
      const signalTypes = signals.map(s => s.feature) as string[];

      // Query for similar verdicts
      const results = await sql`
        SELECT
          id,
          subject,
          from_address,
          ml_classification,
          signals,
          action_taken,
          created_at
        FROM email_verdicts
        WHERE id != ${verdictId}
          AND tenant_id = ${verdictData.tenantId}
          AND verdict IN ('quarantine', 'block')
          AND created_at > NOW() - INTERVAL '90 days'
        ORDER BY created_at DESC
        LIMIT 100
      `;

      // Calculate similarity and filter
      const similar: SimilarThreat[] = [];

      for (const row of results) {
        const rowSignals = (row.signals as Signal[]) || [];
        const rowSignalTypes = rowSignals.map(s => s.type as string);

        // Jaccard similarity
        const intersection = signalTypes.filter(t => rowSignalTypes.includes(t));
        const union = new Set([...signalTypes, ...rowSignalTypes]);
        const similarity = union.size > 0 ? intersection.length / union.size : 0;

        if (similarity >= 0.25) {
          let outcome: SimilarThreat['outcome'];
          if (row.action_taken === 'released') {
            outcome = 'false_positive';
          } else if (row.action_taken === 'blocked' || row.action_taken === 'deleted') {
            outcome = 'confirmed_threat';
          } else {
            outcome = 'pending';
          }

          similar.push({
            verdictId: row.id,
            subject: row.subject || '(No subject)',
            sender: row.from_address || '(Unknown)',
            threatType: row.ml_classification || 'unknown',
            similarity,
            detectedAt: new Date(row.created_at),
            outcome,
          });
        }
      }

      return similar
        .sort((a, b) => b.similarity - a.similarity)
        .slice(0, limit);
    } catch (error) {
      console.error('Error finding similar threats:', error);
      return [];
    }
  }

  /**
   * Generate an executive summary for a tenant over a period
   */
  async generateExecutiveSummary(tenantId: string, period: string): Promise<ExecutiveSummary> {
    // Parse period
    const periodDays = this.parsePeriod(period);
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - periodDays);
    const endDate = new Date();

    try {
      // Fetch statistics
      const stats = await sql`
        SELECT
          COUNT(*) as total_emails,
          SUM(CASE WHEN verdict = 'block' THEN 1 ELSE 0 END) as blocked,
          SUM(CASE WHEN verdict = 'quarantine' THEN 1 ELSE 0 END) as quarantined,
          SUM(CASE WHEN action_taken = 'released' THEN 1 ELSE 0 END) as false_positives
        FROM email_verdicts
        WHERE tenant_id = ${tenantId}
          AND created_at >= ${startDate}
          AND created_at <= ${endDate}
      `;

      const totalEmails = Number(stats[0]?.total_emails || 0);
      const blocked = Number(stats[0]?.blocked || 0);
      const quarantined = Number(stats[0]?.quarantined || 0);
      const falsePositives = Number(stats[0]?.false_positives || 0);
      const accuracy = totalEmails > 0
        ? ((blocked + quarantined - falsePositives) / Math.max(1, blocked + quarantined)) * 100
        : 100;

      // Fetch threat categories
      const categoryStats = await sql`
        SELECT
          ml_classification as category,
          COUNT(*) as count
        FROM email_verdicts
        WHERE tenant_id = ${tenantId}
          AND created_at >= ${startDate}
          AND verdict IN ('block', 'quarantine')
          AND ml_classification IS NOT NULL
        GROUP BY ml_classification
        ORDER BY count DESC
        LIMIT 5
      `;

      const totalThreats = blocked + quarantined;
      const topThreatCategories = categoryStats.map(row => ({
        category: String(row.category),
        count: Number(row.count),
        percentage: totalThreats > 0 ? (Number(row.count) / totalThreats) * 100 : 0,
      }));

      // Fetch trends (compare with previous period)
      const prevStartDate = new Date(startDate);
      prevStartDate.setDate(prevStartDate.getDate() - periodDays);

      const prevStats = await sql`
        SELECT
          SUM(CASE WHEN verdict IN ('block', 'quarantine') THEN 1 ELSE 0 END) as threats
        FROM email_verdicts
        WHERE tenant_id = ${tenantId}
          AND created_at >= ${prevStartDate}
          AND created_at < ${startDate}
      `;

      const prevThreats = Number(prevStats[0]?.threats || 0);
      const threatVolumeChange = prevThreats > 0
        ? ((totalThreats - prevThreats) / prevThreats) * 100
        : 0;

      // Generate highlights
      const highlights: string[] = [];

      highlights.push(`${totalThreats} threat(s) blocked during this period`);

      if (threatVolumeChange > 20) {
        highlights.push(`Threat volume increased by ${Math.round(threatVolumeChange)}% compared to previous period`);
      } else if (threatVolumeChange < -20) {
        highlights.push(`Threat volume decreased by ${Math.round(Math.abs(threatVolumeChange))}% compared to previous period`);
      }

      if (topThreatCategories.length > 0) {
        highlights.push(`Top threat type: ${topThreatCategories[0].category} (${Math.round(topThreatCategories[0].percentage)}%)`);
      }

      if (accuracy >= 95) {
        highlights.push('Detection accuracy remains excellent');
      } else if (accuracy < 85) {
        highlights.push('Detection accuracy requires review');
      }

      // Generate narrative
      const narrative = this.generateExecutiveNarrative({
        totalEmails,
        totalThreats,
        topThreatCategories,
        threatVolumeChange,
        accuracy,
        periodDays,
      });

      return {
        tenantId,
        period: {
          start: startDate,
          end: endDate,
        },
        statistics: {
          totalEmails,
          threatsBlocked: blocked,
          threatsQuarantined: quarantined,
          falsePositives,
          accuracy,
        },
        topThreatCategories,
        trends: {
          threatVolumeChange,
          topTargetedDepartments: [], // Would need recipient analysis
          emergingThreatPatterns: [], // Would need pattern analysis
        },
        highlights,
        narrative,
      };
    } catch (error) {
      console.error('Error generating executive summary:', error);
      throw new Error('Failed to generate executive summary');
    }
  }

  /**
   * Get counterfactual explanation ("What would make this safe?")
   */
  async getCounterfactual(verdictId: string): Promise<CounterfactualExplanation> {
    const verdictData = await this.fetchVerdictWithFeatures(verdictId);
    if (!verdictData) {
      throw new Error(`Verdict not found: ${verdictId}`);
    }

    const { predictionResult, emailFeatures } = verdictData;
    const currentVerdict = predictionResult.riskLevel;
    const changesRequired: CounterfactualChange[] = [];

    // Only generate counterfactual if current verdict is not safe
    if (currentVerdict === 'safe') {
      return {
        currentVerdict,
        hypotheticalVerdict: 'safe',
        changesRequired: [],
        summary: 'This email is already classified as safe.',
      };
    }

    if (emailFeatures) {
      // Authentication factors
      if (!emailFeatures.header.spfPassed) {
        changesRequired.push({
          factor: 'SPF Authentication',
          currentValue: 'Failed',
          requiredValue: 'Passed',
          feasibility: 'impossible',
          explanation: 'SPF is verified at the domain level and cannot be changed by attackers.',
        });
      }

      if (!emailFeatures.header.dkimPassed) {
        changesRequired.push({
          factor: 'DKIM Signature',
          currentValue: 'Failed',
          requiredValue: 'Passed',
          feasibility: 'impossible',
          explanation: 'DKIM requires the private key which only the legitimate domain owner has.',
        });
      }

      // Sender factors
      if (emailFeatures.sender.isLookalikeDomain) {
        changesRequired.push({
          factor: 'Domain Authenticity',
          currentValue: `Lookalike domain (similar to ${emailFeatures.sender.targetedBrand || 'known brand'})`,
          requiredValue: 'Legitimate domain',
          feasibility: 'impossible',
          explanation: 'The sender domain cannot be changed to match the legitimate brand.',
        });
      }

      if (emailFeatures.sender.isFirstContact) {
        changesRequired.push({
          factor: 'Sender History',
          currentValue: 'First contact',
          requiredValue: 'Established relationship',
          feasibility: 'unlikely',
          explanation: 'Building communication history would require prior legitimate contact.',
        });
      }

      if (emailFeatures.sender.domainAgeRisk === 'high' || emailFeatures.sender.domainAgeRisk === 'critical') {
        changesRequired.push({
          factor: 'Domain Age',
          currentValue: `${emailFeatures.sender.domainAge || 'Unknown'} days old`,
          requiredValue: '> 365 days old',
          feasibility: 'unlikely',
          explanation: 'Domain age cannot be artificially increased.',
        });
      }

      // Content factors
      if (emailFeatures.content.hasCredentialRequest) {
        changesRequired.push({
          factor: 'Credential Requests',
          currentValue: 'Requests login credentials',
          requiredValue: 'No credential requests',
          feasibility: 'possible',
          explanation: 'Removing credential requests would lower the risk score.',
        });
      }

      if (emailFeatures.content.hasUrgencyIndicator) {
        changesRequired.push({
          factor: 'Urgency Language',
          currentValue: 'Uses urgent/pressuring language',
          requiredValue: 'Normal business tone',
          feasibility: 'possible',
          explanation: 'Removing urgency language would lower the risk score.',
        });
      }

      if (emailFeatures.content.hasFinancialRequest) {
        changesRequired.push({
          factor: 'Financial Requests',
          currentValue: 'Contains financial request',
          requiredValue: 'No financial requests',
          feasibility: 'possible',
          explanation: 'Removing financial requests would lower the risk score.',
        });
      }

      // URL factors
      if (emailFeatures.url.knownMaliciousCount > 0) {
        changesRequired.push({
          factor: 'Malicious URLs',
          currentValue: `${emailFeatures.url.knownMaliciousCount} malicious URL(s)`,
          requiredValue: 'No malicious URLs',
          feasibility: 'impossible',
          explanation: 'URLs are verified against threat intelligence and cannot be bypassed.',
        });
      }

      if (emailFeatures.url.urlShortenerCount > 0) {
        changesRequired.push({
          factor: 'URL Shorteners',
          currentValue: `${emailFeatures.url.urlShortenerCount} shortened URL(s)`,
          requiredValue: 'Direct URLs only',
          feasibility: 'possible',
          explanation: 'Using direct URLs instead of shorteners would reduce suspicion.',
        });
      }

      // Attachment factors
      if (emailFeatures.attachment.hasExecutable) {
        changesRequired.push({
          factor: 'Executable Attachments',
          currentValue: 'Contains executable files',
          requiredValue: 'No executable files',
          feasibility: 'possible',
          explanation: 'Removing executable attachments would lower the risk score.',
        });
      }

      if (emailFeatures.attachment.hasMacros) {
        changesRequired.push({
          factor: 'Macro Documents',
          currentValue: 'Contains macro-enabled documents',
          requiredValue: 'No macros',
          feasibility: 'possible',
          explanation: 'Removing macros from documents would lower the risk score.',
        });
      }
    }

    // Determine hypothetical verdict based on changes
    const impossibleChanges = changesRequired.filter(c => c.feasibility === 'impossible');
    const hypotheticalVerdict = impossibleChanges.length > 0 ? currentVerdict : 'low';

    // Generate summary
    let summary = '';
    if (impossibleChanges.length > 0) {
      summary = `This email cannot be made safe because ${impossibleChanges.length} factor(s) cannot be changed: ${impossibleChanges.map(c => c.factor).join(', ')}. `;
    }

    const possibleChanges = changesRequired.filter(c => c.feasibility === 'possible');
    if (possibleChanges.length > 0) {
      summary += `Even with possible changes (${possibleChanges.map(c => c.factor).join(', ')}), the email would still be flagged due to immutable factors.`;
    }

    if (changesRequired.length === 0) {
      summary = 'No specific factors identified that could be changed to make this email safer.';
    }

    return {
      currentVerdict,
      hypotheticalVerdict,
      changesRequired: changesRequired.sort((a, b) => {
        const order = { impossible: 0, unlikely: 1, possible: 2 };
        return order[a.feasibility] - order[b.feasibility];
      }),
      summary,
    };
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  /**
   * Fetch verdict with features from database
   */
  private async fetchVerdictWithFeatures(verdictId: string): Promise<{
    verdictId: string;
    tenantId: string;
    predictionResult: PredictionResult;
    emailFeatures?: EmailFeatures;
    layerResults?: LayerResult[];
    analyzedAt?: Date;
  } | null> {
    try {
      const results = await sql`
        SELECT
          id,
          tenant_id,
          verdict,
          confidence,
          signals,
          deterministic_score,
          ml_classification,
          ml_confidence,
          subject,
          from_address,
          processing_time_ms,
          created_at
        FROM email_verdicts
        WHERE id = ${verdictId}
        LIMIT 1
      `;

      if (results.length === 0) return null;

      const row = results[0];
      const signals = (row.signals as Signal[]) || [];

      // Build prediction result from verdict data
      const predictionResult: PredictionResult = {
        threatScore: row.confidence,
        confidence: row.confidence,
        threatType: this.mapVerdictToThreatType(row.ml_classification || row.verdict),
        riskLevel: this.mapVerdictToRiskLevel(row.verdict),
        modelVersion: this.modelVersion,
        predictionTimeMs: row.processing_time_ms || 0,
        featureImportance: this.extractFeatureImportance(signals),
        rawScores: {
          header: this.calculateCategoryScore(signals, ['spf', 'dkim', 'dmarc', 'header']),
          content: this.calculateCategoryScore(signals, ['urgency', 'credential', 'financial', 'threat', 'content']),
          sender: this.calculateCategoryScore(signals, ['sender', 'domain', 'reputation']),
          url: this.calculateCategoryScore(signals, ['url', 'link']),
          attachment: this.calculateCategoryScore(signals, ['attachment', 'macro', 'executable']),
          behavioral: this.calculateCategoryScore(signals, ['behavioral', 'anomaly', 'bec']),
        },
      };

      return {
        verdictId: row.id,
        tenantId: row.tenant_id,
        predictionResult,
        analyzedAt: new Date(row.created_at),
      };
    } catch (error) {
      console.error('Error fetching verdict:', error);
      return null;
    }
  }

  /**
   * Extract top factors from prediction result and features
   */
  private extractTopFactors(
    prediction: PredictionResult,
    features: EmailFeatures | undefined,
    audience: string
  ): ExplanationFactor[] {
    const factors: ExplanationFactor[] = [];

    // Add factors from feature importance
    for (const fi of prediction.featureImportance.slice(0, 10)) {
      const category = this.categorizeFeature(fi.feature);
      const description = this.getFactorDescription(fi.feature, category);

      factors.push({
        factor: this.formatFeatureName(fi.feature),
        description,
        impact: this.importanceToImpact(fi.contribution),
        category,
        contribution: fi.contribution,
        evidence: audience !== 'end_user' ? `Contribution: ${(fi.contribution * 100).toFixed(1)}%` : undefined,
      });
    }

    // Add factors from email features if available
    if (features) {
      // Sender factors
      if (features.sender.isLookalikeDomain) {
        factors.push({
          factor: 'Lookalike Domain',
          description: FACTOR_DESCRIPTIONS.sender.lookalike_domain,
          impact: 'critical',
          category: 'sender',
          evidence: features.sender.targetedBrand
            ? `Impersonating: ${features.sender.targetedBrand}`
            : undefined,
        });
      }

      if (features.sender.isVIPImpersonation) {
        factors.push({
          factor: 'VIP Impersonation',
          description: FACTOR_DESCRIPTIONS.sender.vip_impersonation,
          impact: 'critical',
          category: 'sender',
          evidence: features.sender.impersonatedVIP
            ? `Impersonating: ${features.sender.impersonatedVIP}`
            : undefined,
        });
      }

      // Content factors
      if (features.content.hasCredentialRequest) {
        factors.push({
          factor: 'Credential Request',
          description: FACTOR_DESCRIPTIONS.content.credential_request,
          impact: 'critical',
          category: 'content',
          evidence: features.content.credentialPhrases.slice(0, 2).join(', '),
        });
      }

      // URL factors
      if (features.url.knownMaliciousCount > 0) {
        factors.push({
          factor: 'Malicious URLs',
          description: FACTOR_DESCRIPTIONS.url.malicious_url,
          impact: 'critical',
          category: 'url',
          evidence: `${features.url.knownMaliciousCount} malicious URL(s) detected`,
        });
      }

      // Attachment factors
      if (features.attachment.hasExecutable) {
        factors.push({
          factor: 'Executable Attachment',
          description: FACTOR_DESCRIPTIONS.attachment.executable,
          impact: 'critical',
          category: 'attachment',
          evidence: features.attachment.executableFiles.slice(0, 2).join(', '),
        });
      }

      // Authentication factors
      if (!features.header.spfPassed) {
        factors.push({
          factor: 'SPF Failed',
          description: FACTOR_DESCRIPTIONS.authentication.spf_fail,
          impact: 'high',
          category: 'authentication',
        });
      }

      if (!features.header.dmarcPassed) {
        factors.push({
          factor: 'DMARC Failed',
          description: FACTOR_DESCRIPTIONS.authentication.dmarc_fail,
          impact: 'high',
          category: 'authentication',
        });
      }
    }

    // Deduplicate and sort by impact
    const seen = new Set<string>();
    const uniqueFactors = factors.filter(f => {
      const key = f.factor.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    const impactOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return uniqueFactors
      .sort((a, b) => impactOrder[a.impact] - impactOrder[b.impact])
      .slice(0, audience === 'end_user' ? 3 : 10);
  }

  /**
   * Calculate risk breakdown by category
   */
  private calculateRiskBreakdown(
    prediction: PredictionResult,
    features: EmailFeatures | undefined
  ): RiskBreakdown {
    const rawScores = prediction.rawScores || {
      header: 0,
      content: 0,
      sender: 0,
      url: 0,
      attachment: 0,
      behavioral: 0,
    };

    const categories = {
      sender: Math.round(rawScores.sender * 100),
      content: Math.round(rawScores.content * 100),
      urls: Math.round(rawScores.url * 100),
      attachments: Math.round(rawScores.attachment * 100),
      behavioral: Math.round(rawScores.behavioral * 100),
      authentication: Math.round(rawScores.header * 100),
    };

    // Adjust based on features if available
    if (features) {
      if (features.header.authenticationScore < 50) {
        categories.authentication = Math.max(categories.authentication, 100 - features.header.authenticationScore);
      }
      if (features.sender.domainReputationScore < 50) {
        categories.sender = Math.max(categories.sender, 100 - features.sender.domainReputationScore);
      }
    }

    const overall = Math.round(prediction.threatScore * 100);

    const chartData: ChartDataPoint[] = Object.entries(categories).map(([category, score]) => ({
      category: this.formatCategoryName(category),
      score,
      color: CATEGORY_COLORS[category] || '#6b7280',
      triggered: score > 30,
    }));

    return {
      overall,
      categories,
      chartData,
    };
  }

  /**
   * Generate summary based on audience and verbosity
   */
  private generateSummary(
    prediction: PredictionResult,
    topFactors: ExplanationFactor[],
    audience: string,
    verbosity: string
  ): string {
    const threatType = prediction.threatType;
    const confidence = Math.round(prediction.confidence * 100);

    // End user summaries
    if (audience === 'end_user') {
      const templates = AUDIENCE_TEMPLATES.end_user;
      if (verbosity === 'brief') {
        return templates.brief[threatType] || templates.brief.phishing;
      }

      // Detailed end user summary
      const factors = topFactors.slice(0, 2).map(f => f.factor.toLowerCase());
      const factorList = factors.length > 1
        ? `${factors.slice(0, -1).join(', ')} and ${factors[factors.length - 1]}`
        : factors[0] || 'suspicious patterns';

      return `${templates.detailed.prefix} it shows signs of ${factorList}. ${templates.detailed.suffix}`;
    }

    // Analyst summary
    if (audience === 'analyst') {
      const criticalFactors = topFactors.filter(f => f.impact === 'critical');
      const highFactors = topFactors.filter(f => f.impact === 'high');

      let summary = `${AUDIENCE_TEMPLATES.analyst.prefix}\n`;
      summary += `- Threat Type: ${this.formatThreatType(threatType)} (${confidence}% confidence)\n`;

      if (criticalFactors.length > 0) {
        summary += `- Critical factors: ${criticalFactors.map(f => f.factor).join(', ')}\n`;
      }
      if (highFactors.length > 0) {
        summary += `- High-impact factors: ${highFactors.map(f => f.factor).join(', ')}\n`;
      }

      summary += AUDIENCE_TEMPLATES.analyst.suffix;
      return summary;
    }

    // Admin summary
    if (audience === 'admin') {
      let summary = `${AUDIENCE_TEMPLATES.admin.prefix}\n`;
      summary += `Classification: ${this.formatThreatType(threatType)}\n`;
      summary += `Confidence: ${confidence}%\n`;
      summary += `Risk Level: ${prediction.riskLevel.toUpperCase()}\n`;
      summary += `Model Version: ${prediction.modelVersion}\n`;
      summary += `Processing Time: ${prediction.predictionTimeMs}ms\n`;
      summary += AUDIENCE_TEMPLATES.admin.suffix;
      return summary;
    }

    // Executive summary
    if (audience === 'executive') {
      const severity = prediction.riskLevel === 'critical' || prediction.riskLevel === 'high'
        ? 'high-risk'
        : 'potential';

      return `${AUDIENCE_TEMPLATES.executive.prefix} A ${severity} ${this.formatThreatType(threatType)} attempt was detected and blocked. ${confidence}% confidence. ${AUDIENCE_TEMPLATES.executive.suffix}`;
    }

    return `Threat detected: ${threatType} (${confidence}% confidence)`;
  }

  /**
   * Describe confidence level in human terms
   */
  private describeConfidence(confidence: number): string {
    if (confidence >= 0.9) return CONFIDENCE_DESCRIPTIONS.very_high;
    if (confidence >= 0.75) return CONFIDENCE_DESCRIPTIONS.high;
    if (confidence >= 0.5) return CONFIDENCE_DESCRIPTIONS.moderate;
    if (confidence >= 0.3) return CONFIDENCE_DESCRIPTIONS.low;
    return CONFIDENCE_DESCRIPTIONS.very_low;
  }

  /**
   * Generate recommendations based on verdict
   */
  private generateRecommendations(
    prediction: PredictionResult,
    topFactors: ExplanationFactor[],
    audience: string
  ): string[] {
    const recommendations: string[] = [];
    const riskLevel = prediction.riskLevel;

    // End user recommendations
    if (audience === 'end_user') {
      if (riskLevel === 'critical' || riskLevel === 'high') {
        recommendations.push('Do not click any links or download attachments from this email');
        recommendations.push('Do not reply or provide any personal information');
        recommendations.push('Report this email to your IT security team');
      } else if (riskLevel === 'medium') {
        recommendations.push('Exercise caution with this email');
        recommendations.push('Verify the sender through a different channel before taking action');
      } else {
        recommendations.push('This email appears safe, but always be cautious with unexpected requests');
      }
      return recommendations;
    }

    // Analyst/Admin recommendations
    const hasImpersonation = topFactors.some(f =>
      f.factor.toLowerCase().includes('impersonation') ||
      f.factor.toLowerCase().includes('spoof')
    );

    const hasBEC = topFactors.some(f =>
      f.factor.toLowerCase().includes('bec') ||
      f.factor.toLowerCase().includes('financial')
    );

    const hasMalware = topFactors.some(f =>
      f.factor.toLowerCase().includes('executable') ||
      f.factor.toLowerCase().includes('macro') ||
      f.factor.toLowerCase().includes('malware')
    );

    if (riskLevel === 'critical') {
      recommendations.push('IMMEDIATE: Block sender domain organization-wide');
      if (hasImpersonation) {
        recommendations.push('Alert potential targets of the impersonation attempt');
      }
    }

    if (hasBEC) {
      recommendations.push('Verify any financial requests through voice call');
      recommendations.push('Alert finance team about this BEC attempt');
      recommendations.push('Consider security awareness training for targeted users');
    }

    if (hasMalware) {
      recommendations.push('Submit attachments to sandbox for deep analysis');
      recommendations.push('Check if similar attachments were received by other users');
    }

    if (prediction.confidence < 0.6) {
      recommendations.push('Consider manual review due to moderate confidence score');
    }

    const similarThreats = topFactors.filter(f => f.evidence?.includes('similar'));
    if (similarThreats.length > 0) {
      recommendations.push('Review similar historical threats for pattern analysis');
    }

    return recommendations;
  }

  /**
   * Generate technical details for admin/analyst
   */
  private async generateTechnicalDetails(
    verdictId: string,
    prediction: PredictionResult,
    features: EmailFeatures | undefined
  ): Promise<TechnicalDetails> {
    // Feature importance with details
    const featureImportance: FeatureImportanceDetail[] = prediction.featureImportance.map(fi => ({
      feature: fi.feature,
      importance: Math.abs(fi.contribution),
      value: String(fi.contribution),
      direction: fi.direction,
      category: this.categorizeFeature(fi.feature),
    }));

    // Threshold information
    const thresholds: ThresholdInfo[] = [
      {
        name: 'Block Threshold',
        value: 0.85,
        actualScore: prediction.threatScore,
        exceeded: prediction.threatScore >= 0.85,
      },
      {
        name: 'Quarantine Threshold',
        value: 0.70,
        actualScore: prediction.threatScore,
        exceeded: prediction.threatScore >= 0.70,
      },
      {
        name: 'Suspicious Threshold',
        value: 0.50,
        actualScore: prediction.threatScore,
        exceeded: prediction.threatScore >= 0.50,
      },
      {
        name: 'Pass Threshold',
        value: 0.30,
        actualScore: prediction.threatScore,
        exceeded: prediction.threatScore >= 0.30,
      },
    ];

    // Layer scores
    const rawScores = prediction.rawScores || {
      header: 0,
      content: 0,
      sender: 0,
      url: 0,
      attachment: 0,
      behavioral: 0,
    };

    const layerScores: LayerScoreDetail[] = [
      { layer: 'Header/Auth', score: rawScores.header * 100, confidence: 0.9, weight: 0.20, skipped: false },
      { layer: 'Content', score: rawScores.content * 100, confidence: 0.85, weight: 0.25, skipped: false },
      { layer: 'Sender', score: rawScores.sender * 100, confidence: 0.88, weight: 0.20, skipped: false },
      { layer: 'URL', score: rawScores.url * 100, confidence: 0.92, weight: 0.15, skipped: false },
      { layer: 'Attachment', score: rawScores.attachment * 100, confidence: 0.95, weight: 0.10, skipped: false },
      { layer: 'Behavioral', score: rawScores.behavioral * 100, confidence: 0.75, weight: 0.10, skipped: false },
    ];

    // Triggered signals
    const triggeredSignals: Signal[] = prediction.featureImportance
      .filter(fi => fi.contribution > 0.05)
      .map(fi => ({
        type: fi.feature as Signal['type'],
        severity: this.importanceToSeverity(fi.contribution),
        score: fi.contribution * 100,
        detail: `${fi.feature}: ${fi.direction}`,
      }));

    return {
      featureImportance,
      thresholds,
      modelInfo: {
        version: prediction.modelVersion,
        layersUsed: layerScores.filter(l => !l.skipped).map(l => l.layer),
        processingTimeMs: prediction.predictionTimeMs,
        calibrationApplied: false,
      },
      layerScores,
      triggeredSignals,
    };
  }

  /**
   * Find similar safe email for comparison
   */
  private async findSimilarSafeEmail(
    tenantId: string,
    _prediction: PredictionResult
  ): Promise<{
    verdictId: string;
    emailFeatures?: EmailFeatures;
  } | null> {
    try {
      const results = await sql`
        SELECT id
        FROM email_verdicts
        WHERE tenant_id = ${tenantId}
          AND verdict = 'pass'
          AND created_at > NOW() - INTERVAL '30 days'
        ORDER BY created_at DESC
        LIMIT 1
      `;

      if (results.length === 0) return null;

      return {
        verdictId: results[0].id,
        // Would need to fetch and reconstruct email features
      };
    } catch {
      return null;
    }
  }

  /**
   * Generate executive narrative
   */
  private generateExecutiveNarrative(data: {
    totalEmails: number;
    totalThreats: number;
    topThreatCategories: Array<{ category: string; count: number; percentage: number }>;
    threatVolumeChange: number;
    accuracy: number;
    periodDays: number;
  }): string {
    const { totalEmails, totalThreats, topThreatCategories, threatVolumeChange, accuracy, periodDays } = data;

    let narrative = `Over the past ${periodDays} days, your email security system processed ${totalEmails.toLocaleString()} emails and blocked ${totalThreats.toLocaleString()} threats. `;

    if (topThreatCategories.length > 0) {
      const topCategory = topThreatCategories[0];
      narrative += `The most common threat type was ${topCategory.category.toLowerCase()}, accounting for ${Math.round(topCategory.percentage)}% of all detected threats. `;
    }

    if (threatVolumeChange > 10) {
      narrative += `Threat volume increased by ${Math.round(threatVolumeChange)}% compared to the previous period, indicating heightened attack activity. `;
    } else if (threatVolumeChange < -10) {
      narrative += `Threat volume decreased by ${Math.round(Math.abs(threatVolumeChange))}%, suggesting improved security posture or reduced attacker interest. `;
    } else {
      narrative += `Threat volume remained stable compared to the previous period. `;
    }

    narrative += `Detection accuracy stands at ${Math.round(accuracy)}%.`;

    return narrative;
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  private mapVerdictToThreatType(verdict: string): PredictionResult['threatType'] {
    const mapping: Record<string, PredictionResult['threatType']> = {
      phishing: 'phishing',
      bec: 'bec',
      malware: 'malware',
      spam: 'spam',
      block: 'phishing',
      quarantine: 'phishing',
      suspicious: 'spam',
      pass: 'clean',
    };
    return mapping[verdict.toLowerCase()] || 'phishing';
  }

  private mapVerdictToRiskLevel(verdict: string): PredictionResult['riskLevel'] {
    const mapping: Record<string, PredictionResult['riskLevel']> = {
      block: 'critical',
      quarantine: 'high',
      suspicious: 'medium',
      pass: 'safe',
    };
    return mapping[verdict.toLowerCase()] || 'medium';
  }

  private extractFeatureImportance(signals: Signal[]): FeatureImportance[] {
    return signals.map(s => ({
      feature: s.type,
      contribution: s.score / 100,
      direction: s.score > 0 ? 'increases_risk' as const : 'decreases_risk' as const,
      category: this.signalToFeatureCategory(s.type),
    }));
  }

  /**
   * Map signal type to feature category
   */
  private signalToFeatureCategory(signalType: string): FeatureImportance['category'] {
    const lowerType = signalType.toLowerCase();
    if (lowerType.includes('spf') || lowerType.includes('dkim') || lowerType.includes('dmarc') || lowerType.includes('header')) {
      return 'header';
    }
    if (lowerType.includes('urgency') || lowerType.includes('content') || lowerType.includes('language') || lowerType.includes('credential') || lowerType.includes('financial')) {
      return 'content';
    }
    if (lowerType.includes('sender') || lowerType.includes('domain') || lowerType.includes('reputation')) {
      return 'sender';
    }
    if (lowerType.includes('url') || lowerType.includes('link')) {
      return 'url';
    }
    if (lowerType.includes('attach') || lowerType.includes('file') || lowerType.includes('macro') || lowerType.includes('executable')) {
      return 'attachment';
    }
    return 'behavioral';
  }

  private calculateCategoryScore(signals: Signal[], keywords: string[]): number {
    const categorySignals = signals.filter(s =>
      keywords.some(kw => s.type.toLowerCase().includes(kw))
    );
    const totalScore = categorySignals.reduce((sum, s) => sum + Math.max(0, s.score), 0);
    return Math.min(1, totalScore / 100);
  }

  private categorizeFeature(feature: string): ExplanationFactor['category'] {
    const lowerFeature = feature.toLowerCase();
    if (lowerFeature.includes('sender') || lowerFeature.includes('domain') || lowerFeature.includes('reputation')) {
      return 'sender';
    }
    if (lowerFeature.includes('content') || lowerFeature.includes('urgency') || lowerFeature.includes('language')) {
      return 'content';
    }
    if (lowerFeature.includes('url') || lowerFeature.includes('link')) {
      return 'url';
    }
    if (lowerFeature.includes('attach') || lowerFeature.includes('file') || lowerFeature.includes('macro')) {
      return 'attachment';
    }
    if (lowerFeature.includes('behavior') || lowerFeature.includes('anomaly') || lowerFeature.includes('bec')) {
      return 'behavioral';
    }
    if (lowerFeature.includes('spf') || lowerFeature.includes('dkim') || lowerFeature.includes('dmarc') || lowerFeature.includes('auth')) {
      return 'authentication';
    }
    return 'content';
  }

  private getFactorDescription(feature: string, category: string): string {
    const categoryDescriptions = FACTOR_DESCRIPTIONS[category] || {};
    for (const [key, description] of Object.entries(categoryDescriptions)) {
      if (feature.toLowerCase().includes(key)) {
        return description;
      }
    }
    return `Analysis of ${feature.replace(/_/g, ' ')}`;
  }

  private formatFeatureName(feature: string): string {
    return feature
      .replace(/_/g, ' ')
      .replace(/([A-Z])/g, ' $1')
      .replace(/^./, c => c.toUpperCase())
      .trim()
      .replace(/  +/g, ' ');
  }

  private formatCategoryName(category: string): string {
    const names: Record<string, string> = {
      sender: 'Sender',
      content: 'Content',
      urls: 'URLs',
      attachments: 'Attachments',
      behavioral: 'Behavioral',
      authentication: 'Authentication',
    };
    return names[category] || category;
  }

  private formatThreatType(type: string): string {
    const names: Record<string, string> = {
      phishing: 'Phishing',
      bec: 'Business Email Compromise (BEC)',
      malware: 'Malware',
      spam: 'Spam',
      clean: 'Clean',
    };
    return names[type] || type;
  }

  private importanceToImpact(importance: number): ExplanationFactor['impact'] {
    if (importance >= 0.20) return 'critical';
    if (importance >= 0.10) return 'high';
    if (importance >= 0.05) return 'medium';
    return 'low';
  }

  private importanceToSeverity(importance: number): Signal['severity'] {
    if (importance >= 0.15) return 'critical';
    if (importance >= 0.05) return 'warning';
    return 'info';
  }

  private parsePeriod(period: string): number {
    const match = period.match(/(\d+)\s*(day|week|month)/i);
    if (!match) return 7; // Default to 7 days

    const value = parseInt(match[1], 10);
    const unit = match[2].toLowerCase();

    switch (unit) {
      case 'week':
        return value * 7;
      case 'month':
        return value * 30;
      default:
        return value;
    }
  }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Create a ThreatExplainer instance
 */
export function createThreatExplainer(): ThreatExplainer {
  return new ThreatExplainer();
}

/**
 * Generate explanation for a verdict
 */
export async function explainThreat(request: ExplanationRequest): Promise<Explanation> {
  const explainer = new ThreatExplainer();
  return explainer.explain(request);
}

/**
 * Get a brief summary for a verdict
 */
export async function summarizeThreat(verdictId: string): Promise<string> {
  const explainer = new ThreatExplainer();
  return explainer.summarize(verdictId);
}

/**
 * Get risk breakdown for a verdict
 */
export async function getRiskBreakdown(verdictId: string): Promise<RiskBreakdown> {
  const explainer = new ThreatExplainer();
  return explainer.getRiskBreakdown(verdictId);
}

/**
 * Get counterfactual explanation
 */
export async function getCounterfactual(verdictId: string): Promise<CounterfactualExplanation> {
  const explainer = new ThreatExplainer();
  return explainer.getCounterfactual(verdictId);
}

/**
 * Get similar threats
 */
export async function getSimilarThreats(verdictId: string, limit?: number): Promise<SimilarThreat[]> {
  const explainer = new ThreatExplainer();
  return explainer.getSimilarThreats(verdictId, limit);
}

/**
 * Get detection timeline
 */
export async function getDetectionTimeline(verdictId: string): Promise<DetectionTimeline> {
  const explainer = new ThreatExplainer();
  return explainer.getDetectionTimeline(verdictId);
}

/**
 * Generate executive summary
 */
export async function generateExecutiveSummary(
  tenantId: string,
  period: string
): Promise<ExecutiveSummary> {
  const explainer = new ThreatExplainer();
  return explainer.generateExecutiveSummary(tenantId, period);
}

/**
 * Compare threat with safe email
 */
export async function compareWithSafe(verdictId: string): Promise<ComparativeExplanation> {
  const explainer = new ThreatExplainer();
  return explainer.compareWithSafe(verdictId);
}

// Default export
export default ThreatExplainer;
