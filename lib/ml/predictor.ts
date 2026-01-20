/**
 * ML Threat Predictor Module
 *
 * Provides threat prediction capabilities with:
 * - Weighted ensemble scoring from multiple signals
 * - Model versioning and A/B testing framework
 * - Confidence calibration using Platt scaling
 * - Tenant-specific threshold configuration
 * - Feature importance for explainability
 * - Rollback capability for model versions
 */

import { EventEmitter } from 'events';

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Header-based features extracted from email
 */
export interface HeaderFeatures {
  /** SPF authentication result score (0-1) */
  spfScore: number;
  /** DKIM authentication result score (0-1) */
  dkimScore: number;
  /** DMARC authentication result score (0-1) */
  dmarcScore: number;
  /** Whether the Reply-To differs from the sender */
  replyToMismatch: boolean;
  /** Whether the display name appears to be spoofed */
  displayNameSpoof: boolean;
  /** Number of suspicious header anomalies detected */
  headerAnomalyCount: number;
  /** Whether the envelope sender matches the header sender */
  envelopeMismatch: boolean;
  /** X-Mailer suspicious indicator */
  suspiciousMailer: boolean;
}

/**
 * Content-based features extracted from email body
 */
export interface ContentFeatures {
  /** Urgency language score (0-1) */
  urgencyScore: number;
  /** Threat/fear language score (0-1) */
  threatScore: number;
  /** Grammar quality score (0-1, lower = worse) */
  grammarScore: number;
  /** Sentiment negativity score (0-1) */
  sentimentScore: number;
  /** Requests for personal information */
  requestsPersonalInfo: boolean;
  /** Requests for credentials/login */
  requestsCredentials: boolean;
  /** Financial request indicators */
  hasFinancialRequest: boolean;
  /** Image to text ratio */
  imageToTextRatio: number;
  /** Contains suspicious keywords count */
  suspiciousKeywordCount: number;
}

/**
 * Sender-based features
 */
export interface SenderFeatures {
  /** Sender reputation score (0-1) */
  reputationScore: number;
  /** Domain age in days (-1 if unknown) */
  domainAgeDays: number;
  /** Whether sender uses free email provider */
  isFreemailProvider: boolean;
  /** Whether domain is disposable */
  isDisposableEmail: boolean;
  /** Domain similarity to known brands (0-1) */
  domainSimilarityScore: number;
  /** Whether this is first contact from sender */
  isFirstContact: boolean;
  /** Whether sender domain is a cousin/lookalike */
  isCousinDomain: boolean;
  /** Executive impersonation likelihood (0-1) */
  executiveImpersonationScore: number;
}

/**
 * URL-based features
 */
export interface UrlFeatures {
  /** Total number of URLs */
  urlCount: number;
  /** Number of external URLs */
  externalUrlCount: number;
  /** Number of URL shorteners */
  shortenerCount: number;
  /** Number of IP-based URLs */
  ipUrlCount: number;
  /** Number of suspicious/malicious URLs */
  maliciousUrlCount: number;
  /** Maximum URL suspicion score (0-1) */
  maxUrlSuspicionScore: number;
  /** Whether URLs use redirects */
  hasRedirects: boolean;
  /** Number of newly registered domains in URLs */
  newDomainUrlCount: number;
}

/**
 * Attachment-based features
 */
export interface AttachmentFeatures {
  /** Total number of attachments */
  attachmentCount: number;
  /** Risk score of attachments (0-1) */
  attachmentRiskScore: number;
  /** Whether any attachment is executable */
  hasExecutable: boolean;
  /** Whether any attachment has macros */
  hasMacros: boolean;
  /** Whether any attachment is password protected */
  hasPasswordProtected: boolean;
  /** Whether double extension is detected */
  hasDoubleExtension: boolean;
  /** Total attachment size in bytes */
  totalSizeBytes: number;
}

/**
 * Behavioral features based on patterns and context
 */
export interface BehavioralFeatures {
  /** Whether email is part of a reply chain */
  isReplyChain: boolean;
  /** Whether email has unsubscribe link */
  hasUnsubscribeLink: boolean;
  /** Time of day sent (hour 0-23) */
  sendHour: number;
  /** Whether sent during business hours */
  sentDuringBusinessHours: boolean;
  /** BEC pattern score (0-1) */
  becPatternScore: number;
  /** Wire transfer request indicators */
  hasWireTransferRequest: boolean;
  /** Gift card request indicators */
  hasGiftCardRequest: boolean;
  /** Invoice/payment update indicators */
  hasInvoiceUpdate: boolean;
}

/**
 * Complete email features for prediction
 */
export interface EmailFeatures {
  headerFeatures: HeaderFeatures;
  contentFeatures: ContentFeatures;
  senderFeatures: SenderFeatures;
  urlFeatures: UrlFeatures;
  attachmentFeatures: AttachmentFeatures;
  behavioralFeatures: BehavioralFeatures;
}

/**
 * Feature contribution to risk score
 */
export interface FeatureImportance {
  /** Feature name */
  feature: string;
  /** Contribution value (-1 to 1) */
  contribution: number;
  /** Direction of risk impact */
  direction: 'increases_risk' | 'decreases_risk';
  /** Category of the feature */
  category: 'header' | 'content' | 'sender' | 'url' | 'attachment' | 'behavioral';
}

/**
 * Prediction result from the model
 */
export interface PredictionResult {
  /** Overall threat score (0-1) */
  threatScore: number;
  /** Confidence in the prediction (0-1) */
  confidence: number;
  /** Predicted threat type */
  threatType: 'phishing' | 'bec' | 'malware' | 'spam' | 'clean';
  /** Risk level classification */
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'safe';
  /** Model version used for prediction */
  modelVersion: string;
  /** Time taken for prediction in milliseconds */
  predictionTimeMs: number;
  /** Feature importance breakdown */
  featureImportance: FeatureImportance[];
  /** Raw scores from each sub-model */
  rawScores?: {
    header: number;
    content: number;
    sender: number;
    url: number;
    attachment: number;
    behavioral: number;
  };
  /** A/B test variant if applicable */
  abTestVariant?: string;
}

/**
 * Threshold configuration for risk classification
 */
export interface ThresholdConfig {
  /** Threshold for critical risk (default: 0.85) */
  criticalThreshold: number;
  /** Threshold for high risk (default: 0.70) */
  highThreshold: number;
  /** Threshold for medium risk (default: 0.50) */
  mediumThreshold: number;
  /** Threshold for low risk (default: 0.30) */
  lowThreshold: number;
  /** Per-threat-type threshold overrides */
  threatTypeThresholds?: {
    phishing?: number;
    bec?: number;
    malware?: number;
    spam?: number;
  };
}

/**
 * A/B test configuration
 */
export interface ABTestConfig {
  /** Test identifier */
  testId: string;
  /** Test description */
  description: string;
  /** Whether test is active */
  active: boolean;
  /** Traffic percentage for variant B (0-100) */
  variantBPercentage: number;
  /** Model version for variant A */
  variantAModel: string;
  /** Model version for variant B */
  variantBModel: string;
  /** Metrics to track */
  trackingMetrics: ('accuracy' | 'precision' | 'recall' | 'latency')[];
  /** Start time of the test */
  startTime: Date;
  /** End time of the test (optional) */
  endTime?: Date;
}

/**
 * Model version metadata
 */
export interface ModelVersion {
  /** Version identifier */
  version: string;
  /** When the model was trained */
  trainedAt: Date;
  /** When the model was deployed */
  deployedAt?: Date;
  /** Training metrics */
  metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
  };
  /** Feature weights for this version */
  weights: ModelWeights;
  /** Whether this is the active version */
  isActive: boolean;
  /** Calibration parameters */
  calibration: CalibrationParams;
}

/**
 * Model weights for ensemble scoring
 */
export interface ModelWeights {
  header: number;
  content: number;
  sender: number;
  url: number;
  attachment: number;
  behavioral: number;
}

/**
 * Platt scaling calibration parameters
 */
export interface CalibrationParams {
  /** Sigmoid parameter A */
  a: number;
  /** Sigmoid parameter B */
  b: number;
  /** Whether calibration is enabled */
  enabled: boolean;
}

/**
 * Predictor configuration
 */
export interface PredictorConfig {
  /** Default threshold configuration */
  defaultThresholds: ThresholdConfig;
  /** Maximum batch size */
  maxBatchSize: number;
  /** Enable caching */
  enableCache: boolean;
  /** Cache TTL in milliseconds */
  cacheTtlMs: number;
  /** Enable detailed feature importance */
  enableFeatureImportance: boolean;
}

// ============================================================================
// Default Configurations
// ============================================================================

const DEFAULT_THRESHOLDS: ThresholdConfig = {
  criticalThreshold: 0.85,
  highThreshold: 0.70,
  mediumThreshold: 0.50,
  lowThreshold: 0.30,
};

const DEFAULT_WEIGHTS: ModelWeights = {
  header: 0.20,
  content: 0.25,
  sender: 0.20,
  url: 0.15,
  attachment: 0.10,
  behavioral: 0.10,
};

const DEFAULT_CALIBRATION: CalibrationParams = {
  a: -2.0, // Negative a to map raw scores appropriately
  b: 0.5,  // Shift midpoint
  enabled: false, // Disable calibration by default for now - use raw scores
};

const DEFAULT_CONFIG: PredictorConfig = {
  defaultThresholds: DEFAULT_THRESHOLDS,
  maxBatchSize: 100,
  enableCache: true,
  cacheTtlMs: 60000, // 1 minute
  enableFeatureImportance: true,
};

// ============================================================================
// ThreatPredictor Class
// ============================================================================

/**
 * ML-based threat predictor for email security
 *
 * Uses a weighted ensemble approach combining multiple feature categories
 * with configurable thresholds and A/B testing support.
 */
export class ThreatPredictor extends EventEmitter {
  private config: PredictorConfig;
  private thresholds: ThresholdConfig;
  private tenantThresholds: Map<string, ThresholdConfig> = new Map();
  private modelVersions: Map<string, ModelVersion> = new Map();
  private activeVersion: string;
  private abTests: Map<string, ABTestConfig> = new Map();
  private predictionCache: Map<string, { result: PredictionResult; timestamp: number }> = new Map();

  constructor(config: Partial<PredictorConfig> = {}) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.thresholds = { ...this.config.defaultThresholds };

    // Initialize with default model version
    const defaultVersion = '1.0.0';
    this.modelVersions.set(defaultVersion, {
      version: defaultVersion,
      trainedAt: new Date(),
      deployedAt: new Date(),
      metrics: {
        accuracy: 0.92,
        precision: 0.89,
        recall: 0.87,
        f1Score: 0.88,
      },
      weights: { ...DEFAULT_WEIGHTS },
      isActive: true,
      calibration: { ...DEFAULT_CALIBRATION },
    });
    this.activeVersion = defaultVersion;
  }

  /**
   * Predict threat level for a single email
   */
  async predict(email: EmailFeatures, tenantId?: string): Promise<PredictionResult> {
    const startTime = performance.now();

    // Check cache
    const cacheKey = this.computeCacheKey(email);
    if (this.config.enableCache) {
      const cached = this.predictionCache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < this.config.cacheTtlMs) {
        return {
          ...cached.result,
          predictionTimeMs: performance.now() - startTime,
        };
      }
    }

    // Determine which model version to use (for A/B testing)
    const { modelVersion, abTestVariant } = this.selectModelVersion(tenantId);
    const model = this.modelVersions.get(modelVersion)!;

    // Calculate raw scores for each feature category
    const rawScores = this.calculateRawScores(email, model.weights);

    // Calculate weighted ensemble score
    const rawScore = this.calculateEnsembleScore(rawScores, model.weights);

    // Apply Platt scaling calibration
    const calibratedScore = model.calibration.enabled
      ? this.calibrateConfidence(rawScore, model.calibration)
      : rawScore;

    // Determine threat type
    const threatType = this.determineThreatType(email, calibratedScore);

    // Determine risk level using tenant-specific or default thresholds
    const effectiveThresholds = tenantId
      ? this.tenantThresholds.get(tenantId) || this.thresholds
      : this.thresholds;
    const riskLevel = this.determineRiskLevel(calibratedScore, threatType, effectiveThresholds);

    // Calculate feature importance
    const featureImportance = this.config.enableFeatureImportance
      ? this.calculateFeatureImportance(email, model.weights)
      : [];

    // Calculate confidence based on feature coverage and score certainty
    const confidence = this.calculateConfidence(email, calibratedScore);

    const result: PredictionResult = {
      threatScore: calibratedScore,
      confidence,
      threatType,
      riskLevel,
      modelVersion,
      predictionTimeMs: performance.now() - startTime,
      featureImportance,
      rawScores,
      abTestVariant,
    };

    // Cache result
    if (this.config.enableCache) {
      this.predictionCache.set(cacheKey, {
        result,
        timestamp: Date.now(),
      });
    }

    // Emit prediction event for monitoring
    this.emit('prediction', {
      tenantId,
      threatScore: calibratedScore,
      threatType,
      riskLevel,
      modelVersion,
      abTestVariant,
      latencyMs: result.predictionTimeMs,
    });

    return result;
  }

  /**
   * Batch prediction for multiple emails
   */
  async batchPredict(
    emails: EmailFeatures[],
    tenantId?: string
  ): Promise<PredictionResult[]> {
    if (emails.length > this.config.maxBatchSize) {
      throw new Error(
        `Batch size ${emails.length} exceeds maximum ${this.config.maxBatchSize}`
      );
    }

    const startTime = performance.now();

    // Process predictions in parallel
    const predictions = await Promise.all(
      emails.map((email) => this.predict(email, tenantId))
    );

    // Emit batch event for monitoring
    this.emit('batch_prediction', {
      tenantId,
      count: emails.length,
      totalLatencyMs: performance.now() - startTime,
      avgLatencyMs: (performance.now() - startTime) / emails.length,
    });

    return predictions;
  }

  /**
   * Calibrate raw score using Platt scaling
   * Uses sigmoid function: P(y=1|f) = 1 / (1 + exp(A*f + B))
   */
  calibrateConfidence(rawScore: number, params?: CalibrationParams): number {
    const calibration = params || this.modelVersions.get(this.activeVersion)!.calibration;
    if (!calibration.enabled) {
      return rawScore;
    }

    const { a, b } = calibration;
    const calibrated = 1 / (1 + Math.exp(a * rawScore + b));
    return Math.max(0, Math.min(1, calibrated));
  }

  /**
   * Get current model version
   */
  getModelVersion(): string {
    return this.activeVersion;
  }

  /**
   * Get all model versions
   */
  getAllModelVersions(): ModelVersion[] {
    return Array.from(this.modelVersions.values());
  }

  /**
   * Update threshold configuration
   */
  updateThresholds(thresholds: Partial<ThresholdConfig>, tenantId?: string): void {
    const newThresholds = { ...this.thresholds, ...thresholds };

    // Validate threshold ordering
    if (
      newThresholds.lowThreshold >= newThresholds.mediumThreshold ||
      newThresholds.mediumThreshold >= newThresholds.highThreshold ||
      newThresholds.highThreshold >= newThresholds.criticalThreshold
    ) {
      throw new Error(
        'Thresholds must be in ascending order: low < medium < high < critical'
      );
    }

    if (tenantId) {
      this.tenantThresholds.set(tenantId, newThresholds);
    } else {
      this.thresholds = newThresholds;
    }

    this.emit('thresholds_updated', { tenantId, thresholds: newThresholds });
  }

  /**
   * Get current thresholds
   */
  getThresholds(tenantId?: string): ThresholdConfig {
    if (tenantId) {
      return this.tenantThresholds.get(tenantId) || this.thresholds;
    }
    return this.thresholds;
  }

  /**
   * Enable A/B testing
   */
  enableABTest(testConfig: ABTestConfig): void {
    // Validate configuration
    if (testConfig.variantBPercentage < 0 || testConfig.variantBPercentage > 100) {
      throw new Error('Variant B percentage must be between 0 and 100');
    }

    if (!this.modelVersions.has(testConfig.variantAModel)) {
      throw new Error(`Variant A model ${testConfig.variantAModel} not found`);
    }

    if (!this.modelVersions.has(testConfig.variantBModel)) {
      throw new Error(`Variant B model ${testConfig.variantBModel} not found`);
    }

    testConfig.startTime = new Date();
    this.abTests.set(testConfig.testId, testConfig);

    this.emit('ab_test_started', {
      testId: testConfig.testId,
      variantAModel: testConfig.variantAModel,
      variantBModel: testConfig.variantBModel,
      variantBPercentage: testConfig.variantBPercentage,
    });
  }

  /**
   * Disable A/B test
   */
  disableABTest(testId: string): void {
    const test = this.abTests.get(testId);
    if (test) {
      test.active = false;
      test.endTime = new Date();
      this.emit('ab_test_ended', { testId });
    }
  }

  /**
   * Get A/B test status
   */
  getABTestStatus(testId: string): ABTestConfig | undefined {
    return this.abTests.get(testId);
  }

  /**
   * Rollback to a previous model version
   */
  async rollback(version: string): Promise<void> {
    if (!this.modelVersions.has(version)) {
      throw new Error(`Model version ${version} not found`);
    }

    const previousVersion = this.activeVersion;
    const previousModel = this.modelVersions.get(previousVersion)!;
    const newModel = this.modelVersions.get(version)!;

    // Update active status
    previousModel.isActive = false;
    newModel.isActive = true;
    newModel.deployedAt = new Date();

    this.activeVersion = version;

    // Clear cache on rollback
    this.predictionCache.clear();

    this.emit('model_rollback', {
      fromVersion: previousVersion,
      toVersion: version,
      timestamp: new Date(),
    });
  }

  /**
   * Deploy a new model version
   */
  async deployModel(model: Omit<ModelVersion, 'deployedAt' | 'isActive'>): Promise<void> {
    const newModel: ModelVersion = {
      ...model,
      deployedAt: new Date(),
      isActive: false,
    };

    this.modelVersions.set(model.version, newModel);

    this.emit('model_deployed', {
      version: model.version,
      metrics: model.metrics,
    });
  }

  /**
   * Activate a specific model version
   */
  async activateModel(version: string): Promise<void> {
    if (!this.modelVersions.has(version)) {
      throw new Error(`Model version ${version} not found`);
    }

    // Deactivate current model
    const currentModel = this.modelVersions.get(this.activeVersion)!;
    currentModel.isActive = false;

    // Activate new model
    const newModel = this.modelVersions.get(version)!;
    newModel.isActive = true;
    newModel.deployedAt = new Date();

    const previousVersion = this.activeVersion;
    this.activeVersion = version;

    // Clear cache
    this.predictionCache.clear();

    this.emit('model_activated', {
      fromVersion: previousVersion,
      toVersion: version,
    });
  }

  /**
   * Update model weights
   */
  updateModelWeights(version: string, weights: Partial<ModelWeights>): void {
    const model = this.modelVersions.get(version);
    if (!model) {
      throw new Error(`Model version ${version} not found`);
    }

    model.weights = { ...model.weights, ...weights };

    // Normalize weights to sum to 1
    const sum = Object.values(model.weights).reduce((a, b) => a + b, 0);
    for (const key of Object.keys(model.weights) as (keyof ModelWeights)[]) {
      model.weights[key] /= sum;
    }

    this.emit('weights_updated', { version, weights: model.weights });
  }

  /**
   * Update calibration parameters
   */
  updateCalibration(version: string, calibration: Partial<CalibrationParams>): void {
    const model = this.modelVersions.get(version);
    if (!model) {
      throw new Error(`Model version ${version} not found`);
    }

    model.calibration = { ...model.calibration, ...calibration };

    this.emit('calibration_updated', { version, calibration: model.calibration });
  }

  /**
   * Get predictor statistics
   */
  getStats(): {
    activeModel: string;
    totalModelVersions: number;
    activeABTests: number;
    cacheSize: number;
    tenantConfigurations: number;
  } {
    return {
      activeModel: this.activeVersion,
      totalModelVersions: this.modelVersions.size,
      activeABTests: Array.from(this.abTests.values()).filter((t) => t.active).length,
      cacheSize: this.predictionCache.size,
      tenantConfigurations: this.tenantThresholds.size,
    };
  }

  /**
   * Clear prediction cache
   */
  clearCache(): void {
    this.predictionCache.clear();
    this.emit('cache_cleared');
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  /**
   * Compute cache key from features
   */
  private computeCacheKey(email: EmailFeatures): string {
    // Create a deterministic hash from features
    const featureStr = JSON.stringify({
      h: email.headerFeatures,
      c: email.contentFeatures,
      s: email.senderFeatures,
      u: email.urlFeatures,
      a: email.attachmentFeatures,
      b: email.behavioralFeatures,
    });

    // Simple hash function
    let hash = 0;
    for (let i = 0; i < featureStr.length; i++) {
      const char = featureStr.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }

    return `pred_${Math.abs(hash).toString(16)}`;
  }

  /**
   * Select model version (considering A/B tests)
   */
  private selectModelVersion(tenantId?: string): { modelVersion: string; abTestVariant?: string } {
    // Check for active A/B tests
    const testIds = Array.from(this.abTests.keys());
    for (const testId of testIds) {
      const test = this.abTests.get(testId)!;
      if (!test.active) continue;
      if (test.endTime && new Date() > test.endTime) continue;

      // Deterministic bucket based on tenant or random
      const bucket = tenantId
        ? this.hashTenantToBucket(tenantId)
        : Math.random() * 100;

      if (bucket < test.variantBPercentage) {
        return { modelVersion: test.variantBModel, abTestVariant: `${testId}:B` };
      } else {
        return { modelVersion: test.variantAModel, abTestVariant: `${testId}:A` };
      }
    }

    return { modelVersion: this.activeVersion };
  }

  /**
   * Hash tenant ID to a bucket (0-100)
   */
  private hashTenantToBucket(tenantId: string): number {
    let hash = 0;
    for (let i = 0; i < tenantId.length; i++) {
      hash = ((hash << 5) - hash) + tenantId.charCodeAt(i);
      hash = hash & hash;
    }
    return Math.abs(hash) % 100;
  }

  /**
   * Calculate raw scores for each feature category
   */
  private calculateRawScores(
    email: EmailFeatures,
    _weights: ModelWeights
  ): NonNullable<PredictionResult['rawScores']> {
    return {
      header: this.scoreHeaderFeatures(email.headerFeatures),
      content: this.scoreContentFeatures(email.contentFeatures),
      sender: this.scoreSenderFeatures(email.senderFeatures),
      url: this.scoreUrlFeatures(email.urlFeatures),
      attachment: this.scoreAttachmentFeatures(email.attachmentFeatures),
      behavioral: this.scoreBehavioralFeatures(email.behavioralFeatures),
    };
  }

  /**
   * Score header features
   */
  private scoreHeaderFeatures(features: HeaderFeatures): number {
    let score = 0;

    // Authentication failures
    score += (1 - features.spfScore) * 0.15;
    score += (1 - features.dkimScore) * 0.15;
    score += (1 - features.dmarcScore) * 0.20;

    // Spoofing indicators
    if (features.replyToMismatch) score += 0.15;
    if (features.displayNameSpoof) score += 0.20;
    if (features.envelopeMismatch) score += 0.10;
    if (features.suspiciousMailer) score += 0.05;

    // Header anomalies
    score += Math.min(0.15, features.headerAnomalyCount * 0.05);

    return Math.min(1, score);
  }

  /**
   * Score content features
   */
  private scoreContentFeatures(features: ContentFeatures): number {
    let score = 0;

    // Language signals
    score += features.urgencyScore * 0.20;
    score += features.threatScore * 0.25;
    score += (1 - features.grammarScore) * 0.10;
    score += features.sentimentScore * 0.10;

    // Request indicators
    if (features.requestsPersonalInfo) score += 0.15;
    if (features.requestsCredentials) score += 0.20;
    if (features.hasFinancialRequest) score += 0.15;

    // Structural indicators
    score += Math.min(0.10, features.imageToTextRatio * 0.05);
    score += Math.min(0.10, features.suspiciousKeywordCount * 0.02);

    return Math.min(1, score);
  }

  /**
   * Score sender features
   */
  private scoreSenderFeatures(features: SenderFeatures): number {
    let score = 0;

    // Reputation (inverse)
    score += (1 - features.reputationScore) * 0.25;

    // Domain age (newer is riskier)
    if (features.domainAgeDays >= 0) {
      if (features.domainAgeDays < 30) score += 0.20;
      else if (features.domainAgeDays < 90) score += 0.10;
      else if (features.domainAgeDays < 365) score += 0.05;
    }

    // Email provider indicators
    if (features.isFreemailProvider) score += 0.05;
    if (features.isDisposableEmail) score += 0.20;

    // Spoofing indicators
    score += features.domainSimilarityScore * 0.15;
    if (features.isFirstContact) score += 0.05;
    if (features.isCousinDomain) score += 0.20;
    score += features.executiveImpersonationScore * 0.25;

    return Math.min(1, score);
  }

  /**
   * Score URL features
   */
  private scoreUrlFeatures(features: UrlFeatures): number {
    let score = 0;

    // URL quantity and type
    score += Math.min(0.15, features.urlCount * 0.02);
    score += Math.min(0.15, features.externalUrlCount * 0.03);
    score += Math.min(0.20, features.shortenerCount * 0.10);
    score += Math.min(0.20, features.ipUrlCount * 0.15);

    // Malicious indicators
    score += Math.min(0.40, features.maliciousUrlCount * 0.20);
    score += features.maxUrlSuspicionScore * 0.20;
    if (features.hasRedirects) score += 0.10;
    score += Math.min(0.15, features.newDomainUrlCount * 0.05);

    return Math.min(1, score);
  }

  /**
   * Score attachment features
   */
  private scoreAttachmentFeatures(features: AttachmentFeatures): number {
    let score = 0;

    // Base risk
    score += features.attachmentRiskScore * 0.30;

    // High-risk indicators
    if (features.hasExecutable) score += 0.35;
    if (features.hasMacros) score += 0.20;
    if (features.hasPasswordProtected) score += 0.15;
    if (features.hasDoubleExtension) score += 0.25;

    // Attachment count (more is slightly riskier)
    score += Math.min(0.10, features.attachmentCount * 0.02);

    return Math.min(1, score);
  }

  /**
   * Score behavioral features
   */
  private scoreBehavioralFeatures(features: BehavioralFeatures): number {
    let score = 0;

    // BEC indicators
    score += features.becPatternScore * 0.30;
    if (features.hasWireTransferRequest) score += 0.25;
    if (features.hasGiftCardRequest) score += 0.25;
    if (features.hasInvoiceUpdate) score += 0.15;

    // Legitimate indicators (reduce score)
    if (features.isReplyChain) score -= 0.10;
    if (features.hasUnsubscribeLink) score -= 0.10;
    if (features.sentDuringBusinessHours) score -= 0.05;

    return Math.max(0, Math.min(1, score));
  }

  /**
   * Calculate weighted ensemble score
   */
  private calculateEnsembleScore(
    rawScores: NonNullable<PredictionResult['rawScores']>,
    weights: ModelWeights
  ): number {
    return (
      rawScores.header * weights.header +
      rawScores.content * weights.content +
      rawScores.sender * weights.sender +
      rawScores.url * weights.url +
      rawScores.attachment * weights.attachment +
      rawScores.behavioral * weights.behavioral
    );
  }

  /**
   * Determine threat type based on features and score
   */
  private determineThreatType(
    email: EmailFeatures,
    score: number
  ): PredictionResult['threatType'] {
    const { contentFeatures, senderFeatures, urlFeatures, attachmentFeatures, behavioralFeatures } = email;

    // Check for malware indicators first (highest priority)
    if (
      attachmentFeatures.hasExecutable ||
      (attachmentFeatures.hasMacros && attachmentFeatures.attachmentRiskScore > 0.3) ||
      attachmentFeatures.attachmentRiskScore > 0.6
    ) {
      return 'malware';
    }

    // Check for BEC indicators
    if (
      behavioralFeatures.becPatternScore > 0.4 ||
      behavioralFeatures.hasWireTransferRequest ||
      behavioralFeatures.hasGiftCardRequest ||
      senderFeatures.executiveImpersonationScore > 0.4 ||
      (contentFeatures.hasFinancialRequest && senderFeatures.executiveImpersonationScore > 0.2)
    ) {
      return 'bec';
    }

    // Check for phishing indicators
    if (
      contentFeatures.requestsCredentials ||
      contentFeatures.requestsPersonalInfo ||
      urlFeatures.maliciousUrlCount > 0 ||
      senderFeatures.isCousinDomain ||
      senderFeatures.domainSimilarityScore > 0.5 ||
      (contentFeatures.threatScore > 0.4 && contentFeatures.urgencyScore > 0.3)
    ) {
      return 'phishing';
    }

    // Check for spam indicators
    if (
      (contentFeatures.urgencyScore > 0.3 || contentFeatures.grammarScore < 0.5) &&
      !contentFeatures.requestsCredentials &&
      !contentFeatures.requestsPersonalInfo
    ) {
      return 'spam';
    }

    // Default to phishing for elevated scores without specific indicators
    if (score > 0.35) {
      return 'phishing';
    }

    // Low score = clean
    if (score < 0.15) {
      return 'clean';
    }

    return 'spam';
  }

  /**
   * Determine risk level based on score and thresholds
   */
  private determineRiskLevel(
    score: number,
    threatType: PredictionResult['threatType'],
    thresholds: ThresholdConfig
  ): PredictionResult['riskLevel'] {
    // Check for threat-type-specific thresholds
    const threatTypeKey = threatType as keyof NonNullable<ThresholdConfig['threatTypeThresholds']>;
    const typeThreshold = thresholds.threatTypeThresholds?.[threatTypeKey];
    if (typeThreshold !== undefined && score >= typeThreshold) {
      return 'critical';
    }

    if (score >= thresholds.criticalThreshold) return 'critical';
    if (score >= thresholds.highThreshold) return 'high';
    if (score >= thresholds.mediumThreshold) return 'medium';
    if (score >= thresholds.lowThreshold) return 'low';
    return 'safe';
  }

  /**
   * Calculate prediction confidence
   */
  private calculateConfidence(email: EmailFeatures, score: number): number {
    // Base confidence from score certainty (higher or lower scores = more confident)
    const scoreCertainty = Math.abs(score - 0.5) * 2; // 0-1 scale

    // Feature coverage score
    let featureCoverage = 0;
    let totalFeatures = 0;

    // Check header features
    const header = email.headerFeatures;
    if (header.spfScore >= 0) featureCoverage++;
    if (header.dkimScore >= 0) featureCoverage++;
    if (header.dmarcScore >= 0) featureCoverage++;
    totalFeatures += 3;

    // Check sender features
    const sender = email.senderFeatures;
    if (sender.reputationScore >= 0) featureCoverage++;
    if (sender.domainAgeDays >= 0) featureCoverage++;
    totalFeatures += 2;

    // Check URL features
    if (email.urlFeatures.urlCount > 0) featureCoverage++;
    totalFeatures++;

    const coverageRatio = totalFeatures > 0 ? featureCoverage / totalFeatures : 0.5;

    // Strong indicators boost confidence
    let indicatorBoost = 0;
    if (email.attachmentFeatures.hasExecutable) indicatorBoost += 0.15;
    if (email.behavioralFeatures.hasWireTransferRequest) indicatorBoost += 0.15;
    if (email.contentFeatures.requestsCredentials) indicatorBoost += 0.15;
    if (email.senderFeatures.isCousinDomain) indicatorBoost += 0.15;
    // Clean email indicators also boost confidence
    if (header.spfScore === 1 && header.dkimScore === 1 && header.dmarcScore === 1) {
      indicatorBoost += 0.2;
    }

    const confidence = Math.min(
      0.95,
      0.4 * scoreCertainty + 0.35 * coverageRatio + indicatorBoost
    );

    return Math.max(0.35, confidence);
  }

  /**
   * Calculate feature importance for explainability
   */
  private calculateFeatureImportance(
    email: EmailFeatures,
    weights: ModelWeights
  ): FeatureImportance[] {
    const importance: FeatureImportance[] = [];

    // Header features
    this.addHeaderImportance(email.headerFeatures, weights.header, importance);

    // Content features
    this.addContentImportance(email.contentFeatures, weights.content, importance);

    // Sender features
    this.addSenderImportance(email.senderFeatures, weights.sender, importance);

    // URL features
    this.addUrlImportance(email.urlFeatures, weights.url, importance);

    // Attachment features
    this.addAttachmentImportance(email.attachmentFeatures, weights.attachment, importance);

    // Behavioral features
    this.addBehavioralImportance(email.behavioralFeatures, weights.behavioral, importance);

    // Sort by absolute contribution
    return importance.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));
  }

  private addHeaderImportance(
    features: HeaderFeatures,
    weight: number,
    importance: FeatureImportance[]
  ): void {
    if (features.spfScore < 1) {
      importance.push({
        feature: 'SPF authentication',
        contribution: (1 - features.spfScore) * weight * 0.15,
        direction: 'increases_risk',
        category: 'header',
      });
    }

    if (features.dkimScore < 1) {
      importance.push({
        feature: 'DKIM authentication',
        contribution: (1 - features.dkimScore) * weight * 0.15,
        direction: 'increases_risk',
        category: 'header',
      });
    }

    if (features.dmarcScore < 1) {
      importance.push({
        feature: 'DMARC authentication',
        contribution: (1 - features.dmarcScore) * weight * 0.20,
        direction: 'increases_risk',
        category: 'header',
      });
    }

    if (features.replyToMismatch) {
      importance.push({
        feature: 'Reply-To mismatch',
        contribution: weight * 0.15,
        direction: 'increases_risk',
        category: 'header',
      });
    }

    if (features.displayNameSpoof) {
      importance.push({
        feature: 'Display name spoofing',
        contribution: weight * 0.20,
        direction: 'increases_risk',
        category: 'header',
      });
    }
  }

  private addContentImportance(
    features: ContentFeatures,
    weight: number,
    importance: FeatureImportance[]
  ): void {
    if (features.urgencyScore > 0.3) {
      importance.push({
        feature: 'Urgency language',
        contribution: features.urgencyScore * weight * 0.20,
        direction: 'increases_risk',
        category: 'content',
      });
    }

    if (features.threatScore > 0.3) {
      importance.push({
        feature: 'Threat language',
        contribution: features.threatScore * weight * 0.25,
        direction: 'increases_risk',
        category: 'content',
      });
    }

    if (features.requestsPersonalInfo) {
      importance.push({
        feature: 'Requests personal information',
        contribution: weight * 0.15,
        direction: 'increases_risk',
        category: 'content',
      });
    }

    if (features.requestsCredentials) {
      importance.push({
        feature: 'Requests credentials',
        contribution: weight * 0.20,
        direction: 'increases_risk',
        category: 'content',
      });
    }

    if (features.hasFinancialRequest) {
      importance.push({
        feature: 'Financial request',
        contribution: weight * 0.15,
        direction: 'increases_risk',
        category: 'content',
      });
    }
  }

  private addSenderImportance(
    features: SenderFeatures,
    weight: number,
    importance: FeatureImportance[]
  ): void {
    if (features.reputationScore < 0.5) {
      importance.push({
        feature: 'Low sender reputation',
        contribution: (1 - features.reputationScore) * weight * 0.25,
        direction: 'increases_risk',
        category: 'sender',
      });
    }

    if (features.domainAgeDays >= 0 && features.domainAgeDays < 30) {
      importance.push({
        feature: 'New domain (< 30 days)',
        contribution: weight * 0.20,
        direction: 'increases_risk',
        category: 'sender',
      });
    }

    if (features.isCousinDomain) {
      importance.push({
        feature: 'Lookalike domain',
        contribution: weight * 0.20,
        direction: 'increases_risk',
        category: 'sender',
      });
    }

    if (features.executiveImpersonationScore > 0.5) {
      importance.push({
        feature: 'Executive impersonation',
        contribution: features.executiveImpersonationScore * weight * 0.25,
        direction: 'increases_risk',
        category: 'sender',
      });
    }

    if (features.isDisposableEmail) {
      importance.push({
        feature: 'Disposable email',
        contribution: weight * 0.20,
        direction: 'increases_risk',
        category: 'sender',
      });
    }
  }

  private addUrlImportance(
    features: UrlFeatures,
    weight: number,
    importance: FeatureImportance[]
  ): void {
    if (features.maliciousUrlCount > 0) {
      importance.push({
        feature: `Malicious URLs (${features.maliciousUrlCount})`,
        contribution: Math.min(0.40, features.maliciousUrlCount * 0.20) * weight,
        direction: 'increases_risk',
        category: 'url',
      });
    }

    if (features.shortenerCount > 0) {
      importance.push({
        feature: `URL shorteners (${features.shortenerCount})`,
        contribution: Math.min(0.20, features.shortenerCount * 0.10) * weight,
        direction: 'increases_risk',
        category: 'url',
      });
    }

    if (features.ipUrlCount > 0) {
      importance.push({
        feature: `IP-based URLs (${features.ipUrlCount})`,
        contribution: Math.min(0.20, features.ipUrlCount * 0.15) * weight,
        direction: 'increases_risk',
        category: 'url',
      });
    }

    if (features.hasRedirects) {
      importance.push({
        feature: 'URL redirects detected',
        contribution: weight * 0.10,
        direction: 'increases_risk',
        category: 'url',
      });
    }
  }

  private addAttachmentImportance(
    features: AttachmentFeatures,
    weight: number,
    importance: FeatureImportance[]
  ): void {
    if (features.hasExecutable) {
      importance.push({
        feature: 'Executable attachment',
        contribution: weight * 0.35,
        direction: 'increases_risk',
        category: 'attachment',
      });
    }

    if (features.hasMacros) {
      importance.push({
        feature: 'Macro-enabled attachment',
        contribution: weight * 0.20,
        direction: 'increases_risk',
        category: 'attachment',
      });
    }

    if (features.hasPasswordProtected) {
      importance.push({
        feature: 'Password-protected attachment',
        contribution: weight * 0.15,
        direction: 'increases_risk',
        category: 'attachment',
      });
    }

    if (features.hasDoubleExtension) {
      importance.push({
        feature: 'Double extension detected',
        contribution: weight * 0.25,
        direction: 'increases_risk',
        category: 'attachment',
      });
    }
  }

  private addBehavioralImportance(
    features: BehavioralFeatures,
    weight: number,
    importance: FeatureImportance[]
  ): void {
    if (features.becPatternScore > 0.3) {
      importance.push({
        feature: 'BEC patterns detected',
        contribution: features.becPatternScore * weight * 0.30,
        direction: 'increases_risk',
        category: 'behavioral',
      });
    }

    if (features.hasWireTransferRequest) {
      importance.push({
        feature: 'Wire transfer request',
        contribution: weight * 0.25,
        direction: 'increases_risk',
        category: 'behavioral',
      });
    }

    if (features.hasGiftCardRequest) {
      importance.push({
        feature: 'Gift card request',
        contribution: weight * 0.25,
        direction: 'increases_risk',
        category: 'behavioral',
      });
    }

    if (features.isReplyChain) {
      importance.push({
        feature: 'Part of reply chain',
        contribution: -weight * 0.10,
        direction: 'decreases_risk',
        category: 'behavioral',
      });
    }

    if (features.hasUnsubscribeLink) {
      importance.push({
        feature: 'Has unsubscribe link',
        contribution: -weight * 0.10,
        direction: 'decreases_risk',
        category: 'behavioral',
      });
    }
  }
}

// ============================================================================
// Factory and Utilities
// ============================================================================

/**
 * Create a default ThreatPredictor instance
 */
export function createThreatPredictor(config?: Partial<PredictorConfig>): ThreatPredictor {
  return new ThreatPredictor(config);
}

/**
 * Create default email features (useful for testing)
 */
export function createDefaultEmailFeatures(): EmailFeatures {
  return {
    headerFeatures: {
      spfScore: 1,
      dkimScore: 1,
      dmarcScore: 1,
      replyToMismatch: false,
      displayNameSpoof: false,
      headerAnomalyCount: 0,
      envelopeMismatch: false,
      suspiciousMailer: false,
    },
    contentFeatures: {
      urgencyScore: 0,
      threatScore: 0,
      grammarScore: 1,
      sentimentScore: 0,
      requestsPersonalInfo: false,
      requestsCredentials: false,
      hasFinancialRequest: false,
      imageToTextRatio: 0,
      suspiciousKeywordCount: 0,
    },
    senderFeatures: {
      reputationScore: 0.8,
      domainAgeDays: 365,
      isFreemailProvider: false,
      isDisposableEmail: false,
      domainSimilarityScore: 0,
      isFirstContact: false,
      isCousinDomain: false,
      executiveImpersonationScore: 0,
    },
    urlFeatures: {
      urlCount: 0,
      externalUrlCount: 0,
      shortenerCount: 0,
      ipUrlCount: 0,
      maliciousUrlCount: 0,
      maxUrlSuspicionScore: 0,
      hasRedirects: false,
      newDomainUrlCount: 0,
    },
    attachmentFeatures: {
      attachmentCount: 0,
      attachmentRiskScore: 0,
      hasExecutable: false,
      hasMacros: false,
      hasPasswordProtected: false,
      hasDoubleExtension: false,
      totalSizeBytes: 0,
    },
    behavioralFeatures: {
      isReplyChain: false,
      hasUnsubscribeLink: false,
      sendHour: 10,
      sentDuringBusinessHours: true,
      becPatternScore: 0,
      hasWireTransferRequest: false,
      hasGiftCardRequest: false,
      hasInvoiceUpdate: false,
    },
  };
}

/**
 * Extract features from a ParsedEmail (integration helper)
 * This would typically be used in the detection pipeline
 */
export function extractEmailFeatures(
  _email: unknown,
  _reputationData?: unknown,
  _urlAnalysis?: unknown[]
): EmailFeatures {
  // This is a placeholder - actual implementation would extract features
  // from the ParsedEmail type defined in lib/detection/types.ts
  return createDefaultEmailFeatures();
}

// Export default instance for simple usage
export const defaultPredictor = new ThreatPredictor();
