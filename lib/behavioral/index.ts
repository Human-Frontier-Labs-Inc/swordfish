/**
 * Behavioral Analysis Module
 * Phase 4: Contact Graph and Communication Baselines
 *
 * Exports for behavioral analysis features:
 * - Contact graph tracking
 * - Communication baselines
 * - Deviation detection
 * - Statistical utilities
 */

// Contact Graph
export {
  ContactGraph,
  type EmailInput,
  type EmailAddress,
  type ContactPair,
  type ContactRelationship,
  type ContactType,
  type CommunicationStats,
  type Relationship,
  type Contact,
} from './contact-graph';

// Graph Storage
export {
  GraphStorage,
  type StoredContact,
  type StoredRelationship,
  type ContactStats,
} from './graph-storage';

// Baselines
export {
  BaselineService,
  type UserBaseline,
  type VolumeStats,
  type SendTimeDistribution,
  type SubjectPatterns,
  type BaselineDeviation,
  type Deviation,
  type DeviationCheck,
  type OrgDefaults,
  type BaselineConfig,
  type ConfidenceFactors,
} from './baselines';

// Statistics
export {
  calculateMean,
  calculateStdDev,
  calculateSampleStdDev,
  exponentialMovingAverage,
  calculatePercentile,
  normalizeDistribution,
  calculateZScore,
  isOutlier,
  calculateCV,
  calculateMedian,
  calculateIQR,
  detectOutliersIQR,
  calculateTrend,
  rollingAverage,
  cosineSimilarity,
  jsDivergence,
  entropy,
  histogram,
} from './statistics';

// Anomaly Detection
export {
  AnomalyDetector,
  type AnomalyConfig,
  type AnomalyResult,
  type AnomalyFeedback,
  type TenantBaseline,
  type EmailBehaviorData,
  type VolumeAnomaly,
  type TimeAnomaly,
  type RecipientAnomaly,
  type ContentAnomaly,
  type AlertMetadata,
} from './anomaly-engine';

// Anomaly Explanation
export {
  generateAnomalyExplanation,
  formatAnomalyForAudit,
  type AnomalyExplanation,
  type AnomalyDetail,
} from './explainer';

// First Contact Detection
export {
  FirstContactDetector,
  type FirstContactConfig,
  type FirstContactInput,
  type FirstContactResult,
  type VIPEntry,
  type VendorEntry,
  type WhitelistEntry,
  type ContactRecord,
} from './first-contact';

// Lookalike Detection
export {
  LookalikeDetector,
  type LookalikeResult,
  type LookalikeMatch,
  type KnownContact,
} from './lookalike-detector';
