/**
 * BEC Detection Module - Public API
 * Exports all BEC detection functionality
 */

// Main detector
export {
  detectBEC,
  quickBECCheck,
  getTenantBECRiskFactors,
  type BECDetectionResult,
  type BECSignal,
  type FinancialRisk,
  type EmailData,
} from './detector';

// Pattern detection
export {
  checkBECPatterns,
  extractAmounts,
  assessAmountRisk,
  detectCompoundAttack,
  BEC_PATTERNS,
  type BECPattern,
  type BECCategory,
  type PatternMatch,
  type PatternIndicator,
} from './patterns';

// Impersonation detection
export {
  detectImpersonation,
  calculateImpersonationRisk,
  type ImpersonationResult,
  type ImpersonationType,
  type ImpersonationSignal,
} from './impersonation';

// VIP list management
export {
  getVIPList,
  addVIP,
  updateVIP,
  removeVIP,
  findVIPByEmail,
  findVIPByDisplayName,
  checkVIPImpersonation,
  detectPotentialVIP,
  bulkImportVIPs,
  getVIPStats,
  type VIPEntry,
  type VIPRole,
} from './vip-list';
