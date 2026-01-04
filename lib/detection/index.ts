/**
 * Detection Engine - Main exports
 */

// Types
export type {
  ParsedEmail,
  EmailAddress,
  Attachment,
  AuthenticationResults,
  AuthResult,
  Signal,
  SignalType,
  LayerResult,
  EmailVerdict,
  DetectionConfig,
  UrlAnalysis,
  FileAnalysis,
} from './types';

export { DEFAULT_DETECTION_CONFIG } from './types';

// Parsers
export {
  parseEmail,
  parseGraphEmail,
  parseGmailEmail,
  parseAuthenticationResults,
} from './parser';

// Detection layers
export { runDeterministicAnalysis } from './deterministic';
export { runLLMAnalysis, shouldInvokeLLM } from './llm';

// Main pipeline
export { analyzeEmail, quickCheck } from './pipeline';

// Storage
export {
  storeVerdict,
  getVerdictByMessageId,
  getRecentVerdicts,
  getVerdictStats,
  getTopThreats,
  quarantineEmail,
  releaseFromQuarantine,
  getQuarantinedEmails,
} from './storage';
