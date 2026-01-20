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

// Attachment Analysis (Phase 5.4)
export {
  AttachmentAnalyzer,
  attachmentAnalyzer,
  analyzeAttachment,
  detectFileType,
  extractMacros,
  extractUrls,
  inspectArchive,
  calculateRiskScore,
  type AttachmentAnalysis,
  type FileTypeResult,
  type MacroInfo,
  type ArchiveContents,
  type ArchiveEntry,
} from './attachment-analyzer';

// File Signatures
export {
  FILE_SIGNATURES,
  DANGEROUS_EXTENSIONS,
  SCRIPT_EXTENSIONS,
  EXECUTABLE_EXTENSIONS,
  ARCHIVE_EXTENSIONS,
  OFFICE_EXTENSIONS,
  VBA_INDICATORS,
  SUSPICIOUS_VBA_KEYWORDS,
  RTL_OVERRIDE,
  DANGEROUS_UNICODE_CHARS,
  matchMagicBytes,
  detectFileTypeFromBuffer,
  isDangerousExtension,
  isScriptExtension,
  isExecutableExtension,
  isArchiveExtension,
  isOfficeExtension,
  getExtension,
  getAllExtensions,
  hasDoubleExtension,
  hasRtlOverride,
  getRealExtension,
  type FileSignature,
} from './file-signatures';
