/**
 * Protection Module
 *
 * Provides URL rewriting, click-time protection, and other security measures
 * for email content passing through Swordfish.
 */

// URL Rewriter exports
export {
  UrlRewriter,
  getUrlRewriter,
  createUrlRewriter,
  quickShouldRewrite,
  extractUrls,
  cleanupExpiredUrls,
  KNOWN_SAFE_DOMAINS,
  URL_SHORTENERS,
  NON_REWRITABLE_PROTOCOLS,
  DEFAULT_REWRITER_CONFIG,
  type RewriterConfig,
  type RewrittenEmail,
  type RewriteStats,
  type UrlMapping,
  type RewriteReason,
  type RewrittenUrlRecord,
  type ClickVerdict,
  type EmailContent,
  type RewriteResult,
  type EmailRewriteResult,
  type ExtractedUrl,
  type RewriteStatistics,
  type UrlLookupResult as RewriterUrlLookupResult,
} from './url-rewriter';

// Rewritten URLs Database exports
export {
  generateUrlId,
  generateShortUrlId,
  isValidUrlId,
  storeRewrittenUrl,
  batchStoreRewrittenUrls,
  lookupOriginalUrl,
  recordUrlClick,
  getRewrittenUrl,
  getRewrittenUrlsForEmail,
  cleanupExpiredUrls as cleanupExpiredRewrittenUrls,
  extendUrlExpiration,
  getExpiringUrls,
  getRewriteStats,
  getExcludedDomains,
  getExcludedPatterns,
  updateExclusions,
  searchRewrittenUrls,
  type RewrittenUrlRecord as RewrittenUrlDbRecord,
  type UrlLookupResult,
  type RewriteStats as RewriteStatsDb,
  type ExclusionUpdate,
  type BatchStoreResult,
} from './rewritten-urls';

// Click Scanner exports
export {
  ClickScanner,
  getClickScanner,
  scanUrlAtClickTime,
  generateClickWarningPage,
  type ClickScanResult,
  type UrlThreat,
  type ReputationResult,
  type ClickFilters,
  type ClickAnalytics,
  type ClickScannerConfig,
  // New interface types for enhanced click scanning
  type ClickEvent,
  type ClickScannerScanResult,
  type ThreatIndicator,
  type ClickDecision,
  type RedirectResult,
  type ThreatIntelResult,
  type TopUrl,
  type BlockedClick,
} from './click-scanner';
