/**
 * Actions Module
 * Central exports for all action-related functionality
 */

// Banner injection
export {
  injectBanner,
  removeBanners,
  determineBannerType,
  buildDetailsText,
  type InjectionResult,
} from './banner/inject';

export {
  generateBannerHTML,
  generateBannerText,
  getDefaultBannerConfig,
  type BannerType,
  type BannerConfig,
} from './banner/templates';

// Link rewriting
export {
  rewriteUrl,
  rewriteLinksInHTML,
  rewriteLinksInText,
  shouldRewriteUrl,
  generateClickId,
  createClickMapping,
  type RewriteResult,
  type LinkRewriteConfig,
  type ClickMapping,
} from './links/rewrite';

// Click-time protection
export {
  checkUrlAtClickTime,
  clearExpiredCache,
  getCacheStats,
  type ClickTimeResult,
  type ClickTimeSignal,
  type ClickTimeConfig,
} from './links/click-time-check';

// Audit logging
export {
  logAction,
  logClickAction,
  logBannerAction,
  logLinkRewriteAction,
  logQuarantineAction,
  logVIPAction,
  logPolicyAction,
  logThreatReportAction,
  logAttachmentAction,
  queryActionLogs,
  getActionStats,
  getClickMapping,
  saveClickMapping,
  updateClickStats,
  type ActionType,
  type ActionLogEntry,
  type ActionLogQuery,
  type ActionLogResult,
} from './logger';
