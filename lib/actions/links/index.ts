/**
 * Links Module Exports
 */

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
} from './rewrite';

export {
  checkUrlAtClickTime,
  clearExpiredCache,
  getCacheStats,
  type ClickTimeResult,
  type ClickTimeSignal,
  type ClickTimeConfig,
} from './click-time-check';
