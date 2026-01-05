/**
 * Banner Module Exports
 */

export {
  injectBanner,
  removeBanners,
  determineBannerType,
  buildDetailsText,
  type InjectionResult,
} from './inject';

export {
  generateBannerHTML,
  generateBannerText,
  getDefaultBannerConfig,
  type BannerType,
  type BannerConfig,
} from './templates';
