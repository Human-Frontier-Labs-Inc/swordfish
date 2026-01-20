/**
 * Email Classifier Module
 *
 * Classifies emails by type (marketing, transactional, personal, etc.)
 * BEFORE threat detection runs, enabling context-aware security rules.
 */

export {
  classifyEmailType,
  explainClassification,
  type EmailType,
  type EmailClassification,
} from './email-type';

export {
  lookupSender,
  isLegitimateReplyTo,
  getAllKnownSenders,
  getSendersByCategory,
  SenderCategory,
  type SenderInfo,
} from './sender-registry';

export {
  detectMarketingSignals,
  shouldReduceThreatScore,
  type MarketingSignals,
} from './marketing-signals';
