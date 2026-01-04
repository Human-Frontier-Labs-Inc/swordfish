/**
 * Integrations - Main exports
 */

// Types
export type {
  IntegrationType,
  IntegrationStatus,
  Integration,
  IntegrationConfig,
  O365Config,
  GmailConfig,
  SMTPConfig,
  OAuthTokens,
  SyncJob,
} from './types';

// Microsoft 365
export {
  getO365AuthUrl,
  exchangeO365Code,
  refreshO365Token,
  getO365UserProfile,
  listO365Emails,
  getO365Email,
  moveO365Email,
  createO365Subscription,
  renewO365Subscription,
  deleteO365Subscription,
  getOrCreateQuarantineFolder,
} from './o365';

// Gmail
export {
  getGmailAuthUrl,
  exchangeGmailCode,
  refreshGmailToken,
  getGmailUserProfile,
  listGmailMessages,
  getGmailMessage,
  modifyGmailMessage,
  trashGmailMessage,
  createGmailLabel,
  getOrCreateQuarantineLabel,
  watchGmailInbox,
  stopGmailWatch,
  getGmailHistory,
} from './gmail';
