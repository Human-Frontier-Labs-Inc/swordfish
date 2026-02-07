/**
 * Gmail Integration Module
 *
 * Exports all Gmail integration components
 */

// Re-export from the parent gmail.ts for OAuth and API functions
export {
  getGmailAuthUrl,
  exchangeGmailCode,
  refreshGmailToken,
  getGmailUserProfile,
  getGmailMessage,
  getGmailHistory,
  getGmailAccessToken,
  getOrCreateQuarantineLabel,
  findGmailMessageByMessageId,
  listGmailMessages,
  modifyGmailMessage,
  trashGmailMessage,
  untrashGmailMessage,
  createGmailLabel,
  watchGmailInbox,
  stopGmailWatch,
} from '../gmail';

export * from './sync-worker';
