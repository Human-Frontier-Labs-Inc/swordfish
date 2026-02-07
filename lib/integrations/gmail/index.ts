/**
 * Gmail Integration Module
 *
 * Exports all Gmail integration components
 */

// Re-export from the parent gmail.ts for OAuth functions
export {
  getGmailAuthUrl,
  exchangeGmailCode,
  refreshGmailToken,
  getGmailUserProfile,
  getGmailMessage,
  getGmailHistory,
  getGmailAccessToken,
  getOrCreateQuarantineLabel,
  moveToQuarantine,
  deleteGmailMessage,
  findGmailMessageByMessageId,
} from '../gmail';

export * from './sync-worker';
