/**
 * OAuth Module
 *
 * Centralized OAuth management for SwordPhish.
 * Replaces Nango with direct OAuth token management.
 */

export {
  createOAuthState,
  validateOAuthState,
  verifyEmailMatch,
  cleanupExpiredStates,
  generatePKCE,
  type OAuthState,
  type OAuthStateParams,
  type StateValidationResult,
} from './state-manager';

export {
  storeTokens,
  getAccessToken,
  getConnectedEmail,
  revokeTokens,
  isEmailAlreadyConnected,
  findIntegrationByEmail,
  type StoredTokens,
  type StoreTokensParams,
} from './token-manager';
