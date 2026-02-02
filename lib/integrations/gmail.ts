/**
 * Gmail / Google Workspace Integration
 * Handles Gmail API interactions
 *
 * Token management is handled by the OAuth token manager.
 * Use getGmailAccessToken() to get a fresh token (auto-refreshes if needed).
 */

import type { OAuthTokens } from './types';
import { getAccessToken as getTokenFromManager } from '@/lib/oauth/token-manager';

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GMAIL_API_URL = 'https://gmail.googleapis.com/gmail/v1';

/**
 * Retry configuration for Gmail API calls
 */
interface RetryConfig {
  maxRetries?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
}

const DEFAULT_RETRY_CONFIG: Required<RetryConfig> = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
};

/**
 * Sleep for a given number of milliseconds
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Fetch wrapper with retry logic for rate limiting (429) and server errors (5xx)
 */
async function gmailFetchWithRetry(
  url: string,
  options: RequestInit,
  config: RetryConfig = {}
): Promise<Response> {
  const { maxRetries, baseDelayMs, maxDelayMs } = { ...DEFAULT_RETRY_CONFIG, ...config };
  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(url, options);

      // Success or client error (not retryable)
      if (response.ok || (response.status >= 400 && response.status < 429)) {
        return response;
      }

      // Rate limiting - respect Retry-After header if present
      if (response.status === 429) {
        if (attempt >= maxRetries) {
          return response; // Return the 429 after max retries
        }

        const retryAfter = response.headers.get('Retry-After');
        const delayMs = retryAfter
          ? parseInt(retryAfter, 10) * 1000
          : Math.min(baseDelayMs * Math.pow(2, attempt), maxDelayMs);

        await sleep(delayMs);
        continue;
      }

      // Server errors (5xx) - retry with exponential backoff
      if (response.status >= 500) {
        if (attempt >= maxRetries) {
          return response;
        }

        const delayMs = Math.min(baseDelayMs * Math.pow(2, attempt), maxDelayMs);
        await sleep(delayMs);
        continue;
      }

      // Other errors (401, 403, etc.) - don't retry
      return response;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      // Network errors - retry with backoff
      if (attempt >= maxRetries) {
        throw lastError;
      }

      const delayMs = Math.min(baseDelayMs * Math.pow(2, attempt), maxDelayMs);
      await sleep(delayMs);
    }
  }

  throw lastError || new Error('Max retries exceeded');
}

/**
 * Get a fresh Gmail access token
 * Automatically refreshes if expired or about to expire
 *
 * @param tenantId - The tenant ID to get the token for
 */
export async function getGmailAccessToken(tenantId: string): Promise<string> {
  return getTokenFromManager(tenantId, 'gmail');
}

// Required scopes for email access
const SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/userinfo.email',
].join(' ');

/**
 * Generate OAuth authorization URL for Gmail
 *
 * @param params.clientId - Google OAuth client ID
 * @param params.redirectUri - Callback URL
 * @param params.state - CSRF protection state token
 * @param params.codeChallenge - PKCE code challenge (optional but recommended)
 * @param params.loginHint - Pre-fill email address (optional)
 */
export function getGmailAuthUrl(params: {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge?: string;
  loginHint?: string;
}): string {
  const { clientId, redirectUri, state, codeChallenge, loginHint } = params;

  const authParams = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: SCOPES,
    state: state,
    access_type: 'offline',
    prompt: 'consent',
  });

  // Add PKCE if provided
  if (codeChallenge) {
    authParams.set('code_challenge', codeChallenge);
    authParams.set('code_challenge_method', 'S256');
  }

  // Add login hint to pre-fill email
  if (loginHint) {
    authParams.set('login_hint', loginHint);
  }

  return `${GOOGLE_AUTH_URL}?${authParams}`;
}

/**
 * Exchange authorization code for tokens
 *
 * @param params.code - Authorization code from OAuth callback
 * @param params.clientId - Google OAuth client ID
 * @param params.clientSecret - Google OAuth client secret
 * @param params.redirectUri - Same redirect URI used in authorization request
 * @param params.codeVerifier - PKCE code verifier (if PKCE was used)
 */
export async function exchangeGmailCode(params: {
  code: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  codeVerifier?: string;
}): Promise<OAuthTokens> {
  const { code, clientId, clientSecret, redirectUri, codeVerifier } = params;

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code: code,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
  });

  // Add PKCE code verifier if provided
  if (codeVerifier) {
    body.set('code_verifier', codeVerifier);
  }

  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    const error = await response.json();
    console.error('[Gmail OAuth] Token exchange FAILED');
    console.error('[Gmail OAuth]   Status:', response.status, response.statusText);
    console.error('[Gmail OAuth]   Error:', JSON.stringify(error));
    console.error('[Gmail OAuth]   Config used:');
    console.error('[Gmail OAuth]     redirectUri:', redirectUri);
    console.error('[Gmail OAuth]     clientId:', clientId?.substring(0, 30) + '...');
    console.error('[Gmail OAuth]     clientSecret length:', clientSecret?.length || 0);
    console.error('[Gmail OAuth]   Possible causes:');
    if (error.error === 'redirect_uri_mismatch') {
      console.error('[Gmail OAuth]     -> Redirect URI does not match Google Cloud Console config');
      console.error('[Gmail OAuth]     -> Check: https://console.cloud.google.com/apis/credentials');
    } else if (error.error === 'invalid_grant') {
      console.error('[Gmail OAuth]     -> Authorization code already used or expired');
    } else if (error.error === 'unauthorized_client') {
      console.error('[Gmail OAuth]     -> Client ID/Secret may be invalid or not authorized for this redirect URI');
    }
    throw new Error(`OAuth error: ${error.error_description || error.error}`);
  }

  const data = await response.json();
  console.log('[Gmail OAuth] Token exchange SUCCESS');
  console.log('[Gmail OAuth]   Scopes granted:', data.scope);
  console.log('[Gmail OAuth]   Token expires in:', data.expires_in, 'seconds');

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresAt: new Date(Date.now() + data.expires_in * 1000),
    scope: data.scope,
  };
}

/**
 * Refresh access token
 */
export async function refreshGmailToken(params: {
  refreshToken: string;
  clientId: string;
  clientSecret: string;
}): Promise<OAuthTokens> {
  const { refreshToken, clientId, clientSecret } = params;

  console.log('[Gmail OAuth] Attempting token refresh');
  console.log('[Gmail OAuth]   clientId:', clientId?.substring(0, 30) + '...');
  console.log('[Gmail OAuth]   refreshToken length:', refreshToken?.length || 0);

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    refresh_token: refreshToken,
    grant_type: 'refresh_token',
  });

  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    const error = await response.json();
    console.error('[Gmail OAuth] Token refresh FAILED');
    console.error('[Gmail OAuth]   Status:', response.status, response.statusText);
    console.error('[Gmail OAuth]   Error:', JSON.stringify(error));
    console.error('[Gmail OAuth]   Possible causes:');
    if (error.error === 'invalid_grant') {
      console.error('[Gmail OAuth]     -> Refresh token revoked or expired');
      console.error('[Gmail OAuth]     -> User needs to re-authorize the application');
    } else if (error.error === 'unauthorized_client') {
      console.error('[Gmail OAuth]     -> Client credentials may be invalid');
    }
    throw new Error(`Token refresh error: ${error.error_description || error.error}`);
  }

  const data = await response.json();
  console.log('[Gmail OAuth] Token refresh SUCCESS');
  console.log('[Gmail OAuth]   New token expires in:', data.expires_in, 'seconds');

  return {
    accessToken: data.access_token,
    refreshToken: refreshToken, // Google doesn't always return new refresh token
    expiresAt: new Date(Date.now() + data.expires_in * 1000),
    scope: data.scope,
  };
}

/**
 * Get user profile
 */
export async function getGmailUserProfile(accessToken: string): Promise<{
  email: string;
  messagesTotal: number;
  historyId: string;
}> {
  const response = await fetch(`${GMAIL_API_URL}/users/me/profile`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    throw new Error('Failed to get Gmail profile');
  }

  const data = await response.json();

  return {
    email: data.emailAddress,
    messagesTotal: data.messagesTotal,
    historyId: data.historyId,
  };
}

/**
 * List messages
 */
export async function listGmailMessages(params: {
  accessToken: string;
  query?: string;
  maxResults?: number;
  pageToken?: string;
  labelIds?: string[];
}): Promise<{
  messages: Array<{ id: string; threadId: string }>;
  nextPageToken: string | null;
  resultSizeEstimate: number;
}> {
  const { accessToken, query, maxResults = 50, pageToken, labelIds } = params;

  const queryParams = new URLSearchParams({
    maxResults: maxResults.toString(),
  });

  if (query) queryParams.set('q', query);
  if (pageToken) queryParams.set('pageToken', pageToken);
  if (labelIds?.length) queryParams.set('labelIds', labelIds.join(','));

  const response = await fetch(
    `${GMAIL_API_URL}/users/me/messages?${queryParams}`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );

  if (!response.ok) {
    throw new Error('Failed to list messages');
  }

  const data = await response.json();

  return {
    messages: data.messages || [],
    nextPageToken: data.nextPageToken || null,
    resultSizeEstimate: data.resultSizeEstimate || 0,
  };
}

/**
 * Get full message details
 */
export async function getGmailMessage(params: {
  accessToken: string;
  messageId: string;
  format?: 'full' | 'metadata' | 'minimal' | 'raw';
}): Promise<Record<string, unknown>> {
  const { accessToken, messageId, format = 'full' } = params;

  const response = await fetch(
    `${GMAIL_API_URL}/users/me/messages/${messageId}?format=${format}`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );

  if (!response.ok) {
    throw new Error('Failed to get message');
  }

  return response.json();
}

/**
 * Modify message labels (for quarantine)
 * Includes retry logic for rate limiting and transient errors
 */
export async function modifyGmailMessage(params: {
  accessToken: string;
  messageId: string;
  addLabelIds?: string[];
  removeLabelIds?: string[];
}): Promise<void> {
  const { accessToken, messageId, addLabelIds = [], removeLabelIds = [] } = params;

  const response = await gmailFetchWithRetry(
    `${GMAIL_API_URL}/users/me/messages/${messageId}/modify`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ addLabelIds, removeLabelIds }),
    }
  );

  if (!response.ok) {
    throw new Error('Failed to modify message');
  }
}

/**
 * Trash a message
 * Includes retry logic for rate limiting and transient errors
 */
export async function trashGmailMessage(params: {
  accessToken: string;
  messageId: string;
}): Promise<void> {
  const { accessToken, messageId } = params;

  const response = await gmailFetchWithRetry(
    `${GMAIL_API_URL}/users/me/messages/${messageId}/trash`,
    {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}` },
    }
  );

  if (!response.ok) {
    throw new Error('Failed to trash message');
  }
}

/**
 * Untrash a message (restore from Trash)
 * Includes retry logic for rate limiting and transient errors
 */
export async function untrashGmailMessage(params: {
  accessToken: string;
  messageId: string;
}): Promise<void> {
  const { accessToken, messageId } = params;

  const response = await gmailFetchWithRetry(
    `${GMAIL_API_URL}/users/me/messages/${messageId}/untrash`,
    {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}` },
    }
  );

  if (!response.ok) {
    throw new Error('Failed to untrash message');
  }
}

/**
 * Search for a Gmail message by RFC 2822 Message-ID header
 * Useful when we only have the Message-ID but need the Gmail internal ID
 */
export async function findGmailMessageByMessageId(params: {
  accessToken: string;
  rfc822MessageId: string;
}): Promise<string | null> {
  const { accessToken, rfc822MessageId } = params;

  // Gmail search query for RFC 2822 Message-ID
  const query = `rfc822msgid:${rfc822MessageId}`;

  const response = await gmailFetchWithRetry(
    `${GMAIL_API_URL}/users/me/messages?q=${encodeURIComponent(query)}&maxResults=1`,
    {
      method: 'GET',
      headers: { Authorization: `Bearer ${accessToken}` },
    }
  );

  if (!response.ok) {
    console.log(`[gmail] Search failed for Message-ID: ${rfc822MessageId}`);
    return null;
  }

  const data = (await response.json()) as { messages?: Array<{ id: string }> };

  if (data.messages && data.messages.length > 0) {
    return data.messages[0].id;
  }

  return null;
}

/**
 * Create a label (for quarantine)
 * Includes retry logic for rate limiting and transient errors
 */
export async function createGmailLabel(params: {
  accessToken: string;
  name: string;
  labelListVisibility?: 'labelShow' | 'labelShowIfUnread' | 'labelHide';
  messageListVisibility?: 'show' | 'hide';
}): Promise<{ id: string; name: string }> {
  const {
    accessToken,
    name,
    labelListVisibility = 'labelShow',
    messageListVisibility = 'show',
  } = params;

  const response = await gmailFetchWithRetry(`${GMAIL_API_URL}/users/me/labels`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      name,
      labelListVisibility,
      messageListVisibility,
    }),
  });

  if (!response.ok) {
    throw new Error('Failed to create label');
  }

  return response.json();
}

/**
 * Get or create quarantine label
 * Includes retry logic for rate limiting and transient errors
 */
export async function getOrCreateQuarantineLabel(accessToken: string): Promise<string> {
  // List existing labels with retry
  const listResponse = await gmailFetchWithRetry(`${GMAIL_API_URL}/users/me/labels`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (listResponse.ok) {
    const data = await listResponse.json();
    const existing = data.labels?.find((l: { name: string }) => l.name === 'Swordfish/Quarantine');
    if (existing) {
      return existing.id;
    }
  }

  // Create new label
  const label = await createGmailLabel({
    accessToken,
    name: 'Swordfish/Quarantine',
    labelListVisibility: 'labelShow',
    messageListVisibility: 'show',
  });

  return label.id;
}

/**
 * Setup push notifications (watch)
 */
export async function watchGmailInbox(params: {
  accessToken: string;
  topicName: string; // Google Cloud Pub/Sub topic
  labelIds?: string[];
}): Promise<{ historyId: string; expiration: Date }> {
  const { accessToken, topicName, labelIds = ['INBOX'] } = params;

  const response = await fetch(`${GMAIL_API_URL}/users/me/watch`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      topicName,
      labelIds,
    }),
  });

  if (!response.ok) {
    throw new Error('Failed to setup watch');
  }

  const data = await response.json();

  return {
    historyId: data.historyId,
    expiration: new Date(parseInt(data.expiration)),
  };
}

/**
 * Stop push notifications
 */
export async function stopGmailWatch(accessToken: string): Promise<void> {
  const response = await fetch(`${GMAIL_API_URL}/users/me/stop`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok && response.status !== 404) {
    throw new Error('Failed to stop watch');
  }
}

/**
 * Get history (changes since last sync)
 */
export async function getGmailHistory(params: {
  accessToken: string;
  startHistoryId: string;
  historyTypes?: Array<'messageAdded' | 'messageDeleted' | 'labelAdded' | 'labelRemoved'>;
  labelId?: string;
  maxResults?: number;
  pageToken?: string;
}): Promise<{
  history: Array<{
    id: string;
    messages?: Array<{ id: string }>;
    messagesAdded?: Array<{ message: { id: string } }>;
  }>;
  historyId: string;
  nextPageToken: string | null;
}> {
  const { accessToken, startHistoryId, historyTypes, labelId, maxResults = 100, pageToken } = params;

  const queryParams = new URLSearchParams({
    startHistoryId,
    maxResults: maxResults.toString(),
  });

  if (historyTypes?.length) queryParams.set('historyTypes', historyTypes.join(','));
  if (labelId) queryParams.set('labelId', labelId);
  if (pageToken) queryParams.set('pageToken', pageToken);

  const response = await fetch(
    `${GMAIL_API_URL}/users/me/history?${queryParams}`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );

  if (!response.ok) {
    if (response.status === 404) {
      // History too old, need full sync
      return { history: [], historyId: startHistoryId, nextPageToken: null };
    }
    throw new Error('Failed to get history');
  }

  const data = await response.json();

  return {
    history: data.history || [],
    historyId: data.historyId,
    nextPageToken: data.nextPageToken || null,
  };
}
