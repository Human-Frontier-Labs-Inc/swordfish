/**
 * Gmail / Google Workspace Integration
 * Handles OAuth flow and Gmail API interactions
 */

import type { GmailConfig, OAuthTokens } from './types';

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GMAIL_API_URL = 'https://gmail.googleapis.com/gmail/v1';

// Required scopes for email access
const SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/userinfo.email',
].join(' ');

/**
 * Generate OAuth authorization URL for Gmail
 */
export function getGmailAuthUrl(params: {
  clientId: string;
  redirectUri: string;
  state: string;
}): string {
  const { clientId, redirectUri, state } = params;

  const authParams = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: SCOPES,
    state: state,
    access_type: 'offline',
    prompt: 'consent',
  });

  return `${GOOGLE_AUTH_URL}?${authParams}`;
}

/**
 * Exchange authorization code for tokens
 */
export async function exchangeGmailCode(params: {
  code: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}): Promise<OAuthTokens> {
  const { code, clientId, clientSecret, redirectUri } = params;

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code: code,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
  });

  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    const error = await response.json();
    console.error('Google OAuth error response:', JSON.stringify(error));
    console.error('Request params - clientId:', clientId?.substring(0, 20) + '...', 'redirectUri:', redirectUri);
    throw new Error(`OAuth error: ${error.error_description || error.error}`);
  }

  const data = await response.json();

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
    throw new Error(`Token refresh error: ${error.error_description || error.error}`);
  }

  const data = await response.json();

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
 */
export async function modifyGmailMessage(params: {
  accessToken: string;
  messageId: string;
  addLabelIds?: string[];
  removeLabelIds?: string[];
}): Promise<void> {
  const { accessToken, messageId, addLabelIds = [], removeLabelIds = [] } = params;

  const response = await fetch(
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
 */
export async function trashGmailMessage(params: {
  accessToken: string;
  messageId: string;
}): Promise<void> {
  const { accessToken, messageId } = params;

  const response = await fetch(
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
 * Create a label (for quarantine)
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

  const response = await fetch(`${GMAIL_API_URL}/users/me/labels`, {
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
 */
export async function getOrCreateQuarantineLabel(accessToken: string): Promise<string> {
  // List existing labels
  const listResponse = await fetch(`${GMAIL_API_URL}/users/me/labels`, {
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
