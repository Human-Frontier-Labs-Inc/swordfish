/**
 * Microsoft 365 / Azure AD Integration
 * Handles OAuth flow and Graph API interactions
 */

import type { O365Config, OAuthTokens } from './types';

const MICROSOFT_AUTH_URL = 'https://login.microsoftonline.com';
const GRAPH_API_URL = 'https://graph.microsoft.com/v1.0';

// Required scopes for email access
const SCOPES = [
  'https://graph.microsoft.com/Mail.Read',
  'https://graph.microsoft.com/Mail.ReadWrite',
  'https://graph.microsoft.com/User.Read',
  'offline_access',
].join(' ');

/**
 * Generate OAuth authorization URL for Microsoft 365
 */
export function getO365AuthUrl(params: {
  clientId: string;
  redirectUri: string;
  state: string;
  tenantId?: string;
}): string {
  const { clientId, redirectUri, state, tenantId = 'common' } = params;

  const authParams = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    response_mode: 'query',
    scope: SCOPES,
    state: state,
    prompt: 'consent',
  });

  return `${MICROSOFT_AUTH_URL}/${tenantId}/oauth2/v2.0/authorize?${authParams}`;
}

/**
 * Exchange authorization code for tokens
 */
export async function exchangeO365Code(params: {
  code: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  tenantId?: string;
}): Promise<OAuthTokens> {
  const { code, clientId, clientSecret, redirectUri, tenantId = 'common' } = params;

  const tokenUrl = `${MICROSOFT_AUTH_URL}/${tenantId}/oauth2/v2.0/token`;

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code: code,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
    scope: SCOPES,
  });

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!response.ok) {
    const error = await response.json();
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
export async function refreshO365Token(params: {
  refreshToken: string;
  clientId: string;
  clientSecret: string;
  tenantId?: string;
}): Promise<OAuthTokens> {
  const { refreshToken, clientId, clientSecret, tenantId = 'common' } = params;

  const tokenUrl = `${MICROSOFT_AUTH_URL}/${tenantId}/oauth2/v2.0/token`;

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    refresh_token: refreshToken,
    grant_type: 'refresh_token',
    scope: SCOPES,
  });

  const response = await fetch(tokenUrl, {
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
    refreshToken: data.refresh_token || refreshToken,
    expiresAt: new Date(Date.now() + data.expires_in * 1000),
    scope: data.scope,
  };
}

/**
 * Get user profile from Graph API
 */
export async function getO365UserProfile(accessToken: string): Promise<{
  id: string;
  email: string;
  displayName: string;
  tenantId: string;
}> {
  const response = await fetch(`${GRAPH_API_URL}/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    throw new Error('Failed to get user profile');
  }

  const data = await response.json();

  // Get tenant ID from organization endpoint
  const orgResponse = await fetch(`${GRAPH_API_URL}/organization`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  let tenantId = '';
  if (orgResponse.ok) {
    const orgData = await orgResponse.json();
    tenantId = orgData.value?.[0]?.id || '';
  }

  return {
    id: data.id,
    email: data.mail || data.userPrincipalName,
    displayName: data.displayName,
    tenantId,
  };
}

/**
 * List emails from mailbox
 */
export async function listO365Emails(params: {
  accessToken: string;
  folderId?: string;
  top?: number;
  skip?: number;
  filter?: string;
}): Promise<{
  emails: Array<Record<string, unknown>>;
  nextLink: string | null;
}> {
  const { accessToken, folderId = 'inbox', top = 50, skip = 0, filter } = params;

  const queryParams = new URLSearchParams({
    $top: top.toString(),
    $skip: skip.toString(),
    $select: 'id,subject,from,toRecipients,receivedDateTime,body,internetMessageHeaders,hasAttachments',
  });

  if (filter) {
    queryParams.set('$filter', filter);
  }

  const url = `${GRAPH_API_URL}/me/mailFolders/${folderId}/messages?${queryParams}`;

  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    throw new Error('Failed to list emails');
  }

  const data = await response.json();

  return {
    emails: data.value,
    nextLink: data['@odata.nextLink'] || null,
  };
}

/**
 * Get single email with full details
 */
export async function getO365Email(params: {
  accessToken: string;
  messageId: string;
}): Promise<Record<string, unknown>> {
  const { accessToken, messageId } = params;

  const url = `${GRAPH_API_URL}/me/messages/${messageId}?$select=id,internetMessageId,subject,from,toRecipients,ccRecipients,receivedDateTime,body,internetMessageHeaders,hasAttachments,attachments`;

  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    throw new Error('Failed to get email');
  }

  return response.json();
}

/**
 * Move email to folder (for quarantine)
 */
export async function moveO365Email(params: {
  accessToken: string;
  messageId: string;
  destinationFolderId: string;
}): Promise<void> {
  const { accessToken, messageId, destinationFolderId } = params;

  const response = await fetch(`${GRAPH_API_URL}/me/messages/${messageId}/move`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ destinationId: destinationFolderId }),
  });

  if (!response.ok) {
    throw new Error('Failed to move email');
  }
}

/**
 * Create webhook subscription for real-time notifications
 */
export async function createO365Subscription(params: {
  accessToken: string;
  notificationUrl: string;
  clientState: string;
  expirationMinutes?: number;
}): Promise<{ subscriptionId: string; expiresAt: Date }> {
  const { accessToken, notificationUrl, clientState, expirationMinutes = 4230 } = params;

  const expirationDateTime = new Date(Date.now() + expirationMinutes * 60 * 1000);

  const response = await fetch(`${GRAPH_API_URL}/subscriptions`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      changeType: 'created',
      notificationUrl,
      resource: '/me/mailFolders/inbox/messages',
      expirationDateTime: expirationDateTime.toISOString(),
      clientState,
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(`Failed to create subscription: ${error.error?.message || 'Unknown error'}`);
  }

  const data = await response.json();

  return {
    subscriptionId: data.id,
    expiresAt: new Date(data.expirationDateTime),
  };
}

/**
 * Renew webhook subscription
 */
export async function renewO365Subscription(params: {
  accessToken: string;
  subscriptionId: string;
  expirationMinutes?: number;
}): Promise<Date> {
  const { accessToken, subscriptionId, expirationMinutes = 4230 } = params;

  const expirationDateTime = new Date(Date.now() + expirationMinutes * 60 * 1000);

  const response = await fetch(`${GRAPH_API_URL}/subscriptions/${subscriptionId}`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      expirationDateTime: expirationDateTime.toISOString(),
    }),
  });

  if (!response.ok) {
    throw new Error('Failed to renew subscription');
  }

  return expirationDateTime;
}

/**
 * Delete webhook subscription
 */
export async function deleteO365Subscription(params: {
  accessToken: string;
  subscriptionId: string;
}): Promise<void> {
  const { accessToken, subscriptionId } = params;

  const response = await fetch(`${GRAPH_API_URL}/subscriptions/${subscriptionId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok && response.status !== 404) {
    throw new Error('Failed to delete subscription');
  }
}

/**
 * Create or get quarantine folder
 */
export async function getOrCreateQuarantineFolder(accessToken: string): Promise<string> {
  // First try to find existing folder
  const listResponse = await fetch(
    `${GRAPH_API_URL}/me/mailFolders?$filter=displayName eq 'Swordfish Quarantine'`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );

  if (listResponse.ok) {
    const data = await listResponse.json();
    if (data.value?.length > 0) {
      return data.value[0].id;
    }
  }

  // Create new folder
  const createResponse = await fetch(`${GRAPH_API_URL}/me/mailFolders`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      displayName: 'Swordfish Quarantine',
      isHidden: false,
    }),
  });

  if (!createResponse.ok) {
    throw new Error('Failed to create quarantine folder');
  }

  const folder = await createResponse.json();
  return folder.id;
}
