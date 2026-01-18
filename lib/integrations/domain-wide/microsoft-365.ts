/**
 * Microsoft 365 Application Permissions
 *
 * Uses application permissions (not delegated) to:
 * 1. List all users in the Azure AD tenant via Graph API
 * 2. Access any mailbox without user consent
 * 3. Set up change notifications for mail events
 *
 * Setup Requirements:
 * 1. Create an app registration in Azure Portal
 * 2. Add API permissions: Microsoft Graph > Application permissions > Mail.Read
 * 3. Grant admin consent for the tenant
 * 4. Create a client secret
 */

import type { DirectoryUser, DomainSyncResult, Microsoft365SetupParams } from './types';
import {
  createDomainConfig,
  getDomainConfig,
  getAzureClientSecret,
  updateDomainConfigStatus,
  updateDomainConfigStats,
  upsertDomainUser,
  getMonitoredDomainUsers,
  updateDomainUserSyncState,
  markUsersNotInList,
} from './storage';

const AZURE_TOKEN_URL = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token';
const GRAPH_API_URL = 'https://graph.microsoft.com/v1.0';

// Token cache to avoid repeated token requests
const tokenCache = new Map<string, { token: string; expiresAt: number }>();

/**
 * Setup Microsoft 365 domain-wide monitoring
 */
export async function setupMicrosoft365(params: Microsoft365SetupParams): Promise<{
  configId: string;
  success: boolean;
  error?: string;
}> {
  const { tenantId, azureTenantId, clientId, clientSecret, createdBy } = params;

  try {
    // Create config in database
    const configId = await createDomainConfig({
      tenantId,
      provider: 'microsoft_365',
      createdBy,
      azureTenantId,
      azureClientId: clientId,
      azureClientSecret: clientSecret,
    });

    // Test the connection by getting an access token and listing users
    const accessToken = await getClientCredentialsToken(azureTenantId, clientId, clientSecret);

    // Try to list users to verify permissions
    const response = await fetch(`${GRAPH_API_URL}/users?$top=1&$select=id,mail,displayName`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      const error = await response.json();
      await updateDomainConfigStatus(
        configId,
        'error',
        `API permissions not granted: ${error.error?.message || 'Unknown error'}`
      );
      return {
        configId,
        success: false,
        error: `API permissions not granted. Please ensure admin consent has been granted for User.Read.All and Mail.Read permissions. Error: ${error.error?.message}`,
      };
    }

    // Success - mark as active
    await updateDomainConfigStatus(configId, 'active');

    return { configId, success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return { configId: '', success: false, error: errorMessage };
  }
}

/**
 * Get access token using client credentials flow
 */
async function getClientCredentialsToken(
  azureTenantId: string,
  clientId: string,
  clientSecret: string
): Promise<string> {
  const cacheKey = `${azureTenantId}:${clientId}`;
  const cached = tokenCache.get(cacheKey);

  if (cached && cached.expiresAt > Date.now() + 60000) {
    return cached.token;
  }

  const tokenUrl = AZURE_TOKEN_URL.replace('{tenant}', azureTenantId);

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      scope: 'https://graph.microsoft.com/.default',
      grant_type: 'client_credentials',
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(`Token request failed: ${error.error_description || error.error}`);
  }

  const data = await response.json();

  // Cache the token
  tokenCache.set(cacheKey, {
    token: data.access_token,
    expiresAt: Date.now() + data.expires_in * 1000,
  });

  return data.access_token;
}

/**
 * Get access token for a domain config
 */
export async function getGraphTokenForConfig(configId: string): Promise<string> {
  const config = await getDomainConfig(configId);
  if (!config || config.provider !== 'microsoft_365') {
    throw new Error('Config not found or wrong provider');
  }

  const clientSecret = await getAzureClientSecret(configId);
  if (!clientSecret) {
    throw new Error('Client secret not found');
  }

  return getClientCredentialsToken(
    config.azureTenantId!,
    config.azureClientId!,
    clientSecret
  );
}

/**
 * Sync all users from Azure AD
 */
export async function syncMicrosoft365Users(configId: string): Promise<DomainSyncResult> {
  const config = await getDomainConfig(configId);
  if (!config || config.provider !== 'microsoft_365') {
    return { usersDiscovered: 0, usersAdded: 0, usersUpdated: 0, usersRemoved: 0, errors: ['Config not found'] };
  }

  const result: DomainSyncResult = {
    usersDiscovered: 0,
    usersAdded: 0,
    usersUpdated: 0,
    usersRemoved: 0,
    errors: [],
  };

  try {
    const accessToken = await getGraphTokenForConfig(configId);
    const users = await listAllUsers(accessToken);

    result.usersDiscovered = users.length;
    const activeEmails: string[] = [];

    for (const user of users) {
      if (!user.email) continue; // Skip users without email

      try {
        activeEmails.push(user.email);
        await upsertDomainUser({
          domainConfigId: configId,
          tenantId: config.tenantId,
          email: user.email,
          displayName: user.displayName,
          providerUserId: user.providerId,
          status: 'active',
        });
        result.usersAdded++;
      } catch (error) {
        result.errors.push(`Failed to sync user ${user.email}: ${error}`);
      }
    }

    // Mark users not in the list as deleted
    result.usersRemoved = await markUsersNotInList(configId, activeEmails);

    // Update stats
    await updateDomainConfigStats(configId, {
      totalUsersDiscovered: result.usersDiscovered,
      totalUsersActive: activeEmails.length,
      lastUserSyncAt: new Date(),
    });
  } catch (error) {
    result.errors.push(`Directory sync failed: ${error}`);
    await updateDomainConfigStatus(configId, 'error', String(error));
  }

  return result;
}

interface GraphUserResponse {
  value?: Array<{
    id: string;
    mail?: string;
    displayName?: string;
    userPrincipalName?: string;
    accountEnabled?: boolean;
  }>;
  '@odata.nextLink'?: string;
}

/**
 * List all users in the Azure AD tenant
 */
async function listAllUsers(accessToken: string): Promise<DirectoryUser[]> {
  const users: DirectoryUser[] = [];
  let nextLink: string | undefined = `${GRAPH_API_URL}/users?$top=999&$select=id,mail,displayName,userPrincipalName,accountEnabled`;

  while (nextLink) {
    const response: Response = await fetch(nextLink, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      throw new Error(`Failed to list users: ${response.statusText}`);
    }

    const data: GraphUserResponse = await response.json();

    for (const user of data.value || []) {
      // Skip disabled accounts and accounts without email
      if (!user.accountEnabled) continue;

      const email = user.mail || user.userPrincipalName;
      if (!email || !email.includes('@')) continue;

      users.push({
        email: email.toLowerCase(),
        displayName: user.displayName || email,
        providerId: user.id,
      });
    }

    nextLink = data['@odata.nextLink'];
  }

  return users;
}

/**
 * Create mail change notification subscription for a user
 */
export async function createMailSubscription(
  configId: string,
  userEmail: string,
  webhookUrl: string
): Promise<{ subscriptionId: string; expiresAt: Date }> {
  const accessToken = await getGraphTokenForConfig(configId);

  // Subscription expires in 3 days max for mail
  const expirationDateTime = new Date();
  expirationDateTime.setDate(expirationDateTime.getDate() + 3);

  const response = await fetch(`${GRAPH_API_URL}/subscriptions`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      changeType: 'created',
      notificationUrl: webhookUrl,
      resource: `/users/${userEmail}/messages`,
      expirationDateTime: expirationDateTime.toISOString(),
      clientState: configId, // Use configId as client state for verification
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(`Failed to create subscription: ${error.error?.message || response.statusText}`);
  }

  const data = await response.json();

  return {
    subscriptionId: data.id,
    expiresAt: new Date(data.expirationDateTime),
  };
}

/**
 * Setup mail subscriptions for all monitored users
 */
export async function setupMailSubscriptionsForAllUsers(
  configId: string,
  webhookUrl: string
): Promise<{ success: number; failed: number; errors: string[] }> {
  const users = await getMonitoredDomainUsers(configId);
  const results = { success: 0, failed: 0, errors: [] as string[] };

  for (const user of users) {
    try {
      const { subscriptionId, expiresAt } = await createMailSubscription(
        configId,
        user.email,
        webhookUrl
      );

      await updateDomainUserSyncState(user.id, {
        webhookSubscriptionId: subscriptionId,
        webhookExpiresAt: expiresAt,
      });

      results.success++;
    } catch (error) {
      results.errors.push(`${user.email}: ${error}`);
      results.failed++;
    }
  }

  return results;
}

/**
 * Renew a mail subscription
 */
export async function renewMailSubscription(
  configId: string,
  subscriptionId: string
): Promise<Date> {
  const accessToken = await getGraphTokenForConfig(configId);

  const expirationDateTime = new Date();
  expirationDateTime.setDate(expirationDateTime.getDate() + 3);

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
    const error = await response.json();
    throw new Error(`Failed to renew subscription: ${error.error?.message || response.statusText}`);
  }

  const data = await response.json();
  return new Date(data.expirationDateTime);
}

/**
 * Get mail message by ID
 */
export async function getMailMessage(
  configId: string,
  userEmail: string,
  messageId: string
): Promise<Record<string, unknown>> {
  const accessToken = await getGraphTokenForConfig(configId);

  const response = await fetch(
    `${GRAPH_API_URL}/users/${userEmail}/messages/${messageId}?$select=id,subject,from,toRecipients,ccRecipients,receivedDateTime,bodyPreview,body,hasAttachments,internetMessageHeaders`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );

  if (!response.ok) {
    throw new Error(`Failed to get message: ${response.statusText}`);
  }

  return response.json();
}

/**
 * Move message to junk folder (quarantine)
 */
export async function moveToJunk(
  configId: string,
  userEmail: string,
  messageId: string
): Promise<void> {
  const accessToken = await getGraphTokenForConfig(configId);

  // Get junk folder ID
  const foldersResponse: Response = await fetch(
    `${GRAPH_API_URL}/users/${userEmail}/mailFolders?$filter=displayName eq 'Junk Email'`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );

  if (!foldersResponse.ok) {
    throw new Error('Failed to get junk folder');
  }

  const foldersData: { value?: Array<{ id: string }> } = await foldersResponse.json();
  const junkFolderId = foldersData.value?.[0]?.id;

  if (!junkFolderId) {
    throw new Error('Junk folder not found');
  }

  // Move message
  const moveResponse: Response = await fetch(
    `${GRAPH_API_URL}/users/${userEmail}/messages/${messageId}/move`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ destinationId: junkFolderId }),
    }
  );

  if (!moveResponse.ok) {
    throw new Error(`Failed to move message: ${moveResponse.statusText}`);
  }
}

/**
 * Delete message permanently
 */
export async function deleteMessage(
  configId: string,
  userEmail: string,
  messageId: string
): Promise<void> {
  const accessToken = await getGraphTokenForConfig(configId);

  const response = await fetch(
    `${GRAPH_API_URL}/users/${userEmail}/messages/${messageId}`,
    {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` },
    }
  );

  if (!response.ok && response.status !== 404) {
    throw new Error(`Failed to delete message: ${response.statusText}`);
  }
}
