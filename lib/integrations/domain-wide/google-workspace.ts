/**
 * Google Workspace Domain-Wide Delegation
 *
 * Uses a service account with domain-wide delegation to:
 * 1. List all users in the Google Workspace domain via Admin SDK
 * 2. Impersonate each user to access their Gmail
 * 3. Set up push notifications for all users
 *
 * Setup Requirements:
 * 1. Create a service account in Google Cloud Console
 * 2. Enable domain-wide delegation for the service account
 * 3. In Google Admin Console, grant the service account these scopes:
 *    - https://www.googleapis.com/auth/admin.directory.user.readonly
 *    - https://www.googleapis.com/auth/gmail.readonly
 *    - https://www.googleapis.com/auth/gmail.modify
 */

import { SignJWT, importPKCS8 } from 'jose';
import type { DirectoryUser, DomainSyncResult, GoogleWorkspaceSetupParams } from './types';
import {
  createDomainConfig,
  getDomainConfig,
  getGoogleServiceAccountKey,
  updateDomainConfigStatus,
  updateDomainConfigStats,
  upsertDomainUser,
  getMonitoredDomainUsers,
  updateDomainUserSyncState,
  markUsersNotInList,
} from './storage';

const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const ADMIN_DIRECTORY_API = 'https://admin.googleapis.com/admin/directory/v1';
const GMAIL_API_URL = 'https://gmail.googleapis.com/gmail/v1';

// Required scopes for domain-wide delegation
const ADMIN_SCOPES = [
  'https://www.googleapis.com/auth/admin.directory.user.readonly',
];

const GMAIL_SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.modify',
];

interface ServiceAccountKey {
  type: string;
  project_id: string;
  private_key_id: string;
  private_key: string;
  client_email: string;
  client_id: string;
  auth_uri: string;
  token_uri: string;
}

/**
 * Setup Google Workspace domain-wide monitoring
 */
export async function setupGoogleWorkspace(params: GoogleWorkspaceSetupParams): Promise<{
  configId: string;
  success: boolean;
  error?: string;
}> {
  const { tenantId, serviceAccountKey, adminEmail, createdBy } = params;

  try {
    // Parse and validate service account key
    const keyData = JSON.parse(serviceAccountKey) as ServiceAccountKey;

    if (keyData.type !== 'service_account') {
      return { configId: '', success: false, error: 'Invalid service account key: type must be "service_account"' };
    }

    // Create config in database
    const configId = await createDomainConfig({
      tenantId,
      provider: 'google_workspace',
      createdBy,
      googleServiceAccountEmail: keyData.client_email,
      googleServiceAccountKey: serviceAccountKey,
      googleAdminEmail: adminEmail,
    });

    // Test the connection by getting an access token and listing users
    const accessToken = await getServiceAccountToken(keyData, adminEmail, ADMIN_SCOPES);

    // Try to list users to verify domain-wide delegation is set up
    const response = await fetch(
      `${ADMIN_DIRECTORY_API}/users?customer=my_customer&maxResults=1`,
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      }
    );

    if (!response.ok) {
      const error = await response.json();
      await updateDomainConfigStatus(
        configId,
        'error',
        `Domain-wide delegation not configured: ${error.error?.message || 'Unknown error'}`
      );
      return {
        configId,
        success: false,
        error: `Domain-wide delegation not configured. Please ensure the service account has been granted the required scopes in Google Admin Console. Error: ${error.error?.message}`,
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
 * Get access token for service account using JWT assertion
 */
async function getServiceAccountToken(
  keyData: ServiceAccountKey,
  subject: string, // Email to impersonate
  scopes: string[]
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  // Import the private key
  const privateKey = await importPKCS8(keyData.private_key, 'RS256');

  // Create JWT assertion
  const jwt = await new SignJWT({
    scope: scopes.join(' '),
    sub: subject,
  })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
    .setIssuer(keyData.client_email)
    .setAudience(GOOGLE_TOKEN_URL)
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(privateKey);

  // Exchange JWT for access token
  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(`Token exchange failed: ${error.error_description || error.error}`);
  }

  const data = await response.json();
  return data.access_token;
}

/**
 * Sync all users from Google Workspace directory
 */
export async function syncGoogleWorkspaceUsers(configId: string): Promise<DomainSyncResult> {
  const config = await getDomainConfig(configId);
  if (!config || config.provider !== 'google_workspace') {
    return { usersDiscovered: 0, usersAdded: 0, usersUpdated: 0, usersRemoved: 0, errors: ['Config not found'] };
  }

  const keyJson = await getGoogleServiceAccountKey(configId);
  if (!keyJson) {
    return { usersDiscovered: 0, usersAdded: 0, usersUpdated: 0, usersRemoved: 0, errors: ['Service account key not found'] };
  }

  const keyData = JSON.parse(keyJson) as ServiceAccountKey;
  const adminEmail = config.googleAdminEmail!;

  const result: DomainSyncResult = {
    usersDiscovered: 0,
    usersAdded: 0,
    usersUpdated: 0,
    usersRemoved: 0,
    errors: [],
  };

  try {
    const accessToken = await getServiceAccountToken(keyData, adminEmail, ADMIN_SCOPES);
    const users = await listAllUsers(accessToken, config.syncExcludeGroups);

    result.usersDiscovered = users.length;
    const activeEmails: string[] = [];

    for (const user of users) {
      try {
        activeEmails.push(user.email);
        await upsertDomainUser({
          domainConfigId: configId,
          tenantId: config.tenantId,
          email: user.email,
          displayName: user.displayName,
          providerUserId: user.providerId,
          status: user.suspended ? 'suspended' : 'active',
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

/**
 * List all users in the Google Workspace domain
 */
async function listAllUsers(
  accessToken: string,
  excludeGroups?: string[]
): Promise<DirectoryUser[]> {
  const users: DirectoryUser[] = [];
  let pageToken: string | undefined;

  do {
    const url = new URL(`${ADMIN_DIRECTORY_API}/users`);
    url.searchParams.set('customer', 'my_customer');
    url.searchParams.set('maxResults', '500');
    url.searchParams.set('projection', 'basic');
    if (pageToken) url.searchParams.set('pageToken', pageToken);

    const response = await fetch(url.toString(), {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      throw new Error(`Failed to list users: ${response.statusText}`);
    }

    const data = await response.json();

    for (const user of data.users || []) {
      // Skip suspended or deleted users
      if (user.suspended || user.archived) continue;

      users.push({
        email: user.primaryEmail,
        displayName: user.name?.fullName || user.primaryEmail,
        providerId: user.id,
        suspended: user.suspended,
        deleted: user.archived,
      });
    }

    pageToken = data.nextPageToken;
  } while (pageToken);

  return users;
}

/**
 * Get Gmail access token for a specific user (impersonation)
 */
export async function getGmailTokenForUser(
  configId: string,
  userEmail: string
): Promise<string> {
  const keyJson = await getGoogleServiceAccountKey(configId);
  if (!keyJson) {
    throw new Error('Service account key not found');
  }

  const keyData = JSON.parse(keyJson) as ServiceAccountKey;
  return getServiceAccountToken(keyData, userEmail, GMAIL_SCOPES);
}

/**
 * Setup Gmail push notifications for all monitored users
 */
export async function setupGmailWatchForAllUsers(
  configId: string,
  topicName: string
): Promise<{ success: number; failed: number; errors: string[] }> {
  const users = await getMonitoredDomainUsers(configId);
  const results = { success: 0, failed: 0, errors: [] as string[] };

  for (const user of users) {
    try {
      const accessToken = await getGmailTokenForUser(configId, user.email);

      const response = await fetch(`${GMAIL_API_URL}/users/me/watch`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          topicName,
          labelIds: ['INBOX'],
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        results.errors.push(`${user.email}: ${error.error?.message || 'Watch failed'}`);
        results.failed++;
        continue;
      }

      const data = await response.json();

      await updateDomainUserSyncState(user.id, {
        lastHistoryId: data.historyId,
        webhookExpiresAt: new Date(parseInt(data.expiration)),
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
 * Process Gmail history for a domain user (called by webhook)
 */
export async function processGmailHistoryForUser(
  configId: string,
  userEmail: string,
  historyId: string
): Promise<{ messageIds: string[]; newHistoryId: string }> {
  const users = await getMonitoredDomainUsers(configId);
  const user = users.find(u => u.email === userEmail);

  if (!user) {
    return { messageIds: [], newHistoryId: historyId };
  }

  const accessToken = await getGmailTokenForUser(configId, userEmail);
  const startHistoryId = user.lastHistoryId || historyId;

  const response = await fetch(
    `${GMAIL_API_URL}/users/me/history?startHistoryId=${startHistoryId}&historyTypes=messageAdded`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );

  if (!response.ok) {
    if (response.status === 404) {
      // History too old, need full sync
      return { messageIds: [], newHistoryId: historyId };
    }
    throw new Error(`Failed to get history: ${response.statusText}`);
  }

  const data = await response.json();
  const messageIds: string[] = [];

  for (const history of data.history || []) {
    for (const added of history.messagesAdded || []) {
      messageIds.push(added.message.id);
    }
  }

  // Update the user's history ID
  await updateDomainUserSyncState(user.id, {
    lastHistoryId: data.historyId,
    lastSyncAt: new Date(),
  });

  return { messageIds, newHistoryId: data.historyId };
}
