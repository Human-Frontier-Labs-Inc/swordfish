/**
 * Domain-Wide Configuration Storage
 * Database operations for domain-wide monitoring configs
 */

import { sql } from '@/lib/db';
import { encrypt, decrypt } from '@/lib/security/encryption';
import type {
  DomainWideConfig,
  DomainUser,
  DomainProvider,
  DomainConfigStatus,
  DomainUserStatus,
} from './types';

/**
 * Create a new domain-wide configuration
 */
export async function createDomainConfig(params: {
  tenantId: string;
  provider: DomainProvider;
  createdBy: string;
  // Google specific
  googleServiceAccountEmail?: string;
  googleServiceAccountKey?: string;
  googleAdminEmail?: string;
  googleCustomerId?: string;
  // Microsoft specific
  azureTenantId?: string;
  azureClientId?: string;
  azureClientSecret?: string;
}): Promise<string> {
  const {
    tenantId,
    provider,
    createdBy,
    googleServiceAccountEmail,
    googleServiceAccountKey,
    googleAdminEmail,
    googleCustomerId,
    azureTenantId,
    azureClientId,
    azureClientSecret,
  } = params;

  // Encrypt sensitive data
  const encryptedKey = googleServiceAccountKey
    ? encrypt(googleServiceAccountKey)
    : null;
  const encryptedSecret = azureClientSecret
    ? encrypt(azureClientSecret)
    : null;

  const result = await sql`
    INSERT INTO domain_wide_configs (
      tenant_id, provider, status, created_by,
      google_service_account_email, google_service_account_key,
      google_admin_email, google_customer_id,
      azure_tenant_id, azure_client_id, azure_client_secret
    ) VALUES (
      ${tenantId}, ${provider}, 'pending', ${createdBy},
      ${googleServiceAccountEmail || null},
      ${encryptedKey ? Buffer.from(encryptedKey) : null},
      ${googleAdminEmail || null}, ${googleCustomerId || null},
      ${azureTenantId || null}, ${azureClientId || null},
      ${encryptedSecret || null}
    )
    ON CONFLICT (tenant_id, provider) DO UPDATE SET
      status = 'pending',
      google_service_account_email = EXCLUDED.google_service_account_email,
      google_service_account_key = EXCLUDED.google_service_account_key,
      google_admin_email = EXCLUDED.google_admin_email,
      google_customer_id = EXCLUDED.google_customer_id,
      azure_tenant_id = EXCLUDED.azure_tenant_id,
      azure_client_id = EXCLUDED.azure_client_id,
      azure_client_secret = EXCLUDED.azure_client_secret,
      updated_at = NOW()
    RETURNING id
  `;

  return result[0].id;
}

/**
 * Get domain config by ID
 */
export async function getDomainConfig(configId: string): Promise<DomainWideConfig | null> {
  const result = await sql`
    SELECT * FROM domain_wide_configs WHERE id = ${configId}
  `;

  if (result.length === 0) return null;
  return mapDomainConfig(result[0]);
}

/**
 * Get domain config for a tenant and provider
 */
export async function getDomainConfigByTenant(
  tenantId: string,
  provider: DomainProvider
): Promise<DomainWideConfig | null> {
  const result = await sql`
    SELECT * FROM domain_wide_configs
    WHERE tenant_id = ${tenantId} AND provider = ${provider}
  `;

  if (result.length === 0) return null;
  return mapDomainConfig(result[0]);
}

/**
 * Get all active domain configs (for cron jobs)
 * Returns empty array if table doesn't exist (migration not yet run)
 */
export async function getActiveDomainConfigs(): Promise<DomainWideConfig[]> {
  try {
    const result = await sql`
      SELECT * FROM domain_wide_configs
      WHERE status = 'active' AND sync_enabled = true
    `;

    return result.map(mapDomainConfig);
  } catch (error) {
    // Handle case where domain_wide_configs table doesn't exist yet
    // This can happen if migration 013 hasn't been run in production
    if (error instanceof Error && error.message.includes('domain_wide_configs')) {
      console.log('[Domain-Wide] Table not yet created, skipping domain-wide checks');
      return [];
    }
    throw error;
  }
}

/**
 * Update domain config status
 */
export async function updateDomainConfigStatus(
  configId: string,
  status: DomainConfigStatus,
  errorMessage?: string
): Promise<void> {
  await sql`
    UPDATE domain_wide_configs
    SET status = ${status},
        error_message = ${errorMessage || null},
        updated_at = NOW()
    WHERE id = ${configId}
  `;
}

/**
 * Update domain config stats
 */
export async function updateDomainConfigStats(
  configId: string,
  stats: {
    totalUsersDiscovered?: number;
    totalUsersActive?: number;
    lastUserSyncAt?: Date;
    lastEmailSyncAt?: Date;
  }
): Promise<void> {
  await sql`
    UPDATE domain_wide_configs
    SET total_users_discovered = COALESCE(${stats.totalUsersDiscovered ?? null}, total_users_discovered),
        total_users_active = COALESCE(${stats.totalUsersActive ?? null}, total_users_active),
        last_user_sync_at = COALESCE(${stats.lastUserSyncAt?.toISOString() ?? null}, last_user_sync_at),
        last_email_sync_at = COALESCE(${stats.lastEmailSyncAt?.toISOString() ?? null}, last_email_sync_at),
        updated_at = NOW()
    WHERE id = ${configId}
  `;
}

/**
 * Get decrypted Google service account key
 */
export async function getGoogleServiceAccountKey(configId: string): Promise<string | null> {
  const result = await sql`
    SELECT google_service_account_key FROM domain_wide_configs WHERE id = ${configId}
  `;

  if (result.length === 0 || !result[0].google_service_account_key) return null;

  const keyBuffer = result[0].google_service_account_key as Buffer;
  return decrypt(keyBuffer.toString());
}

/**
 * Get decrypted Azure client secret
 */
export async function getAzureClientSecret(configId: string): Promise<string | null> {
  const result = await sql`
    SELECT azure_client_secret FROM domain_wide_configs WHERE id = ${configId}
  `;

  if (result.length === 0 || !result[0].azure_client_secret) return null;
  return decrypt(result[0].azure_client_secret as string);
}

// ============ Domain Users ============

/**
 * Upsert a domain user
 */
export async function upsertDomainUser(params: {
  domainConfigId: string;
  tenantId: string;
  email: string;
  displayName?: string;
  providerUserId?: string;
  status?: DomainUserStatus;
}): Promise<string> {
  const { domainConfigId, tenantId, email, displayName, providerUserId, status = 'active' } = params;

  const result = await sql`
    INSERT INTO domain_users (
      domain_config_id, tenant_id, email, display_name, provider_user_id, status
    ) VALUES (
      ${domainConfigId}, ${tenantId}, ${email}, ${displayName || null},
      ${providerUserId || null}, ${status}
    )
    ON CONFLICT (domain_config_id, email) DO UPDATE SET
      display_name = COALESCE(EXCLUDED.display_name, domain_users.display_name),
      provider_user_id = COALESCE(EXCLUDED.provider_user_id, domain_users.provider_user_id),
      status = EXCLUDED.status,
      updated_at = NOW()
    RETURNING id
  `;

  return result[0].id;
}

/**
 * Get all monitored users for a domain config
 */
export async function getMonitoredDomainUsers(domainConfigId: string): Promise<DomainUser[]> {
  const result = await sql`
    SELECT * FROM domain_users
    WHERE domain_config_id = ${domainConfigId}
    AND is_monitored = true
    AND status = 'active'
  `;

  return result.map(mapDomainUser);
}

/**
 * Get domain user by email
 */
export async function getDomainUserByEmail(
  domainConfigId: string,
  email: string
): Promise<DomainUser | null> {
  const result = await sql`
    SELECT * FROM domain_users
    WHERE domain_config_id = ${domainConfigId} AND email = ${email}
  `;

  if (result.length === 0) return null;
  return mapDomainUser(result[0]);
}

/**
 * Update domain user sync state
 */
export async function updateDomainUserSyncState(
  userId: string,
  state: {
    lastSyncAt?: Date;
    lastHistoryId?: string;
    webhookSubscriptionId?: string;
    webhookExpiresAt?: Date;
  }
): Promise<void> {
  await sql`
    UPDATE domain_users
    SET last_sync_at = COALESCE(${state.lastSyncAt?.toISOString() ?? null}, last_sync_at),
        last_history_id = COALESCE(${state.lastHistoryId ?? null}, last_history_id),
        webhook_subscription_id = COALESCE(${state.webhookSubscriptionId ?? null}, webhook_subscription_id),
        webhook_expires_at = COALESCE(${state.webhookExpiresAt?.toISOString() ?? null}, webhook_expires_at),
        updated_at = NOW()
    WHERE id = ${userId}
  `;
}

/**
 * Increment domain user stats
 */
export async function incrementDomainUserStats(
  userId: string,
  stats: { emailsScanned?: number; threatsDetected?: number }
): Promise<void> {
  await sql`
    UPDATE domain_users
    SET emails_scanned = emails_scanned + ${stats.emailsScanned || 0},
        threats_detected = threats_detected + ${stats.threatsDetected || 0},
        updated_at = NOW()
    WHERE id = ${userId}
  `;
}

/**
 * Get users with expiring webhooks
 */
export async function getUsersWithExpiringWebhooks(
  beforeDate: Date
): Promise<DomainUser[]> {
  const result = await sql`
    SELECT du.* FROM domain_users du
    JOIN domain_wide_configs dwc ON du.domain_config_id = dwc.id
    WHERE du.webhook_expires_at <= ${beforeDate.toISOString()}
    AND du.is_monitored = true
    AND du.status = 'active'
    AND dwc.status = 'active'
  `;

  return result.map(mapDomainUser);
}

/**
 * Mark users as deleted/suspended
 */
export async function markUsersNotInList(
  domainConfigId: string,
  activeEmails: string[]
): Promise<number> {
  if (activeEmails.length === 0) return 0;

  // Build the IN clause manually since sql template doesn't handle arrays directly
  const placeholders = activeEmails.map((_, i) => `$${i + 2}`).join(', ');
  const query = `
    UPDATE domain_users
    SET status = 'deleted', is_monitored = false, updated_at = NOW()
    WHERE domain_config_id = $1
    AND email NOT IN (${placeholders})
    AND status = 'active'
  `;

  const result = await sql.query(query, [domainConfigId, ...activeEmails]);
  return (result as { rowCount?: number }).rowCount || 0;
}

// ============ Helpers ============

function mapDomainConfig(row: Record<string, unknown>): DomainWideConfig {
  return {
    id: row.id as string,
    tenantId: row.tenant_id as string,
    provider: row.provider as DomainProvider,
    status: row.status as DomainConfigStatus,
    errorMessage: row.error_message as string | null,
    googleServiceAccountEmail: row.google_service_account_email as string | undefined,
    googleAdminEmail: row.google_admin_email as string | undefined,
    googleCustomerId: row.google_customer_id as string | undefined,
    azureTenantId: row.azure_tenant_id as string | undefined,
    azureClientId: row.azure_client_id as string | undefined,
    syncEnabled: row.sync_enabled as boolean,
    syncAllUsers: row.sync_all_users as boolean,
    syncIncludeGroups: row.sync_include_groups as string[] | undefined,
    syncExcludeGroups: row.sync_exclude_groups as string[] | undefined,
    monitorIncoming: row.monitor_incoming as boolean,
    monitorOutgoing: row.monitor_outgoing as boolean,
    monitorInternal: row.monitor_internal as boolean,
    totalUsersDiscovered: row.total_users_discovered as number,
    totalUsersActive: row.total_users_active as number,
    lastUserSyncAt: row.last_user_sync_at ? new Date(row.last_user_sync_at as string) : null,
    lastEmailSyncAt: row.last_email_sync_at ? new Date(row.last_email_sync_at as string) : null,
    createdAt: new Date(row.created_at as string),
    updatedAt: new Date(row.updated_at as string),
    createdBy: row.created_by as string,
  };
}

function mapDomainUser(row: Record<string, unknown>): DomainUser {
  return {
    id: row.id as string,
    domainConfigId: row.domain_config_id as string,
    tenantId: row.tenant_id as string,
    email: row.email as string,
    displayName: row.display_name as string | null,
    providerUserId: row.provider_user_id as string | null,
    status: row.status as DomainUserStatus,
    excludedReason: row.excluded_reason as string | null,
    isMonitored: row.is_monitored as boolean,
    lastSyncAt: row.last_sync_at ? new Date(row.last_sync_at as string) : null,
    lastHistoryId: row.last_history_id as string | null,
    webhookSubscriptionId: row.webhook_subscription_id as string | null,
    webhookExpiresAt: row.webhook_expires_at ? new Date(row.webhook_expires_at as string) : null,
    emailsScanned: row.emails_scanned as number,
    threatsDetected: row.threats_detected as number,
    createdAt: new Date(row.created_at as string),
    updatedAt: new Date(row.updated_at as string),
  };
}
