/**
 * Email Sync Worker
 * Background worker that syncs emails from connected integrations
 */

import { sql } from '@/lib/db';
import {
  listO365Emails,
  getO365Email,
  refreshO365Token,
} from '@/lib/integrations/o365';
import {
  listGmailMessages,
  getGmailMessage,
  refreshGmailToken,
} from '@/lib/integrations/gmail';
import { parseGraphEmail, parseGmailEmail } from '@/lib/detection/parser';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import { logAuditEvent } from '@/lib/db/audit';
import type { ParsedEmail } from '@/lib/detection/types';

const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID!;
const MICROSOFT_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET!;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;

// Sync configuration - optimized for Vercel's 60s timeout
const BATCH_SIZE = 5;
const MAX_EMAILS_PER_SYNC = 20; // Increased with 60s timeout
const SYNC_TIMEOUT_MS = 50000; // Exit before Vercel's 60s limit

export interface SyncResult {
  integrationId: string;
  tenantId: string;
  type: 'o365' | 'gmail';
  emailsProcessed: number;
  threatsFound: number;
  errors: string[];
  duration: number;
}

export interface IntegrationRecord {
  id: string;
  tenant_id: string;
  type: string;
  config: Record<string, unknown>;
  last_sync_at: Date | null;
}

/**
 * Run sync for all active integrations
 */
export async function runFullSync(): Promise<SyncResult[]> {
  console.log('Starting full email sync...');

  const integrations = await sql`
    SELECT id, tenant_id, type, config, last_sync_at
    FROM integrations
    WHERE status = 'connected'
    AND (config->>'syncEnabled')::boolean = true
  ` as IntegrationRecord[];

  const results: SyncResult[] = [];

  for (const integration of integrations) {
    try {
      const result = await syncIntegration(integration);
      results.push(result);
    } catch (error) {
      console.error(`Sync failed for integration ${integration.id}:`, error);
      results.push({
        integrationId: integration.id,
        tenantId: integration.tenant_id,
        type: integration.type as 'o365' | 'gmail',
        emailsProcessed: 0,
        threatsFound: 0,
        errors: [error instanceof Error ? error.message : 'Unknown error'],
        duration: 0,
      });
    }
  }

  console.log(`Full sync complete. Processed ${results.length} integrations.`);
  return results;
}

/**
 * Sync a single integration
 */
export async function syncIntegration(integration: IntegrationRecord): Promise<SyncResult> {
  const startTime = Date.now();

  console.log(`Syncing ${integration.type} integration for tenant ${integration.tenant_id}`);

  if (integration.type === 'o365') {
    return syncO365Integration(integration, startTime);
  } else if (integration.type === 'gmail') {
    return syncGmailIntegration(integration, startTime);
  }

  throw new Error(`Unsupported integration type: ${integration.type}`);
}

/**
 * Sync Microsoft 365 integration
 */
async function syncO365Integration(
  integration: IntegrationRecord,
  startTime: number
): Promise<SyncResult> {
  const errors: string[] = [];
  let emailsProcessed = 0;
  let threatsFound = 0;
  let timedOut = false;

  const config = integration.config as {
    accessToken: string;
    refreshToken: string;
    tokenExpiresAt: string;
  };

  // Refresh token if needed
  let accessToken = config.accessToken;
  if (new Date(config.tokenExpiresAt) <= new Date()) {
    try {
      const newTokens = await refreshO365Token({
        refreshToken: config.refreshToken,
        clientId: MICROSOFT_CLIENT_ID,
        clientSecret: MICROSOFT_CLIENT_SECRET,
      });

      accessToken = newTokens.accessToken;

      await sql`
        UPDATE integrations
        SET config = config || ${JSON.stringify({
          accessToken: newTokens.accessToken,
          refreshToken: newTokens.refreshToken || config.refreshToken,
          tokenExpiresAt: newTokens.expiresAt.toISOString(),
        })}::jsonb,
        updated_at = NOW()
        WHERE id = ${integration.id}
      `;
    } catch (error) {
      errors.push(`Token refresh failed: ${error}`);
      await updateIntegrationError(integration.id, 'Token refresh failed');
      return createResult(integration, emailsProcessed, threatsFound, errors, startTime);
    }
  }

  // Get emails received since last sync (or last 24 hours)
  const sinceDate = integration.last_sync_at
    ? new Date(integration.last_sync_at)
    : new Date(Date.now() - 24 * 60 * 60 * 1000);

  try {
    const { emails } = await listO365Emails({
      accessToken,
      filter: `receivedDateTime ge ${sinceDate.toISOString()}`,
      top: MAX_EMAILS_PER_SYNC,
    });

    for (const emailMeta of emails) {
      // Check timeout before processing each email
      if (Date.now() - startTime > SYNC_TIMEOUT_MS) {
        console.log('O365 sync timeout reached, stopping early');
        timedOut = true;
        break;
      }

      try {
        // Check if already processed
        const existing = await sql`
          SELECT id FROM email_verdicts
          WHERE tenant_id = ${integration.tenant_id}
          AND message_id = ${emailMeta.internetMessageId || emailMeta.id}
        `;

        if (existing.length > 0) {
          continue;
        }

        // Get full email
        const fullEmail = await getO365Email({
          accessToken,
          messageId: emailMeta.id as string,
        });

        // Parse and analyze (skip LLM for background sync - too slow)
        const parsedEmail = parseGraphEmail(fullEmail);
        const verdict = await analyzeEmail(parsedEmail, integration.tenant_id, {
          skipLLM: true, // Skip LLM to stay within timeout
        });

        // Store results
        await storeVerdict(integration.tenant_id, parsedEmail.messageId, verdict);

        if (verdict.verdict !== 'pass' && verdict.overallScore >= 30) {
          threatsFound++;
        }

        emailsProcessed++;
      } catch (error) {
        errors.push(`Email ${emailMeta.id}: ${error}`);
      }
    }

    // Update last sync time (even if partial sync due to timeout)
    await sql`
      UPDATE integrations
      SET last_sync_at = NOW(), error_message = ${timedOut ? 'Partial sync - timeout' : null}, updated_at = NOW()
      WHERE id = ${integration.id}
    `;
  } catch (error) {
    errors.push(`List emails failed: ${error}`);
    await updateIntegrationError(integration.id, 'Sync failed');
  }

  // Audit log
  await logAuditEvent({
    tenantId: integration.tenant_id,
    actorId: null, // System action
    actorEmail: null,
    action: 'email.sync',
    resourceType: 'integration',
    resourceId: 'o365',
    afterState: {
      emailsProcessed,
      threatsFound,
      errors: errors.length,
      timedOut,
    },
  });

  return createResult(integration, emailsProcessed, threatsFound, errors, startTime);
}

/**
 * Sync Gmail integration
 */
async function syncGmailIntegration(
  integration: IntegrationRecord,
  startTime: number
): Promise<SyncResult> {
  const errors: string[] = [];
  let emailsProcessed = 0;
  let threatsFound = 0;
  let timedOut = false;

  const config = integration.config as {
    accessToken: string;
    refreshToken: string;
    tokenExpiresAt: string;
  };

  // Refresh token if needed
  let accessToken = config.accessToken;
  if (new Date(config.tokenExpiresAt) <= new Date()) {
    try {
      const newTokens = await refreshGmailToken({
        refreshToken: config.refreshToken,
        clientId: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
      });

      accessToken = newTokens.accessToken;

      await sql`
        UPDATE integrations
        SET config = config || ${JSON.stringify({
          accessToken: newTokens.accessToken,
          tokenExpiresAt: newTokens.expiresAt.toISOString(),
        })}::jsonb,
        updated_at = NOW()
        WHERE id = ${integration.id}
      `;
    } catch (error) {
      errors.push(`Token refresh failed: ${error}`);
      await updateIntegrationError(integration.id, 'Token refresh failed');
      return createResult(integration, emailsProcessed, threatsFound, errors, startTime);
    }
  }

  // Get emails received since last sync
  const sinceDate = integration.last_sync_at
    ? new Date(integration.last_sync_at)
    : new Date(Date.now() - 24 * 60 * 60 * 1000);

  const sinceTimestamp = Math.floor(sinceDate.getTime() / 1000);

  try {
    const { messages } = await listGmailMessages({
      accessToken,
      query: `after:${sinceTimestamp}`,
      maxResults: MAX_EMAILS_PER_SYNC,
      labelIds: ['INBOX'],
    });

    for (const messageMeta of messages) {
      // Check timeout before processing each email
      if (Date.now() - startTime > SYNC_TIMEOUT_MS) {
        console.log('Sync timeout reached, stopping early to avoid Vercel timeout');
        timedOut = true;
        break;
      }

      try {
        // Check if already processed
        const existing = await sql`
          SELECT id FROM email_verdicts
          WHERE tenant_id = ${integration.tenant_id}
          AND message_id LIKE ${`%${messageMeta.id}%`}
        `;

        if (existing.length > 0) {
          continue;
        }

        // Get full message
        const fullMessage = await getGmailMessage({
          accessToken,
          messageId: messageMeta.id,
          format: 'full',
        });

        // Parse and analyze (skip LLM for background sync - too slow)
        const parsedEmail = parseGmailEmail(fullMessage);
        const verdict = await analyzeEmail(parsedEmail, integration.tenant_id, {
          skipLLM: true, // Skip LLM to stay within timeout
        });

        // Store results
        await storeVerdict(integration.tenant_id, parsedEmail.messageId, verdict);

        if (verdict.verdict !== 'pass' && verdict.overallScore >= 30) {
          threatsFound++;
        }

        emailsProcessed++;
      } catch (error) {
        errors.push(`Message ${messageMeta.id}: ${error}`);
      }
    }

    // Update last sync time (even if partial sync due to timeout)
    await sql`
      UPDATE integrations
      SET last_sync_at = NOW(), error_message = ${timedOut ? 'Partial sync - timeout' : null}, updated_at = NOW()
      WHERE id = ${integration.id}
    `;
  } catch (error) {
    errors.push(`List messages failed: ${error}`);
    await updateIntegrationError(integration.id, 'Sync failed');
  }

  // Audit log
  await logAuditEvent({
    tenantId: integration.tenant_id,
    actorId: null, // System action
    actorEmail: null,
    action: 'email.sync',
    resourceType: 'integration',
    resourceId: 'gmail',
    afterState: {
      emailsProcessed,
      threatsFound,
      errors: errors.length,
      timedOut,
    },
  });

  return createResult(integration, emailsProcessed, threatsFound, errors, startTime);
}

/**
 * Update integration with error message
 */
async function updateIntegrationError(integrationId: string, errorMessage: string): Promise<void> {
  await sql`
    UPDATE integrations
    SET status = 'error', error_message = ${errorMessage}, updated_at = NOW()
    WHERE id = ${integrationId}
  `;
}

/**
 * Create sync result object
 */
function createResult(
  integration: IntegrationRecord,
  emailsProcessed: number,
  threatsFound: number,
  errors: string[],
  startTime: number
): SyncResult {
  return {
    integrationId: integration.id,
    tenantId: integration.tenant_id,
    type: integration.type as 'o365' | 'gmail',
    emailsProcessed,
    threatsFound,
    errors,
    duration: Date.now() - startTime,
  };
}

/**
 * Sync a specific tenant
 */
export async function syncTenant(tenantId: string): Promise<SyncResult[]> {
  const integrations = await sql`
    SELECT id, tenant_id, type, config, last_sync_at
    FROM integrations
    WHERE tenant_id = ${tenantId}
    AND status = 'connected'
    AND (config->>'syncEnabled')::boolean = true
  ` as IntegrationRecord[];

  const results: SyncResult[] = [];

  for (const integration of integrations) {
    const result = await syncIntegration(integration);
    results.push(result);
  }

  return results;
}
