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
import { autoRemediate } from '@/lib/workers/remediation';
import type { ParsedEmail } from '@/lib/detection/types';

const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID!;
const MICROSOFT_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET!;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;

// Sync configuration - optimized for Vercel's 60s timeout
const BATCH_SIZE = 5;
const MAX_EMAILS_PER_SYNC = 20; // Increased with 60s timeout
const SYNC_TIMEOUT_MS = 50000; // Exit before Vercel's 60s limit

export interface SyncError {
  type: 'token_refresh' | 'api_error' | 'rate_limit' | 'parse_error' | 'storage_error' | 'unknown';
  messageId?: string;
  message: string;
  details?: string;
  timestamp: string;
}

export interface SyncResult {
  integrationId: string;
  tenantId: string;
  type: 'o365' | 'gmail';
  emailsProcessed: number;
  emailsSkipped: number;
  threatsFound: number;
  errors: string[];
  detailedErrors: SyncError[];
  duration: number;
  timedOut: boolean;
}

/**
 * Categorize error type for better reporting
 */
function categorizeError(error: unknown, messageId?: string): SyncError {
  const errorMessage = error instanceof Error ? error.message : String(error);
  const errorDetails = error instanceof Error ? error.stack : undefined;
  const timestamp = new Date().toISOString();

  // Rate limit errors
  if (errorMessage.includes('429') || errorMessage.includes('rate limit') || errorMessage.includes('quota')) {
    return { type: 'rate_limit', messageId, message: 'API rate limit exceeded', details: errorMessage, timestamp };
  }

  // Token/auth errors
  if (errorMessage.includes('401') || errorMessage.includes('403') || errorMessage.includes('token') || errorMessage.includes('auth')) {
    return { type: 'token_refresh', messageId, message: 'Authentication error', details: errorMessage, timestamp };
  }

  // API errors
  if (errorMessage.includes('fetch') || errorMessage.includes('network') || errorMessage.includes('ECONNREFUSED')) {
    return { type: 'api_error', messageId, message: 'API connection error', details: errorMessage, timestamp };
  }

  // Parse errors
  if (errorMessage.includes('parse') || errorMessage.includes('undefined') || errorMessage.includes('null')) {
    return { type: 'parse_error', messageId, message: 'Email parsing error', details: errorMessage, timestamp };
  }

  // Storage errors
  if (errorMessage.includes('sql') || errorMessage.includes('database') || errorMessage.includes('constraint')) {
    return { type: 'storage_error', messageId, message: 'Database storage error', details: errorMessage, timestamp };
  }

  return { type: 'unknown', messageId, message: errorMessage, details: errorDetails, timestamp };
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
      const syncError = categorizeError(error);
      results.push({
        integrationId: integration.id,
        tenantId: integration.tenant_id,
        type: integration.type as 'o365' | 'gmail',
        emailsProcessed: 0,
        emailsSkipped: 0,
        threatsFound: 0,
        errors: [error instanceof Error ? error.message : 'Unknown error'],
        detailedErrors: [syncError],
        duration: 0,
        timedOut: false,
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
  const detailedErrors: SyncError[] = [];
  let emailsProcessed = 0;
  let emailsSkipped = 0;
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
      const syncError = categorizeError(error);
      errors.push(`Token refresh failed: ${error}`);
      detailedErrors.push(syncError);
      await updateIntegrationError(integration.id, 'Token refresh failed');
      return createResult(integration, emailsProcessed, emailsSkipped, threatsFound, errors, detailedErrors, startTime, timedOut);
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

    console.log(`[O365 Sync] Found ${emails.length} emails to process for tenant ${integration.tenant_id}`);

    for (const emailMeta of emails) {
      // Check timeout before processing each email
      if (Date.now() - startTime > SYNC_TIMEOUT_MS) {
        console.log('[O365 Sync] Timeout reached, stopping early');
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
          emailsSkipped++;
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

        // Store results with email metadata
        await storeVerdict(integration.tenant_id, parsedEmail.messageId, verdict, parsedEmail);

        if (verdict.verdict !== 'pass' && verdict.overallScore >= 30) {
          threatsFound++;
        }

        // Auto-remediate threats (quarantine or block)
        if (verdict.verdict === 'quarantine' || verdict.verdict === 'block') {
          try {
            await autoRemediate({
              tenantId: integration.tenant_id,
              messageId: parsedEmail.messageId,
              externalMessageId: emailMeta.id as string,
              integrationId: integration.id,
              integrationType: 'o365',
              verdict: verdict.verdict,
              score: verdict.overallScore,
            });
            console.log(`[O365 Sync] Auto-remediated email ${emailMeta.id} with verdict: ${verdict.verdict}`);
          } catch (remediationError) {
            console.error(`[O365 Sync] Auto-remediation failed for ${emailMeta.id}:`, remediationError);
          }
        }

        emailsProcessed++;
      } catch (error) {
        const syncError = categorizeError(error, emailMeta.id as string);
        errors.push(`Email ${emailMeta.id}: ${syncError.message}`);
        detailedErrors.push(syncError);
        console.error(`[O365 Sync] Error processing email ${emailMeta.id}:`, syncError.message, syncError.details?.substring(0, 200));
      }
    }

    // Update last sync time (even if partial sync due to timeout)
    await sql`
      UPDATE integrations
      SET last_sync_at = NOW(), error_message = ${timedOut ? 'Partial sync - timeout' : null}, updated_at = NOW()
      WHERE id = ${integration.id}
    `;

    console.log(`[O365 Sync] Completed: ${emailsProcessed} processed, ${emailsSkipped} skipped, ${errors.length} errors`);
  } catch (error) {
    const syncError = categorizeError(error);
    errors.push(`List emails failed: ${syncError.message}`);
    detailedErrors.push(syncError);
    await updateIntegrationError(integration.id, 'Sync failed');
    console.error('[O365 Sync] Failed to list emails:', syncError.message);
  }

  // Audit log
  await logAuditEvent({
    tenantId: integration.tenant_id,
    actorId: null, // System action
    actorEmail: 'system',
    action: 'email.sync',
    resourceType: 'integration',
    resourceId: integration.id, // Use actual integration UUID
    afterState: {
      emailsProcessed,
      emailsSkipped,
      threatsFound,
      errors: errors.length,
      errorTypes: detailedErrors.map(e => e.type),
      timedOut,
      integrationType: 'o365',
    },
  });

  return createResult(integration, emailsProcessed, emailsSkipped, threatsFound, errors, detailedErrors, startTime, timedOut);
}

/**
 * Sync Gmail integration
 */
async function syncGmailIntegration(
  integration: IntegrationRecord,
  startTime: number
): Promise<SyncResult> {
  const errors: string[] = [];
  const detailedErrors: SyncError[] = [];
  let emailsProcessed = 0;
  let emailsSkipped = 0;
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
      const syncError = categorizeError(error);
      errors.push(`Token refresh failed: ${error}`);
      detailedErrors.push(syncError);
      await updateIntegrationError(integration.id, 'Token refresh failed');
      return createResult(integration, emailsProcessed, emailsSkipped, threatsFound, errors, detailedErrors, startTime, timedOut);
    }
  }

  // Get emails received since last sync
  // Use a slightly earlier timestamp to catch emails that might be missed due to timing
  const sinceDate = integration.last_sync_at
    ? new Date(new Date(integration.last_sync_at).getTime() - 60000) // 1 minute buffer
    : new Date(Date.now() - 24 * 60 * 60 * 1000);

  const sinceTimestamp = Math.floor(sinceDate.getTime() / 1000);

  try {
    // Use query parameter instead of labelIds for more reliable filtering
    // The 'in:inbox' query is more reliable than labelIds filter
    const { messages } = await listGmailMessages({
      accessToken,
      query: `in:inbox after:${sinceTimestamp}`,
      maxResults: MAX_EMAILS_PER_SYNC,
      // Don't use labelIds - it can cause issues with Gmail's filtering
    });

    console.log(`[Gmail Sync] Found ${messages.length} messages since ${sinceDate.toISOString()} for tenant ${integration.tenant_id}`);

    for (const messageMeta of messages) {
      // Check timeout before processing each email
      if (Date.now() - startTime > SYNC_TIMEOUT_MS) {
        console.log('[Gmail Sync] Timeout reached, stopping early to avoid Vercel timeout');
        timedOut = true;
        break;
      }

      try {
        // Get full message first to get the actual message ID
        const fullMessage = await getGmailMessage({
          accessToken,
          messageId: messageMeta.id,
          format: 'full',
        });

        // Parse email to get proper message ID
        const parsedEmail = parseGmailEmail(fullMessage);

        // Check if already processed using exact match on parsed message ID
        const existing = await sql`
          SELECT id FROM email_verdicts
          WHERE tenant_id = ${integration.tenant_id}
          AND (message_id = ${parsedEmail.messageId} OR message_id LIKE ${`%${messageMeta.id}%`})
        `;

        if (existing.length > 0) {
          emailsSkipped++;
          continue;
        }

        // Analyze email (skip LLM for background sync - too slow)
        const verdict = await analyzeEmail(parsedEmail, integration.tenant_id, {
          skipLLM: true, // Skip LLM to stay within timeout
        });

        // Store results with email metadata
        await storeVerdict(integration.tenant_id, parsedEmail.messageId, verdict, parsedEmail);

        if (verdict.verdict !== 'pass' && verdict.overallScore >= 30) {
          threatsFound++;
        }

        // Auto-remediate threats (quarantine or block)
        if (verdict.verdict === 'quarantine' || verdict.verdict === 'block') {
          try {
            await autoRemediate({
              tenantId: integration.tenant_id,
              messageId: parsedEmail.messageId,
              externalMessageId: messageMeta.id,
              integrationId: integration.id,
              integrationType: 'gmail',
              verdict: verdict.verdict,
              score: verdict.overallScore,
            });
            console.log(`[Gmail Sync] Auto-remediated email ${messageMeta.id} with verdict: ${verdict.verdict}`);
          } catch (remediationError) {
            console.error(`[Gmail Sync] Auto-remediation failed for ${messageMeta.id}:`, remediationError);
          }
        }

        emailsProcessed++;
      } catch (error) {
        const syncError = categorizeError(error, messageMeta.id);
        errors.push(`Message ${messageMeta.id}: ${syncError.message}`);
        detailedErrors.push(syncError);
        console.error(`[Gmail Sync] Error processing message ${messageMeta.id}:`, syncError.message, syncError.details?.substring(0, 200));
      }
    }

    // Update last sync time (even if partial sync due to timeout)
    await sql`
      UPDATE integrations
      SET last_sync_at = NOW(), error_message = ${timedOut ? 'Partial sync - timeout' : null}, updated_at = NOW()
      WHERE id = ${integration.id}
    `;

    console.log(`[Gmail Sync] Completed: ${emailsProcessed} processed, ${emailsSkipped} skipped, ${errors.length} errors`);
  } catch (error) {
    const syncError = categorizeError(error);
    errors.push(`List messages failed: ${syncError.message}`);
    detailedErrors.push(syncError);
    await updateIntegrationError(integration.id, 'Sync failed');
    console.error('[Gmail Sync] Failed to list messages:', syncError.message);
  }

  // Audit log
  await logAuditEvent({
    tenantId: integration.tenant_id,
    actorId: null, // System action
    actorEmail: 'system',
    action: 'email.sync',
    resourceType: 'integration',
    resourceId: integration.id, // Use actual integration UUID
    afterState: {
      emailsProcessed,
      emailsSkipped,
      threatsFound,
      errors: errors.length,
      errorTypes: detailedErrors.map(e => e.type),
      timedOut,
      integrationType: 'gmail',
    },
  });

  return createResult(integration, emailsProcessed, emailsSkipped, threatsFound, errors, detailedErrors, startTime, timedOut);
}

/**
 * Update integration with error message
 * Sets 'requires_reauth' status for token-related errors, 'error' for others
 */
async function updateIntegrationError(integrationId: string, errorMessage: string): Promise<void> {
  const isTokenError = errorMessage.toLowerCase().includes('token') ||
                       errorMessage.toLowerCase().includes('refresh') ||
                       errorMessage.toLowerCase().includes('unauthorized') ||
                       errorMessage.toLowerCase().includes('invalid_grant');

  const status = isTokenError ? 'requires_reauth' : 'error';

  await sql`
    UPDATE integrations
    SET status = ${status}, error_message = ${errorMessage}, updated_at = NOW()
    WHERE id = ${integrationId}
  `;
}

/**
 * Create sync result object
 */
function createResult(
  integration: IntegrationRecord,
  emailsProcessed: number,
  emailsSkipped: number,
  threatsFound: number,
  errors: string[],
  detailedErrors: SyncError[],
  startTime: number,
  timedOut: boolean = false
): SyncResult {
  return {
    integrationId: integration.id,
    tenantId: integration.tenant_id,
    type: integration.type as 'o365' | 'gmail',
    emailsProcessed,
    emailsSkipped,
    threatsFound,
    errors,
    detailedErrors,
    duration: Date.now() - startTime,
    timedOut,
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
