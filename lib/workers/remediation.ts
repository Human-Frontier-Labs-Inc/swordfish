/**
 * Email Remediation Service
 * Handles quarantine, release, and delete actions on actual mailboxes
 */

import { sql } from '@/lib/db';
import {
  moveO365Email,
  getOrCreateQuarantineFolder,
  getO365AccessToken,
} from '@/lib/integrations/o365';
import {
  modifyGmailMessage,
  trashGmailMessage,
  untrashGmailMessage,
  findGmailMessageByMessageId,
  getOrCreateQuarantineLabel,
  getGmailAccessToken,
} from '@/lib/integrations/gmail';
import { logAuditEvent } from '@/lib/db/audit';
import { sendNotification } from '@/lib/notifications/service';
import { retryWithBackoff, isRetryable } from '@/lib/performance/retry';
import { loggers } from '@/lib/logging/logger';

const log = loggers.remediation;

/**
 * Retry configuration for email API operations
 * Uses exponential backoff with jitter for transient failures
 */
const REMEDIATION_RETRY_CONFIG = {
  maxAttempts: 3,
  baseDelay: 1000, // 1 second
  maxDelay: 10000, // 10 seconds max
  jitter: true,
};

/**
 * Check if an error from email APIs is retryable
 * Extends default isRetryable with API-specific checks
 */
function isEmailApiRetryable(error: unknown): boolean {
  // Use default retryable check first
  if (isRetryable(error)) return true;

  if (error instanceof Error) {
    const message = error.message.toLowerCase();

    // Gmail API specific errors
    if (
      message.includes('quota exceeded') ||
      message.includes('user rate limit') ||
      message.includes('backend error') ||
      message.includes('internal error')
    ) {
      return true;
    }

    // O365 Graph API specific errors
    if (
      message.includes('activitylimitreached') ||
      message.includes('applicationthrottled') ||
      message.includes('servicenotavailable') ||
      message.includes('toomanyrequests')
    ) {
      return true;
    }
  }

  return false;
}

export type RemediationAction = 'quarantine' | 'release' | 'delete' | 'block';

/**
 * Detect message ID format - helps diagnose data integrity issues
 */
function detectMessageIdFormat(messageId: string): 'gmail' | 'o365' | 'unknown' {
  if (!messageId) return 'unknown';

  // Gmail message IDs are typically alphanumeric without special characters
  // Example: "18e1a2b3c4d5e6f7"
  if (/^[a-zA-Z0-9]+$/.test(messageId) && messageId.length <= 32) {
    return 'gmail';
  }

  // O365/Outlook message IDs contain angle brackets and domain references
  // Example: "<IA4PR10MB8730...@namprd10.prod.outlook.com>"
  if (messageId.includes('@') && (
    messageId.includes('outlook.com') ||
    messageId.includes('namprd') ||
    messageId.includes('prod.outlook') ||
    messageId.startsWith('<') && messageId.endsWith('>')
  )) {
    return 'o365';
  }

  // O365 Graph API message IDs are typically base64-like
  // Example: "AAMkAGIwMjAwMDM0..."
  if (/^AAMk[A-Za-z0-9+/=]+$/.test(messageId)) {
    return 'o365';
  }

  return 'unknown';
}

/**
 * Validate external message ID format matches integration type
 * Only validates when we have a true external_message_id (platform API ID).
 * The RFC 5322 Message-ID header (message_id) can be any format since it's
 * set by the SENDING server - e.g., an email FROM Outlook TO Gmail will have
 * an Outlook-format Message-ID but should be processed by Gmail API.
 *
 * Returns error message if mismatch, null if ok
 */
function validateExternalMessageIdFormat(
  externalMessageId: string | null,
  messageId: string,
  integrationType: 'o365' | 'gmail'
): string | null {
  // Only validate format when we have a proper external_message_id
  // The external_message_id is the platform-specific API message ID (e.g., Gmail ID or O365 Graph ID)
  // It SHOULD match the integration type
  if (externalMessageId) {
    const detectedFormat = detectMessageIdFormat(externalMessageId);

    if (detectedFormat === 'unknown') {
      return null; // Can't validate, proceed
    }

    if (detectedFormat !== integrationType) {
      // This is a real data integrity issue - external_message_id should match integration
      return `External message ID format (${detectedFormat}) does not match integration type (${integrationType}). Data integrity issue - external_message_id should be the ${integrationType} API message ID.`;
    }

    return null;
  }

  // When falling back to message_id (RFC 5322 header), DON'T validate format
  // The Message-ID header is set by the sending server, not the receiving platform
  // An email FROM Outlook TO Gmail will have Outlook-format Message-ID but gmail integration
  const detectedFormat = detectMessageIdFormat(messageId);
  if (detectedFormat !== 'unknown' && detectedFormat !== integrationType) {
    log.debug('Falling back to message_id with cross-platform format', {
      detectedFormat,
      integrationType,
      note: 'Expected for cross-platform emails',
    });
  }

  return null;
}

export interface RemediationResult {
  success: boolean;
  action: RemediationAction;
  messageId: string;
  integrationId: string;
  integrationType: 'o365' | 'gmail';
  error?: string;
}

interface ThreatRecord {
  id: string;
  tenant_id: string;
  message_id: string;
  external_message_id: string | null;
  integration_id: string;
  integration_type: 'o365' | 'gmail';
  status: string;
}

interface IntegrationRecord {
  id: string;
  tenant_id: string;
  type: string;
  config: Record<string, unknown>;
}

/**
 * Quarantine an email - move to quarantine folder/label
 */
export async function quarantineEmail(params: {
  tenantId: string;
  threatId: string;
  actorId: string;
  actorEmail: string | null;
}): Promise<RemediationResult> {
  const { tenantId, threatId, actorId, actorEmail } = params;

  // Get threat details
  const threats = await sql`
    SELECT t.*
    FROM threats t
    WHERE t.id = ${threatId} AND t.tenant_id = ${tenantId}
  ` as Array<ThreatRecord>;

  if (threats.length === 0) {
    return {
      success: false,
      action: 'quarantine',
      messageId: '',
      integrationId: '',
      integrationType: 'o365',
      error: 'Threat not found',
    };
  }

  const threat = threats[0];
  const externalMessageId = threat.external_message_id || threat.message_id;

  // Validate external message ID format matches integration type (only for external_message_id)
  const formatError = validateExternalMessageIdFormat(threat.external_message_id, threat.message_id, threat.integration_type);
  if (formatError) {
    return {
      success: false,
      action: 'quarantine',
      messageId: threat.message_id,
      integrationId: threat.integration_id || '',
      integrationType: threat.integration_type,
      error: formatError,
    };
  }

  try {
    // Use tenantId-based token retrieval (direct OAuth, no Nango)
    if (threat.integration_type === 'o365') {
      await quarantineO365Email(tenantId, externalMessageId);
    } else if (threat.integration_type === 'gmail') {
      await quarantineGmailEmail(tenantId, externalMessageId);
    }

    // Update threat status
    await sql`
      UPDATE threats
      SET status = 'quarantined', quarantined_at = NOW(), quarantined_by = ${actorId}
      WHERE id = ${threatId}
    `;

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId,
      actorEmail,
      action: 'threat.quarantine',
      resourceType: 'threat',
      resourceId: threatId,
      afterState: { status: 'quarantined' },
    });

    // Send notification
    await sendNotification({
      tenantId,
      type: 'threat_quarantined',
      title: 'Email Quarantined',
      message: `A threat has been quarantined by ${actorEmail || 'system'}.`,
      severity: 'info',
      resourceType: 'threat',
      resourceId: threatId,
    });

    return {
      success: true,
      action: 'quarantine',
      messageId: threat.message_id,
      integrationId: threat.integration_id,
      integrationType: threat.integration_type,
    };
  } catch (error) {
    log.error('Quarantine failed', error instanceof Error ? error : new Error(String(error)), { threatId, tenantId });
    return {
      success: false,
      action: 'quarantine',
      messageId: threat.message_id,
      integrationId: threat.integration_id,
      integrationType: threat.integration_type,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Release an email from quarantine - move back to inbox
 */
export async function releaseEmail(params: {
  tenantId: string;
  threatId: string;
  actorId: string;
  actorEmail: string | null;
}): Promise<RemediationResult> {
  const { tenantId, threatId, actorId, actorEmail } = params;

  // Get threat details
  const threats = await sql`
    SELECT t.*
    FROM threats t
    WHERE t.id = ${threatId} AND t.tenant_id = ${tenantId}
  ` as Array<ThreatRecord>;

  if (threats.length === 0) {
    return {
      success: false,
      action: 'release',
      messageId: '',
      integrationId: '',
      integrationType: 'o365',
      error: 'Threat not found',
    };
  }

  const threat = threats[0];
  const externalMessageId = threat.external_message_id || threat.message_id;

  // Validate external message ID format matches integration type (only for external_message_id)
  const formatError = validateExternalMessageIdFormat(threat.external_message_id, threat.message_id, threat.integration_type);
  if (formatError) {
    return {
      success: false,
      action: 'release',
      messageId: threat.message_id,
      integrationId: threat.integration_id || '',
      integrationType: threat.integration_type,
      error: formatError,
    };
  }

  try {
    // Use tenantId-based token retrieval (direct OAuth, no Nango)
    if (threat.integration_type === 'o365') {
      await releaseO365Email(tenantId, externalMessageId);
    } else if (threat.integration_type === 'gmail') {
      // Pass wasDeleted flag so we can untrash before releasing
      await releaseGmailEmail(tenantId, externalMessageId, threat.status === 'deleted');
    }

    // Update threat status
    await sql`
      UPDATE threats
      SET status = 'released', released_at = NOW(), released_by = ${actorId}
      WHERE id = ${threatId}
    `;

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId,
      actorEmail,
      action: 'threat.release',
      resourceType: 'threat',
      resourceId: threatId,
      afterState: { status: 'released' },
    });

    await sendNotification({
      tenantId,
      type: 'threat_released',
      title: 'Email Released from Quarantine',
      message: `A quarantined email has been released by ${actorEmail || 'system'}.`,
      severity: 'warning',
      resourceType: 'threat',
      resourceId: threatId,
    });

    return {
      success: true,
      action: 'release',
      messageId: threat.message_id,
      integrationId: threat.integration_id,
      integrationType: threat.integration_type,
    };
  } catch (error) {
    log.error('Release failed', error instanceof Error ? error : new Error(String(error)), { threatId, tenantId });
    return {
      success: false,
      action: 'release',
      messageId: threat.message_id,
      integrationId: threat.integration_id,
      integrationType: threat.integration_type,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Delete an email permanently
 */
export async function deleteEmail(params: {
  tenantId: string;
  threatId: string;
  actorId: string;
  actorEmail: string | null;
}): Promise<RemediationResult> {
  const { tenantId, threatId, actorId, actorEmail } = params;

  // Get threat details
  const threats = await sql`
    SELECT t.*
    FROM threats t
    WHERE t.id = ${threatId} AND t.tenant_id = ${tenantId}
  ` as Array<ThreatRecord>;

  if (threats.length === 0) {
    return {
      success: false,
      action: 'delete',
      messageId: '',
      integrationId: '',
      integrationType: 'o365',
      error: 'Threat not found',
    };
  }

  const threat = threats[0];
  const externalMessageId = threat.external_message_id || threat.message_id;

  // Validate external message ID format matches integration type (only for external_message_id)
  const formatError = validateExternalMessageIdFormat(threat.external_message_id, threat.message_id, threat.integration_type);
  if (formatError) {
    return {
      success: false,
      action: 'delete',
      messageId: threat.message_id,
      integrationId: threat.integration_id || '',
      integrationType: threat.integration_type,
      error: formatError,
    };
  }

  try {
    // Use tenantId-based token retrieval (direct OAuth, no Nango)
    if (threat.integration_type === 'o365') {
      await deleteO365Email(tenantId, externalMessageId);
    } else if (threat.integration_type === 'gmail') {
      await deleteGmailEmail(tenantId, externalMessageId);
    }

    // Update threat status
    await sql`
      UPDATE threats
      SET status = 'deleted', deleted_at = NOW(), deleted_by = ${actorId}
      WHERE id = ${threatId}
    `;

    // Audit log
    await logAuditEvent({
      tenantId,
      actorId,
      actorEmail,
      action: 'threat.delete',
      resourceType: 'threat',
      resourceId: threatId,
      afterState: { status: 'deleted' },
    });

    return {
      success: true,
      action: 'delete',
      messageId: threat.message_id,
      integrationId: threat.integration_id,
      integrationType: threat.integration_type,
    };
  } catch (error) {
    log.error('Delete failed', error instanceof Error ? error : new Error(String(error)), { threatId, tenantId });
    return {
      success: false,
      action: 'delete',
      messageId: threat.message_id,
      integrationId: threat.integration_id,
      integrationType: threat.integration_type,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Batch remediation for multiple threats
 */
export async function batchRemediate(params: {
  tenantId: string;
  threatIds: string[];
  action: RemediationAction;
  actorId: string;
  actorEmail: string | null;
}): Promise<RemediationResult[]> {
  const { tenantId, threatIds, action, actorId, actorEmail } = params;
  const results: RemediationResult[] = [];

  for (const threatId of threatIds) {
    let result: RemediationResult;

    switch (action) {
      case 'quarantine':
        result = await quarantineEmail({ tenantId, threatId, actorId, actorEmail });
        break;
      case 'release':
        result = await releaseEmail({ tenantId, threatId, actorId, actorEmail });
        break;
      case 'delete':
        result = await deleteEmail({ tenantId, threatId, actorId, actorEmail });
        break;
      default:
        result = {
          success: false,
          action,
          messageId: '',
          integrationId: '',
          integrationType: 'o365',
          error: `Unsupported action: ${action}`,
        };
    }

    results.push(result);
  }

  return results;
}

// ============================================
// O365-specific remediation functions
// ============================================

async function quarantineO365Email(
  tenantId: string,
  messageId: string
): Promise<void> {
  const accessToken = await getO365AccessToken(tenantId);
  const quarantineFolderId = await getOrCreateQuarantineFolder(accessToken);

  await retryWithBackoff(
    async () => {
      await moveO365Email({
        accessToken,
        messageId,
        destinationFolderId: quarantineFolderId,
      });
    },
    {
      ...REMEDIATION_RETRY_CONFIG,
      shouldRetry: isEmailApiRetryable,
      onRetry: (error, attempt) => {
        log.warn('O365 quarantine retry', { attempt, error: error.message });
      },
    }
  );
}

async function releaseO365Email(
  tenantId: string,
  messageId: string
): Promise<void> {
  const accessToken = await getO365AccessToken(tenantId);

  // Move back to inbox with retry
  await retryWithBackoff(
    async () => {
      await moveO365Email({
        accessToken,
        messageId,
        destinationFolderId: 'inbox',
      });
    },
    {
      ...REMEDIATION_RETRY_CONFIG,
      shouldRetry: isEmailApiRetryable,
      onRetry: (error, attempt) => {
        log.warn('O365 release retry', { attempt, error: error.message });
      },
    }
  );
}

async function deleteO365Email(
  tenantId: string,
  messageId: string
): Promise<void> {
  const accessToken = await getO365AccessToken(tenantId);

  // Move to deleted items (Graph API requires this before permanent delete) with retry
  await retryWithBackoff(
    async () => {
      await moveO365Email({
        accessToken,
        messageId,
        destinationFolderId: 'deleteditems',
      });
    },
    {
      ...REMEDIATION_RETRY_CONFIG,
      shouldRetry: isEmailApiRetryable,
      onRetry: (error, attempt) => {
        log.warn('O365 delete retry', { attempt, error: error.message });
      },
    }
  );
}

// ============================================
// Gmail-specific remediation functions
// ============================================

async function quarantineGmailEmail(
  tenantId: string,
  messageId: string
): Promise<void> {
  const accessToken = await getGmailAccessToken(tenantId);
  const quarantineLabelId = await getOrCreateQuarantineLabel(accessToken);

  // Add quarantine label and remove from INBOX with retry
  await retryWithBackoff(
    async () => {
      await modifyGmailMessage({
        accessToken,
        messageId,
        addLabelIds: [quarantineLabelId],
        removeLabelIds: ['INBOX'],
      });
    },
    {
      ...REMEDIATION_RETRY_CONFIG,
      shouldRetry: isEmailApiRetryable,
      onRetry: (error, attempt) => {
        log.warn('Gmail quarantine retry', { attempt, error: error.message });
      },
    }
  );
}

async function releaseGmailEmail(
  tenantId: string,
  messageId: string,
  wasDeleted: boolean = false
): Promise<void> {
  const accessToken = await getGmailAccessToken(tenantId);
  const quarantineLabelId = await getOrCreateQuarantineLabel(accessToken);

  // Check if messageId looks like a Gmail ID (alphanumeric, no special chars except dashes)
  // Gmail IDs are typically hex strings like "18e1a2b3c4d5e6f7"
  // O365/RFC822 Message-IDs contain <, >, @, etc.
  let resolvedMessageId = messageId;
  const looksLikeGmailId = /^[a-zA-Z0-9-]+$/.test(messageId) && !messageId.includes('<');

  if (!looksLikeGmailId) {
    log.info('Message ID does not look like Gmail ID, searching by Message-ID header', { messageId });

    // Try to find the Gmail message ID by searching for the RFC822 Message-ID with retry
    const foundId = await retryWithBackoff(
      async () => {
        return await findGmailMessageByMessageId({
          accessToken,
          rfc822MessageId: messageId,
        });
      },
      {
        ...REMEDIATION_RETRY_CONFIG,
        shouldRetry: isEmailApiRetryable,
        onRetry: (error, attempt) => {
          log.warn('Gmail message search retry', { attempt, error: error.message });
        },
      }
    );

    if (foundId) {
      log.info('Found Gmail ID for Message-ID', { gmailId: foundId, messageId });
      resolvedMessageId = foundId;
    } else {
      // Try without angle brackets if they're present
      const cleanedId = messageId.replace(/^<|>$/g, '');
      if (cleanedId !== messageId) {
        const foundCleanId = await retryWithBackoff(
          async () => {
            return await findGmailMessageByMessageId({
              accessToken,
              rfc822MessageId: cleanedId,
            });
          },
          {
            ...REMEDIATION_RETRY_CONFIG,
            shouldRetry: isEmailApiRetryable,
            onRetry: (error, attempt) => {
              log.warn('Gmail message search retry', { attempt, error: error.message });
            },
          }
        );
        if (foundCleanId) {
          log.info('Found Gmail ID for cleaned Message-ID', { gmailId: foundCleanId, cleanedId });
          resolvedMessageId = foundCleanId;
        }
      }

      if (resolvedMessageId === messageId) {
        // SECURITY FIX: Instead of failing silently or proceeding with wrong ID,
        // log detailed info for troubleshooting and mark for manual review
        log.error('CRITICAL: Gmail message lookup failed, manual review required', {
          messageId,
          cleanedId,
          possibleCauses: [
            'Email was permanently deleted from Gmail',
            'Message-ID header was modified',
            'Email is in a label the integration cannot access',
            'Gmail API rate limit or temporary outage',
          ],
        });

        // Mark for manual review instead of throwing
        throw new Error(
          `Gmail message lookup failed for Message-ID: ${messageId}. ` +
          `Email may have been deleted or Message-ID modified. ` +
          `Manual remediation required via Gmail web interface.`
        );
      }
    }
  }

  // If the email was deleted (trashed), untrash it first with retry
  if (wasDeleted) {
    try {
      await retryWithBackoff(
        async () => {
          await untrashGmailMessage({
            accessToken,
            messageId: resolvedMessageId,
          });
        },
        {
          ...REMEDIATION_RETRY_CONFIG,
          shouldRetry: isEmailApiRetryable,
          onRetry: (error, attempt) => {
            log.warn('Gmail untrash retry', { attempt, error: error.message });
          },
        }
      );
      log.info('Untrashed message', { messageId: resolvedMessageId });
    } catch (err) {
      // If untrash fails, the message might not be in Trash - try to continue
      log.debug('Untrash failed, message may not be in Trash', { error: err instanceof Error ? err.message : String(err) });
    }
  }

  // Remove quarantine label and add back to INBOX with retry
  await retryWithBackoff(
    async () => {
      await modifyGmailMessage({
        accessToken,
        messageId: resolvedMessageId,
        addLabelIds: ['INBOX'],
        removeLabelIds: [quarantineLabelId],
      });
    },
    {
      ...REMEDIATION_RETRY_CONFIG,
      shouldRetry: isEmailApiRetryable,
      onRetry: (error, attempt) => {
        log.warn('Gmail release retry', { attempt, error: error.message });
      },
    }
  );
}

async function deleteGmailEmail(
  tenantId: string,
  messageId: string
): Promise<void> {
  const accessToken = await getGmailAccessToken(tenantId);

  await retryWithBackoff(
    async () => {
      await trashGmailMessage({
        accessToken,
        messageId,
      });
    },
    {
      ...REMEDIATION_RETRY_CONFIG,
      shouldRetry: isEmailApiRetryable,
      onRetry: (error, attempt) => {
        log.warn('Gmail delete retry', { attempt, error: error.message });
      },
    }
  );
}

/**
 * Auto-remediate based on verdict
 * Called by the detection pipeline when a threat is found
 */
export async function autoRemediate(params: {
  tenantId: string;
  messageId: string;
  externalMessageId: string;
  integrationId: string;
  integrationType: 'o365' | 'gmail';
  verdict: 'quarantine' | 'block';
  score: number;
}): Promise<RemediationResult> {
  const { tenantId, messageId, externalMessageId, integrationId, integrationType, verdict, score } = params;

  // Helper to truncate strings for database column limits
  const truncate = (str: string | null | undefined, maxLen: number): string | null => {
    if (!str) return null;
    return str.length > maxLen ? str.substring(0, maxLen - 3) + '...' : str;
  };

  // Verify integration exists (no longer need nango_connection_id)
  const integrations = await sql`
    SELECT id FROM integrations WHERE id = ${integrationId} AND status = 'connected'
  ` as Array<{ id: string }>;

  if (integrations.length === 0) {
    return {
      success: false,
      action: 'quarantine',
      messageId,
      integrationId,
      integrationType,
      error: 'Integration not found or not connected',
    };
  }

  // Truncate values to fit database column constraints
  const safeMessageId = truncate(messageId, 490);
  const safeExternalMessageId = truncate(externalMessageId, 500);

  try {
    // Get email details from email_verdicts for the threats record
    const emailVerdicts = await sql`
      SELECT subject, from_address, to_addresses, signals
      FROM email_verdicts
      WHERE tenant_id = ${tenantId} AND message_id = ${messageId}
      LIMIT 1
    ` as Array<{
      subject: string;
      from_address: string;
      to_addresses: string[];
      signals: unknown;
    }>;

    const emailDetails = emailVerdicts[0] || {
      subject: '(Unknown)',
      from_address: 'unknown@unknown.com',
      to_addresses: [],
      signals: null,
    };

    const safeSubject = truncate(emailDetails.subject, 250);
    const safeSenderEmail = truncate(emailDetails.from_address, 250);
    const safeRecipientEmail = truncate(
      Array.isArray(emailDetails.to_addresses)
        ? emailDetails.to_addresses[0]
        : emailDetails.to_addresses,
      250
    );

    // HIGH-2 FIX: First create/update threat record with 'remediation_pending' status
    // This ensures we can track failures properly
    const existingThreats = await sql`
      SELECT id FROM threats WHERE tenant_id = ${tenantId} AND message_id = ${safeMessageId}
    `;

    if (existingThreats.length > 0) {
      await sql`
        UPDATE threats SET
          status = 'remediation_pending',
          verdict = ${verdict},
          score = ${score},
          integration_id = COALESCE(integration_id, ${integrationId}),
          external_message_id = COALESCE(external_message_id, ${safeExternalMessageId}),
          signals = ${JSON.stringify(emailDetails.signals || [])}::jsonb,
          updated_at = NOW()
        WHERE tenant_id = ${tenantId} AND message_id = ${safeMessageId}
      `;
    } else {
      await sql`
        INSERT INTO threats (
          tenant_id, message_id, external_message_id, subject, sender_email, recipient_email,
          verdict, score, status, integration_id, integration_type, signals, created_at
        ) VALUES (
          ${tenantId},
          ${safeMessageId},
          ${safeExternalMessageId},
          ${safeSubject},
          ${safeSenderEmail},
          ${safeRecipientEmail || ''},
          ${verdict},
          ${score},
          'remediation_pending',
          ${integrationId},
          ${integrationType},
          ${JSON.stringify(emailDetails.signals || [])}::jsonb,
          NOW()
        )
      `;
    }

    // Now attempt the actual quarantine action
    // IMPORTANT: Always quarantine, never delete automatically
    // This allows users to review and release false positives
    try {
      // Use tenantId-based token retrieval (direct OAuth, no Nango)
      if (integrationType === 'o365') {
        await quarantineO365Email(tenantId, externalMessageId);
      } else {
        await quarantineGmailEmail(tenantId, externalMessageId);
      }

      // HIGH-2 FIX: Update to 'quarantined' on success
      await sql`
        UPDATE threats SET
          status = 'quarantined',
          updated_at = NOW()
        WHERE tenant_id = ${tenantId} AND message_id = ${safeMessageId}
      `;

      return {
        success: true,
        action: verdict === 'block' ? 'block' : 'quarantine',
        messageId,
        integrationId,
        integrationType,
      };
    } catch (mailboxError) {
      // HIGH-2 FIX: Update to 'remediation_failed' on mailbox operation failure
      // This prevents showing 'quarantined' when the email wasn't actually moved
      const errorMessage = mailboxError instanceof Error ? mailboxError.message : 'Unknown mailbox error';

      await sql`
        UPDATE threats SET
          status = 'remediation_failed',
          error_message = ${truncate(errorMessage, 500)},
          updated_at = NOW()
        WHERE tenant_id = ${tenantId} AND message_id = ${safeMessageId}
      `;

      log.error('Mailbox operation failed, status set to remediation_failed', mailboxError instanceof Error ? mailboxError : new Error(String(mailboxError)), { tenantId, messageId });

      return {
        success: false,
        action: verdict === 'block' ? 'block' : 'quarantine',
        messageId,
        integrationId,
        integrationType,
        error: `Mailbox operation failed: ${errorMessage}`,
      };
    }
  } catch (error) {
    // HIGH-2 FIX: If we fail before DB write, try to mark as failed if record exists
    log.error('Auto-remediation failed', error instanceof Error ? error : new Error(String(error)), { tenantId, messageId });

    try {
      await sql`
        UPDATE threats SET
          status = 'remediation_failed',
          error_message = ${truncate(error instanceof Error ? error.message : 'Unknown error', 500)},
          updated_at = NOW()
        WHERE tenant_id = ${tenantId} AND message_id = ${safeMessageId}
      `;
    } catch (dbError) {
      log.error('Failed to update threat status after error', dbError instanceof Error ? dbError : new Error(String(dbError)));
    }

    return {
      success: false,
      action: verdict === 'block' ? 'block' : 'quarantine',
      messageId,
      integrationId,
      integrationType,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
