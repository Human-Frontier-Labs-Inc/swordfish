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
  getOrCreateQuarantineLabel,
  getGmailAccessToken,
} from '@/lib/integrations/gmail';
import { logAuditEvent } from '@/lib/db/audit';
import { sendNotification } from '@/lib/notifications/service';

export type RemediationAction = 'quarantine' | 'release' | 'delete' | 'block';

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
  nango_connection_id: string | null;
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

  // Get threat details - use LEFT JOIN to handle NULL integration_id
  const threats = await sql`
    SELECT t.*, i.type as i_type, i.nango_connection_id
    FROM threats t
    LEFT JOIN integrations i ON t.integration_id = i.id
    WHERE t.id = ${threatId} AND t.tenant_id = ${tenantId}
  ` as Array<ThreatRecord & { i_type: string | null; nango_connection_id: string | null }>;

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

  // If no nango_connection_id from JOIN, look up by tenant and integration_type
  let nangoConnectionId = threat.nango_connection_id;
  if (!nangoConnectionId && threat.integration_type) {
    const integrations = await sql`
      SELECT nango_connection_id FROM integrations
      WHERE tenant_id = ${tenantId} AND type = ${threat.integration_type}
      LIMIT 1
    ` as Array<{ nango_connection_id: string | null }>;
    if (integrations.length > 0) {
      nangoConnectionId = integrations[0].nango_connection_id;
    }
  }

  if (!nangoConnectionId) {
    return {
      success: false,
      action: 'quarantine',
      messageId: threat.message_id,
      integrationId: threat.integration_id || '',
      integrationType: threat.integration_type,
      error: 'No Nango connection configured',
    };
  }

  try {
    if (threat.integration_type === 'o365') {
      await quarantineO365Email(nangoConnectionId, externalMessageId);
    } else if (threat.integration_type === 'gmail') {
      await quarantineGmailEmail(nangoConnectionId, externalMessageId);
    }

    // Update threat status
    await sql`
      UPDATE threats
      SET status = 'quarantined', remediation_at = NOW(), remediated_by = ${actorId}
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
    console.error('Quarantine failed:', error);
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

  // Use LEFT JOIN to handle NULL integration_id
  const threats = await sql`
    SELECT t.*, i.type as i_type, i.nango_connection_id
    FROM threats t
    LEFT JOIN integrations i ON t.integration_id = i.id
    WHERE t.id = ${threatId} AND t.tenant_id = ${tenantId}
  ` as Array<ThreatRecord & { i_type: string | null; nango_connection_id: string | null }>;

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

  // If no nango_connection_id from JOIN, look up by tenant and integration_type
  let nangoConnectionId = threat.nango_connection_id;
  if (!nangoConnectionId && threat.integration_type) {
    const integrations = await sql`
      SELECT nango_connection_id FROM integrations
      WHERE tenant_id = ${tenantId} AND type = ${threat.integration_type}
      LIMIT 1
    ` as Array<{ nango_connection_id: string | null }>;
    if (integrations.length > 0) {
      nangoConnectionId = integrations[0].nango_connection_id;
    }
  }

  if (!nangoConnectionId) {
    return {
      success: false,
      action: 'release',
      messageId: threat.message_id,
      integrationId: threat.integration_id || '',
      integrationType: threat.integration_type,
      error: 'No Nango connection configured',
    };
  }

  try {
    if (threat.integration_type === 'o365') {
      await releaseO365Email(nangoConnectionId, externalMessageId);
    } else if (threat.integration_type === 'gmail') {
      await releaseGmailEmail(nangoConnectionId, externalMessageId);
    }

    // Update threat status
    await sql`
      UPDATE threats
      SET status = 'released', remediation_at = NOW(), remediated_by = ${actorId}
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
    console.error('Release failed:', error);
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

  // Use LEFT JOIN to handle NULL integration_id
  const threats = await sql`
    SELECT t.*, i.type as i_type, i.nango_connection_id
    FROM threats t
    LEFT JOIN integrations i ON t.integration_id = i.id
    WHERE t.id = ${threatId} AND t.tenant_id = ${tenantId}
  ` as Array<ThreatRecord & { i_type: string | null; nango_connection_id: string | null }>;

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

  // If no nango_connection_id from JOIN, look up by tenant and integration_type
  let nangoConnectionId = threat.nango_connection_id;
  if (!nangoConnectionId && threat.integration_type) {
    const integrations = await sql`
      SELECT nango_connection_id FROM integrations
      WHERE tenant_id = ${tenantId} AND type = ${threat.integration_type}
      LIMIT 1
    ` as Array<{ nango_connection_id: string | null }>;
    if (integrations.length > 0) {
      nangoConnectionId = integrations[0].nango_connection_id;
    }
  }

  if (!nangoConnectionId) {
    return {
      success: false,
      action: 'delete',
      messageId: threat.message_id,
      integrationId: threat.integration_id || '',
      integrationType: threat.integration_type,
      error: 'No Nango connection configured',
    };
  }

  try {
    if (threat.integration_type === 'o365') {
      await deleteO365Email(nangoConnectionId, externalMessageId);
    } else if (threat.integration_type === 'gmail') {
      await deleteGmailEmail(nangoConnectionId, externalMessageId);
    }

    // Update threat status
    await sql`
      UPDATE threats
      SET status = 'deleted', remediation_at = NOW(), remediated_by = ${actorId}
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
    console.error('Delete failed:', error);
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
  nangoConnectionId: string,
  messageId: string
): Promise<void> {
  const accessToken = await getO365AccessToken(nangoConnectionId);
  const quarantineFolderId = await getOrCreateQuarantineFolder(accessToken);

  await moveO365Email({
    accessToken,
    messageId,
    destinationFolderId: quarantineFolderId,
  });
}

async function releaseO365Email(
  nangoConnectionId: string,
  messageId: string
): Promise<void> {
  const accessToken = await getO365AccessToken(nangoConnectionId);

  // Move back to inbox
  await moveO365Email({
    accessToken,
    messageId,
    destinationFolderId: 'inbox',
  });
}

async function deleteO365Email(
  nangoConnectionId: string,
  messageId: string
): Promise<void> {
  const accessToken = await getO365AccessToken(nangoConnectionId);

  // Move to deleted items (Graph API requires this before permanent delete)
  await moveO365Email({
    accessToken,
    messageId,
    destinationFolderId: 'deleteditems',
  });
}

// ============================================
// Gmail-specific remediation functions
// ============================================

async function quarantineGmailEmail(
  nangoConnectionId: string,
  messageId: string
): Promise<void> {
  const accessToken = await getGmailAccessToken(nangoConnectionId);
  const quarantineLabelId = await getOrCreateQuarantineLabel(accessToken);

  // Add quarantine label and remove from INBOX
  await modifyGmailMessage({
    accessToken,
    messageId,
    addLabelIds: [quarantineLabelId],
    removeLabelIds: ['INBOX'],
  });
}

async function releaseGmailEmail(
  nangoConnectionId: string,
  messageId: string
): Promise<void> {
  const accessToken = await getGmailAccessToken(nangoConnectionId);
  const quarantineLabelId = await getOrCreateQuarantineLabel(accessToken);

  // Remove quarantine label and add back to INBOX
  await modifyGmailMessage({
    accessToken,
    messageId,
    addLabelIds: ['INBOX'],
    removeLabelIds: [quarantineLabelId],
  });
}

async function deleteGmailEmail(
  nangoConnectionId: string,
  messageId: string
): Promise<void> {
  const accessToken = await getGmailAccessToken(nangoConnectionId);

  await trashGmailMessage({
    accessToken,
    messageId,
  });
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

  // Get integration nango_connection_id
  const integrations = await sql`
    SELECT nango_connection_id FROM integrations WHERE id = ${integrationId}
  ` as Array<{ nango_connection_id: string | null }>;

  if (integrations.length === 0) {
    return {
      success: false,
      action: 'quarantine',
      messageId,
      integrationId,
      integrationType,
      error: 'Integration not found',
    };
  }

  const nangoConnectionId = integrations[0].nango_connection_id;

  if (!nangoConnectionId) {
    return {
      success: false,
      action: verdict === 'block' ? 'block' : 'quarantine',
      messageId,
      integrationId,
      integrationType,
      error: 'No Nango connection configured',
    };
  }

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

    const status = verdict === 'block' ? 'deleted' : 'quarantined';

    // Truncate values to fit database column constraints
    const safeMessageId = truncate(messageId, 490);
    const safeSubject = truncate(emailDetails.subject, 250);
    const safeSenderEmail = truncate(emailDetails.from_address, 250);
    const safeRecipientEmail = truncate(
      Array.isArray(emailDetails.to_addresses)
        ? emailDetails.to_addresses[0]
        : emailDetails.to_addresses,
      250
    );

    if (verdict === 'block') {
      // Delete immediately for blocked emails
      if (integrationType === 'o365') {
        await deleteO365Email(nangoConnectionId, externalMessageId);
      } else {
        await deleteGmailEmail(nangoConnectionId, externalMessageId);
      }
    } else {
      // Quarantine for suspicious emails
      if (integrationType === 'o365') {
        await quarantineO365Email(nangoConnectionId, externalMessageId);
      } else {
        await quarantineGmailEmail(nangoConnectionId, externalMessageId);
      }
    }

    // Write to threats table so it appears in Threats/Quarantine pages
    // Use only columns that exist in the original migration (002_policies_and_threats.sql)
    // First check if threat already exists
    const existingThreats = await sql`
      SELECT id FROM threats WHERE tenant_id = ${tenantId} AND message_id = ${safeMessageId}
    `;

    if (existingThreats.length > 0) {
      // Update existing threat - also set integration_id if missing
      await sql`
        UPDATE threats SET
          status = ${status},
          verdict = ${verdict},
          score = ${score},
          integration_id = COALESCE(integration_id, ${integrationId}),
          signals = ${JSON.stringify(emailDetails.signals || [])}::jsonb,
          updated_at = NOW()
        WHERE tenant_id = ${tenantId} AND message_id = ${safeMessageId}
      `;
    } else {
      // Insert new threat - include integration_id for proper remediation later
      await sql`
        INSERT INTO threats (
          tenant_id, message_id, subject, sender_email, recipient_email,
          verdict, score, status, integration_id, integration_type, signals, created_at
        ) VALUES (
          ${tenantId},
          ${safeMessageId},
          ${safeSubject},
          ${safeSenderEmail},
          ${safeRecipientEmail || ''},
          ${verdict},
          ${score},
          ${status},
          ${integrationId},
          ${integrationType},
          ${JSON.stringify(emailDetails.signals || [])}::jsonb,
          NOW()
        )
      `;
    }

    return {
      success: true,
      action: verdict === 'block' ? 'block' : 'quarantine',
      messageId,
      integrationId,
      integrationType,
    };
  } catch (error) {
    console.error('Auto-remediation failed:', error);
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
