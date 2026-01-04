/**
 * Email Remediation Service
 * Handles quarantine, release, and delete actions on actual mailboxes
 */

import { sql } from '@/lib/db';
import {
  moveO365Email,
  getOrCreateQuarantineFolder,
  getO365Email,
  refreshO365Token,
} from '@/lib/integrations/o365';
import {
  modifyGmailMessage,
  trashGmailMessage,
  getOrCreateQuarantineLabel,
  getGmailMessage,
  refreshGmailToken,
} from '@/lib/integrations/gmail';
import { logAuditEvent } from '@/lib/db/audit';
import { sendNotification } from '@/lib/notifications/service';

const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID!;
const MICROSOFT_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET!;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;

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
    SELECT t.*, i.type as integration_type, i.config as integration_config
    FROM threats t
    JOIN integrations i ON t.integration_id = i.id
    WHERE t.id = ${threatId} AND t.tenant_id = ${tenantId}
  ` as Array<ThreatRecord & { integration_config: Record<string, unknown> }>;

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

  try {
    if (threat.integration_type === 'o365') {
      await quarantineO365Email(threat.integration_id, externalMessageId, threat.integration_config);
    } else if (threat.integration_type === 'gmail') {
      await quarantineGmailEmail(threat.integration_id, externalMessageId, threat.integration_config);
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

  const threats = await sql`
    SELECT t.*, i.type as integration_type, i.config as integration_config
    FROM threats t
    JOIN integrations i ON t.integration_id = i.id
    WHERE t.id = ${threatId} AND t.tenant_id = ${tenantId}
  ` as Array<ThreatRecord & { integration_config: Record<string, unknown> }>;

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

  try {
    if (threat.integration_type === 'o365') {
      await releaseO365Email(threat.integration_id, externalMessageId, threat.integration_config);
    } else if (threat.integration_type === 'gmail') {
      await releaseGmailEmail(threat.integration_id, externalMessageId, threat.integration_config);
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

  const threats = await sql`
    SELECT t.*, i.type as integration_type, i.config as integration_config
    FROM threats t
    JOIN integrations i ON t.integration_id = i.id
    WHERE t.id = ${threatId} AND t.tenant_id = ${tenantId}
  ` as Array<ThreatRecord & { integration_config: Record<string, unknown> }>;

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

  try {
    if (threat.integration_type === 'o365') {
      await deleteO365Email(threat.integration_id, externalMessageId, threat.integration_config);
    } else if (threat.integration_type === 'gmail') {
      await deleteGmailEmail(threat.integration_id, externalMessageId, threat.integration_config);
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

async function getO365AccessToken(
  integrationId: string,
  config: Record<string, unknown>
): Promise<string> {
  const accessToken = config.accessToken as string;
  const refreshToken = config.refreshToken as string;
  const tokenExpiresAt = config.tokenExpiresAt as string;

  if (new Date(tokenExpiresAt) > new Date()) {
    return accessToken;
  }

  // Refresh the token
  const newTokens = await refreshO365Token({
    refreshToken,
    clientId: MICROSOFT_CLIENT_ID,
    clientSecret: MICROSOFT_CLIENT_SECRET,
  });

  // Update stored tokens
  await sql`
    UPDATE integrations
    SET config = config || ${JSON.stringify({
      accessToken: newTokens.accessToken,
      refreshToken: newTokens.refreshToken || refreshToken,
      tokenExpiresAt: newTokens.expiresAt.toISOString(),
    })}::jsonb,
    updated_at = NOW()
    WHERE id = ${integrationId}
  `;

  return newTokens.accessToken;
}

async function quarantineO365Email(
  integrationId: string,
  messageId: string,
  config: Record<string, unknown>
): Promise<void> {
  const accessToken = await getO365AccessToken(integrationId, config);
  const quarantineFolderId = await getOrCreateQuarantineFolder(accessToken);

  await moveO365Email({
    accessToken,
    messageId,
    destinationFolderId: quarantineFolderId,
  });
}

async function releaseO365Email(
  integrationId: string,
  messageId: string,
  config: Record<string, unknown>
): Promise<void> {
  const accessToken = await getO365AccessToken(integrationId, config);

  // Move back to inbox
  await moveO365Email({
    accessToken,
    messageId,
    destinationFolderId: 'inbox',
  });
}

async function deleteO365Email(
  integrationId: string,
  messageId: string,
  config: Record<string, unknown>
): Promise<void> {
  const accessToken = await getO365AccessToken(integrationId, config);

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

async function getGmailAccessToken(
  integrationId: string,
  config: Record<string, unknown>
): Promise<string> {
  const accessToken = config.accessToken as string;
  const refreshToken = config.refreshToken as string;
  const tokenExpiresAt = config.tokenExpiresAt as string;

  if (new Date(tokenExpiresAt) > new Date()) {
    return accessToken;
  }

  // Refresh the token
  const newTokens = await refreshGmailToken({
    refreshToken,
    clientId: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
  });

  // Update stored tokens
  await sql`
    UPDATE integrations
    SET config = config || ${JSON.stringify({
      accessToken: newTokens.accessToken,
      tokenExpiresAt: newTokens.expiresAt.toISOString(),
    })}::jsonb,
    updated_at = NOW()
    WHERE id = ${integrationId}
  `;

  return newTokens.accessToken;
}

async function quarantineGmailEmail(
  integrationId: string,
  messageId: string,
  config: Record<string, unknown>
): Promise<void> {
  const accessToken = await getGmailAccessToken(integrationId, config);
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
  integrationId: string,
  messageId: string,
  config: Record<string, unknown>
): Promise<void> {
  const accessToken = await getGmailAccessToken(integrationId, config);
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
  integrationId: string,
  messageId: string,
  config: Record<string, unknown>
): Promise<void> {
  const accessToken = await getGmailAccessToken(integrationId, config);

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
  const { tenantId, messageId, externalMessageId, integrationId, integrationType, verdict } = params;

  // Get integration config
  const integrations = await sql`
    SELECT config FROM integrations WHERE id = ${integrationId}
  ` as Array<{ config: Record<string, unknown> }>;

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

  const config = integrations[0].config;

  try {
    if (verdict === 'block') {
      // Delete immediately for blocked emails
      if (integrationType === 'o365') {
        await deleteO365Email(integrationId, externalMessageId, config);
      } else {
        await deleteGmailEmail(integrationId, externalMessageId, config);
      }

      return {
        success: true,
        action: 'block',
        messageId,
        integrationId,
        integrationType,
      };
    } else {
      // Quarantine for suspicious emails
      if (integrationType === 'o365') {
        await quarantineO365Email(integrationId, externalMessageId, config);
      } else {
        await quarantineGmailEmail(integrationId, externalMessageId, config);
      }

      return {
        success: true,
        action: 'quarantine',
        messageId,
        integrationId,
        integrationType,
      };
    }
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
