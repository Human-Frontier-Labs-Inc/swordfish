/**
 * Quarantine Service
 * Handles moving, releasing, and deleting quarantined emails
 */

import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';
import type { EmailVerdict } from '@/lib/detection/types';

export type QuarantineAction = 'quarantine' | 'release' | 'delete' | 'report_false_positive';

export interface QuarantineResult {
  success: boolean;
  messageId: string;
  action: QuarantineAction;
  error?: string;
}

export interface ThreatRecord {
  id: string;
  tenantId: string;
  messageId: string;
  subject: string;
  senderEmail: string;
  recipientEmail: string;
  verdict: EmailVerdict['verdict'];
  score: number;
  status: 'quarantined' | 'released' | 'deleted' | 'delivered';
  originalFolder?: string;
  provider: 'microsoft' | 'google' | 'smtp';
  providerMessageId?: string;
  quarantinedAt: Date;
  releasedAt?: Date;
  releasedBy?: string;
}

/**
 * Quarantine an email - move to quarantine folder and record in database
 */
export async function quarantineEmail(
  tenantId: string,
  email: {
    messageId: string;
    subject: string;
    from: string;
    to: string;
    receivedAt: Date;
  },
  verdict: EmailVerdict,
  provider: 'microsoft' | 'google' | 'smtp',
  providerMessageId?: string
): Promise<QuarantineResult> {
  try {
    // Store threat record in database
    const result = await sql`
      INSERT INTO threats (
        tenant_id, message_id, subject, sender_email, recipient_email,
        verdict, score, status, provider, provider_message_id, quarantined_at
      ) VALUES (
        ${tenantId},
        ${email.messageId},
        ${email.subject},
        ${email.from},
        ${email.to},
        ${verdict.verdict},
        ${verdict.overallScore},
        'quarantined',
        ${provider},
        ${providerMessageId || null},
        NOW()
      )
      ON CONFLICT (tenant_id, message_id)
      DO UPDATE SET
        status = 'quarantined',
        verdict = ${verdict.verdict},
        score = ${verdict.overallScore},
        quarantined_at = NOW()
      RETURNING id
    `;

    // Move email in provider (delegate to provider-specific service)
    if (provider === 'microsoft') {
      await moveToMicrosoftQuarantine(tenantId, providerMessageId!);
    } else if (provider === 'google') {
      await moveToGmailQuarantine(tenantId, providerMessageId!);
    }

    await logAuditEvent({
      tenantId,
      actorId: 'system',
      actorEmail: null,
      action: 'threat.quarantine',
      resourceType: 'threat',
      resourceId: result[0].id as string,
      afterState: {
        messageId: email.messageId,
        verdict: verdict.verdict,
        score: verdict.overallScore,
      },
    });

    return {
      success: true,
      messageId: email.messageId,
      action: 'quarantine',
    };
  } catch (error) {
    console.error('Quarantine error:', error);
    return {
      success: false,
      messageId: email.messageId,
      action: 'quarantine',
      error: error instanceof Error ? error.message : 'Quarantine failed',
    };
  }
}

/**
 * Release an email from quarantine - move back to inbox
 */
export async function releaseEmail(
  tenantId: string,
  threatId: string,
  userId: string,
  addToAllowlist: boolean = false
): Promise<QuarantineResult> {
  try {
    // Get threat record
    const threats = await sql`
      SELECT * FROM threats
      WHERE id = ${threatId}
      AND tenant_id = ${tenantId}
      AND status = 'quarantined'
    `;

    if (threats.length === 0) {
      return {
        success: false,
        messageId: '',
        action: 'release',
        error: 'Threat not found or not quarantined',
      };
    }

    const threat = threats[0];

    // Move email back in provider
    if (threat.provider === 'microsoft') {
      await releaseFromMicrosoftQuarantine(tenantId, threat.provider_message_id);
    } else if (threat.provider === 'google') {
      await releaseFromGmailQuarantine(tenantId, threat.provider_message_id);
    }

    // Update threat status
    await sql`
      UPDATE threats
      SET status = 'released', released_at = NOW(), released_by = ${userId}
      WHERE id = ${threatId}
    `;

    // Optionally add sender to allowlist
    if (addToAllowlist && threat.sender_email) {
      const domain = threat.sender_email.split('@')[1];
      await sql`
        INSERT INTO list_entries (
          tenant_id, list_type, entry_type, value, reason, created_by
        ) VALUES (
          ${tenantId}, 'allowlist', 'email', ${threat.sender_email.toLowerCase()},
          'Released from quarantine', ${userId}
        )
        ON CONFLICT (tenant_id, list_type, entry_type, value) DO NOTHING
      `;
    }

    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'threat.release',
      resourceType: 'threat',
      resourceId: threatId,
      afterState: {
        messageId: threat.message_id,
        addedToAllowlist: addToAllowlist,
      },
    });

    return {
      success: true,
      messageId: threat.message_id as string,
      action: 'release',
    };
  } catch (error) {
    console.error('Release error:', error);
    return {
      success: false,
      messageId: '',
      action: 'release',
      error: error instanceof Error ? error.message : 'Release failed',
    };
  }
}

/**
 * Permanently delete a quarantined email
 */
export async function deleteQuarantinedEmail(
  tenantId: string,
  threatId: string,
  userId: string
): Promise<QuarantineResult> {
  try {
    // Get threat record
    const threats = await sql`
      SELECT * FROM threats
      WHERE id = ${threatId}
      AND tenant_id = ${tenantId}
    `;

    if (threats.length === 0) {
      return {
        success: false,
        messageId: '',
        action: 'delete',
        error: 'Threat not found',
      };
    }

    const threat = threats[0];

    // Delete email in provider
    if (threat.provider === 'microsoft') {
      await deleteFromMicrosoft(tenantId, threat.provider_message_id);
    } else if (threat.provider === 'google') {
      await deleteFromGmail(tenantId, threat.provider_message_id);
    }

    // Update threat status
    await sql`
      UPDATE threats
      SET status = 'deleted', released_at = NOW(), released_by = ${userId}
      WHERE id = ${threatId}
    `;

    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'threat.delete',
      resourceType: 'threat',
      resourceId: threatId,
      afterState: { messageId: threat.message_id },
    });

    return {
      success: true,
      messageId: threat.message_id as string,
      action: 'delete',
    };
  } catch (error) {
    console.error('Delete error:', error);
    return {
      success: false,
      messageId: '',
      action: 'delete',
      error: error instanceof Error ? error.message : 'Delete failed',
    };
  }
}

/**
 * Report email as false positive
 */
export async function reportFalsePositive(
  tenantId: string,
  threatId: string,
  userId: string,
  notes?: string
): Promise<QuarantineResult> {
  try {
    // Release the email first
    const releaseResult = await releaseEmail(tenantId, threatId, userId, true);
    if (!releaseResult.success) {
      return releaseResult;
    }

    // Log the false positive report
    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'threat.false_positive',
      resourceType: 'threat',
      resourceId: threatId,
      afterState: { notes },
    });

    // Store false positive for ML training
    await sql`
      INSERT INTO feedback (
        tenant_id, threat_id, feedback_type, notes, created_by, created_at
      ) VALUES (
        ${tenantId}, ${threatId}, 'false_positive', ${notes || null}, ${userId}, NOW()
      )
      ON CONFLICT DO NOTHING
    `;

    return {
      success: true,
      messageId: releaseResult.messageId,
      action: 'report_false_positive',
    };
  } catch (error) {
    console.error('False positive report error:', error);
    return {
      success: false,
      messageId: '',
      action: 'report_false_positive',
      error: error instanceof Error ? error.message : 'Report failed',
    };
  }
}

/**
 * Get quarantined threats for a tenant
 */
export async function getQuarantinedThreats(
  tenantId: string,
  options: {
    status?: 'quarantined' | 'released' | 'deleted' | 'all';
    limit?: number;
    offset?: number;
  } = {}
): Promise<ThreatRecord[]> {
  const { status = 'quarantined', limit = 50, offset = 0 } = options;

  let threats;
  if (status === 'all') {
    threats = await sql`
      SELECT * FROM threats
      WHERE tenant_id = ${tenantId}
      ORDER BY quarantined_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `;
  } else {
    threats = await sql`
      SELECT * FROM threats
      WHERE tenant_id = ${tenantId}
      AND status = ${status}
      ORDER BY quarantined_at DESC
      LIMIT ${limit} OFFSET ${offset}
    `;
  }

  return threats.map((t: Record<string, unknown>) => ({
    id: t.id as string,
    tenantId: t.tenant_id as string,
    messageId: t.message_id as string,
    subject: t.subject as string,
    senderEmail: t.sender_email as string,
    recipientEmail: t.recipient_email as string,
    verdict: t.verdict as EmailVerdict['verdict'],
    score: t.score as number,
    status: t.status as ThreatRecord['status'],
    originalFolder: t.original_folder as string | undefined,
    provider: t.provider as ThreatRecord['provider'],
    providerMessageId: t.provider_message_id as string | undefined,
    quarantinedAt: new Date(t.quarantined_at as string),
    releasedAt: t.released_at ? new Date(t.released_at as string) : undefined,
    releasedBy: t.released_by as string | undefined,
  }));
}

/**
 * Get threat statistics for dashboard
 */
export async function getThreatStats(tenantId: string) {
  const stats = await sql`
    SELECT
      COUNT(*) FILTER (WHERE status = 'quarantined') as quarantined_count,
      COUNT(*) FILTER (WHERE status = 'released') as released_count,
      COUNT(*) FILTER (WHERE status = 'deleted') as deleted_count,
      COUNT(*) FILTER (WHERE quarantined_at > NOW() - INTERVAL '24 hours') as last_24h,
      COUNT(*) FILTER (WHERE quarantined_at > NOW() - INTERVAL '7 days') as last_7d,
      AVG(score) FILTER (WHERE status = 'quarantined') as avg_score
    FROM threats
    WHERE tenant_id = ${tenantId}
  `;

  return {
    quarantinedCount: Number(stats[0].quarantined_count) || 0,
    releasedCount: Number(stats[0].released_count) || 0,
    deletedCount: Number(stats[0].deleted_count) || 0,
    last24Hours: Number(stats[0].last_24h) || 0,
    last7Days: Number(stats[0].last_7d) || 0,
    avgScore: Math.round(Number(stats[0].avg_score) || 0),
  };
}

// ============================================
// Provider-specific implementations
// ============================================

/**
 * Move email to quarantine folder in Microsoft 365
 */
async function moveToMicrosoftQuarantine(
  tenantId: string,
  messageId: string
): Promise<void> {
  const integration = await getIntegration(tenantId, 'microsoft');
  if (!integration) {
    throw new Error('Microsoft integration not configured');
  }

  const accessToken = await refreshMicrosoftToken(integration);

  // Get or create quarantine folder
  const quarantineFolderId = await getOrCreateMicrosoftFolder(
    accessToken,
    'Swordfish Quarantine'
  );

  // Move message to quarantine folder
  const response = await fetch(
    `https://graph.microsoft.com/v1.0/me/messages/${messageId}/move`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        destinationId: quarantineFolderId,
      }),
    }
  );

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to move message: ${error}`);
  }
}

/**
 * Release email from Microsoft quarantine back to inbox
 */
async function releaseFromMicrosoftQuarantine(
  tenantId: string,
  messageId: string
): Promise<void> {
  const integration = await getIntegration(tenantId, 'microsoft');
  if (!integration) {
    throw new Error('Microsoft integration not configured');
  }

  const accessToken = await refreshMicrosoftToken(integration);

  // Move message back to inbox
  const response = await fetch(
    `https://graph.microsoft.com/v1.0/me/messages/${messageId}/move`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        destinationId: 'inbox',
      }),
    }
  );

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to release message: ${error}`);
  }
}

/**
 * Permanently delete email from Microsoft
 */
async function deleteFromMicrosoft(
  tenantId: string,
  messageId: string
): Promise<void> {
  const integration = await getIntegration(tenantId, 'microsoft');
  if (!integration) {
    throw new Error('Microsoft integration not configured');
  }

  const accessToken = await refreshMicrosoftToken(integration);

  const response = await fetch(
    `https://graph.microsoft.com/v1.0/me/messages/${messageId}`,
    {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }
  );

  if (!response.ok && response.status !== 404) {
    const error = await response.text();
    throw new Error(`Failed to delete message: ${error}`);
  }
}

/**
 * Move email to quarantine label in Gmail
 */
async function moveToGmailQuarantine(
  tenantId: string,
  messageId: string
): Promise<void> {
  const integration = await getIntegration(tenantId, 'google');
  if (!integration) {
    throw new Error('Gmail integration not configured');
  }

  const accessToken = await refreshGoogleToken(integration);

  // Get or create quarantine label
  const quarantineLabelId = await getOrCreateGmailLabel(
    accessToken,
    'Swordfish-Quarantine'
  );

  // Modify labels: add quarantine, remove INBOX
  const response = await fetch(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}/modify`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        addLabelIds: [quarantineLabelId],
        removeLabelIds: ['INBOX'],
      }),
    }
  );

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to quarantine message: ${error}`);
  }
}

/**
 * Release email from Gmail quarantine back to inbox
 */
async function releaseFromGmailQuarantine(
  tenantId: string,
  messageId: string
): Promise<void> {
  const integration = await getIntegration(tenantId, 'google');
  if (!integration) {
    throw new Error('Gmail integration not configured');
  }

  const accessToken = await refreshGoogleToken(integration);

  const quarantineLabelId = await getOrCreateGmailLabel(
    accessToken,
    'Swordfish-Quarantine'
  );

  // Modify labels: remove quarantine, add INBOX
  const response = await fetch(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}/modify`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        addLabelIds: ['INBOX'],
        removeLabelIds: [quarantineLabelId],
      }),
    }
  );

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to release message: ${error}`);
  }
}

/**
 * Permanently delete email from Gmail
 */
async function deleteFromGmail(
  tenantId: string,
  messageId: string
): Promise<void> {
  const integration = await getIntegration(tenantId, 'google');
  if (!integration) {
    throw new Error('Gmail integration not configured');
  }

  const accessToken = await refreshGoogleToken(integration);

  const response = await fetch(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}`,
    {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }
  );

  if (!response.ok && response.status !== 404) {
    const error = await response.text();
    throw new Error(`Failed to delete message: ${error}`);
  }
}

// ============================================
// Helper functions
// ============================================

async function getIntegration(tenantId: string, provider: string) {
  const integrations = await sql`
    SELECT * FROM integrations
    WHERE tenant_id = ${tenantId}
    AND provider = ${provider}
    AND status = 'active'
    LIMIT 1
  `;
  return integrations[0] || null;
}

async function refreshMicrosoftToken(
  integration: Record<string, unknown>
): Promise<string> {
  // Check if token is still valid
  const expiresAt = new Date(integration.token_expires_at as string);
  if (expiresAt > new Date()) {
    return integration.access_token as string;
  }

  // Refresh token
  const response = await fetch(
    'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.MICROSOFT_CLIENT_ID!,
        client_secret: process.env.MICROSOFT_CLIENT_SECRET!,
        refresh_token: integration.refresh_token as string,
        grant_type: 'refresh_token',
      }),
    }
  );

  if (!response.ok) {
    throw new Error('Failed to refresh Microsoft token');
  }

  const tokens = await response.json();

  // Update stored tokens
  await sql`
    UPDATE integrations
    SET
      access_token = ${tokens.access_token},
      refresh_token = ${tokens.refresh_token || integration.refresh_token},
      token_expires_at = ${new Date(Date.now() + tokens.expires_in * 1000).toISOString()}
    WHERE id = ${integration.id}
  `;

  return tokens.access_token;
}

async function refreshGoogleToken(
  integration: Record<string, unknown>
): Promise<string> {
  const expiresAt = new Date(integration.token_expires_at as string);
  if (expiresAt > new Date()) {
    return integration.access_token as string;
  }

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID!,
      client_secret: process.env.GOOGLE_CLIENT_SECRET!,
      refresh_token: integration.refresh_token as string,
      grant_type: 'refresh_token',
    }),
  });

  if (!response.ok) {
    throw new Error('Failed to refresh Google token');
  }

  const tokens = await response.json();

  await sql`
    UPDATE integrations
    SET
      access_token = ${tokens.access_token},
      token_expires_at = ${new Date(Date.now() + tokens.expires_in * 1000).toISOString()}
    WHERE id = ${integration.id}
  `;

  return tokens.access_token;
}

async function getOrCreateMicrosoftFolder(
  accessToken: string,
  folderName: string
): Promise<string> {
  // First, try to find existing folder
  const searchResponse = await fetch(
    `https://graph.microsoft.com/v1.0/me/mailFolders?$filter=displayName eq '${folderName}'`,
    {
      headers: { Authorization: `Bearer ${accessToken}` },
    }
  );

  if (searchResponse.ok) {
    const data = await searchResponse.json();
    if (data.value && data.value.length > 0) {
      return data.value[0].id;
    }
  }

  // Create new folder
  const createResponse = await fetch(
    'https://graph.microsoft.com/v1.0/me/mailFolders',
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ displayName: folderName }),
    }
  );

  if (!createResponse.ok) {
    throw new Error('Failed to create quarantine folder');
  }

  const folder = await createResponse.json();
  return folder.id;
}

async function getOrCreateGmailLabel(
  accessToken: string,
  labelName: string
): Promise<string> {
  // First, try to find existing label
  const listResponse = await fetch(
    'https://gmail.googleapis.com/gmail/v1/users/me/labels',
    {
      headers: { Authorization: `Bearer ${accessToken}` },
    }
  );

  if (listResponse.ok) {
    const data = await listResponse.json();
    const existing = data.labels?.find(
      (l: { name: string }) => l.name === labelName
    );
    if (existing) {
      return existing.id;
    }
  }

  // Create new label
  const createResponse = await fetch(
    'https://gmail.googleapis.com/gmail/v1/users/me/labels',
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: labelName,
        labelListVisibility: 'labelShow',
        messageListVisibility: 'show',
      }),
    }
  );

  if (!createResponse.ok) {
    throw new Error('Failed to create quarantine label');
  }

  const label = await createResponse.json();
  return label.id;
}
