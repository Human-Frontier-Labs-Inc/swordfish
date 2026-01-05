/**
 * Action Audit Trail System
 * Logs all security actions for compliance and analytics
 */

import { sql } from '@/lib/db';
import type { ClickTimeSignal } from './links/click-time-check';

export type ActionType =
  | 'click_check'           // Link click-time check
  | 'click_proceed'         // User proceeded after warning
  | 'click_blocked'         // Click was blocked
  | 'banner_injected'       // Warning banner added
  | 'link_rewritten'        // URL was rewritten
  | 'email_quarantined'     // Email moved to quarantine
  | 'email_released'        // Email released from quarantine
  | 'email_deleted'         // Email permanently deleted
  | 'vip_added'             // VIP added to list
  | 'vip_removed'           // VIP removed from list
  | 'policy_applied'        // Policy action applied
  | 'threat_reported'       // Threat reported to intel
  | 'attachment_sandboxed'  // Attachment sent to sandbox
  | 'attachment_blocked';   // Attachment blocked

export interface ActionLogEntry {
  type: ActionType;
  tenantId: string;
  userId?: string;
  emailId?: string;
  targetUrl?: string;
  verdict?: string;
  riskScore?: number;
  signals?: Array<{ type: string; severity: string; detail: string }>;
  metadata?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
}

export interface ClickActionParams {
  clickId: string;
  originalUrl: string;
  verdict: string;
  action: string;
  riskScore: number;
  signals: ClickTimeSignal[];
  userId?: string;
  tenantId: string;
  emailId: string;
  bypassedWarning?: boolean;
}

/**
 * Log a generic action to the audit trail
 */
export async function logAction(entry: ActionLogEntry): Promise<string | null> {
  try {
    const result = await sql`
      INSERT INTO action_logs (
        type, tenant_id, user_id, email_id, target_url,
        verdict, risk_score, signals, metadata,
        ip_address, user_agent, created_at
      ) VALUES (
        ${entry.type},
        ${entry.tenantId},
        ${entry.userId || null},
        ${entry.emailId || null},
        ${entry.targetUrl || null},
        ${entry.verdict || null},
        ${entry.riskScore || null},
        ${entry.signals ? JSON.stringify(entry.signals) : null},
        ${entry.metadata ? JSON.stringify(entry.metadata) : null},
        ${entry.ipAddress || null},
        ${entry.userAgent || null},
        NOW()
      )
      RETURNING id
    `;

    return result[0]?.id || null;
  } catch (error) {
    console.error('Failed to log action:', error);
    return null;
  }
}

/**
 * Log a click-time protection action
 */
export async function logClickAction(params: ClickActionParams): Promise<string | null> {
  const actionType: ActionType =
    params.action === 'block' ? 'click_blocked' :
    params.bypassedWarning ? 'click_proceed' : 'click_check';

  return logAction({
    type: actionType,
    tenantId: params.tenantId,
    userId: params.userId,
    emailId: params.emailId,
    targetUrl: params.originalUrl,
    verdict: params.verdict,
    riskScore: params.riskScore,
    signals: params.signals.map(s => ({
      type: s.type,
      severity: s.severity,
      detail: s.detail,
    })),
    metadata: {
      clickId: params.clickId,
      action: params.action,
      bypassedWarning: params.bypassedWarning,
    },
  });
}

/**
 * Log banner injection action
 */
export async function logBannerAction(params: {
  emailId: string;
  tenantId: string;
  bannerType: string;
  signals: Array<{ type: string; severity: string; detail: string }>;
}): Promise<string | null> {
  return logAction({
    type: 'banner_injected',
    tenantId: params.tenantId,
    emailId: params.emailId,
    metadata: {
      bannerType: params.bannerType,
    },
    signals: params.signals,
  });
}

/**
 * Log link rewriting action
 */
export async function logLinkRewriteAction(params: {
  emailId: string;
  tenantId: string;
  originalUrl: string;
  rewrittenUrl: string;
  reason: string;
  riskScore?: number;
}): Promise<string | null> {
  return logAction({
    type: 'link_rewritten',
    tenantId: params.tenantId,
    emailId: params.emailId,
    targetUrl: params.originalUrl,
    riskScore: params.riskScore,
    metadata: {
      rewrittenUrl: params.rewrittenUrl,
      reason: params.reason,
    },
  });
}

/**
 * Log quarantine action
 */
export async function logQuarantineAction(params: {
  emailId: string;
  tenantId: string;
  userId?: string;
  action: 'quarantine' | 'release' | 'delete';
  verdict: string;
  riskScore: number;
  signals: Array<{ type: string; severity: string; detail: string }>;
  reason?: string;
}): Promise<string | null> {
  const actionType: ActionType =
    params.action === 'quarantine' ? 'email_quarantined' :
    params.action === 'release' ? 'email_released' : 'email_deleted';

  return logAction({
    type: actionType,
    tenantId: params.tenantId,
    userId: params.userId,
    emailId: params.emailId,
    verdict: params.verdict,
    riskScore: params.riskScore,
    signals: params.signals,
    metadata: {
      reason: params.reason,
    },
  });
}

/**
 * Log VIP list modification
 */
export async function logVIPAction(params: {
  tenantId: string;
  userId: string;
  action: 'add' | 'remove';
  vipEmail: string;
  vipName: string;
  vipRole: string;
}): Promise<string | null> {
  return logAction({
    type: params.action === 'add' ? 'vip_added' : 'vip_removed',
    tenantId: params.tenantId,
    userId: params.userId,
    metadata: {
      vipEmail: params.vipEmail,
      vipName: params.vipName,
      vipRole: params.vipRole,
    },
  });
}

/**
 * Log policy application
 */
export async function logPolicyAction(params: {
  emailId: string;
  tenantId: string;
  policyId: string;
  policyName: string;
  actionTaken: string;
  verdict: string;
  riskScore: number;
}): Promise<string | null> {
  return logAction({
    type: 'policy_applied',
    tenantId: params.tenantId,
    emailId: params.emailId,
    verdict: params.verdict,
    riskScore: params.riskScore,
    metadata: {
      policyId: params.policyId,
      policyName: params.policyName,
      actionTaken: params.actionTaken,
    },
  });
}

/**
 * Log threat report to intel
 */
export async function logThreatReportAction(params: {
  tenantId: string;
  userId: string;
  emailId?: string;
  threatType: string;
  indicators: string[];
  reportedTo: string;
}): Promise<string | null> {
  return logAction({
    type: 'threat_reported',
    tenantId: params.tenantId,
    userId: params.userId,
    emailId: params.emailId,
    metadata: {
      threatType: params.threatType,
      indicators: params.indicators,
      reportedTo: params.reportedTo,
    },
  });
}

/**
 * Log attachment sandbox action
 */
export async function logAttachmentAction(params: {
  emailId: string;
  tenantId: string;
  attachmentName: string;
  attachmentHash: string;
  action: 'sandboxed' | 'blocked';
  verdict?: string;
  riskScore?: number;
}): Promise<string | null> {
  return logAction({
    type: params.action === 'sandboxed' ? 'attachment_sandboxed' : 'attachment_blocked',
    tenantId: params.tenantId,
    emailId: params.emailId,
    verdict: params.verdict,
    riskScore: params.riskScore,
    metadata: {
      attachmentName: params.attachmentName,
      attachmentHash: params.attachmentHash,
    },
  });
}

/**
 * Query action logs with filters
 */
export interface ActionLogQuery {
  tenantId: string;
  type?: ActionType;
  userId?: string;
  emailId?: string;
  startDate?: Date;
  endDate?: Date;
  limit?: number;
  offset?: number;
}

export interface ActionLogResult {
  id: string;
  type: ActionType;
  userId: string | null;
  emailId: string | null;
  targetUrl: string | null;
  verdict: string | null;
  riskScore: number | null;
  signals: unknown;
  metadata: unknown;
  createdAt: Date;
}

export async function queryActionLogs(query: ActionLogQuery): Promise<{
  logs: ActionLogResult[];
  total: number;
}> {
  try {
    const limit = query.limit || 50;
    const offset = query.offset || 0;

    // Build dynamic query based on filters
    let logs;

    if (query.type && query.userId && query.emailId) {
      logs = await sql`
        SELECT id, type, user_id, email_id, target_url, verdict, risk_score, signals, metadata, created_at
        FROM action_logs
        WHERE tenant_id = ${query.tenantId}
          AND type = ${query.type}
          AND user_id = ${query.userId}
          AND email_id = ${query.emailId}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
    } else if (query.type && query.userId) {
      logs = await sql`
        SELECT id, type, user_id, email_id, target_url, verdict, risk_score, signals, metadata, created_at
        FROM action_logs
        WHERE tenant_id = ${query.tenantId}
          AND type = ${query.type}
          AND user_id = ${query.userId}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
    } else if (query.type && query.emailId) {
      logs = await sql`
        SELECT id, type, user_id, email_id, target_url, verdict, risk_score, signals, metadata, created_at
        FROM action_logs
        WHERE tenant_id = ${query.tenantId}
          AND type = ${query.type}
          AND email_id = ${query.emailId}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
    } else if (query.type) {
      logs = await sql`
        SELECT id, type, user_id, email_id, target_url, verdict, risk_score, signals, metadata, created_at
        FROM action_logs
        WHERE tenant_id = ${query.tenantId}
          AND type = ${query.type}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
    } else if (query.emailId) {
      logs = await sql`
        SELECT id, type, user_id, email_id, target_url, verdict, risk_score, signals, metadata, created_at
        FROM action_logs
        WHERE tenant_id = ${query.tenantId}
          AND email_id = ${query.emailId}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
    } else {
      logs = await sql`
        SELECT id, type, user_id, email_id, target_url, verdict, risk_score, signals, metadata, created_at
        FROM action_logs
        WHERE tenant_id = ${query.tenantId}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
    }

    return {
      logs: logs.map(log => ({
        id: log.id,
        type: log.type as ActionType,
        userId: log.user_id,
        emailId: log.email_id,
        targetUrl: log.target_url,
        verdict: log.verdict,
        riskScore: log.risk_score,
        signals: log.signals ? (typeof log.signals === 'string' ? JSON.parse(log.signals) : log.signals) : null,
        metadata: log.metadata ? (typeof log.metadata === 'string' ? JSON.parse(log.metadata) : log.metadata) : null,
        createdAt: log.created_at,
      })),
      total: logs.length,
    };
  } catch (error) {
    console.error('Failed to query action logs:', error);
    return { logs: [], total: 0 };
  }
}

/**
 * Get action statistics for a tenant
 */
export async function getActionStats(tenantId: string, days: number = 30): Promise<{
  totalActions: number;
  byType: Record<ActionType, number>;
  blockedClicks: number;
  bypassedWarnings: number;
  quarantinedEmails: number;
}> {
  try {
    const stats = await sql`
      SELECT
        type,
        COUNT(*) as count
      FROM action_logs
      WHERE tenant_id = ${tenantId}
        AND created_at >= NOW() - INTERVAL '${days} days'
      GROUP BY type
    `;

    const byType: Record<string, number> = {};
    let totalActions = 0;
    let blockedClicks = 0;
    let bypassedWarnings = 0;
    let quarantinedEmails = 0;

    for (const row of stats) {
      const count = Number(row.count);
      byType[row.type] = count;
      totalActions += count;

      if (row.type === 'click_blocked') {
        blockedClicks = count;
      }
      if (row.type === 'click_proceed') {
        bypassedWarnings = count;
      }
      if (row.type === 'email_quarantined') {
        quarantinedEmails = count;
      }
    }

    return {
      totalActions,
      byType: byType as Record<ActionType, number>,
      blockedClicks,
      bypassedWarnings,
      quarantinedEmails,
    };
  } catch (error) {
    console.error('Failed to get action stats:', error);
    return {
      totalActions: 0,
      byType: {} as Record<ActionType, number>,
      blockedClicks: 0,
      bypassedWarnings: 0,
      quarantinedEmails: 0,
    };
  }
}

/**
 * Get click mapping by ID
 */
export async function getClickMapping(clickId: string): Promise<{
  id: string;
  tenantId: string;
  emailId: string;
  originalUrl: string;
  clickCount: number;
  expiresAt: Date;
} | null> {
  try {
    const result = await sql`
      SELECT id, tenant_id, email_id, original_url, click_count, expires_at
      FROM click_mappings
      WHERE id = ${clickId}
      LIMIT 1
    `;

    if (result.length === 0) {
      return null;
    }

    const row = result[0];
    return {
      id: row.id,
      tenantId: row.tenant_id,
      emailId: row.email_id,
      originalUrl: row.original_url,
      clickCount: row.click_count,
      expiresAt: row.expires_at,
    };
  } catch (error) {
    console.error('Failed to get click mapping:', error);
    return null;
  }
}

/**
 * Save click mapping
 */
export async function saveClickMapping(params: {
  id: string;
  tenantId: string;
  emailId: string;
  originalUrl: string;
  reason?: string;
  riskScore?: number;
}): Promise<boolean> {
  try {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30); // 30 day expiry

    await sql`
      INSERT INTO click_mappings (
        id, tenant_id, email_id, original_url, click_count, expires_at, metadata, created_at
      ) VALUES (
        ${params.id},
        ${params.tenantId},
        ${params.emailId},
        ${params.originalUrl},
        0,
        ${expiresAt.toISOString()},
        ${JSON.stringify({ reason: params.reason, riskScore: params.riskScore })},
        NOW()
      )
      ON CONFLICT (id) DO NOTHING
    `;

    return true;
  } catch (error) {
    console.error('Failed to save click mapping:', error);
    return false;
  }
}

/**
 * Update click mapping stats
 */
export async function updateClickStats(clickId: string): Promise<boolean> {
  try {
    await sql`
      UPDATE click_mappings
      SET click_count = click_count + 1,
          last_click_at = NOW()
      WHERE id = ${clickId}
    `;
    return true;
  } catch (error) {
    console.error('Failed to update click stats:', error);
    return false;
  }
}
