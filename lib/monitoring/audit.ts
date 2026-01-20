/**
 * Audit Logging Module
 *
 * Provides security and compliance audit trail functionality.
 */

import { nanoid } from 'nanoid';
import { sql } from '@/lib/db';

/**
 * Audit actions
 */
export const AuditAction = {
  // Authentication
  LOGIN: 'auth.login',
  LOGOUT: 'auth.logout',
  LOGIN_FAILED: 'auth.login_failed',

  // Data operations
  CREATE: 'data.create',
  READ: 'data.read',
  UPDATE: 'data.update',
  DELETE: 'data.delete',

  // Security
  THREAT_RELEASED: 'security.threat_released',
  POLICY_CHANGED: 'security.policy_changed',
  PERMISSION_CHANGED: 'security.permission_changed',

  // Integration
  INTEGRATION_CONNECTED: 'integration.connected',
  INTEGRATION_DISCONNECTED: 'integration.disconnected',
} as const;

export type AuditActionType = (typeof AuditAction)[keyof typeof AuditAction];

/**
 * Audit categories
 */
export const AuditCategory = {
  AUTHENTICATION: 'authentication',
  AUTHORIZATION: 'authorization',
  DATA_ACCESS: 'data_access',
  CONFIGURATION: 'configuration',
  SECURITY: 'security',
} as const;

export type AuditCategoryType = (typeof AuditCategory)[keyof typeof AuditCategory];

/**
 * Audit entry
 */
export interface AuditEntry {
  id: string;
  action: AuditActionType;
  category: AuditCategoryType;
  tenantId: string;
  userId: string;
  timestamp: string;
  resourceType?: string;
  resourceId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  retentionDays?: number;
  sensitive?: boolean;
}

/**
 * Audit log input
 */
interface AuditLogInput {
  action: AuditActionType;
  category: AuditCategoryType;
  tenantId: string;
  userId: string;
  resourceType?: string;
  resourceId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  retentionDays?: number;
}

/**
 * Audit query options
 */
interface AuditQueryOptions {
  tenantId: string;
  userId?: string;
  action?: AuditActionType;
  category?: AuditCategoryType;
  from?: Date;
  to?: Date;
  limit?: number;
}

/**
 * Audit logger class
 */
export class AuditLogger {
  async log(input: AuditLogInput): Promise<AuditEntry> {
    const entry: AuditEntry = {
      id: 'aud_' + nanoid(21),
      action: input.action,
      category: input.category,
      tenantId: input.tenantId,
      userId: input.userId,
      timestamp: new Date().toISOString(),
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      details: input.details,
      ipAddress: input.ipAddress,
      userAgent: input.userAgent,
      retentionDays: input.retentionDays,
    };

    // Store in database
    await sql`
      INSERT INTO audit_log (
        id, tenant_id, user_id, action, category,
        resource_type, resource_id, details, ip_address, user_agent,
        created_at
      ) VALUES (
        ${entry.id}, ${entry.tenantId}, ${entry.userId}, ${entry.action}, ${entry.category},
        ${entry.resourceType || null}, ${entry.resourceId || null},
        ${JSON.stringify(entry.details || {})}, ${entry.ipAddress || null}, ${entry.userAgent || null},
        NOW()
      )
    `;

    return entry;
  }

  async logLogin(
    tenantId: string,
    userId: string,
    details?: Record<string, unknown>
  ): Promise<AuditEntry> {
    return this.log({
      action: AuditAction.LOGIN,
      category: AuditCategory.AUTHENTICATION,
      tenantId,
      userId,
      details,
    });
  }

  async logDataAccess(
    tenantId: string,
    userId: string,
    action: AuditActionType,
    resourceType: string,
    resourceId: string
  ): Promise<AuditEntry> {
    return this.log({
      action,
      category: AuditCategory.DATA_ACCESS,
      tenantId,
      userId,
      resourceType,
      resourceId,
    });
  }

  async logSecurityEvent(
    tenantId: string,
    userId: string,
    action: AuditActionType,
    details?: Record<string, unknown>
  ): Promise<AuditEntry> {
    const entry = await this.log({
      action,
      category: AuditCategory.SECURITY,
      tenantId,
      userId,
      details,
    });
    return { ...entry, sensitive: true };
  }

  async logConfigChange(
    tenantId: string,
    userId: string,
    resourceType: string,
    resourceId: string,
    details?: Record<string, unknown>
  ): Promise<AuditEntry> {
    return this.log({
      action: AuditAction.UPDATE,
      category: AuditCategory.CONFIGURATION,
      tenantId,
      userId,
      resourceType,
      resourceId,
      details,
    });
  }

  async query(options: AuditQueryOptions): Promise<AuditEntry[]> {
    const results = await sql`
      SELECT * FROM audit_log
      WHERE tenant_id = ${options.tenantId}
      ${options.userId ? sql`AND user_id = ${options.userId}` : sql``}
      ${options.action ? sql`AND action = ${options.action}` : sql``}
      ${options.from ? sql`AND created_at >= ${options.from}` : sql``}
      ${options.to ? sql`AND created_at <= ${options.to}` : sql``}
      ORDER BY created_at DESC
      LIMIT ${options.limit || 100}
    `;

    return results as unknown as AuditEntry[];
  }
}

export function createAuditLogger(): AuditLogger {
  return new AuditLogger();
}

export const defaultAuditLogger = createAuditLogger();
