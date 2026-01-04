import { sql } from './index';

export interface AuditLogEntry {
  tenantId: string | null;
  actorId: string | null;
  actorEmail: string | null;
  action: string;
  resourceType: string;
  resourceId?: string;
  beforeState?: Record<string, unknown>;
  afterState?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Log an audit event
 * Audit logs are immutable - they cannot be updated or deleted
 */
export async function logAuditEvent(entry: AuditLogEntry): Promise<string> {
  const result = await sql`
    INSERT INTO audit_log (
      tenant_id,
      actor_id,
      actor_email,
      action,
      resource_type,
      resource_id,
      before_state,
      after_state,
      ip_address,
      user_agent
    ) VALUES (
      ${entry.tenantId},
      ${entry.actorId},
      ${entry.actorEmail},
      ${entry.action},
      ${entry.resourceType},
      ${entry.resourceId || null},
      ${entry.beforeState ? JSON.stringify(entry.beforeState) : null},
      ${entry.afterState ? JSON.stringify(entry.afterState) : null},
      ${entry.ipAddress || null},
      ${entry.userAgent || null}
    )
    RETURNING id
  `;

  return result[0].id;
}

/**
 * Get audit logs with filtering
 */
export async function getAuditLogs(filters: {
  tenantId?: string;
  actorId?: string;
  action?: string;
  resourceType?: string;
  resourceId?: string;
  startDate?: Date;
  endDate?: Date;
  limit?: number;
  offset?: number;
}): Promise<AuditLogEntry[]> {
  const {
    tenantId,
    actorId,
    action,
    resourceType,
    resourceId,
    startDate,
    endDate,
    limit = 50,
    offset = 0,
  } = filters;

  // Build dynamic query
  const conditions: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  if (tenantId) {
    conditions.push(`tenant_id = $${paramIndex++}`);
    values.push(tenantId);
  }

  if (actorId) {
    conditions.push(`actor_id = $${paramIndex++}`);
    values.push(actorId);
  }

  if (action) {
    conditions.push(`action = $${paramIndex++}`);
    values.push(action);
  }

  if (resourceType) {
    conditions.push(`resource_type = $${paramIndex++}`);
    values.push(resourceType);
  }

  if (resourceId) {
    conditions.push(`resource_id = $${paramIndex++}`);
    values.push(resourceId);
  }

  if (startDate) {
    conditions.push(`created_at >= $${paramIndex++}`);
    values.push(startDate.toISOString());
  }

  if (endDate) {
    conditions.push(`created_at <= $${paramIndex++}`);
    values.push(endDate.toISOString());
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  values.push(limit, offset);

  const query = `
    SELECT
      id,
      tenant_id as "tenantId",
      actor_id as "actorId",
      actor_email as "actorEmail",
      action,
      resource_type as "resourceType",
      resource_id as "resourceId",
      before_state as "beforeState",
      after_state as "afterState",
      ip_address as "ipAddress",
      user_agent as "userAgent",
      created_at as "createdAt"
    FROM audit_log
    ${whereClause}
    ORDER BY created_at DESC
    LIMIT $${paramIndex++} OFFSET $${paramIndex}
  `;

  const result = await sql.query(query, values);
  return result as unknown as AuditLogEntry[];
}

/**
 * Standard audit actions
 */
export const AuditAction = {
  // Auth actions
  LOGIN: 'login',
  LOGOUT: 'logout',
  ACCESS_DENIED: 'access_denied',

  // CRUD actions
  CREATE: 'create',
  READ: 'read',
  UPDATE: 'update',
  DELETE: 'delete',

  // Email actions
  QUARANTINE: 'quarantine',
  RELEASE: 'release',
  BLOCK: 'block',

  // Policy actions
  POLICY_CREATE: 'policy_create',
  POLICY_UPDATE: 'policy_update',
  POLICY_DELETE: 'policy_delete',

  // Integration actions
  INTEGRATION_CONNECT: 'integration_connect',
  INTEGRATION_DISCONNECT: 'integration_disconnect',
  INTEGRATION_SYNC: 'integration_sync',

  // Settings actions
  SETTINGS_UPDATE: 'settings_update',
} as const;

export type AuditActionType = (typeof AuditAction)[keyof typeof AuditAction];

/**
 * Resource types for audit logging
 */
export const AuditResourceType = {
  TENANT: 'tenant',
  USER: 'user',
  EMAIL: 'email',
  VERDICT: 'verdict',
  QUARANTINE: 'quarantine',
  POLICY: 'policy',
  INTEGRATION: 'integration',
  SETTINGS: 'settings',
} as const;

export type AuditResourceTypeValue = (typeof AuditResourceType)[keyof typeof AuditResourceType];

/**
 * Helper to create audit log from request context
 */
export function createAuditContext(req: Request): Pick<AuditLogEntry, 'ipAddress' | 'userAgent'> {
  return {
    ipAddress: req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || undefined,
    userAgent: req.headers.get('user-agent') || undefined,
  };
}
