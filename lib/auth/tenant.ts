/**
 * Server-side Tenant Isolation Module
 *
 * Provides secure tenant isolation for API routes and server-side operations.
 * Ensures data is always scoped to the authenticated tenant.
 */

import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { nanoid } from 'nanoid';

/**
 * Custom error for tenant access violations
 */
export class TenantAccessDenied extends Error {
  constructor(message = 'Access denied to this resource') {
    super(message);
    this.name = 'TenantAccessDenied';
  }
}

/**
 * Custom error for unauthenticated requests
 */
export class Unauthorized extends Error {
  constructor(message = 'Unauthorized') {
    super(message);
    this.name = 'Unauthorized';
  }
}

/**
 * Get the current tenant ID from the authenticated user
 *
 * - Returns orgId if user is in an organization
 * - Returns personal_userId if user is not in an organization
 * - Throws Unauthorized if user is not authenticated
 */
export async function getTenantId(): Promise<string> {
  const { userId, orgId } = await auth();

  if (!userId) {
    throw new Unauthorized('Unauthorized');
  }

  // If user is in an organization, use orgId
  if (orgId) {
    return orgId;
  }

  // Otherwise, use personal tenant ID
  return `personal_${userId}`;
}

/**
 * Verify if the current user has access to a specific tenant
 *
 * @param targetTenantId The tenant ID to check access for
 * @returns true if user has access, false otherwise
 */
export async function verifyTenantAccess(targetTenantId: string): Promise<boolean> {
  if (!targetTenantId) {
    return false;
  }

  try {
    const currentTenantId = await getTenantId();
    return currentTenantId === targetTenantId;
  } catch {
    return false;
  }
}

/**
 * Assert that the current user has access to a tenant
 *
 * @param targetTenantId The tenant ID to check
 * @throws TenantAccessDenied if user doesn't have access
 */
export async function assertTenantAccess(targetTenantId: string): Promise<void> {
  const hasAccess = await verifyTenantAccess(targetTenantId);

  if (!hasAccess) {
    throw new TenantAccessDenied(`Access denied to tenant ${targetTenantId}`);
  }
}

/**
 * Execute a callback with the current tenant scope
 *
 * This ensures all database queries within the callback are scoped to the tenant.
 *
 * @param callback Function that receives tenantId and performs operations
 * @returns The result of the callback
 */
export async function withTenantScope<T>(
  callback: (tenantId: string) => Promise<T>
): Promise<T> {
  const tenantId = await getTenantId();
  return callback(tenantId);
}

/**
 * Tables that have tenant_id column for access checks
 */
const TENANT_SCOPED_TABLES = [
  'threats',
  'email_verdicts',
  'integrations',
  'policies',
  'quarantine',
  'notifications',
  'webhooks',
  'feedback',
  'audit_log',
] as const;

type TenantScopedTable = (typeof TENANT_SCOPED_TABLES)[number];

/**
 * Verify if the current user has access to a specific resource
 *
 * @param table The table/resource type
 * @param resourceId The resource ID
 * @returns true if user has access, false otherwise
 */
export async function verifyResourceAccess(
  table: TenantScopedTable,
  resourceId: string
): Promise<boolean> {
  try {
    const tenantId = await getTenantId();

    // Query the resource to check its tenant_id
    // Note: Using parameterized query for safety
    const result = await sql`
      SELECT tenant_id FROM ${sql(table)}
      WHERE id = ${resourceId}
      LIMIT 1
    `;

    if (result.length === 0) {
      return false; // Resource doesn't exist
    }

    return result[0].tenant_id === tenantId;
  } catch {
    return false;
  }
}

/**
 * Verify MSP admin access to a managed tenant
 *
 * @param targetTenantId The tenant ID the MSP wants to access
 * @returns true if MSP has access to manage this tenant
 */
export async function verifyMSPAccess(targetTenantId: string): Promise<boolean> {
  try {
    const { orgId } = await auth();

    if (!orgId) {
      return false;
    }

    // Check if there's an MSP relationship
    const result = await sql`
      SELECT msp_tenant_id, managed_tenant_id
      FROM msp_tenant_relationships
      WHERE msp_tenant_id = ${orgId}
        AND managed_tenant_id = ${targetTenantId}
        AND status = 'active'
      LIMIT 1
    `;

    return result.length > 0;
  } catch {
    return false;
  }
}

/**
 * Log cross-tenant access for audit purposes
 *
 * @param targetTenantId The tenant that was accessed
 * @param action The action performed
 */
export async function logCrossTenantAccess(
  targetTenantId: string,
  action: string
): Promise<void> {
  try {
    const { userId, orgId } = await auth();

    await sql`
      INSERT INTO audit_log (
        id,
        tenant_id,
        user_id,
        action,
        resource_type,
        resource_id,
        metadata,
        created_at
      ) VALUES (
        ${nanoid()},
        ${orgId || `personal_${userId}`},
        ${userId},
        'cross_tenant_access',
        'tenant',
        ${targetTenantId},
        ${JSON.stringify({ action, accessed_tenant: targetTenantId })},
        NOW()
      )
    `;
  } catch (error) {
    console.error('Failed to log cross-tenant access:', error);
  }
}

/**
 * Tenant context for request tracing and auditing
 */
export interface TenantContext {
  tenantId: string;
  userId: string;
  requestId: string;
  orgId: string | null;
}

/**
 * Create a tenant context for the current request
 *
 * @returns TenantContext with tenant ID, user ID, and request ID
 */
export async function createTenantContext(): Promise<TenantContext> {
  const { userId, orgId } = await auth();

  if (!userId) {
    throw new Unauthorized('Unauthorized');
  }

  const tenantId = orgId || `personal_${userId}`;
  const requestId = nanoid();

  return {
    tenantId,
    userId,
    requestId,
    orgId,
  };
}

/**
 * Helper to check if the current user is the owner of a resource
 *
 * @param resourceTenantId The tenant_id of the resource
 * @returns true if current user owns the resource
 */
export async function isResourceOwner(resourceTenantId: string): Promise<boolean> {
  return verifyTenantAccess(resourceTenantId);
}

/**
 * Get tenant-scoped data with automatic filtering
 *
 * This is a convenience wrapper that ensures queries are always scoped.
 *
 * @param queryFn A function that returns a query result
 * @returns Query results filtered to current tenant
 */
export async function getTenantScopedData<T extends { tenant_id: string }>(
  queryFn: () => Promise<T[]>
): Promise<T[]> {
  const tenantId = await getTenantId();
  const results = await queryFn();

  // Double-check filtering (defense in depth)
  return results.filter((item) => item.tenant_id === tenantId);
}
