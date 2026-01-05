/**
 * API Authentication
 *
 * API key validation and management for REST API v1
 */

import { NextRequest } from 'next/server';
import { sql } from '@/lib/db';
import { nanoid } from 'nanoid';
import crypto from 'crypto';

export interface ApiKeyValidation {
  valid: boolean;
  tenantId?: string;
  keyId?: string;
  scopes?: string[];
  error?: string;
}

export interface ApiKey {
  id: string;
  tenantId: string;
  name: string;
  keyHash: string;
  keyPrefix: string;
  scopes: string[];
  lastUsedAt: Date | null;
  expiresAt: Date | null;
  isActive: boolean;
  createdAt: Date;
  createdBy: string;
}

// Available API scopes
export const API_SCOPES = {
  THREATS_READ: 'threats:read',
  THREATS_WRITE: 'threats:write',
  QUARANTINE_READ: 'quarantine:read',
  QUARANTINE_WRITE: 'quarantine:write',
  POLICIES_READ: 'policies:read',
  POLICIES_WRITE: 'policies:write',
  REPORTS_READ: 'reports:read',
  WEBHOOKS_MANAGE: 'webhooks:manage',
  ADMIN: 'admin',
} as const;

/**
 * Generate a new API key
 */
export function generateApiKey(): { key: string; hash: string; prefix: string } {
  // Format: sf_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXX
  const randomPart = crypto.randomBytes(24).toString('base64url');
  const key = `sf_live_${randomPart}`;
  const prefix = key.substring(0, 12);
  const hash = crypto.createHash('sha256').update(key).digest('hex');

  return { key, hash, prefix };
}

/**
 * Validate an API key from request
 */
export async function validateApiKey(request: NextRequest): Promise<ApiKeyValidation> {
  // Check Authorization header
  const authHeader = request.headers.get('Authorization');
  if (!authHeader) {
    return { valid: false, error: 'Missing Authorization header' };
  }

  // Support both "Bearer <key>" and "ApiKey <key>" formats
  const [scheme, key] = authHeader.split(' ');
  if (!key || !['Bearer', 'ApiKey'].includes(scheme)) {
    return { valid: false, error: 'Invalid Authorization format. Use: Bearer <api_key>' };
  }

  // Validate key format
  if (!key.startsWith('sf_live_') && !key.startsWith('sf_test_')) {
    return { valid: false, error: 'Invalid API key format' };
  }

  // Hash the provided key
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');

  try {
    // Look up the key in database
    const result = await sql`
      SELECT id, tenant_id, scopes, expires_at, is_active
      FROM api_keys
      WHERE key_hash = ${keyHash}
      LIMIT 1
    `;

    if (result.length === 0) {
      return { valid: false, error: 'Invalid API key' };
    }

    const apiKey = result[0];

    // Check if key is active
    if (!apiKey.is_active) {
      return { valid: false, error: 'API key is disabled' };
    }

    // Check expiration
    if (apiKey.expires_at && new Date(apiKey.expires_at) < new Date()) {
      return { valid: false, error: 'API key has expired' };
    }

    // Update last used timestamp (non-blocking)
    sql`
      UPDATE api_keys SET last_used_at = NOW() WHERE id = ${apiKey.id}
    `.catch(() => {}); // Ignore errors

    return {
      valid: true,
      tenantId: apiKey.tenant_id,
      keyId: apiKey.id,
      scopes: apiKey.scopes || [],
    };
  } catch (error) {
    console.error('API key validation error:', error);
    return { valid: false, error: 'Authentication failed' };
  }
}

/**
 * Check if API key has required scope
 */
export function hasScope(scopes: string[], required: string): boolean {
  // Admin scope grants all permissions
  if (scopes.includes(API_SCOPES.ADMIN)) {
    return true;
  }
  return scopes.includes(required);
}

/**
 * Create a new API key for a tenant
 */
export async function createApiKey(
  tenantId: string,
  name: string,
  scopes: string[],
  createdBy: string,
  expiresInDays?: number
): Promise<{ id: string; key: string }> {
  const { key, hash, prefix } = generateApiKey();
  const id = nanoid();

  const expiresAt = expiresInDays
    ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000)
    : null;

  await sql`
    INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scopes, expires_at, is_active, created_at, created_by)
    VALUES (
      ${id},
      ${tenantId},
      ${name},
      ${hash},
      ${prefix},
      ${JSON.stringify(scopes)},
      ${expiresAt?.toISOString() || null},
      true,
      NOW(),
      ${createdBy}
    )
  `;

  return { id, key };
}

/**
 * Revoke an API key
 */
export async function revokeApiKey(keyId: string, tenantId: string): Promise<boolean> {
  const result = await sql`
    UPDATE api_keys
    SET is_active = false
    WHERE id = ${keyId} AND tenant_id = ${tenantId}
    RETURNING id
  `;

  return result.length > 0;
}

/**
 * List API keys for a tenant (without exposing the actual keys)
 */
export async function listApiKeys(tenantId: string): Promise<Omit<ApiKey, 'keyHash'>[]> {
  const result = await sql`
    SELECT id, tenant_id, name, key_prefix, scopes, last_used_at, expires_at, is_active, created_at, created_by
    FROM api_keys
    WHERE tenant_id = ${tenantId}
    ORDER BY created_at DESC
  `;

  return result.map((row: Record<string, unknown>) => ({
    id: row.id as string,
    tenantId: row.tenant_id as string,
    name: row.name as string,
    keyPrefix: row.key_prefix as string,
    scopes: (row.scopes as string[]) || [],
    lastUsedAt: row.last_used_at as Date | null,
    expiresAt: row.expires_at as Date | null,
    isActive: row.is_active as boolean,
    createdAt: row.created_at as Date,
    createdBy: row.created_by as string,
  }));
}
