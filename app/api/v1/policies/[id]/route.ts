/**
 * REST API v1 - Individual Policy Endpoint
 *
 * GET /api/v1/policies/:id - Get policy
 * PATCH /api/v1/policies/:id - Update policy
 * DELETE /api/v1/policies/:id - Delete policy
 */

import { NextRequest } from 'next/server';
import { sql } from '@/lib/db';
import { validateApiKey, hasScope, API_SCOPES } from '@/lib/api/auth';
import { rateLimitMiddleware, getRateLimitHeaders } from '@/lib/api/rate-limit';
import { apiSuccess, errors, withErrorHandling } from '@/lib/api/response';
import { nanoid } from 'nanoid';

interface RouteParams {
  params: Promise<{ id: string }>;
}

// GET /api/v1/policies/:id
export async function GET(request: NextRequest, { params }: RouteParams) {
  return withErrorHandling(async () => {
    const auth = await validateApiKey(request);
    if (!auth.valid) return errors.unauthorized(auth.error);

    if (!hasScope(auth.scopes!, API_SCOPES.POLICIES_READ)) {
      return errors.invalidScope(API_SCOPES.POLICIES_READ);
    }

    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    const { id } = await params;

    const result = await sql`
      SELECT id, type, target, value, action, priority, is_active, created_by, created_at, updated_at
      FROM policies
      WHERE id = ${id} AND tenant_id = ${auth.tenantId}
      LIMIT 1
    `;

    if (result.length === 0) {
      return errors.notFound('Policy');
    }

    const p = result[0];
    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiSuccess({
      policy: {
        id: p.id,
        type: p.type,
        target: p.target,
        value: p.value,
        action: p.action,
        priority: p.priority,
        isActive: p.is_active,
        createdBy: p.created_by,
        createdAt: p.created_at,
        updatedAt: p.updated_at,
      },
    }, undefined, headers);
  });
}

// PATCH /api/v1/policies/:id
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  return withErrorHandling(async () => {
    const auth = await validateApiKey(request);
    if (!auth.valid) return errors.unauthorized(auth.error);

    if (!hasScope(auth.scopes!, API_SCOPES.POLICIES_WRITE)) {
      return errors.invalidScope(API_SCOPES.POLICIES_WRITE);
    }

    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    const { id } = await params;
    const body = await request.json();
    const { value, action, priority, isActive } = body;

    // Verify policy exists
    const existing = await sql`
      SELECT * FROM policies WHERE id = ${id} AND tenant_id = ${auth.tenantId} LIMIT 1
    `;

    if (existing.length === 0) {
      return errors.notFound('Policy');
    }

    // Validate updates
    if (action && !['allow', 'block', 'quarantine'].includes(action)) {
      return errors.badRequest('action must be: allow, block, or quarantine');
    }

    if (priority !== undefined && (priority < 0 || priority > 100)) {
      return errors.badRequest('priority must be between 0 and 100');
    }

    // Update
    const updated = await sql`
      UPDATE policies SET
        value = COALESCE(${value}, value),
        action = COALESCE(${action}, action),
        priority = COALESCE(${priority}, priority),
        is_active = COALESCE(${isActive}, is_active),
        updated_at = NOW()
      WHERE id = ${id} AND tenant_id = ${auth.tenantId}
      RETURNING *
    `;

    // Log update
    await sql`
      INSERT INTO audit_logs (id, tenant_id, actor_id, action, resource_type, resource_id, before_state, after_state, created_at)
      VALUES (
        ${nanoid()},
        ${auth.tenantId},
        ${auth.keyId},
        'policy.updated',
        'policy',
        ${id},
        ${JSON.stringify(existing[0])},
        ${JSON.stringify(updated[0])},
        NOW()
      )
    `;

    const p = updated[0];
    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiSuccess({
      policy: {
        id: p.id,
        type: p.type,
        target: p.target,
        value: p.value,
        action: p.action,
        priority: p.priority,
        isActive: p.is_active,
        updatedAt: p.updated_at,
      },
    }, undefined, headers);
  });
}

// DELETE /api/v1/policies/:id
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  return withErrorHandling(async () => {
    const auth = await validateApiKey(request);
    if (!auth.valid) return errors.unauthorized(auth.error);

    if (!hasScope(auth.scopes!, API_SCOPES.POLICIES_WRITE)) {
      return errors.invalidScope(API_SCOPES.POLICIES_WRITE);
    }

    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    const { id } = await params;

    // Verify and delete
    const deleted = await sql`
      DELETE FROM policies
      WHERE id = ${id} AND tenant_id = ${auth.tenantId}
      RETURNING *
    `;

    if (deleted.length === 0) {
      return errors.notFound('Policy');
    }

    // Log deletion
    await sql`
      INSERT INTO audit_logs (id, tenant_id, actor_id, action, resource_type, resource_id, before_state, created_at)
      VALUES (
        ${nanoid()},
        ${auth.tenantId},
        ${auth.keyId},
        'policy.deleted',
        'policy',
        ${id},
        ${JSON.stringify(deleted[0])},
        NOW()
      )
    `;

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiSuccess({ deleted: true, id }, undefined, headers);
  });
}
