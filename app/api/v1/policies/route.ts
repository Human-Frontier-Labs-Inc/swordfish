/**
 * REST API v1 - Policies Endpoint
 *
 * GET /api/v1/policies - List policies
 * POST /api/v1/policies - Create policy
 */

import { NextRequest } from 'next/server';
import { sql } from '@/lib/db';
import { validateApiKey, hasScope, API_SCOPES } from '@/lib/api/auth';
import { rateLimitMiddleware, getRateLimitHeaders } from '@/lib/api/rate-limit';
import { apiSuccess, apiCreated, errors, parsePagination, withErrorHandling } from '@/lib/api/response';
import { nanoid } from 'nanoid';

// GET /api/v1/policies
export async function GET(request: NextRequest) {
  return withErrorHandling(async () => {
    const auth = await validateApiKey(request);
    if (!auth.valid) return errors.unauthorized(auth.error);

    if (!hasScope(auth.scopes!, API_SCOPES.POLICIES_READ)) {
      return errors.invalidScope(API_SCOPES.POLICIES_READ);
    }

    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    const searchParams = request.nextUrl.searchParams;
    const { page, pageSize, offset } = parsePagination(searchParams);
    const type = searchParams.get('type'); // allowlist, blocklist, rule
    const isActive = searchParams.get('active');

    const policies = await sql`
      SELECT id, type, target, value, action, priority, is_active, created_by, created_at, updated_at
      FROM policies
      WHERE tenant_id = ${auth.tenantId}
        ${type ? sql`AND type = ${type}` : sql``}
        ${isActive !== null ? sql`AND is_active = ${isActive === 'true'}` : sql``}
      ORDER BY priority DESC, created_at DESC
      LIMIT ${pageSize} OFFSET ${offset}
    `;

    const countResult = await sql`
      SELECT COUNT(*)::int as count
      FROM policies
      WHERE tenant_id = ${auth.tenantId}
        ${type ? sql`AND type = ${type}` : sql``}
        ${isActive !== null ? sql`AND is_active = ${isActive === 'true'}` : sql``}
    `;
    const total = countResult[0]?.count || 0;

    const formattedPolicies = policies.map((p: Record<string, unknown>) => ({
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
    }));

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiSuccess(
      { policies: formattedPolicies },
      { page, pageSize, total, totalPages: Math.ceil(total / pageSize) },
      headers
    );
  });
}

// POST /api/v1/policies
export async function POST(request: NextRequest) {
  return withErrorHandling(async () => {
    const auth = await validateApiKey(request);
    if (!auth.valid) return errors.unauthorized(auth.error);

    if (!hasScope(auth.scopes!, API_SCOPES.POLICIES_WRITE)) {
      return errors.invalidScope(API_SCOPES.POLICIES_WRITE);
    }

    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    const body = await request.json();
    const { type, target, value, action, priority = 50, isActive = true } = body;

    // Validate required fields
    if (!type || !['allowlist', 'blocklist', 'rule'].includes(type)) {
      return errors.badRequest('type must be: allowlist, blocklist, or rule');
    }

    if (!target || !['domain', 'email', 'ip', 'pattern'].includes(target)) {
      return errors.badRequest('target must be: domain, email, ip, or pattern');
    }

    if (!value || typeof value !== 'string') {
      return errors.badRequest('value is required');
    }

    if (!action || !['allow', 'block', 'quarantine'].includes(action)) {
      return errors.badRequest('action must be: allow, block, or quarantine');
    }

    // Check for duplicate
    const existing = await sql`
      SELECT id FROM policies
      WHERE tenant_id = ${auth.tenantId}
        AND type = ${type}
        AND target = ${target}
        AND value = ${value}
      LIMIT 1
    `;

    if (existing.length > 0) {
      return errors.conflict('A policy with this type, target, and value already exists');
    }

    const id = nanoid();
    await sql`
      INSERT INTO policies (id, tenant_id, type, target, value, action, priority, is_active, created_by, created_at, updated_at)
      VALUES (
        ${id},
        ${auth.tenantId},
        ${type},
        ${target},
        ${value},
        ${action},
        ${priority},
        ${isActive},
        ${auth.keyId},
        NOW(),
        NOW()
      )
    `;

    // Log creation
    await sql`
      INSERT INTO audit_logs (id, tenant_id, actor_id, action, resource_type, resource_id, after_state, created_at)
      VALUES (
        ${nanoid()},
        ${auth.tenantId},
        ${auth.keyId},
        'policy.created',
        'policy',
        ${id},
        ${JSON.stringify({ type, target, value, action, priority, isActive, via: 'api' })},
        NOW()
      )
    `;

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiCreated({
      policy: { id, type, target, value, action, priority, isActive },
    }, headers);
  });
}
