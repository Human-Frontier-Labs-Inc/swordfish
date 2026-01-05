/**
 * REST API v1 - Quarantine Endpoint
 *
 * GET /api/v1/quarantine - List quarantined items
 * POST /api/v1/quarantine/bulk - Bulk actions
 */

import { NextRequest } from 'next/server';
import { sql } from '@/lib/db';
import { validateApiKey, hasScope, API_SCOPES } from '@/lib/api/auth';
import { rateLimitMiddleware, getRateLimitHeaders } from '@/lib/api/rate-limit';
import { apiSuccess, errors, parsePagination, withErrorHandling } from '@/lib/api/response';
import { nanoid } from 'nanoid';

// GET /api/v1/quarantine
export async function GET(request: NextRequest) {
  return withErrorHandling(async () => {
    const auth = await validateApiKey(request);
    if (!auth.valid) return errors.unauthorized(auth.error);

    if (!hasScope(auth.scopes!, API_SCOPES.QUARANTINE_READ)) {
      return errors.invalidScope(API_SCOPES.QUARANTINE_READ);
    }

    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    const searchParams = request.nextUrl.searchParams;
    const { page, pageSize, offset } = parsePagination(searchParams);
    const status = searchParams.get('status') || 'pending'; // pending, released, deleted

    const items = await sql`
      SELECT
        q.id, q.status, q.expires_at, q.created_at,
        q.released_at, q.released_by, q.deleted_at, q.deleted_by,
        ev.id as verdict_id, ev.message_id, ev.subject, ev.from_address,
        ev.from_display_name, ev.to_addresses, ev.verdict, ev.confidence,
        ev.verdict_reason, ev.signals
      FROM quarantine q
      JOIN email_verdicts ev ON q.verdict_id = ev.id
      WHERE q.tenant_id = ${auth.tenantId}
        AND q.status = ${status}
      ORDER BY q.created_at DESC
      LIMIT ${pageSize} OFFSET ${offset}
    `;

    const countResult = await sql`
      SELECT COUNT(*)::int as count
      FROM quarantine
      WHERE tenant_id = ${auth.tenantId} AND status = ${status}
    `;
    const total = countResult[0]?.count || 0;

    const formattedItems = items.map((item: Record<string, unknown>) => ({
      id: item.id,
      status: item.status,
      expiresAt: item.expires_at,
      createdAt: item.created_at,
      releasedAt: item.released_at,
      releasedBy: item.released_by,
      deletedAt: item.deleted_at,
      deletedBy: item.deleted_by,
      threat: {
        id: item.verdict_id,
        messageId: item.message_id,
        subject: item.subject,
        from: {
          address: item.from_address,
          displayName: item.from_display_name,
        },
        to: item.to_addresses,
        verdict: item.verdict,
        confidence: item.confidence,
        reason: item.verdict_reason,
        signals: item.signals,
      },
    }));

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiSuccess(
      { items: formattedItems },
      { page, pageSize, total, totalPages: Math.ceil(total / pageSize) },
      headers
    );
  });
}

// POST /api/v1/quarantine/bulk - Bulk actions
export async function POST(request: NextRequest) {
  return withErrorHandling(async () => {
    const auth = await validateApiKey(request);
    if (!auth.valid) return errors.unauthorized(auth.error);

    if (!hasScope(auth.scopes!, API_SCOPES.QUARANTINE_WRITE)) {
      return errors.invalidScope(API_SCOPES.QUARANTINE_WRITE);
    }

    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    const body = await request.json();
    const { ids, action } = body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return errors.badRequest('ids must be a non-empty array');
    }

    if (!action || !['release', 'delete'].includes(action)) {
      return errors.badRequest('action must be: release or delete');
    }

    if (ids.length > 100) {
      return errors.badRequest('Maximum 100 items per bulk operation');
    }

    // Verify all items belong to tenant
    const existing = await sql`
      SELECT id FROM quarantine
      WHERE id = ANY(${ids}) AND tenant_id = ${auth.tenantId}
    `;

    const existingIds = existing.map((r: Record<string, unknown>) => r.id as string);
    const notFound = ids.filter((id: string) => !existingIds.includes(id));

    if (notFound.length > 0) {
      return errors.badRequest(`Items not found: ${notFound.join(', ')}`);
    }

    // Perform bulk action
    if (action === 'release') {
      await sql`
        UPDATE quarantine
        SET status = 'released', released_at = NOW(), released_by = ${auth.keyId}
        WHERE id = ANY(${ids}) AND tenant_id = ${auth.tenantId}
      `;

      // Update corresponding email verdicts
      await sql`
        UPDATE email_verdicts
        SET action_taken = 'release', action_taken_at = NOW(), action_taken_by = ${auth.keyId}
        WHERE id IN (SELECT verdict_id FROM quarantine WHERE id = ANY(${ids}))
      `;
    } else {
      await sql`
        UPDATE quarantine
        SET status = 'deleted', deleted_at = NOW(), deleted_by = ${auth.keyId}
        WHERE id = ANY(${ids}) AND tenant_id = ${auth.tenantId}
      `;

      await sql`
        UPDATE email_verdicts
        SET action_taken = 'delete', action_taken_at = NOW(), action_taken_by = ${auth.keyId}
        WHERE id IN (SELECT verdict_id FROM quarantine WHERE id = ANY(${ids}))
      `;
    }

    // Log bulk action
    await sql`
      INSERT INTO audit_logs (id, tenant_id, actor_id, action, resource_type, after_state, created_at)
      VALUES (
        ${nanoid()},
        ${auth.tenantId},
        ${auth.keyId},
        ${'quarantine.bulk_' + action},
        'quarantine',
        ${JSON.stringify({ ids, action, count: ids.length, via: 'api' })},
        NOW()
      )
    `;

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiSuccess({
      action,
      processed: ids.length,
      ids,
    }, undefined, headers);
  });
}
