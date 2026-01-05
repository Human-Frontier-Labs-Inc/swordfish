/**
 * REST API v1 - Individual Threat Endpoint
 *
 * GET /api/v1/threats/:id - Get threat details
 * POST /api/v1/threats/:id/release - Release from quarantine
 * POST /api/v1/threats/:id/delete - Delete threat
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

// GET /api/v1/threats/:id
export async function GET(request: NextRequest, { params }: RouteParams) {
  return withErrorHandling(async () => {
    const auth = await validateApiKey(request);
    if (!auth.valid) return errors.unauthorized(auth.error);

    if (!hasScope(auth.scopes!, API_SCOPES.THREATS_READ)) {
      return errors.invalidScope(API_SCOPES.THREATS_READ);
    }

    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    const { id } = await params;

    const result = await sql`
      SELECT
        ev.*,
        q.status as quarantine_status,
        q.released_at,
        q.released_by
      FROM email_verdicts ev
      LEFT JOIN quarantine q ON ev.id = q.verdict_id
      WHERE ev.id = ${id} AND ev.tenant_id = ${auth.tenantId}
      LIMIT 1
    `;

    if (result.length === 0) {
      return errors.notFound('Threat');
    }

    const t = result[0];
    const threat = {
      id: t.id,
      messageId: t.message_id,
      subject: t.subject,
      from: {
        address: t.from_address,
        displayName: t.from_display_name,
      },
      to: t.to_addresses,
      receivedAt: t.received_at,
      verdict: t.verdict,
      confidence: t.confidence,
      reason: t.verdict_reason,
      signals: t.signals,
      analysis: {
        deterministicScore: t.deterministic_score,
        mlClassification: t.ml_classification,
        mlConfidence: t.ml_confidence,
        llmRecommendation: t.llm_recommendation,
        llmExplanation: t.llm_explanation,
      },
      processingTimeMs: t.processing_time_ms,
      action: t.action_taken,
      actionTakenAt: t.action_taken_at,
      actionTakenBy: t.action_taken_by,
      quarantine: t.quarantine_status ? {
        status: t.quarantine_status,
        releasedAt: t.released_at,
        releasedBy: t.released_by,
      } : null,
      createdAt: t.created_at,
      updatedAt: t.updated_at,
    };

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiSuccess({ threat }, undefined, headers);
  });
}

// PATCH /api/v1/threats/:id - Update threat (take action)
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  return withErrorHandling(async () => {
    const auth = await validateApiKey(request);
    if (!auth.valid) return errors.unauthorized(auth.error);

    if (!hasScope(auth.scopes!, API_SCOPES.THREATS_WRITE)) {
      return errors.invalidScope(API_SCOPES.THREATS_WRITE);
    }

    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    const { id } = await params;
    const body = await request.json();
    const { action } = body; // 'release', 'delete', 'block'

    if (!action || !['release', 'delete', 'block'].includes(action)) {
      return errors.badRequest('Invalid action. Must be: release, delete, or block');
    }

    // Verify threat exists and belongs to tenant
    const existing = await sql`
      SELECT id, verdict FROM email_verdicts
      WHERE id = ${id} AND tenant_id = ${auth.tenantId}
      LIMIT 1
    `;

    if (existing.length === 0) {
      return errors.notFound('Threat');
    }

    // Update threat
    await sql`
      UPDATE email_verdicts
      SET action_taken = ${action}, action_taken_at = NOW(), action_taken_by = ${auth.keyId}
      WHERE id = ${id}
    `;

    // Handle quarantine updates
    if (action === 'release') {
      await sql`
        UPDATE quarantine
        SET status = 'released', released_at = NOW(), released_by = ${auth.keyId}
        WHERE verdict_id = ${id}
      `;
    } else if (action === 'delete') {
      await sql`
        UPDATE quarantine
        SET status = 'deleted', deleted_at = NOW(), deleted_by = ${auth.keyId}
        WHERE verdict_id = ${id}
      `;
    }

    // Log the action
    await sql`
      INSERT INTO audit_logs (id, tenant_id, actor_id, action, resource_type, resource_id, after_state, created_at)
      VALUES (
        ${nanoid()},
        ${auth.tenantId},
        ${auth.keyId},
        ${'threat.' + action},
        'email_verdict',
        ${id},
        ${JSON.stringify({ action, via: 'api' })},
        NOW()
      )
    `;

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiSuccess({ id, action, success: true }, undefined, headers);
  });
}
