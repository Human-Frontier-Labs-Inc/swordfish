/**
 * REST API v1 - Threats Endpoint
 *
 * GET /api/v1/threats - List threats
 * POST /api/v1/threats/:id/action - Take action on threat
 */

import { NextRequest } from 'next/server';
import { sql } from '@/lib/db';
import { validateApiKey, hasScope, API_SCOPES } from '@/lib/api/auth';
import { rateLimitMiddleware, getRateLimitHeaders } from '@/lib/api/rate-limit';
import { apiSuccess, apiError, errors, parsePagination, withErrorHandling } from '@/lib/api/response';

// GET /api/v1/threats
export async function GET(request: NextRequest) {
  return withErrorHandling(async () => {
    // Validate API key
    const auth = await validateApiKey(request);
    if (!auth.valid) {
      return errors.unauthorized(auth.error);
    }

    // Check scope
    if (!hasScope(auth.scopes!, API_SCOPES.THREATS_READ)) {
      return errors.invalidScope(API_SCOPES.THREATS_READ);
    }

    // Check rate limit
    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    // Parse query parameters
    const searchParams = request.nextUrl.searchParams;
    const { page, pageSize, offset } = parsePagination(searchParams);

    const verdict = searchParams.get('verdict'); // pass, quarantine, block
    const severity = searchParams.get('severity'); // low, medium, high, critical
    const startDate = searchParams.get('startDate');
    const endDate = searchParams.get('endDate');
    const search = searchParams.get('search');

    // Build query
    let threats;
    let total;

    if (verdict || severity || startDate || endDate || search) {
      // Filtered query
      threats = await sql`
        SELECT
          id, message_id, subject, from_address, from_display_name,
          to_addresses, received_at, verdict, confidence, verdict_reason,
          signals, ml_classification, action_taken, action_taken_at, created_at
        FROM email_verdicts
        WHERE tenant_id = ${auth.tenantId}
          ${verdict ? sql`AND verdict = ${verdict}` : sql``}
          ${severity ? sql`AND (
            CASE
              WHEN confidence >= 90 THEN 'critical'
              WHEN confidence >= 70 THEN 'high'
              WHEN confidence >= 50 THEN 'medium'
              ELSE 'low'
            END
          ) = ${severity}` : sql``}
          ${startDate ? sql`AND created_at >= ${startDate}` : sql``}
          ${endDate ? sql`AND created_at <= ${endDate}` : sql``}
          ${search ? sql`AND (subject ILIKE ${'%' + search + '%'} OR from_address ILIKE ${'%' + search + '%'})` : sql``}
        ORDER BY created_at DESC
        LIMIT ${pageSize} OFFSET ${offset}
      `;

      const countResult = await sql`
        SELECT COUNT(*)::int as count
        FROM email_verdicts
        WHERE tenant_id = ${auth.tenantId}
          ${verdict ? sql`AND verdict = ${verdict}` : sql``}
          ${startDate ? sql`AND created_at >= ${startDate}` : sql``}
          ${endDate ? sql`AND created_at <= ${endDate}` : sql``}
          ${search ? sql`AND (subject ILIKE ${'%' + search + '%'} OR from_address ILIKE ${'%' + search + '%'})` : sql``}
      `;
      total = countResult[0]?.count || 0;
    } else {
      // Default query
      threats = await sql`
        SELECT
          id, message_id, subject, from_address, from_display_name,
          to_addresses, received_at, verdict, confidence, verdict_reason,
          signals, ml_classification, action_taken, action_taken_at, created_at
        FROM email_verdicts
        WHERE tenant_id = ${auth.tenantId}
        ORDER BY created_at DESC
        LIMIT ${pageSize} OFFSET ${offset}
      `;

      const countResult = await sql`
        SELECT COUNT(*)::int as count FROM email_verdicts WHERE tenant_id = ${auth.tenantId}
      `;
      total = countResult[0]?.count || 0;
    }

    // Format response
    const formattedThreats = threats.map((t: Record<string, unknown>) => ({
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
      classification: t.ml_classification,
      action: t.action_taken,
      actionTakenAt: t.action_taken_at,
      createdAt: t.created_at,
    }));

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');

    return apiSuccess(
      { threats: formattedThreats },
      {
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
      },
      headers
    );
  });
}
