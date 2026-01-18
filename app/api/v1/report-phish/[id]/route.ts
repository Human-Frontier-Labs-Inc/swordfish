/**
 * REST API v1 - Individual Phish Report Endpoint
 *
 * GET /api/v1/report-phish/:id - Get report details
 * PATCH /api/v1/report-phish/:id - Update report (admin feedback)
 * DELETE /api/v1/report-phish/:id - Delete report
 */

import { NextRequest } from 'next/server';
import { validateApiKey, hasScope, API_SCOPES } from '@/lib/api/auth';
import { rateLimitMiddleware, getRateLimitHeaders } from '@/lib/api/rate-limit';
import { apiSuccess, errors, withErrorHandling } from '@/lib/api/response';
import {
  phishReportService,
  type AdminFeedback,
} from '@/lib/reporting/phish-button';

// Additional scopes for phish reports
const PHISH_REPORTS_READ = 'phish_reports:read';
const PHISH_REPORTS_WRITE = 'phish_reports:write';

interface RouteParams {
  params: Promise<{ id: string }>;
}

/**
 * GET /api/v1/report-phish/:id
 * Get detailed information about a specific phish report
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  return withErrorHandling(async () => {
    // Validate API key
    const auth = await validateApiKey(request);
    if (!auth.valid) {
      return errors.unauthorized(auth.error);
    }

    // Check scope
    if (!hasScope(auth.scopes!, API_SCOPES.THREATS_READ) && !hasScope(auth.scopes!, PHISH_REPORTS_READ)) {
      return errors.invalidScope(`${API_SCOPES.THREATS_READ} or ${PHISH_REPORTS_READ}`);
    }

    // Check rate limit
    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    const { id } = await params;

    // Get the report
    const report = await phishReportService.getReportById(id, auth.tenantId!);

    if (!report) {
      return errors.notFound('Phish report');
    }

    // Format detailed response
    const formattedReport = {
      id: report.id,
      tenantId: report.tenantId,
      reporterEmail: report.reporterEmail,
      reportedAt: report.reportedAt.toISOString(),
      originalMessageId: report.originalMessageId,
      subject: report.subject,
      from: {
        address: report.fromAddress,
        displayName: report.fromDisplayName,
      },
      to: report.toAddresses,
      source: report.reportSource,
      reporterComments: report.reporterComments,
      analysis: {
        status: report.analysisStatus,
        verdict: report.verdict,
        score: report.verdictScore,
        signals: report.signals,
      },
      review: {
        reviewedBy: report.reviewedBy,
        reviewedAt: report.reviewedAt?.toISOString(),
        adminNotes: report.adminNotes,
        reporterNotified: report.notifiedReporter,
      },
      timestamps: {
        createdAt: report.createdAt.toISOString(),
        updatedAt: report.updatedAt.toISOString(),
      },
    };

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiSuccess({ report: formattedReport }, undefined, headers);
  });
}

/**
 * PATCH /api/v1/report-phish/:id
 * Update a phish report with admin feedback
 */
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  return withErrorHandling(async () => {
    // Validate API key
    const auth = await validateApiKey(request);
    if (!auth.valid) {
      return errors.unauthorized(auth.error);
    }

    // Check scope - requires write permission
    if (!hasScope(auth.scopes!, API_SCOPES.THREATS_WRITE) && !hasScope(auth.scopes!, PHISH_REPORTS_WRITE)) {
      return errors.invalidScope(`${API_SCOPES.THREATS_WRITE} or ${PHISH_REPORTS_WRITE}`);
    }

    // Check rate limit
    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    const { id } = await params;
    const body = await request.json();

    // Validate the action
    const { action } = body;

    if (action === 'analyze') {
      // Re-run analysis on the report
      try {
        const result = await phishReportService.analyzeReportedEmail(id, auth.tenantId!);
        const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
        return apiSuccess({
          id,
          action: 'analyze',
          success: true,
          analysis: {
            score: result.score,
            signalCount: result.signals.length,
            signals: result.signals,
          },
        }, undefined, headers);
      } catch (error) {
        if (error instanceof Error && error.message.includes('not found')) {
          return errors.notFound('Phish report');
        }
        throw error;
      }
    }

    if (action === 'feedback' || action === 'review') {
      // Admin provides feedback on the report
      const { isPhish, adminNotes, notifyReporter, addToBlocklist, blocklistType } = body;

      if (typeof isPhish !== 'boolean') {
        return errors.badRequest('Missing required field: isPhish (boolean)');
      }

      const feedback: AdminFeedback = {
        isPhish,
        adminNotes,
        notifyReporter: notifyReporter === true,
        addToBlocklist: addToBlocklist === true,
        blocklistType: blocklistType === 'domain' ? 'domain' : 'email',
      };

      try {
        const result = await phishReportService.provideFeedback(
          id,
          auth.tenantId!,
          auth.keyId!,
          feedback
        );

        const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
        return apiSuccess({
          id,
          action: 'feedback',
          success: result.success,
          verdict: isPhish ? 'confirmed_phish' : 'false_positive',
          actionsApplied: result.actionsApplied,
        }, undefined, headers);
      } catch (error) {
        if (error instanceof Error && error.message.includes('not found')) {
          return errors.notFound('Phish report');
        }
        throw error;
      }
    }

    // Invalid action
    return errors.badRequest('Invalid action. Must be: analyze or feedback');
  });
}

/**
 * DELETE /api/v1/report-phish/:id
 * Delete a phish report
 */
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  return withErrorHandling(async () => {
    // Validate API key
    const auth = await validateApiKey(request);
    if (!auth.valid) {
      return errors.unauthorized(auth.error);
    }

    // Check scope - requires write permission
    if (!hasScope(auth.scopes!, API_SCOPES.THREATS_WRITE) && !hasScope(auth.scopes!, PHISH_REPORTS_WRITE)) {
      return errors.invalidScope(`${API_SCOPES.THREATS_WRITE} or ${PHISH_REPORTS_WRITE}`);
    }

    // Check rate limit
    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    const { id } = await params;

    // Delete the report
    const deleted = await phishReportService.deleteReport(id, auth.tenantId!, auth.keyId!);

    if (!deleted) {
      return errors.notFound('Phish report');
    }

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiSuccess({ id, deleted: true }, undefined, headers);
  });
}
