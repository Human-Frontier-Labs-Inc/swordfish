/**
 * REST API v1 - Phish Report Statistics Endpoint
 *
 * GET /api/v1/report-phish/stats - Get phish report statistics
 */

import { NextRequest } from 'next/server';
import { validateApiKey, hasScope, API_SCOPES } from '@/lib/api/auth';
import { rateLimitMiddleware, getRateLimitHeaders } from '@/lib/api/rate-limit';
import { apiSuccess, errors, withErrorHandling } from '@/lib/api/response';
import { phishReportService } from '@/lib/reporting/phish-button';

// Additional scopes for phish reports
const PHISH_REPORTS_READ = 'phish_reports:read';

/**
 * GET /api/v1/report-phish/stats
 * Get statistics on phish reports for the tenant
 */
export async function GET(request: NextRequest) {
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

    // Parse query parameters
    const searchParams = request.nextUrl.searchParams;
    const daysBack = parseInt(searchParams.get('days') || '30');

    // Validate days parameter
    const validDays = Math.min(Math.max(1, isNaN(daysBack) ? 30 : daysBack), 365);

    // Get statistics
    const stats = await phishReportService.getReportStats(auth.tenantId!, validDays);

    // Calculate derived metrics
    const detectionRate = stats.totalReports > 0
      ? ((stats.confirmedPhish / stats.totalReports) * 100).toFixed(1)
      : '0.0';

    const falsePositiveRate = stats.totalReports > 0
      ? ((stats.falsePositives / stats.totalReports) * 100).toFixed(1)
      : '0.0';

    const formattedStats = {
      period: {
        days: validDays,
        startDate: new Date(Date.now() - validDays * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        endDate: new Date().toISOString().split('T')[0],
      },
      summary: {
        totalReports: stats.totalReports,
        pendingReview: stats.pendingReview,
        confirmedPhish: stats.confirmedPhish,
        falsePositives: stats.falsePositives,
        inconclusive: stats.inconclusive,
      },
      rates: {
        detectionRate: `${detectionRate}%`,
        falsePositiveRate: `${falsePositiveRate}%`,
        avgReviewTimeHours: Number(stats.avgReviewTimeHours.toFixed(2)),
      },
      breakdown: {
        bySource: stats.reportsBySource,
        byDay: stats.reportsByDay,
      },
      topReporters: stats.topReporters.slice(0, 10),
    };

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiSuccess({ stats: formattedStats }, undefined, headers);
  });
}
