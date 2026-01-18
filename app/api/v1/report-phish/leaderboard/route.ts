/**
 * REST API v1 - Phish Report Leaderboard Endpoint
 *
 * GET /api/v1/report-phish/leaderboard - Get top reporters leaderboard
 */

import { NextRequest } from 'next/server';
import { validateApiKey, hasScope, API_SCOPES } from '@/lib/api/auth';
import { rateLimitMiddleware, getRateLimitHeaders } from '@/lib/api/rate-limit';
import { apiSuccess, errors, withErrorHandling } from '@/lib/api/response';
import { phishReportService } from '@/lib/reporting/phish-button';

// Additional scopes for phish reports
const PHISH_REPORTS_READ = 'phish_reports:read';

/**
 * GET /api/v1/report-phish/leaderboard
 * Get the top reporters leaderboard for gamification
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
    const limitParam = searchParams.get('limit');
    const limit = limitParam ? Math.min(Math.max(1, parseInt(limitParam) || 10), 100) : 10;

    // Get top reporters
    const leaderboard = await phishReportService.getTopReporters(auth.tenantId!, limit);

    // Format response with level descriptions
    const levelDescriptions: Record<string, string> = {
      novice: 'Just getting started',
      defender: 'Reliable reporter',
      guardian: 'Security advocate',
      champion: 'Elite defender',
      elite: 'Master phish hunter',
    };

    const formattedLeaderboard = leaderboard.map((entry) => ({
      rank: entry.rank,
      email: maskEmail(entry.email), // Privacy: mask email addresses
      displayName: entry.displayName,
      stats: {
        totalReports: entry.totalReports,
        confirmedPhish: entry.confirmedPhish,
        accuracyRate: `${entry.accuracyRate}%`,
      },
      gamification: {
        points: entry.points,
        level: entry.level,
        levelDescription: levelDescriptions[entry.level] || 'Unknown',
        badgeCount: entry.badges,
      },
    }));

    // Add summary statistics
    const totalReportsAcrossAll = leaderboard.reduce((sum, e) => sum + e.totalReports, 0);
    const totalConfirmedAcrossAll = leaderboard.reduce((sum, e) => sum + e.confirmedPhish, 0);

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiSuccess({
      leaderboard: formattedLeaderboard,
      summary: {
        totalReporters: leaderboard.length,
        totalReportsFromTop: totalReportsAcrossAll,
        totalConfirmedFromTop: totalConfirmedAcrossAll,
        averageAccuracy: leaderboard.length > 0
          ? `${Math.round(leaderboard.reduce((sum, e) => sum + e.accuracyRate, 0) / leaderboard.length)}%`
          : '0%',
      },
      levels: {
        novice: { minPoints: 0, description: levelDescriptions.novice },
        defender: { minPoints: 500, description: levelDescriptions.defender },
        guardian: { minPoints: 1000, description: levelDescriptions.guardian },
        champion: { minPoints: 2000, description: levelDescriptions.champion },
        elite: { minPoints: 5000, description: levelDescriptions.elite },
      },
    }, undefined, headers);
  });
}

/**
 * Mask email address for privacy (show first 2 chars and domain)
 */
function maskEmail(email: string): string {
  const [localPart, domain] = email.split('@');
  if (!domain) return email;

  const maskedLocal = localPart.length > 2
    ? `${localPart.slice(0, 2)}${'*'.repeat(Math.min(localPart.length - 2, 5))}`
    : localPart;

  return `${maskedLocal}@${domain}`;
}
