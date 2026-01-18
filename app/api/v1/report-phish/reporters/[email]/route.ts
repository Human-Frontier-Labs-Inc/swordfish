/**
 * REST API v1 - Individual Reporter Stats Endpoint
 *
 * GET /api/v1/report-phish/reporters/:email - Get reporter's gamification stats
 */

import { NextRequest } from 'next/server';
import { validateApiKey, hasScope, API_SCOPES } from '@/lib/api/auth';
import { rateLimitMiddleware, getRateLimitHeaders } from '@/lib/api/rate-limit';
import { apiSuccess, errors, withErrorHandling } from '@/lib/api/response';
import { phishReportService } from '@/lib/reporting/phish-button';

// Additional scopes for phish reports
const PHISH_REPORTS_READ = 'phish_reports:read';

interface RouteParams {
  params: Promise<{ email: string }>;
}

/**
 * GET /api/v1/report-phish/reporters/:email
 * Get detailed gamification statistics for a specific reporter
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

    const { email } = await params;

    // Decode email from URL
    const reporterEmail = decodeURIComponent(email);

    // Validate email format
    if (!isValidEmail(reporterEmail)) {
      return errors.badRequest('Invalid email format');
    }

    // Get reporter stats
    const stats = await phishReportService.getReporterStats(auth.tenantId!, reporterEmail);

    // If no reports found, return empty stats
    if (stats.totalReports === 0) {
      return apiSuccess({
        reporter: {
          email: reporterEmail,
          hasReports: false,
          message: 'No phishing reports found for this email address',
        },
      });
    }

    // Level descriptions and point thresholds
    const levelInfo: Record<string, { minPoints: number; maxPoints: number; description: string }> = {
      novice: { minPoints: 0, maxPoints: 499, description: 'Just getting started' },
      defender: { minPoints: 500, maxPoints: 999, description: 'Reliable reporter' },
      guardian: { minPoints: 1000, maxPoints: 1999, description: 'Security advocate' },
      champion: { minPoints: 2000, maxPoints: 4999, description: 'Elite defender' },
      elite: { minPoints: 5000, maxPoints: Infinity, description: 'Master phish hunter' },
    };

    const currentLevelInfo = levelInfo[stats.level];
    const nextLevel = getNextLevel(stats.level);
    const pointsToNextLevel = nextLevel
      ? levelInfo[nextLevel].minPoints - stats.points
      : 0;

    // Format response
    const formattedStats = {
      reporter: {
        email: stats.email,
        hasReports: true,
      },
      summary: {
        totalReports: stats.totalReports,
        confirmedPhish: stats.confirmedPhish,
        falsePositives: stats.falsePositives,
        pendingReview: stats.pendingReview,
        accuracyRate: `${stats.accuracyRate}%`,
        rank: stats.rank,
      },
      gamification: {
        points: stats.points,
        level: {
          current: stats.level,
          description: currentLevelInfo.description,
          progress: {
            current: stats.points - currentLevelInfo.minPoints,
            required: currentLevelInfo.maxPoints - currentLevelInfo.minPoints + 1,
            percentage: currentLevelInfo.maxPoints === Infinity
              ? 100
              : Math.min(100, Math.round(
                  ((stats.points - currentLevelInfo.minPoints) /
                    (currentLevelInfo.maxPoints - currentLevelInfo.minPoints + 1)) * 100
                )),
          },
        },
        nextLevel: nextLevel
          ? {
              level: nextLevel,
              pointsRequired: levelInfo[nextLevel].minPoints,
              pointsNeeded: pointsToNextLevel,
            }
          : null,
      },
      badges: stats.badges.map((badge) => ({
        id: badge.id,
        name: badge.name,
        description: badge.description,
        icon: badge.icon,
        earnedAt: badge.earnedAt.toISOString(),
      })),
      streak: {
        current: stats.streak.current,
        longest: stats.streak.longest,
        isActive: stats.streak.current > 0,
      },
      activity: {
        firstReportAt: stats.firstReportAt?.toISOString() || null,
        lastReportAt: stats.lastReportAt?.toISOString() || null,
        daysSinceFirstReport: stats.firstReportAt
          ? Math.floor((Date.now() - stats.firstReportAt.getTime()) / (1000 * 60 * 60 * 24))
          : 0,
      },
      pointsBreakdown: {
        basePoints: stats.totalReports * 10,
        confirmationBonus: stats.confirmedPhish * 50,
        falsePositivePenalty: stats.falsePositives * -5,
        total: stats.points,
        formula: '(reports * 10) + (confirmed * 50) - (false_positives * 5)',
      },
    };

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiSuccess(formattedStats, undefined, headers);
  });
}

/**
 * Get the next level after the current one
 */
function getNextLevel(currentLevel: string): string | null {
  const levels = ['novice', 'defender', 'guardian', 'champion', 'elite'];
  const currentIndex = levels.indexOf(currentLevel);
  return currentIndex >= 0 && currentIndex < levels.length - 1
    ? levels[currentIndex + 1]
    : null;
}

/**
 * Validate email format
 */
function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}
