/**
 * REST API v1 - Phish Report Endpoint
 *
 * POST /api/v1/report-phish - Submit a new phish report (from add-in/add-on)
 * GET /api/v1/report-phish - List phish reports (with filters)
 */

import { NextRequest } from 'next/server';
import { sql } from '@/lib/db';
import { validateApiKey, hasScope, API_SCOPES } from '@/lib/api/auth';
import { rateLimitMiddleware, getRateLimitHeaders, checkRateLimit } from '@/lib/api/rate-limit';
import { apiSuccess, apiCreated, errors, parsePagination, withErrorHandling } from '@/lib/api/response';
import {
  phishReportService,
  parseOutlookAddinMessage,
  parseGmailAddonMessage,
  type PhishReportData,
  type ReportFilters,
  type ReportSource,
  type OutlookAddinMessage,
  type GmailAddonMessage,
} from '@/lib/reporting/phish-button';

// Additional scope for phish reports
const PHISH_REPORTS_READ = 'phish_reports:read';
const PHISH_REPORTS_WRITE = 'phish_reports:write';

// Stricter rate limit for report submissions (prevent abuse)
const REPORT_SUBMISSION_LIMIT = {
  maxRequests: 30,  // 30 reports per minute per tenant
  windowMs: 60 * 1000,
  keyPrefix: 'phish-report',
};

/**
 * POST /api/v1/report-phish
 * Submit a new phish report from Outlook Add-in, Gmail Add-on, or manual submission
 */
export async function POST(request: NextRequest) {
  return withErrorHandling(async () => {
    // Validate API key
    const auth = await validateApiKey(request);
    if (!auth.valid) {
      return errors.unauthorized(auth.error);
    }

    // Check scope - allow threats:write or phish_reports:write
    if (!hasScope(auth.scopes!, API_SCOPES.THREATS_WRITE) && !hasScope(auth.scopes!, PHISH_REPORTS_WRITE)) {
      return errors.invalidScope(`${API_SCOPES.THREATS_WRITE} or ${PHISH_REPORTS_WRITE}`);
    }

    // Check standard rate limit
    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    // Check stricter submission rate limit
    const submitLimit = checkRateLimit(auth.tenantId!, REPORT_SUBMISSION_LIMIT);
    if (!submitLimit.allowed) {
      return errors.rateLimited(Math.ceil((submitLimit.resetAt - Date.now()) / 1000));
    }

    // Parse request body
    const body = await request.json();

    // Validate required fields based on source format
    const source = body.source as ReportSource;
    if (!source || !['outlook_addin', 'gmail_addon', 'manual', 'forwarded'].includes(source)) {
      return errors.badRequest('Invalid or missing source. Must be: outlook_addin, gmail_addon, manual, or forwarded');
    }

    let reportData: PhishReportData;

    try {
      if (source === 'outlook_addin') {
        // Parse Outlook Add-in format
        if (!body.message || !body.message.subject || !body.message.from) {
          return errors.badRequest('Invalid Outlook Add-in message format. Missing required fields.');
        }
        reportData = parseOutlookAddinMessage(body.message as OutlookAddinMessage);
        reportData.reporterEmail = body.reporterEmail || getReporterFromAuth(auth);
      } else if (source === 'gmail_addon') {
        // Parse Gmail Add-on format
        if (!body.message || !body.message.payload) {
          return errors.badRequest('Invalid Gmail Add-on message format. Missing required fields.');
        }
        reportData = parseGmailAddonMessage(body.message as GmailAddonMessage);
        reportData.reporterEmail = body.reporterEmail || getReporterFromAuth(auth);
      } else {
        // Manual or forwarded submission
        if (!body.subject || !body.fromAddress) {
          return errors.badRequest('Missing required fields: subject, fromAddress');
        }
        reportData = {
          reporterEmail: body.reporterEmail || getReporterFromAuth(auth),
          originalMessageId: body.messageId || body.originalMessageId,
          subject: body.subject,
          fromAddress: body.fromAddress,
          fromDisplayName: body.fromDisplayName,
          toAddresses: body.toAddresses || [],
          receivedAt: body.receivedAt ? new Date(body.receivedAt) : undefined,
          reportSource: source,
          reporterComments: body.comments || body.reporterComments,
          emailHeaders: body.headers || body.emailHeaders,
          emailBodyText: body.bodyText || body.emailBodyText,
          emailBodyHtml: body.bodyHtml || body.emailBodyHtml,
          clientInfo: body.clientInfo,
        };
      }

      // Validate reporter email
      if (!reportData.reporterEmail || !isValidEmail(reportData.reporterEmail)) {
        return errors.badRequest('Invalid or missing reporter email');
      }

      // Validate from address
      if (!reportData.fromAddress || !isValidEmail(reportData.fromAddress)) {
        return errors.badRequest('Invalid sender email address');
      }

      // Submit the report
      const result = await phishReportService.submitReport(auth.tenantId!, reportData);

      const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
      return apiCreated({
        reportId: result.reportId,
        analysisQueued: result.analysisQueued,
        message: 'Phish report submitted successfully',
      }, headers);

    } catch (error) {
      console.error('Error submitting phish report:', error);
      if (error instanceof Error && error.message.includes('Missing required')) {
        return errors.badRequest(error.message);
      }
      throw error;
    }
  });
}

/**
 * GET /api/v1/report-phish
 * List phish reports with optional filters
 */
export async function GET(request: NextRequest) {
  return withErrorHandling(async () => {
    // Validate API key
    const auth = await validateApiKey(request);
    if (!auth.valid) {
      return errors.unauthorized(auth.error);
    }

    // Check scope - allow threats:read or phish_reports:read
    if (!hasScope(auth.scopes!, API_SCOPES.THREATS_READ) && !hasScope(auth.scopes!, PHISH_REPORTS_READ)) {
      return errors.invalidScope(`${API_SCOPES.THREATS_READ} or ${PHISH_REPORTS_READ}`);
    }

    // Check rate limit
    const rateLimitResponse = rateLimitMiddleware(request, auth.tenantId!, 'pro');
    if (rateLimitResponse) return rateLimitResponse;

    // Parse query parameters
    const searchParams = request.nextUrl.searchParams;
    const { page, pageSize, offset } = parsePagination(searchParams);

    // Build filters
    const filters: ReportFilters = {};

    const status = searchParams.get('status');
    if (status && ['pending', 'analyzing', 'reviewed'].includes(status)) {
      filters.status = status as 'pending' | 'analyzing' | 'reviewed';
    }

    const verdict = searchParams.get('verdict');
    if (verdict && ['confirmed_phish', 'false_positive', 'inconclusive'].includes(verdict)) {
      filters.verdict = verdict as 'confirmed_phish' | 'false_positive' | 'inconclusive';
    }

    const source = searchParams.get('source');
    if (source && ['outlook_addin', 'gmail_addon', 'manual', 'forwarded'].includes(source)) {
      filters.source = source as ReportSource;
    }

    const startDate = searchParams.get('startDate');
    if (startDate) {
      filters.startDate = new Date(startDate);
    }

    const endDate = searchParams.get('endDate');
    if (endDate) {
      filters.endDate = new Date(endDate);
    }

    const search = searchParams.get('search');
    if (search) {
      filters.search = search;
    }

    const reporterEmail = searchParams.get('reporterEmail');
    if (reporterEmail) {
      filters.reporterEmail = reporterEmail;
    }

    // Get reports
    const { reports, total } = await phishReportService.getReportsByTenant(
      auth.tenantId!,
      filters,
      { page, pageSize }
    );

    // Format response
    const formattedReports = reports.map((r) => ({
      id: r.id,
      reporterEmail: r.reporterEmail,
      reportedAt: r.reportedAt.toISOString(),
      messageId: r.originalMessageId,
      subject: r.subject,
      from: {
        address: r.fromAddress,
        displayName: r.fromDisplayName,
      },
      to: r.toAddresses,
      source: r.reportSource,
      status: r.analysisStatus,
      verdict: r.verdict,
      score: r.verdictScore,
      signalCount: r.signals.length,
      hasAdminNotes: !!r.adminNotes,
      reviewedBy: r.reviewedBy,
      reviewedAt: r.reviewedAt?.toISOString(),
      createdAt: r.createdAt.toISOString(),
    }));

    const headers = getRateLimitHeaders(auth.tenantId!, 'pro');
    return apiSuccess(
      { reports: formattedReports },
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

// ============================================
// Helper Functions
// ============================================

function getReporterFromAuth(auth: { keyId?: string; tenantId?: string }): string {
  // In a real implementation, this would get the user email from the API key metadata
  // For now, return a placeholder that indicates it came from API
  return `api-key:${auth.keyId || 'unknown'}`;
}

function isValidEmail(email: string): boolean {
  // Basic email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) || email.startsWith('api-key:');
}
