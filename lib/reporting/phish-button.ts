/**
 * Phish Report Button Service
 *
 * Core logic for handling phish reports from Outlook Add-in, Gmail Add-on,
 * manual submissions, and forwarded emails.
 *
 * Integrates with the existing detection pipeline and SOC queue for triage.
 */

import { sql } from '@/lib/db';
import { nanoid } from 'nanoid';
import { runDeterministicAnalysis } from '@/lib/detection/deterministic';
import { sendNotification } from '@/lib/notifications/service';
import type { ParsedEmail, Signal } from '@/lib/detection/types';

// ============================================
// Types
// ============================================

export type ReportSource = 'outlook_addin' | 'gmail_addon' | 'manual' | 'forwarded';
export type AnalysisStatus = 'pending' | 'analyzing' | 'reviewed';
export type ReportVerdict = 'confirmed_phish' | 'false_positive' | 'inconclusive' | null;

export interface PhishReportData {
  reporterEmail: string;
  originalMessageId?: string;
  subject: string;
  fromAddress: string;
  fromDisplayName?: string;
  toAddresses: string[];
  receivedAt?: Date;
  reportSource: ReportSource;
  reporterComments?: string;
  // Raw email content for analysis
  emailHeaders?: Record<string, string>;
  emailBodyText?: string;
  emailBodyHtml?: string;
  // Additional metadata from add-in/add-on
  clientInfo?: {
    platform?: string;
    version?: string;
    userAgent?: string;
  };
}

export interface PhishReport {
  id: string;
  tenantId: string;
  reporterEmail: string;
  reportedAt: Date;
  originalMessageId: string | null;
  subject: string;
  fromAddress: string;
  fromDisplayName: string | null;
  toAddresses: string[];
  reportSource: ReportSource;
  reporterComments: string | null;
  analysisStatus: AnalysisStatus;
  verdict: ReportVerdict;
  verdictScore: number | null;
  signals: Signal[];
  adminNotes: string | null;
  reviewedBy: string | null;
  reviewedAt: Date | null;
  notifiedReporter: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface ReportFilters {
  status?: AnalysisStatus;
  verdict?: ReportVerdict;
  source?: ReportSource;
  startDate?: Date;
  endDate?: Date;
  search?: string;
  reporterEmail?: string;
}

export interface ReportStats {
  totalReports: number;
  pendingReview: number;
  confirmedPhish: number;
  falsePositives: number;
  inconclusive: number;
  avgReviewTimeHours: number;
  topReporters: Array<{ email: string; count: number }>;
  reportsBySource: Record<ReportSource, number>;
  reportsByDay: Array<{ date: string; count: number }>;
}

export interface AdminFeedback {
  isPhish: boolean;
  adminNotes?: string;
  notifyReporter?: boolean;
  addToBlocklist?: boolean;
  blocklistType?: 'domain' | 'email';
}

// ============================================
// Gamification Types
// ============================================

export interface ReporterStats {
  email: string;
  tenantId: string;
  totalReports: number;
  confirmedPhish: number;
  falsePositives: number;
  pendingReview: number;
  accuracyRate: number; // Percentage of confirmed threats
  rank: number; // Position in tenant leaderboard
  badges: ReporterBadge[];
  streak: {
    current: number; // Days with consecutive reports
    longest: number;
  };
  firstReportAt: Date | null;
  lastReportAt: Date | null;
  points: number; // Gamification points
  level: ReporterLevel;
}

export interface ReporterBadge {
  id: string;
  name: string;
  description: string;
  earnedAt: Date;
  icon: string;
}

export type ReporterLevel = 'novice' | 'defender' | 'guardian' | 'champion' | 'elite';

export interface ReporterLeaderboard {
  rank: number;
  email: string;
  displayName?: string;
  totalReports: number;
  confirmedPhish: number;
  accuracyRate: number;
  points: number;
  level: ReporterLevel;
  badges: number;
}

export interface ReportFeedback {
  isPositive: boolean;
  message?: string;
  pointsAwarded?: number;
}

// ============================================
// PhishReportService
// ============================================

export class PhishReportService {
  /**
   * Submit a new phish report from an add-in, add-on, or manual submission
   */
  async submitReport(
    tenantId: string,
    reportData: PhishReportData
  ): Promise<{ reportId: string; analysisQueued: boolean }> {
    const reportId = nanoid();

    // Validate required fields
    if (!reportData.reporterEmail || !reportData.subject || !reportData.fromAddress) {
      throw new Error('Missing required report fields: reporterEmail, subject, fromAddress');
    }

    // Truncate strings to fit database limits
    const safeSubject = truncate(reportData.subject, 500);
    const safeFromAddress = truncate(reportData.fromAddress, 250);
    const safeFromDisplayName = truncate(reportData.fromDisplayName, 250);
    const safeComments = truncate(reportData.reporterComments, 2000);
    const safeMessageId = truncate(reportData.originalMessageId, 250);

    // Insert the report
    await sql`
      INSERT INTO phish_reports (
        id,
        tenant_id,
        reporter_email,
        reported_at,
        original_message_id,
        subject,
        from_address,
        from_display_name,
        to_addresses,
        report_source,
        reporter_comments,
        analysis_status,
        verdict,
        signals,
        email_headers,
        email_body_text,
        email_body_html,
        client_info,
        notified_reporter,
        created_at,
        updated_at
      ) VALUES (
        ${reportId},
        ${tenantId},
        ${reportData.reporterEmail},
        NOW(),
        ${safeMessageId},
        ${safeSubject},
        ${safeFromAddress},
        ${safeFromDisplayName},
        ${JSON.stringify(reportData.toAddresses)},
        ${reportData.reportSource},
        ${safeComments},
        'pending',
        NULL,
        '[]'::jsonb,
        ${reportData.emailHeaders ? JSON.stringify(reportData.emailHeaders) : null},
        ${reportData.emailBodyText || null},
        ${reportData.emailBodyHtml || null},
        ${reportData.clientInfo ? JSON.stringify(reportData.clientInfo) : null},
        false,
        NOW(),
        NOW()
      )
    `;

    // Log the submission
    await sql`
      INSERT INTO audit_logs (
        id, tenant_id, actor_email, action, resource_type, resource_id, after_state, created_at
      ) VALUES (
        ${nanoid()},
        ${tenantId},
        ${reportData.reporterEmail},
        'phish_report.submitted',
        'phish_report',
        ${reportId},
        ${JSON.stringify({
          source: reportData.reportSource,
          subject: safeSubject,
          fromAddress: safeFromAddress,
        })},
        NOW()
      )
    `;

    // Queue background analysis if we have email content
    const canAnalyze = reportData.emailBodyText || reportData.emailBodyHtml || reportData.emailHeaders;

    if (canAnalyze) {
      // Start async analysis (non-blocking)
      this.analyzeReportedEmail(reportId, tenantId, reportData).catch((err) => {
        console.error(`Failed to analyze phish report ${reportId}:`, err);
      });
    }

    // Send notification to SOC queue
    await sendNotification({
      tenantId,
      type: 'threat_detected',
      title: 'New Phish Report Submitted',
      message: `User ${reportData.reporterEmail} reported a suspicious email: "${safeSubject}" from ${safeFromAddress}`,
      severity: 'warning',
      resourceType: 'phish_report',
      resourceId: reportId,
      metadata: {
        source: reportData.reportSource,
        reporterEmail: reportData.reporterEmail,
        fromAddress: safeFromAddress,
      },
    });

    return { reportId, analysisQueued: !!canAnalyze };
  }

  /**
   * Analyze a reported email using the detection pipeline
   */
  async analyzeReportedEmail(
    reportId: string,
    tenantId?: string,
    reportData?: PhishReportData
  ): Promise<{ score: number; signals: Signal[] }> {
    // Fetch report if not provided
    let report: PhishReport | null = null;
    let emailContent: {
      headers: Record<string, string>;
      bodyText: string | null;
      bodyHtml: string | null;
    } | null = null;

    if (!reportData) {
      const result = await sql`
        SELECT * FROM phish_reports WHERE id = ${reportId}
        ${tenantId ? sql`AND tenant_id = ${tenantId}` : sql``}
        LIMIT 1
      `;

      if (result.length === 0) {
        throw new Error(`Phish report not found: ${reportId}`);
      }

      report = mapReportRow(result[0]);
      tenantId = report.tenantId;

      // Get stored email content
      const contentResult = await sql`
        SELECT email_headers, email_body_text, email_body_html
        FROM phish_reports WHERE id = ${reportId}
      `;
      emailContent = {
        headers: (contentResult[0]?.email_headers as Record<string, string>) || {},
        bodyText: contentResult[0]?.email_body_text as string | null,
        bodyHtml: contentResult[0]?.email_body_html as string | null,
      };
    } else {
      emailContent = {
        headers: reportData.emailHeaders || {},
        bodyText: reportData.emailBodyText || null,
        bodyHtml: reportData.emailBodyHtml || null,
      };
    }

    // Update status to analyzing
    await sql`
      UPDATE phish_reports
      SET analysis_status = 'analyzing', updated_at = NOW()
      WHERE id = ${reportId}
    `;

    // Build parsed email structure for detection
    const parsedEmail: ParsedEmail = {
      messageId: report?.originalMessageId || reportData?.originalMessageId || nanoid(),
      subject: report?.subject || reportData?.subject || '',
      from: {
        address: report?.fromAddress || reportData?.fromAddress || '',
        displayName: report?.fromDisplayName || reportData?.fromDisplayName,
        domain: extractDomain(report?.fromAddress || reportData?.fromAddress || ''),
      },
      to: (report?.toAddresses || reportData?.toAddresses || []).map((addr) => ({
        address: addr,
        domain: extractDomain(addr),
      })),
      date: report?.createdAt || new Date(),
      headers: emailContent.headers,
      body: {
        text: emailContent.bodyText || undefined,
        html: emailContent.bodyHtml || undefined,
      },
      attachments: [],
      rawHeaders: Object.entries(emailContent.headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\r\n'),
    };

    // Run deterministic analysis
    const analysisResult = await runDeterministicAnalysis(parsedEmail);

    // Update report with analysis results
    await sql`
      UPDATE phish_reports
      SET
        analysis_status = 'pending',
        verdict_score = ${analysisResult.score},
        signals = ${JSON.stringify(analysisResult.signals)},
        updated_at = NOW()
      WHERE id = ${reportId}
    `;

    return {
      score: analysisResult.score,
      signals: analysisResult.signals,
    };
  }

  /**
   * Provide admin feedback on a phish report
   */
  async provideFeedback(
    reportId: string,
    tenantId: string,
    adminId: string,
    feedback: AdminFeedback
  ): Promise<{ success: boolean; actionsApplied: string[] }> {
    // Verify report exists and belongs to tenant
    const existing = await sql`
      SELECT id, from_address, reporter_email, subject
      FROM phish_reports
      WHERE id = ${reportId} AND tenant_id = ${tenantId}
      LIMIT 1
    `;

    if (existing.length === 0) {
      throw new Error(`Phish report not found: ${reportId}`);
    }

    const report = existing[0];
    const actionsApplied: string[] = [];

    // Determine verdict
    const verdict: ReportVerdict = feedback.isPhish ? 'confirmed_phish' : 'false_positive';

    // Update the report
    await sql`
      UPDATE phish_reports
      SET
        analysis_status = 'reviewed',
        verdict = ${verdict},
        admin_notes = ${feedback.adminNotes || null},
        reviewed_by = ${adminId},
        reviewed_at = NOW(),
        updated_at = NOW()
      WHERE id = ${reportId}
    `;
    actionsApplied.push(`verdict_set:${verdict}`);

    // Add to blocklist if requested and confirmed phish
    if (feedback.isPhish && feedback.addToBlocklist) {
      const blockValue = feedback.blocklistType === 'domain'
        ? extractDomain(report.from_address)
        : report.from_address;

      await sql`
        INSERT INTO policies (
          id, tenant_id, type, target, value, action, priority, is_active, created_by, created_at, updated_at
        ) VALUES (
          ${nanoid()},
          ${tenantId},
          'blocklist',
          ${feedback.blocklistType || 'email'},
          ${blockValue},
          'block',
          100,
          true,
          ${adminId},
          NOW(),
          NOW()
        )
        ON CONFLICT (tenant_id, type, target, value) DO NOTHING
      `;
      actionsApplied.push(`blocklist_added:${blockValue}`);
    }

    // Notify reporter if requested
    if (feedback.notifyReporter) {
      await this.notifyReporter(reportId, tenantId, verdict, feedback.adminNotes);
      actionsApplied.push('reporter_notified');
    }

    // Log the action
    await sql`
      INSERT INTO audit_logs (
        id, tenant_id, actor_id, action, resource_type, resource_id, before_state, after_state, created_at
      ) VALUES (
        ${nanoid()},
        ${tenantId},
        ${adminId},
        'phish_report.reviewed',
        'phish_report',
        ${reportId},
        ${JSON.stringify({ verdict: null })},
        ${JSON.stringify({
          verdict,
          adminNotes: feedback.adminNotes,
          actionsApplied,
        })},
        NOW()
      )
    `;

    // Track false positive/negative for ML improvement
    await this.trackFeedback(tenantId, reportId, verdict);

    return { success: true, actionsApplied };
  }

  /**
   * Get phish reports for a tenant with optional filters
   */
  async getReportsByTenant(
    tenantId: string,
    filters: ReportFilters = {},
    pagination: { page: number; pageSize: number } = { page: 1, pageSize: 20 }
  ): Promise<{ reports: PhishReport[]; total: number }> {
    const offset = (pagination.page - 1) * pagination.pageSize;

    // Build dynamic query with filters
    const reports = await sql`
      SELECT
        id, tenant_id, reporter_email, reported_at, original_message_id,
        subject, from_address, from_display_name, to_addresses, report_source,
        reporter_comments, analysis_status, verdict, verdict_score, signals,
        admin_notes, reviewed_by, reviewed_at, notified_reporter, created_at, updated_at
      FROM phish_reports
      WHERE tenant_id = ${tenantId}
        ${filters.status ? sql`AND analysis_status = ${filters.status}` : sql``}
        ${filters.verdict ? sql`AND verdict = ${filters.verdict}` : sql``}
        ${filters.source ? sql`AND report_source = ${filters.source}` : sql``}
        ${filters.startDate ? sql`AND reported_at >= ${filters.startDate.toISOString()}` : sql``}
        ${filters.endDate ? sql`AND reported_at <= ${filters.endDate.toISOString()}` : sql``}
        ${filters.reporterEmail ? sql`AND reporter_email = ${filters.reporterEmail}` : sql``}
        ${filters.search ? sql`AND (
          subject ILIKE ${'%' + filters.search + '%'} OR
          from_address ILIKE ${'%' + filters.search + '%'} OR
          reporter_email ILIKE ${'%' + filters.search + '%'}
        )` : sql``}
      ORDER BY reported_at DESC
      LIMIT ${pagination.pageSize} OFFSET ${offset}
    `;

    const countResult = await sql`
      SELECT COUNT(*)::int as count
      FROM phish_reports
      WHERE tenant_id = ${tenantId}
        ${filters.status ? sql`AND analysis_status = ${filters.status}` : sql``}
        ${filters.verdict ? sql`AND verdict = ${filters.verdict}` : sql``}
        ${filters.source ? sql`AND report_source = ${filters.source}` : sql``}
        ${filters.startDate ? sql`AND reported_at >= ${filters.startDate.toISOString()}` : sql``}
        ${filters.endDate ? sql`AND reported_at <= ${filters.endDate.toISOString()}` : sql``}
        ${filters.reporterEmail ? sql`AND reporter_email = ${filters.reporterEmail}` : sql``}
        ${filters.search ? sql`AND (
          subject ILIKE ${'%' + filters.search + '%'} OR
          from_address ILIKE ${'%' + filters.search + '%'} OR
          reporter_email ILIKE ${'%' + filters.search + '%'}
        )` : sql``}
    `;

    return {
      reports: reports.map(mapReportRow),
      total: countResult[0]?.count || 0,
    };
  }

  /**
   * Get a single phish report by ID
   */
  async getReportById(
    reportId: string,
    tenantId: string
  ): Promise<PhishReport | null> {
    const result = await sql`
      SELECT
        id, tenant_id, reporter_email, reported_at, original_message_id,
        subject, from_address, from_display_name, to_addresses, report_source,
        reporter_comments, analysis_status, verdict, verdict_score, signals,
        admin_notes, reviewed_by, reviewed_at, notified_reporter, created_at, updated_at
      FROM phish_reports
      WHERE id = ${reportId} AND tenant_id = ${tenantId}
      LIMIT 1
    `;

    if (result.length === 0) {
      return null;
    }

    return mapReportRow(result[0]);
  }

  /**
   * Delete a phish report
   */
  async deleteReport(
    reportId: string,
    tenantId: string,
    deletedBy: string
  ): Promise<boolean> {
    // Log before deletion
    await sql`
      INSERT INTO audit_logs (
        id, tenant_id, actor_id, action, resource_type, resource_id, created_at
      ) VALUES (
        ${nanoid()},
        ${tenantId},
        ${deletedBy},
        'phish_report.deleted',
        'phish_report',
        ${reportId},
        NOW()
      )
    `;

    const result = await sql`
      DELETE FROM phish_reports
      WHERE id = ${reportId} AND tenant_id = ${tenantId}
      RETURNING id
    `;

    return result.length > 0;
  }

  /**
   * Get statistics on phish reports for a tenant
   */
  async getReportStats(
    tenantId: string,
    daysBack: number = 30
  ): Promise<ReportStats> {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - daysBack);

    // Get overall counts
    const counts = await sql`
      SELECT
        COUNT(*)::int as total,
        COUNT(*) FILTER (WHERE analysis_status = 'pending')::int as pending,
        COUNT(*) FILTER (WHERE verdict = 'confirmed_phish')::int as confirmed_phish,
        COUNT(*) FILTER (WHERE verdict = 'false_positive')::int as false_positives,
        COUNT(*) FILTER (WHERE verdict = 'inconclusive')::int as inconclusive
      FROM phish_reports
      WHERE tenant_id = ${tenantId}
        AND reported_at >= ${startDate.toISOString()}
    `;

    // Get average review time
    const avgTime = await sql`
      SELECT
        AVG(EXTRACT(EPOCH FROM (reviewed_at - reported_at)) / 3600)::float as avg_hours
      FROM phish_reports
      WHERE tenant_id = ${tenantId}
        AND reviewed_at IS NOT NULL
        AND reported_at >= ${startDate.toISOString()}
    `;

    // Get top reporters
    const topReporters = await sql`
      SELECT reporter_email as email, COUNT(*)::int as count
      FROM phish_reports
      WHERE tenant_id = ${tenantId}
        AND reported_at >= ${startDate.toISOString()}
      GROUP BY reporter_email
      ORDER BY count DESC
      LIMIT 10
    `;

    // Get reports by source
    const bySource = await sql`
      SELECT report_source, COUNT(*)::int as count
      FROM phish_reports
      WHERE tenant_id = ${tenantId}
        AND reported_at >= ${startDate.toISOString()}
      GROUP BY report_source
    `;

    // Get reports by day
    const byDay = await sql`
      SELECT
        DATE(reported_at) as date,
        COUNT(*)::int as count
      FROM phish_reports
      WHERE tenant_id = ${tenantId}
        AND reported_at >= ${startDate.toISOString()}
      GROUP BY DATE(reported_at)
      ORDER BY date ASC
    `;

    const sourceMap: Record<ReportSource, number> = {
      outlook_addin: 0,
      gmail_addon: 0,
      manual: 0,
      forwarded: 0,
    };

    bySource.forEach((row: Record<string, unknown>) => {
      const source = row.report_source as ReportSource;
      if (source in sourceMap) {
        sourceMap[source] = row.count as number;
      }
    });

    return {
      totalReports: counts[0]?.total || 0,
      pendingReview: counts[0]?.pending || 0,
      confirmedPhish: counts[0]?.confirmed_phish || 0,
      falsePositives: counts[0]?.false_positives || 0,
      inconclusive: counts[0]?.inconclusive || 0,
      avgReviewTimeHours: avgTime[0]?.avg_hours || 0,
      topReporters: topReporters.map((r: Record<string, unknown>) => ({
        email: r.email as string,
        count: r.count as number,
      })),
      reportsBySource: sourceMap,
      reportsByDay: byDay.map((r: Record<string, unknown>) => ({
        date: (r.date as Date).toISOString().split('T')[0],
        count: r.count as number,
      })),
    };
  }

  /**
   * Notify the reporter of the verdict
   */
  private async notifyReporter(
    reportId: string,
    tenantId: string,
    verdict: ReportVerdict,
    adminNotes?: string
  ): Promise<void> {
    const result = await sql`
      SELECT reporter_email, subject, from_address
      FROM phish_reports
      WHERE id = ${reportId} AND tenant_id = ${tenantId}
    `;

    if (result.length === 0) return;

    const report = result[0];
    const isPhish = verdict === 'confirmed_phish';

    const title = isPhish
      ? 'Thank you for reporting a phishing attempt'
      : 'Report reviewed - Email appears legitimate';

    const message = isPhish
      ? `Your report about "${report.subject}" from ${report.from_address} has been confirmed as a phishing attempt. We have taken action to protect the organization. Thank you for your vigilance!`
      : `Your report about "${report.subject}" from ${report.from_address} has been reviewed and appears to be legitimate. ${adminNotes ? `Note from security team: ${adminNotes}` : ''}`;

    await sendNotification({
      tenantId,
      type: 'threat_released',
      title,
      message,
      severity: 'info',
      resourceType: 'phish_report',
      resourceId: reportId,
      metadata: {
        reporterEmail: report.reporter_email,
        verdict,
        notificationType: 'reporter_feedback',
      },
    });

    // Mark as notified
    await sql`
      UPDATE phish_reports
      SET notified_reporter = true, updated_at = NOW()
      WHERE id = ${reportId}
    `;
  }

  // ============================================
  // Gamification Methods
  // ============================================

  /**
   * Get individual reporter statistics for gamification
   */
  async getReporterStats(
    tenantId: string,
    reporterEmail: string
  ): Promise<ReporterStats> {
    // Get reporter's report counts
    const counts = await sql`
      SELECT
        COUNT(*)::int as total,
        COUNT(*) FILTER (WHERE verdict = 'confirmed_phish')::int as confirmed_phish,
        COUNT(*) FILTER (WHERE verdict = 'false_positive')::int as false_positives,
        COUNT(*) FILTER (WHERE analysis_status = 'pending')::int as pending,
        MIN(reported_at) as first_report,
        MAX(reported_at) as last_report
      FROM phish_reports
      WHERE tenant_id = ${tenantId}
        AND reporter_email = ${reporterEmail}
    `;

    const stats = counts[0] || {
      total: 0,
      confirmed_phish: 0,
      false_positives: 0,
      pending: 0,
      first_report: null,
      last_report: null,
    };

    // Calculate rank within tenant
    const rankResult = await sql`
      WITH reporter_scores AS (
        SELECT
          reporter_email,
          COUNT(*) as total_reports,
          ROW_NUMBER() OVER (ORDER BY COUNT(*) DESC) as rank
        FROM phish_reports
        WHERE tenant_id = ${tenantId}
        GROUP BY reporter_email
      )
      SELECT rank FROM reporter_scores WHERE reporter_email = ${reporterEmail}
    `;
    const rank = rankResult[0]?.rank || 0;

    // Calculate streak (consecutive days with reports)
    const streakResult = await sql`
      WITH daily_reports AS (
        SELECT DISTINCT DATE(reported_at) as report_date
        FROM phish_reports
        WHERE tenant_id = ${tenantId}
          AND reporter_email = ${reporterEmail}
        ORDER BY report_date DESC
      ),
      streaks AS (
        SELECT
          report_date,
          report_date - (ROW_NUMBER() OVER (ORDER BY report_date DESC))::int * INTERVAL '1 day' as streak_group
        FROM daily_reports
      )
      SELECT COUNT(*)::int as streak_length
      FROM streaks
      GROUP BY streak_group
      ORDER BY MIN(report_date) DESC
      LIMIT 1
    `;
    const currentStreak = streakResult[0]?.streak_length || 0;

    // Calculate points
    const points = this.calculatePoints(
      stats.total,
      stats.confirmed_phish,
      stats.false_positives
    );

    // Determine level based on points
    const level = this.determineLevel(points);

    // Calculate badges
    const badges = this.calculateBadges(
      stats.total,
      stats.confirmed_phish,
      currentStreak,
      stats.first_report ? new Date(stats.first_report) : null
    );

    // Calculate accuracy rate
    const reviewedReports = stats.confirmed_phish + stats.false_positives;
    const accuracyRate = reviewedReports > 0
      ? Math.round((stats.confirmed_phish / reviewedReports) * 100)
      : 0;

    return {
      email: reporterEmail,
      tenantId,
      totalReports: stats.total,
      confirmedPhish: stats.confirmed_phish,
      falsePositives: stats.false_positives,
      pendingReview: stats.pending,
      accuracyRate,
      rank,
      badges,
      streak: {
        current: currentStreak,
        longest: currentStreak, // Would need separate tracking for longest
      },
      firstReportAt: stats.first_report ? new Date(stats.first_report) : null,
      lastReportAt: stats.last_report ? new Date(stats.last_report) : null,
      points,
      level,
    };
  }

  /**
   * Get top reporters for leaderboard
   */
  async getTopReporters(
    tenantId: string,
    limit: number = 10
  ): Promise<ReporterLeaderboard[]> {
    const reporters = await sql`
      SELECT
        reporter_email,
        COUNT(*)::int as total_reports,
        COUNT(*) FILTER (WHERE verdict = 'confirmed_phish')::int as confirmed_phish,
        COUNT(*) FILTER (WHERE verdict = 'false_positive')::int as false_positives
      FROM phish_reports
      WHERE tenant_id = ${tenantId}
      GROUP BY reporter_email
      ORDER BY COUNT(*) DESC
      LIMIT ${limit}
    `;

    return reporters.map((row: Record<string, unknown>, index: number) => {
      const totalReports = row.total_reports as number;
      const confirmedPhish = row.confirmed_phish as number;
      const falsePositives = row.false_positives as number;
      const reviewedReports = confirmedPhish + falsePositives;
      const accuracyRate = reviewedReports > 0
        ? Math.round((confirmedPhish / reviewedReports) * 100)
        : 0;

      const points = this.calculatePoints(totalReports, confirmedPhish, falsePositives);
      const level = this.determineLevel(points);

      // Calculate badge count
      const badges = this.calculateBadges(totalReports, confirmedPhish, 0, null);

      return {
        rank: index + 1,
        email: row.reporter_email as string,
        totalReports,
        confirmedPhish,
        accuracyRate,
        points,
        level,
        badges: badges.length,
      };
    });
  }

  /**
   * Provide feedback to a reporter after their report is reviewed
   */
  async sendReporterFeedback(
    reportId: string,
    tenantId: string,
    feedback: ReportFeedback
  ): Promise<void> {
    // Get the report to find the reporter
    const report = await this.getReportById(reportId, tenantId);
    if (!report) {
      throw new Error(`Phish report not found: ${reportId}`);
    }

    const message = feedback.isPositive
      ? `Great catch! Your phishing report was confirmed. ${feedback.message || ''}`
      : `Thank you for your report. ${feedback.message || ''}`;

    await sendNotification({
      tenantId,
      type: 'threat_released',
      title: feedback.isPositive ? 'Phishing Report Confirmed' : 'Report Reviewed',
      message: message.trim(),
      severity: 'info',
      resourceType: 'phish_report',
      resourceId: reportId,
      metadata: {
        reporterEmail: report.reporterEmail,
        pointsAwarded: feedback.pointsAwarded || 0,
        feedbackType: feedback.isPositive ? 'positive' : 'neutral',
      },
    });
  }

  /**
   * Calculate gamification points
   */
  private calculatePoints(
    totalReports: number,
    confirmedPhish: number,
    falsePositives: number
  ): number {
    // Base points: 10 per report
    // Bonus: 50 for confirmed phish
    // Penalty: -5 for false positive (minor, to encourage reporting)
    return (totalReports * 10) + (confirmedPhish * 50) - (falsePositives * 5);
  }

  /**
   * Determine reporter level based on points
   */
  private determineLevel(points: number): ReporterLevel {
    if (points >= 5000) return 'elite';
    if (points >= 2000) return 'champion';
    if (points >= 1000) return 'guardian';
    if (points >= 500) return 'defender';
    return 'novice';
  }

  /**
   * Calculate badges earned by a reporter
   */
  private calculateBadges(
    totalReports: number,
    confirmedPhish: number,
    currentStreak: number,
    firstReportAt: Date | null
  ): ReporterBadge[] {
    const badges: ReporterBadge[] = [];
    const now = new Date();

    // First Report badge
    if (totalReports >= 1) {
      badges.push({
        id: 'first_report',
        name: 'First Report',
        description: 'Submitted your first phishing report',
        earnedAt: firstReportAt || now,
        icon: 'shield-check',
      });
    }

    // Vigilant badge (10+ reports)
    if (totalReports >= 10) {
      badges.push({
        id: 'vigilant',
        name: 'Vigilant',
        description: 'Submitted 10 phishing reports',
        earnedAt: now,
        icon: 'eye',
      });
    }

    // Threat Hunter badge (50+ reports)
    if (totalReports >= 50) {
      badges.push({
        id: 'threat_hunter',
        name: 'Threat Hunter',
        description: 'Submitted 50 phishing reports',
        earnedAt: now,
        icon: 'crosshairs',
      });
    }

    // Phish Slayer badge (100+ reports)
    if (totalReports >= 100) {
      badges.push({
        id: 'phish_slayer',
        name: 'Phish Slayer',
        description: 'Submitted 100 phishing reports',
        earnedAt: now,
        icon: 'trophy',
      });
    }

    // Sharp Eye badge (10+ confirmed phish)
    if (confirmedPhish >= 10) {
      badges.push({
        id: 'sharp_eye',
        name: 'Sharp Eye',
        description: 'Had 10 reports confirmed as phishing',
        earnedAt: now,
        icon: 'target',
      });
    }

    // Expert Spotter badge (50+ confirmed phish)
    if (confirmedPhish >= 50) {
      badges.push({
        id: 'expert_spotter',
        name: 'Expert Spotter',
        description: 'Had 50 reports confirmed as phishing',
        earnedAt: now,
        icon: 'award',
      });
    }

    // Streak badges
    if (currentStreak >= 7) {
      badges.push({
        id: 'week_warrior',
        name: 'Week Warrior',
        description: 'Reported for 7 consecutive days',
        earnedAt: now,
        icon: 'flame',
      });
    }

    if (currentStreak >= 30) {
      badges.push({
        id: 'month_defender',
        name: 'Month Defender',
        description: 'Reported for 30 consecutive days',
        earnedAt: now,
        icon: 'calendar-check',
      });
    }

    return badges;
  }

  /**
   * Track feedback for ML improvement and false positive/negative metrics
   */
  private async trackFeedback(
    tenantId: string,
    reportId: string,
    verdict: ReportVerdict
  ): Promise<void> {
    // Insert feedback tracking record
    await sql`
      INSERT INTO ml_feedback (
        id,
        tenant_id,
        feedback_type,
        source_type,
        source_id,
        label,
        created_at
      ) VALUES (
        ${nanoid()},
        ${tenantId},
        'phish_report_verdict',
        'phish_report',
        ${reportId},
        ${verdict === 'confirmed_phish' ? 'phish' : verdict === 'false_positive' ? 'legitimate' : 'unknown'},
        NOW()
      )
      ON CONFLICT DO NOTHING
    `;
  }
}

// ============================================
// Helper Functions
// ============================================

function truncate(str: string | null | undefined, maxLength: number): string | null {
  if (!str) return null;
  return str.length > maxLength ? str.substring(0, maxLength - 3) + '...' : str;
}

function extractDomain(email: string): string {
  const parts = email.split('@');
  return parts.length > 1 ? parts[1].toLowerCase() : '';
}

function mapReportRow(row: Record<string, unknown>): PhishReport {
  return {
    id: row.id as string,
    tenantId: row.tenant_id as string,
    reporterEmail: row.reporter_email as string,
    reportedAt: new Date(row.reported_at as string),
    originalMessageId: row.original_message_id as string | null,
    subject: row.subject as string,
    fromAddress: row.from_address as string,
    fromDisplayName: row.from_display_name as string | null,
    toAddresses: (row.to_addresses as string[]) || [],
    reportSource: row.report_source as ReportSource,
    reporterComments: row.reporter_comments as string | null,
    analysisStatus: row.analysis_status as AnalysisStatus,
    verdict: row.verdict as ReportVerdict,
    verdictScore: row.verdict_score as number | null,
    signals: (row.signals as Signal[]) || [],
    adminNotes: row.admin_notes as string | null,
    reviewedBy: row.reviewed_by as string | null,
    reviewedAt: row.reviewed_at ? new Date(row.reviewed_at as string) : null,
    notifiedReporter: row.notified_reporter as boolean,
    createdAt: new Date(row.created_at as string),
    updatedAt: new Date(row.updated_at as string),
  };
}

// ============================================
// Outlook Add-in Message Format Parser
// ============================================

export interface OutlookAddinMessage {
  itemId: string;
  conversationId?: string;
  subject: string;
  from: {
    emailAddress: {
      address: string;
      name?: string;
    };
  };
  toRecipients: Array<{
    emailAddress: {
      address: string;
      name?: string;
    };
  }>;
  receivedDateTime: string;
  internetMessageHeaders?: Array<{
    name: string;
    value: string;
  }>;
  body?: {
    contentType: string;
    content: string;
  };
}

export function parseOutlookAddinMessage(message: OutlookAddinMessage): PhishReportData {
  const headers: Record<string, string> = {};
  if (message.internetMessageHeaders) {
    for (const header of message.internetMessageHeaders) {
      headers[header.name.toLowerCase()] = header.value;
    }
  }

  return {
    reporterEmail: '', // Set by caller based on authenticated user
    originalMessageId: message.itemId,
    subject: message.subject,
    fromAddress: message.from.emailAddress.address,
    fromDisplayName: message.from.emailAddress.name,
    toAddresses: message.toRecipients.map((r) => r.emailAddress.address),
    receivedAt: new Date(message.receivedDateTime),
    reportSource: 'outlook_addin',
    emailHeaders: headers,
    emailBodyText: message.body?.contentType === 'Text' ? message.body.content : undefined,
    emailBodyHtml: message.body?.contentType === 'HTML' ? message.body.content : undefined,
    clientInfo: {
      platform: 'outlook',
    },
  };
}

// ============================================
// Gmail Add-on Message Format Parser
// ============================================

export interface GmailAddonMessage {
  id: string;
  threadId: string;
  labelIds?: string[];
  snippet?: string;
  payload: {
    headers: Array<{
      name: string;
      value: string;
    }>;
    mimeType: string;
    body?: {
      size: number;
      data?: string;
    };
    parts?: Array<{
      mimeType: string;
      body?: {
        size: number;
        data?: string;
      };
    }>;
  };
  internalDate: string;
}

export function parseGmailAddonMessage(message: GmailAddonMessage): PhishReportData {
  const headers: Record<string, string> = {};
  let subject = '';
  let fromAddress = '';
  let fromDisplayName: string | undefined;
  const toAddresses: string[] = [];

  for (const header of message.payload.headers) {
    const name = header.name.toLowerCase();
    headers[name] = header.value;

    if (name === 'subject') {
      subject = header.value;
    } else if (name === 'from') {
      const fromMatch = header.value.match(/(?:"?([^"]*)"?\s)?<?([^>]+@[^>]+)>?/);
      if (fromMatch) {
        fromDisplayName = fromMatch[1];
        fromAddress = fromMatch[2];
      } else {
        fromAddress = header.value;
      }
    } else if (name === 'to') {
      const addresses = header.value.split(',').map((a) => {
        const match = a.trim().match(/<([^>]+)>/);
        return match ? match[1] : a.trim();
      });
      toAddresses.push(...addresses);
    }
  }

  // Extract body content
  let bodyText: string | undefined;
  let bodyHtml: string | undefined;

  if (message.payload.parts) {
    for (const part of message.payload.parts) {
      if (part.mimeType === 'text/plain' && part.body?.data) {
        bodyText = Buffer.from(part.body.data, 'base64url').toString('utf-8');
      } else if (part.mimeType === 'text/html' && part.body?.data) {
        bodyHtml = Buffer.from(part.body.data, 'base64url').toString('utf-8');
      }
    }
  } else if (message.payload.body?.data) {
    if (message.payload.mimeType === 'text/plain') {
      bodyText = Buffer.from(message.payload.body.data, 'base64url').toString('utf-8');
    } else if (message.payload.mimeType === 'text/html') {
      bodyHtml = Buffer.from(message.payload.body.data, 'base64url').toString('utf-8');
    }
  }

  return {
    reporterEmail: '', // Set by caller based on authenticated user
    originalMessageId: message.id,
    subject,
    fromAddress,
    fromDisplayName,
    toAddresses,
    receivedAt: new Date(parseInt(message.internalDate)),
    reportSource: 'gmail_addon',
    emailHeaders: headers,
    emailBodyText: bodyText,
    emailBodyHtml: bodyHtml,
    clientInfo: {
      platform: 'gmail',
    },
  };
}

// ============================================
// Add-in Manifest Generation
// ============================================

export interface OutlookManifest {
  type: 'outlook';
  xml: string;
  version: string;
  tenantId: string;
}

export interface GmailManifest {
  type: 'gmail';
  json: GmailAddonManifestJson;
  version: string;
  tenantId: string;
}

export interface GmailAddonManifestJson {
  timeZone: string;
  dependencies: {
    enabledAdvancedServices: Array<{
      userSymbol: string;
      serviceId: string;
      version: string;
    }>;
  };
  exceptionLogging: string;
  oauthScopes: string[];
  gmail: {
    contextualTriggers: Array<{
      unconditional: Record<string, never>;
      onTriggerFunction: string;
    }>;
    composeTrigger?: {
      selectActions: Array<{
        text: string;
        runFunction: string;
      }>;
      draftAccess: string;
    };
  };
}

/**
 * Generate Outlook Add-in manifest XML
 */
export function generateOutlookManifest(
  tenantId: string,
  baseUrl: string,
  options?: {
    displayName?: string;
    description?: string;
    iconUrl?: string;
    version?: string;
  }
): OutlookManifest {
  const version = options?.version || '1.0.0.0';
  const displayName = options?.displayName || 'Report Phish';
  const description = options?.description || 'Report suspicious emails to your security team with one click';
  const iconUrl = options?.iconUrl || `${baseUrl}/icons/phish-report-64.png`;
  const highResIconUrl = options?.iconUrl || `${baseUrl}/icons/phish-report-128.png`;

  // Generate a unique GUID for this tenant's add-in
  const addinId = generateUUID(tenantId);

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<OfficeApp
  xmlns="http://schemas.microsoft.com/office/appforoffice/1.1"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:bt="http://schemas.microsoft.com/office/officeappbasictypes/1.0"
  xmlns:mailappor="http://schemas.microsoft.com/office/mailappversionoverrides/1.0"
  xsi:type="MailApp">
  <Id>${addinId}</Id>
  <Version>${version}</Version>
  <ProviderName>Swordfish Security</ProviderName>
  <DefaultLocale>en-US</DefaultLocale>
  <DisplayName DefaultValue="${displayName}"/>
  <Description DefaultValue="${description}"/>
  <IconUrl DefaultValue="${iconUrl}"/>
  <HighResolutionIconUrl DefaultValue="${highResIconUrl}"/>
  <SupportUrl DefaultValue="${baseUrl}/support"/>

  <AppDomains>
    <AppDomain>${new URL(baseUrl).hostname}</AppDomain>
  </AppDomains>

  <Hosts>
    <Host Name="Mailbox"/>
  </Hosts>

  <Requirements>
    <Sets>
      <Set Name="Mailbox" MinVersion="1.1"/>
    </Sets>
  </Requirements>

  <FormSettings>
    <Form xsi:type="ItemRead">
      <DesktopSettings>
        <SourceLocation DefaultValue="${baseUrl}/addins/outlook/read"/>
        <RequestedHeight>450</RequestedHeight>
      </DesktopSettings>
    </Form>
  </FormSettings>

  <Permissions>ReadItem</Permissions>
  <Rule xsi:type="RuleCollection" Mode="Or">
    <Rule xsi:type="ItemIs" ItemType="Message" FormType="Read"/>
  </Rule>
  <DisableEntityHighlighting>false</DisableEntityHighlighting>

  <VersionOverrides xmlns="http://schemas.microsoft.com/office/mailappversionoverrides" xsi:type="VersionOverridesV1_0">
    <VersionOverrides xmlns="http://schemas.microsoft.com/office/mailappversionoverrides/1.1" xsi:type="VersionOverridesV1_1">
      <Requirements>
        <bt:Sets DefaultMinVersion="1.5">
          <bt:Set Name="Mailbox"/>
        </bt:Sets>
      </Requirements>

      <Hosts>
        <Host xsi:type="MailHost">
          <DesktopFormFactor>
            <FunctionFile resid="functionFile"/>
            <ExtensionPoint xsi:type="MessageReadCommandSurface">
              <OfficeTab id="TabDefault">
                <Group id="msgReadGroup">
                  <Label resid="groupLabel"/>
                  <Control xsi:type="Button" id="reportPhishButton">
                    <Label resid="reportBtnLabel"/>
                    <Supertip>
                      <Title resid="reportBtnLabel"/>
                      <Description resid="reportBtnDesc"/>
                    </Supertip>
                    <Icon>
                      <bt:Image size="16" resid="icon16"/>
                      <bt:Image size="32" resid="icon32"/>
                      <bt:Image size="80" resid="icon80"/>
                    </Icon>
                    <Action xsi:type="ShowTaskpane">
                      <SourceLocation resid="taskpaneUrl"/>
                    </Action>
                  </Control>
                </Group>
              </OfficeTab>
            </ExtensionPoint>
          </DesktopFormFactor>

          <MobileFormFactor>
            <FunctionFile resid="functionFile"/>
            <ExtensionPoint xsi:type="MobileMessageReadCommandSurface">
              <Group id="mobileReadGroup">
                <Label resid="groupLabel"/>
                <Control xsi:type="MobileButton" id="mobileReportPhishButton">
                  <Label resid="reportBtnLabel"/>
                  <Icon>
                    <bt:Image size="25" resid="icon25"/>
                    <bt:Image size="32" resid="icon32"/>
                    <bt:Image size="48" resid="icon48"/>
                  </Icon>
                  <Action xsi:type="ShowTaskpane">
                    <SourceLocation resid="taskpaneUrl"/>
                  </Action>
                </Control>
              </Group>
            </ExtensionPoint>
          </MobileFormFactor>
        </Host>
      </Hosts>

      <Resources>
        <bt:Images>
          <bt:Image id="icon16" DefaultValue="${baseUrl}/icons/phish-report-16.png"/>
          <bt:Image id="icon25" DefaultValue="${baseUrl}/icons/phish-report-25.png"/>
          <bt:Image id="icon32" DefaultValue="${baseUrl}/icons/phish-report-32.png"/>
          <bt:Image id="icon48" DefaultValue="${baseUrl}/icons/phish-report-48.png"/>
          <bt:Image id="icon80" DefaultValue="${baseUrl}/icons/phish-report-80.png"/>
        </bt:Images>
        <bt:Urls>
          <bt:Url id="functionFile" DefaultValue="${baseUrl}/addins/outlook/functions.html"/>
          <bt:Url id="taskpaneUrl" DefaultValue="${baseUrl}/addins/outlook/taskpane?tenantId=${tenantId}"/>
        </bt:Urls>
        <bt:ShortStrings>
          <bt:String id="groupLabel" DefaultValue="Swordfish Security"/>
          <bt:String id="reportBtnLabel" DefaultValue="Report Phish"/>
        </bt:ShortStrings>
        <bt:LongStrings>
          <bt:String id="reportBtnDesc" DefaultValue="Report this email as a potential phishing attempt to your security team"/>
        </bt:LongStrings>
      </Resources>
    </VersionOverrides>
  </VersionOverrides>
</OfficeApp>`;

  return {
    type: 'outlook',
    xml,
    version,
    tenantId,
  };
}

/**
 * Generate Gmail Add-on manifest JSON
 */
export function generateGmailManifest(
  tenantId: string,
  baseUrl: string,
  options?: {
    version?: string;
  }
): GmailManifest {
  const version = options?.version || '1.0.0';

  const json: GmailAddonManifestJson = {
    timeZone: 'America/New_York',
    dependencies: {
      enabledAdvancedServices: [
        {
          userSymbol: 'Gmail',
          serviceId: 'gmail',
          version: 'v1',
        },
      ],
    },
    exceptionLogging: 'STACKDRIVER',
    oauthScopes: [
      'https://www.googleapis.com/auth/gmail.addons.execute',
      'https://www.googleapis.com/auth/gmail.addons.current.message.readonly',
      'https://www.googleapis.com/auth/gmail.addons.current.message.metadata',
      'https://www.googleapis.com/auth/script.external_request',
    ],
    gmail: {
      contextualTriggers: [
        {
          unconditional: {},
          onTriggerFunction: 'buildAddOn',
        },
      ],
    },
  };

  return {
    type: 'gmail',
    json,
    version,
    tenantId,
  };
}

/**
 * Generate Apps Script code for Gmail Add-on
 */
export function generateGmailAppsScript(
  tenantId: string,
  baseUrl: string,
  apiKey: string
): string {
  return `/**
 * Swordfish Phish Report Gmail Add-on
 * Generated for tenant: ${tenantId}
 */

const CONFIG = {
  API_URL: '${baseUrl}/api/v1/report-phish',
  TENANT_ID: '${tenantId}',
  API_KEY: '${apiKey}'
};

/**
 * Callback for rendering the homepage card.
 * @param {Object} e The event object.
 * @return {CardService.Card} The card to show to the user.
 */
function buildAddOn(e) {
  var accessToken = e.gmail.accessToken;
  var messageId = e.gmail.messageId;
  GmailApp.setCurrentMessageAccessToken(accessToken);

  var message = GmailApp.getMessageById(messageId);
  var from = message.getFrom();
  var subject = message.getSubject();

  var card = CardService.newCardBuilder();
  card.setHeader(CardService.newCardHeader()
    .setTitle('Report Phishing')
    .setImageUrl('${baseUrl}/icons/phish-report-64.png'));

  var section = CardService.newCardSection();
  section.addWidget(CardService.newTextParagraph()
    .setText('<b>From:</b> ' + from));
  section.addWidget(CardService.newTextParagraph()
    .setText('<b>Subject:</b> ' + subject));

  section.addWidget(CardService.newTextInput()
    .setFieldName('comments')
    .setTitle('Additional Comments (optional)')
    .setMultiline(true));

  section.addWidget(CardService.newTextButton()
    .setText('Report as Phishing')
    .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    .setBackgroundColor('#dc2626')
    .setOnClickAction(CardService.newAction()
      .setFunctionName('reportPhishing')
      .setParameters({ messageId: messageId })));

  card.addSection(section);
  return card.build();
}

/**
 * Report the current email as phishing.
 * @param {Object} e The event object.
 * @return {CardService.ActionResponse} The action response.
 */
function reportPhishing(e) {
  var messageId = e.parameters.messageId;
  var comments = e.formInput.comments || '';
  var userEmail = Session.getActiveUser().getEmail();

  var message = GmailApp.getMessageById(messageId);
  var thread = message.getThread();

  // Get message details
  var payload = {
    source: 'gmail_addon',
    reporterEmail: userEmail,
    message: {
      id: messageId,
      threadId: thread.getId(),
      payload: {
        headers: getMessageHeaders(message),
        mimeType: 'text/html',
        body: {
          data: Utilities.base64EncodeWebSafe(message.getBody())
        }
      },
      internalDate: String(message.getDate().getTime())
    },
    comments: comments
  };

  try {
    var options = {
      method: 'post',
      contentType: 'application/json',
      headers: {
        'Authorization': 'Bearer ' + CONFIG.API_KEY
      },
      payload: JSON.stringify(payload),
      muteHttpExceptions: true
    };

    var response = UrlFetchApp.fetch(CONFIG.API_URL, options);
    var result = JSON.parse(response.getContentText());

    if (response.getResponseCode() === 201) {
      return CardService.newActionResponseBuilder()
        .setNotification(CardService.newNotification()
          .setText('Thank you! Your report has been submitted.'))
        .build();
    } else {
      throw new Error(result.error?.message || 'Failed to submit report');
    }
  } catch (error) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification()
        .setText('Error: ' + error.message))
      .build();
  }
}

/**
 * Extract headers from a Gmail message.
 * @param {GmailMessage} message The Gmail message.
 * @return {Array} Array of header objects.
 */
function getMessageHeaders(message) {
  var raw = message.getRawContent();
  var headerSection = raw.split('\\r\\n\\r\\n')[0];
  var headerLines = headerSection.split('\\r\\n');
  var headers = [];
  var currentHeader = null;

  for (var i = 0; i < headerLines.length; i++) {
    var line = headerLines[i];
    if (line.match(/^[A-Za-z-]+:/)) {
      if (currentHeader) {
        headers.push(currentHeader);
      }
      var colonIndex = line.indexOf(':');
      currentHeader = {
        name: line.substring(0, colonIndex),
        value: line.substring(colonIndex + 1).trim()
      };
    } else if (currentHeader && line.match(/^\\s+/)) {
      currentHeader.value += ' ' + line.trim();
    }
  }
  if (currentHeader) {
    headers.push(currentHeader);
  }

  return headers;
}
`;
}

/**
 * Generate a UUID from a seed string (for consistent tenant IDs)
 */
function generateUUID(seed: string): string {
  // Simple hash-based UUID generation for consistency
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    const char = seed.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }

  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return `${hex.slice(0, 8)}-${hex.slice(0, 4)}-4${hex.slice(1, 4)}-8${hex.slice(1, 4)}-${hex.slice(0, 12).padEnd(12, '0')}`;
}

// ============================================
// Export singleton instance
// ============================================

export const phishReportService = new PhishReportService();
