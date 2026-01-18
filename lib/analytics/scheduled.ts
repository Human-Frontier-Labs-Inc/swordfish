/**
 * Scheduled Reports Service
 * Manages scheduled report generation and delivery
 */

import { sql } from '@/lib/db';
import { generateExecutiveSummary } from './service';
import { exportExecutiveSummary } from './export';
import { sendNotification } from '@/lib/notifications/service';

export type ReportFrequency = 'daily' | 'weekly' | 'monthly';
export type ReportType = 'executive_summary' | 'threat_report' | 'audit_report';

export interface ScheduledReport {
  id: string;
  tenantId: string;
  name: string;
  type: ReportType;
  frequency: ReportFrequency;
  recipients: string[];
  enabled: boolean;
  lastRunAt?: Date;
  nextRunAt: Date;
  config: {
    daysBack?: number;
    includeCharts?: boolean;
    format?: 'csv' | 'json';
  };
  createdAt: Date;
  createdBy: string;
}

/**
 * Create a scheduled report
 */
export async function createScheduledReport(params: {
  tenantId: string;
  name: string;
  type: ReportType;
  frequency: ReportFrequency;
  recipients: string[];
  config?: ScheduledReport['config'];
  createdBy: string;
}): Promise<string> {
  const { tenantId, name, type, frequency, recipients, config, createdBy } = params;

  const nextRunAt = calculateNextRunTime(frequency);

  const result = await sql`
    INSERT INTO scheduled_reports (
      tenant_id, name, type, frequency, recipients, enabled,
      next_run_at, config, created_by, created_at
    ) VALUES (
      ${tenantId},
      ${name},
      ${type},
      ${frequency},
      ${JSON.stringify(recipients)},
      true,
      ${nextRunAt.toISOString()},
      ${JSON.stringify(config || {})},
      ${createdBy},
      NOW()
    )
    RETURNING id
  `;

  return result[0].id as string;
}

/**
 * Get scheduled reports for a tenant
 */
export async function getScheduledReports(tenantId: string): Promise<ScheduledReport[]> {
  const reports = await sql`
    SELECT * FROM scheduled_reports
    WHERE tenant_id = ${tenantId}
    ORDER BY created_at DESC
  `;

  return reports.map((r: Record<string, unknown>) => ({
    id: r.id as string,
    tenantId: r.tenant_id as string,
    name: r.name as string,
    type: r.type as ReportType,
    frequency: r.frequency as ReportFrequency,
    recipients: r.recipients as string[],
    enabled: r.enabled as boolean,
    lastRunAt: r.last_run_at ? new Date(r.last_run_at as string) : undefined,
    nextRunAt: new Date(r.next_run_at as string),
    config: (r.config as ScheduledReport['config']) || {},
    createdAt: new Date(r.created_at as string),
    createdBy: r.created_by as string,
  }));
}

/**
 * Update a scheduled report
 */
export async function updateScheduledReport(
  tenantId: string,
  reportId: string,
  updates: Partial<Pick<ScheduledReport, 'name' | 'frequency' | 'recipients' | 'enabled' | 'config'>>
): Promise<void> {
  const { name, frequency, recipients, enabled, config } = updates;

  // Recalculate next run time if frequency changed
  let nextRunAt: Date | undefined;
  if (frequency) {
    nextRunAt = calculateNextRunTime(frequency);
  }

  await sql`
    UPDATE scheduled_reports
    SET
      name = COALESCE(${name || null}, name),
      frequency = COALESCE(${frequency || null}, frequency),
      recipients = COALESCE(${recipients ? JSON.stringify(recipients) : null}, recipients),
      enabled = COALESCE(${enabled ?? null}, enabled),
      config = COALESCE(${config ? JSON.stringify(config) : null}, config),
      next_run_at = COALESCE(${nextRunAt?.toISOString() || null}, next_run_at)
    WHERE id = ${reportId}
    AND tenant_id = ${tenantId}
  `;
}

/**
 * Delete a scheduled report
 */
export async function deleteScheduledReport(
  tenantId: string,
  reportId: string
): Promise<void> {
  await sql`
    DELETE FROM scheduled_reports
    WHERE id = ${reportId}
    AND tenant_id = ${tenantId}
  `;
}

/**
 * Run a specific scheduled report
 */
export async function runScheduledReport(report: ScheduledReport): Promise<void> {
  const daysBack = getDaysBackForFrequency(report.frequency, report.config.daysBack);

  try {
    let reportContent: string;

    switch (report.type) {
      case 'executive_summary': {
        const data = await generateExecutiveSummary(report.tenantId, daysBack);
        reportContent = await exportExecutiveSummary(data, report.config.format || 'csv');
        break;
      }
      case 'threat_report':
      case 'audit_report':
      default: {
        // Use executive summary for now
        const summaryData = await generateExecutiveSummary(report.tenantId, daysBack);
        reportContent = await exportExecutiveSummary(summaryData, report.config.format || 'csv');
      }
    }

    // Send to recipients
    for (const recipient of report.recipients) {
      await sendReportEmail(recipient, report.name, reportContent, report.frequency);
    }

    // Create in-app notification
    await sendNotification({
      tenantId: report.tenantId,
      type: report.frequency === 'daily' ? 'daily_summary' : 'weekly_report',
      title: `${report.name} Generated`,
      message: `Your scheduled ${report.frequency} report has been generated and sent to ${report.recipients.length} recipient(s).`,
      severity: 'info',
      resourceType: 'scheduled_report',
      resourceId: report.id,
    });

    // Update last run and next run times
    const nextRunAt = calculateNextRunTime(report.frequency);
    await sql`
      UPDATE scheduled_reports
      SET last_run_at = NOW(), next_run_at = ${nextRunAt.toISOString()}
      WHERE id = ${report.id}
    `;
  } catch (error) {
    console.error(`Failed to run scheduled report ${report.id}:`, error);

    // Notify of failure
    await sendNotification({
      tenantId: report.tenantId,
      type: 'integration_error',
      title: `Report Failed: ${report.name}`,
      message: `Failed to generate scheduled report: ${error instanceof Error ? error.message : 'Unknown error'}`,
      severity: 'warning',
      resourceType: 'scheduled_report',
      resourceId: report.id,
    });
  }
}

/**
 * Process all due scheduled reports (called by cron job)
 */
export async function processDueReports(): Promise<number> {
  const dueReports = await sql`
    SELECT * FROM scheduled_reports
    WHERE enabled = true
    AND next_run_at <= NOW()
  `;

  let processedCount = 0;

  for (const row of dueReports) {
    const report: ScheduledReport = {
      id: row.id as string,
      tenantId: row.tenant_id as string,
      name: row.name as string,
      type: row.type as ReportType,
      frequency: row.frequency as ReportFrequency,
      recipients: row.recipients as string[],
      enabled: row.enabled as boolean,
      lastRunAt: row.last_run_at ? new Date(row.last_run_at as string) : undefined,
      nextRunAt: new Date(row.next_run_at as string),
      config: (row.config as ScheduledReport['config']) || {},
      createdAt: new Date(row.created_at as string),
      createdBy: row.created_by as string,
    };

    await runScheduledReport(report);
    processedCount++;
  }

  return processedCount;
}

/**
 * Calculate next run time based on frequency
 */
function calculateNextRunTime(frequency: ReportFrequency): Date {
  const now = new Date();
  const next = new Date(now);

  // Set to 8 AM
  next.setHours(8, 0, 0, 0);

  switch (frequency) {
    case 'daily':
      // Tomorrow at 8 AM
      next.setDate(next.getDate() + 1);
      break;
    case 'weekly': {
      // Next Monday at 8 AM
      const daysUntilMonday = (8 - now.getDay()) % 7 || 7;
      next.setDate(next.getDate() + daysUntilMonday);
      break;
    }
    case 'monthly':
      // First of next month at 8 AM
      next.setMonth(next.getMonth() + 1, 1);
      break;
  }

  return next;
}

/**
 * Get days to look back based on frequency
 */
function getDaysBackForFrequency(frequency: ReportFrequency, configDays?: number): number {
  if (configDays) return configDays;

  switch (frequency) {
    case 'daily':
      return 1;
    case 'weekly':
      return 7;
    case 'monthly':
      return 30;
    default:
      return 7;
  }
}

/**
 * Send report via email
 */
async function sendReportEmail(
  to: string,
  reportName: string,
  content: string,
  frequency: ReportFrequency
): Promise<void> {
  const emailProvider = process.env.EMAIL_PROVIDER || 'resend';

  if (emailProvider === 'resend' && process.env.RESEND_API_KEY) {
    const frequencyLabel = frequency.charAt(0).toUpperCase() + frequency.slice(1);

    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: process.env.EMAIL_FROM || 'Swordfish <reports@swordfish.security>',
        to: [to],
        subject: `[Swordfish] ${frequencyLabel} Report: ${reportName}`,
        text: `Your ${frequency} security report is attached.\n\n${content}`,
        html: `
          <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #1e40af; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
              <h1 style="margin: 0; font-size: 20px;">Swordfish ${frequencyLabel} Report</h1>
              <p style="margin: 8px 0 0 0; opacity: 0.9;">${reportName}</p>
            </div>
            <div style="padding: 20px; background: #f9fafb; border: 1px solid #e5e7eb; border-top: none;">
              <p style="color: #374151;">Your scheduled security report is ready.</p>
              <pre style="background: #fff; padding: 16px; border-radius: 4px; overflow-x: auto; font-size: 12px; border: 1px solid #e5e7eb;">${content.slice(0, 2000)}${content.length > 2000 ? '\n...(truncated)' : ''}</pre>
            </div>
            <p style="color: #6b7280; font-size: 12px; margin-top: 16px; text-align: center;">
              Swordfish Email Security | <a href="${process.env.NEXT_PUBLIC_APP_URL}/dashboard/reports">View Full Report</a>
            </p>
          </div>
        `,
      }),
    });
  }
}
