/**
 * Report Export Service
 * Generates CSV and PDF exports of analytics data
 */

import { sql } from '@/lib/db';
import type { DashboardStats, SenderStats, ThreatCategory } from './service';

export type ExportFormat = 'csv' | 'json';

export interface ExportOptions {
  format: ExportFormat;
  includeHeaders?: boolean;
  dateRange?: { start: Date; end: Date };
}

/**
 * Export email verdicts to CSV
 */
export async function exportVerdicts(
  tenantId: string,
  options: ExportOptions & { limit?: number }
): Promise<string> {
  const { format, limit = 1000, dateRange } = options;

  let verdicts;
  if (dateRange) {
    verdicts = await sql`
      SELECT
        message_id,
        verdict,
        score,
        confidence,
        explanation,
        processing_time_ms,
        created_at
      FROM email_verdicts
      WHERE tenant_id = ${tenantId}
      AND created_at >= ${dateRange.start.toISOString()}
      AND created_at <= ${dateRange.end.toISOString()}
      ORDER BY created_at DESC
      LIMIT ${limit}
    `;
  } else {
    verdicts = await sql`
      SELECT
        message_id,
        verdict,
        score,
        confidence,
        explanation,
        processing_time_ms,
        created_at
      FROM email_verdicts
      WHERE tenant_id = ${tenantId}
      ORDER BY created_at DESC
      LIMIT ${limit}
    `;
  }

  if (format === 'json') {
    return JSON.stringify(verdicts, null, 2);
  }

  // CSV format
  const headers = ['Message ID', 'Verdict', 'Score', 'Confidence', 'Explanation', 'Processing Time (ms)', 'Date'];
  const rows = verdicts.map((v: Record<string, unknown>) => [
    v.message_id,
    v.verdict,
    v.score,
    v.confidence,
    `"${String(v.explanation || '').replace(/"/g, '""')}"`,
    v.processing_time_ms,
    new Date(v.created_at as string).toISOString(),
  ]);

  return [headers.join(','), ...rows.map((r: unknown[]) => r.join(','))].join('\n');
}

/**
 * Export threats to CSV
 */
export async function exportThreats(
  tenantId: string,
  options: ExportOptions & { status?: string; limit?: number }
): Promise<string> {
  const { format, status = 'all', limit = 1000, dateRange } = options;

  let threats;
  if (status === 'all') {
    if (dateRange) {
      threats = await sql`
        SELECT
          message_id,
          subject,
          sender_email,
          recipient_email,
          verdict,
          score,
          status,
          provider,
          quarantined_at,
          released_at
        FROM threats
        WHERE tenant_id = ${tenantId}
        AND quarantined_at >= ${dateRange.start.toISOString()}
        AND quarantined_at <= ${dateRange.end.toISOString()}
        ORDER BY quarantined_at DESC
        LIMIT ${limit}
      `;
    } else {
      threats = await sql`
        SELECT
          message_id,
          subject,
          sender_email,
          recipient_email,
          verdict,
          score,
          status,
          provider,
          quarantined_at,
          released_at
        FROM threats
        WHERE tenant_id = ${tenantId}
        ORDER BY quarantined_at DESC
        LIMIT ${limit}
      `;
    }
  } else {
    threats = await sql`
      SELECT
        message_id,
        subject,
        sender_email,
        recipient_email,
        verdict,
        score,
        status,
        provider,
        quarantined_at,
        released_at
      FROM threats
      WHERE tenant_id = ${tenantId}
      AND status = ${status}
      ORDER BY quarantined_at DESC
      LIMIT ${limit}
    `;
  }

  if (format === 'json') {
    return JSON.stringify(threats, null, 2);
  }

  // CSV format
  const headers = ['Message ID', 'Subject', 'Sender', 'Recipient', 'Verdict', 'Score', 'Status', 'Provider', 'Quarantined At', 'Released At'];
  const rows = threats.map((t: Record<string, unknown>) => [
    t.message_id,
    `"${String(t.subject || '').replace(/"/g, '""')}"`,
    t.sender_email,
    t.recipient_email,
    t.verdict,
    t.score,
    t.status,
    t.provider,
    t.quarantined_at ? new Date(t.quarantined_at as string).toISOString() : '',
    t.released_at ? new Date(t.released_at as string).toISOString() : '',
  ]);

  return [headers.join(','), ...rows.map((r: unknown[]) => r.join(','))].join('\n');
}

/**
 * Export audit log to CSV
 */
export async function exportAuditLog(
  tenantId: string,
  options: ExportOptions & { limit?: number }
): Promise<string> {
  const { format, limit = 1000, dateRange } = options;

  let logs;
  if (dateRange) {
    logs = await sql`
      SELECT
        action,
        user_id,
        resource_type,
        resource_id,
        details,
        ip_address,
        created_at
      FROM audit_log
      WHERE tenant_id = ${tenantId}
      AND created_at >= ${dateRange.start.toISOString()}
      AND created_at <= ${dateRange.end.toISOString()}
      ORDER BY created_at DESC
      LIMIT ${limit}
    `;
  } else {
    logs = await sql`
      SELECT
        action,
        user_id,
        resource_type,
        resource_id,
        details,
        ip_address,
        created_at
      FROM audit_log
      WHERE tenant_id = ${tenantId}
      ORDER BY created_at DESC
      LIMIT ${limit}
    `;
  }

  if (format === 'json') {
    return JSON.stringify(logs, null, 2);
  }

  const headers = ['Action', 'User ID', 'Resource Type', 'Resource ID', 'Details', 'IP Address', 'Date'];
  const rows = logs.map((l: Record<string, unknown>) => [
    l.action,
    l.user_id,
    l.resource_type,
    l.resource_id,
    `"${JSON.stringify(l.details || {}).replace(/"/g, '""')}"`,
    l.ip_address || '',
    new Date(l.created_at as string).toISOString(),
  ]);

  return [headers.join(','), ...rows.map((r: unknown[]) => r.join(','))].join('\n');
}

/**
 * Export executive summary report
 */
export async function exportExecutiveSummary(
  summary: {
    period: { start: Date; end: Date };
    summary: DashboardStats['summary'];
    verdictBreakdown: DashboardStats['verdictBreakdown'];
    topThreats: ThreatCategory[];
    topSenders: SenderStats[];
  },
  format: ExportFormat
): Promise<string> {
  if (format === 'json') {
    return JSON.stringify(summary, null, 2);
  }

  // Generate text-based report for CSV
  const lines: string[] = [
    'SWORDFISH EMAIL SECURITY - EXECUTIVE SUMMARY',
    '',
    `Report Period: ${summary.period.start.toLocaleDateString()} - ${summary.period.end.toLocaleDateString()}`,
    '',
    '=== SUMMARY STATISTICS ===',
    `Total Emails Analyzed,${summary.summary.totalEmails}`,
    `Threats Blocked,${summary.summary.threatsBlocked}`,
    `Emails Quarantined,${summary.summary.quarantined}`,
    `Pass Rate,${summary.summary.passRate}%`,
    `Avg Processing Time,${summary.summary.avgProcessingTime}ms`,
    '',
    '=== VERDICT BREAKDOWN ===',
    `Pass,${summary.verdictBreakdown.pass}`,
    `Suspicious,${summary.verdictBreakdown.suspicious}`,
    `Quarantine,${summary.verdictBreakdown.quarantine}`,
    `Block,${summary.verdictBreakdown.block}`,
    '',
    '=== TOP THREAT CATEGORIES ===',
    'Category,Count,Percentage',
    ...summary.topThreats.map(t => `${t.category},${t.count},${t.percentage}%`),
    '',
    '=== TOP THREAT SENDERS ===',
    'Email,Domain,Threat Count,Avg Score',
    ...summary.topSenders.map(s => `${s.email},${s.domain},${s.threatCount},${s.avgScore}`),
  ];

  return lines.join('\n');
}

/**
 * Generate filename for export
 */
export function generateExportFilename(
  reportType: string,
  format: ExportFormat,
  dateRange?: { start: Date; end: Date }
): string {
  const timestamp = new Date().toISOString().split('T')[0];
  const dateStr = dateRange
    ? `${dateRange.start.toISOString().split('T')[0]}_to_${dateRange.end.toISOString().split('T')[0]}`
    : timestamp;

  return `swordfish_${reportType}_${dateStr}.${format}`;
}

/**
 * Get threats for PDF report generation
 */
export async function getThreatsForReport(
  tenantId: string,
  dateRange: { start: Date; end: Date },
  limit: number = 100
): Promise<Array<{
  id: string;
  type: string;
  severity: string;
  sender: string;
  subject: string;
  detectedAt: Date;
  status: string;
}>> {
  const threats = await sql`
    SELECT
      id,
      verdict as type,
      CASE 
        WHEN score >= 0.9 THEN 'critical'
        WHEN score >= 0.7 THEN 'high'
        WHEN score >= 0.5 THEN 'medium'
        ELSE 'low'
      END as severity,
      sender_email as sender,
      subject,
      quarantined_at as detected_at,
      status
    FROM threats
    WHERE tenant_id = ${tenantId}
    AND quarantined_at >= ${dateRange.start.toISOString()}
    AND quarantined_at <= ${dateRange.end.toISOString()}
    ORDER BY quarantined_at DESC
    LIMIT ${limit}
  `;

  return threats.map(t => ({
    id: t.id,
    type: t.type || 'unknown',
    severity: t.severity || 'medium',
    sender: t.sender || '',
    subject: t.subject || '(no subject)',
    detectedAt: new Date(t.detected_at),
    status: t.status || 'quarantined',
  }));
}
