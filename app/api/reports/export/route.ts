/**
 * Report Export API
 * GET - Export reports in various formats (CSV, JSON, PDF)
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import {
  exportVerdicts,
  exportThreats,
  exportAuditLog,
  exportExecutiveSummary,
  generateExportFilename,
  type ExportFormat,
} from '@/lib/analytics/export';
import { generateExecutiveSummary } from '@/lib/analytics/service';
import { logAuditEvent } from '@/lib/db/audit';
import { generateExecutivePDF, generateThreatsPDF } from '@/lib/reports/pdf-generator';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const searchParams = request.nextUrl.searchParams;
    const reportType = searchParams.get('type') || 'verdicts';
    const format = (searchParams.get('format') || 'csv') as ExportFormat;
    const daysBack = parseInt(searchParams.get('days') || '30');
    const limit = parseInt(searchParams.get('limit') || '1000');

    const endDate = new Date();
    const startDate = new Date(endDate.getTime() - daysBack * 24 * 60 * 60 * 1000);
    const dateRange = { start: startDate, end: endDate };

    // Handle PDF format separately
    if (format === 'pdf') {
      let pdf;
      switch (reportType) {
        case 'executive': {
          const rawSummary = await generateExecutiveSummary(tenantId, daysBack);
          // Transform to PDF generator's expected format
          const summary = {
            period: rawSummary.period,
            emailsProcessed: rawSummary.summary.totalEmails,
            threatsBlocked: rawSummary.summary.threatsBlocked,
            threatsBreakdown: rawSummary.topThreats.map(t => ({ type: t.category, count: t.count })),
            topSenders: rawSummary.topSenders.map(s => ({ email: s.sender, count: s.count })),
            verdictDistribution: Object.entries(rawSummary.verdictBreakdown).map(([verdict, count]) => ({ verdict, count: count as number })),
            responseTimeAvg: rawSummary.performance.avgProcessingTime || 0,
            falsePositiveRate: rawSummary.performance.falsePositiveRate || 0,
          };
          pdf = await generateExecutivePDF(summary, dateRange);
          break;
        }
        case 'threats': {
          pdf = await generateThreatsPDF(tenantId, dateRange, limit);
          break;
        }
        default:
          return NextResponse.json(
            { error: `PDF export not supported for ${reportType}. Use csv or json.` },
            { status: 400 }
          );
      }

      // Log the export
      await logAuditEvent({
        tenantId,
        actorId: userId,
        actorEmail: null,
        action: 'report.export',
        resourceType: 'report',
        resourceId: reportType,
        afterState: { format: 'pdf', daysBack, limit },
      });

      return new NextResponse(new Uint8Array(pdf.buffer), {
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Disposition': `attachment; filename="${pdf.filename}"`,
        },
      });
    }

    // Handle CSV/JSON formats
    let content: string;
    let filename: string;

    switch (reportType) {
      case 'verdicts':
        content = await exportVerdicts(tenantId, { format, dateRange, limit });
        filename = generateExportFilename('verdicts', format, dateRange);
        break;
      case 'threats':
        content = await exportThreats(tenantId, { format, dateRange, limit });
        filename = generateExportFilename('threats', format, dateRange);
        break;
      case 'audit':
        content = await exportAuditLog(tenantId, { format, dateRange, limit });
        filename = generateExportFilename('audit_log', format, dateRange);
        break;
      case 'executive': {
        const summary = await generateExecutiveSummary(tenantId, daysBack);
        content = await exportExecutiveSummary(summary, format);
        filename = generateExportFilename('executive_summary', format, dateRange);
        break;
      }
      default:
        return NextResponse.json(
          { error: 'Invalid report type' },
          { status: 400 }
        );
    }

    // Log the export
    await logAuditEvent({
      tenantId,
      actorId: userId,
      actorEmail: null,
      action: 'report.export',
      resourceType: 'report',
      resourceId: reportType,
      afterState: { format, daysBack, limit },
    });

    // Return file with appropriate headers
    const contentType = format === 'json' ? 'application/json' : 'text/csv';

    return new NextResponse(content, {
      headers: {
        'Content-Type': contentType,
        'Content-Disposition': `attachment; filename="${filename}"`,
      },
    });
  } catch (error) {
    console.error('Export error:', error);
    return NextResponse.json(
      { error: 'Failed to export report' },
      { status: 500 }
    );
  }
}
