/**
 * Cron: Scheduled Reports
 * Runs hourly to check and execute scheduled reports
 */

import { NextRequest, NextResponse } from 'next/server';
import { sql } from '@/lib/db';

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

export async function GET(request: NextRequest) {
  try {
    // Verify cron secret (Vercel sets this automatically)
    const authHeader = request.headers.get('authorization');
    if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Find reports due to run
    const dueReports = await sql`
      SELECT id, tenant_id, name, type, format, recipients, filters
      FROM scheduled_reports
      WHERE is_active = TRUE
      AND next_run_at <= NOW()
      ORDER BY next_run_at
      LIMIT 10
    `;

    let processed = 0;
    const errors: string[] = [];

    for (const report of dueReports) {
      try {
        // Create report job
        await sql`
          INSERT INTO report_jobs (scheduled_report_id, tenant_id, status, started_at, created_at)
          VALUES (${report.id}, ${report.tenant_id}, 'processing', NOW(), NOW())
        `;

        // Calculate next run time based on schedule
        await sql`
          UPDATE scheduled_reports SET
            last_run_at = NOW(),
            next_run_at = CASE
              WHEN schedule = 'daily' THEN NOW() + INTERVAL '1 day'
              WHEN schedule = 'weekly' THEN NOW() + INTERVAL '1 week'
              WHEN schedule = 'monthly' THEN NOW() + INTERVAL '1 month'
              ELSE NOW() + INTERVAL '1 day'
            END,
            updated_at = NOW()
          WHERE id = ${report.id}
        `;

        // TODO: Generate actual report and send to recipients
        // await generateReport(report);
        // await sendReportEmail(report.recipients, reportUrl);

        processed++;
      } catch (error) {
        errors.push(`${report.id}: ${error instanceof Error ? error.message : 'Failed'}`);
      }
    }

    return NextResponse.json({
      success: true,
      processed,
      total: dueReports.length,
      errors: errors.length > 0 ? errors : undefined,
    });
  } catch (error) {
    console.error('Scheduled reports cron error:', error);
    return NextResponse.json(
      { error: 'Cron job failed' },
      { status: 500 }
    );
  }
}
