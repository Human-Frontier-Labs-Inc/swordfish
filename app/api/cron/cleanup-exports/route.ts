/**
 * Cron: Cleanup Expired Exports
 * Runs daily to remove expired export files
 */

import { NextRequest, NextResponse } from 'next/server';
import { sql } from '@/lib/db';

export const dynamic = 'force-dynamic';
export const maxDuration = 30;

export async function GET(request: NextRequest) {
  try {
    // Verify cron secret
    const authHeader = request.headers.get('authorization');
    if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Find expired exports
    const expiredExports = await sql`
      SELECT id, file_url FROM export_jobs
      WHERE expires_at < NOW()
      AND status = 'completed'
      AND file_url IS NOT NULL
    `;

    let deleted = 0;

    for (const exportJob of expiredExports) {
      try {
        // TODO: Delete file from R2/S3 storage
        // await deleteFromStorage(exportJob.file_url);

        // Mark as expired in database
        await sql`
          UPDATE export_jobs SET
            status = 'expired',
            file_url = NULL
          WHERE id = ${exportJob.id}
        `;

        deleted++;
      } catch (error) {
        console.error(`Failed to cleanup export ${exportJob.id}:`, error);
      }
    }

    // Also cleanup old pending/failed exports (older than 7 days)
    const cleaned = await sql`
      DELETE FROM export_jobs
      WHERE status IN ('pending', 'failed')
      AND created_at < NOW() - INTERVAL '7 days'
      RETURNING id
    `;

    // Cleanup old report jobs (older than 90 days)
    const reportsCleaned = await sql`
      DELETE FROM report_jobs
      WHERE created_at < NOW() - INTERVAL '90 days'
      RETURNING id
    `;

    return NextResponse.json({
      success: true,
      expiredExportsDeleted: deleted,
      staleExportsCleaned: cleaned.length,
      oldReportsCleaned: reportsCleaned.length,
    });
  } catch (error) {
    console.error('Cleanup exports cron error:', error);
    return NextResponse.json(
      { error: 'Cron job failed' },
      { status: 500 }
    );
  }
}
