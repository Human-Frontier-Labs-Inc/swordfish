/**
 * Email Sync API
 * Triggers email sync for a tenant
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { syncTenant, type SyncError } from '@/lib/workers/email-sync';

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    // Run sync
    const results = await syncTenant(tenantId);

    // Count error types
    const errorTypeCounts: Record<string, number> = {};
    for (const result of results) {
      for (const err of result.detailedErrors) {
        errorTypeCounts[err.type] = (errorTypeCounts[err.type] || 0) + 1;
      }
    }

    // Aggregate results with detailed error info
    const summary = {
      success: true,
      totalIntegrations: results.length,
      totalEmailsProcessed: results.reduce((sum, r) => sum + r.emailsProcessed, 0),
      totalEmailsSkipped: results.reduce((sum, r) => sum + r.emailsSkipped, 0),
      totalThreatsFound: results.reduce((sum, r) => sum + r.threatsFound, 0),
      totalErrors: results.reduce((sum, r) => sum + r.errors.length, 0),
      errorSummary: errorTypeCounts,
      anyTimedOut: results.some(r => r.timedOut),
      integrations: results.map(r => ({
        type: r.type,
        emailsProcessed: r.emailsProcessed,
        emailsSkipped: r.emailsSkipped,
        threatsFound: r.threatsFound,
        duration: r.duration,
        timedOut: r.timedOut,
        errorCount: r.errors.length,
        // Group errors by type for clearer reporting
        errorsByType: groupErrorsByType(r.detailedErrors),
        // Still include raw errors for debugging
        errors: r.errors.slice(0, 10),
      })),
    };

    return NextResponse.json(summary);
  } catch (error) {
    console.error('Sync error:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Sync failed',
        errorType: categorizeTopLevelError(error),
      },
      { status: 500 }
    );
  }
}

/**
 * Group errors by type for clearer reporting
 */
function groupErrorsByType(errors: SyncError[]): Record<string, { count: number; samples: string[] }> {
  const grouped: Record<string, { count: number; samples: string[] }> = {};

  for (const error of errors) {
    if (!grouped[error.type]) {
      grouped[error.type] = { count: 0, samples: [] };
    }
    grouped[error.type].count++;
    // Keep up to 3 sample messages per type
    if (grouped[error.type].samples.length < 3) {
      grouped[error.type].samples.push(error.message);
    }
  }

  return grouped;
}

/**
 * Categorize top-level sync errors
 */
function categorizeTopLevelError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);

  if (message.includes('rate limit') || message.includes('429')) return 'rate_limit';
  if (message.includes('auth') || message.includes('401') || message.includes('403')) return 'authentication';
  if (message.includes('network') || message.includes('fetch')) return 'network';
  if (message.includes('timeout')) return 'timeout';
  return 'unknown';
}
