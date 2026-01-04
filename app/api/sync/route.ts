/**
 * Email Sync API
 * Triggers email sync for a tenant
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { syncTenant } from '@/lib/workers/email-sync';

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;

    // Run sync
    const results = await syncTenant(tenantId);

    // Aggregate results
    const summary = {
      totalIntegrations: results.length,
      totalEmailsProcessed: results.reduce((sum, r) => sum + r.emailsProcessed, 0),
      totalThreatsFound: results.reduce((sum, r) => sum + r.threatsFound, 0),
      totalErrors: results.reduce((sum, r) => sum + r.errors.length, 0),
      integrations: results.map(r => ({
        type: r.type,
        emailsProcessed: r.emailsProcessed,
        threatsFound: r.threatsFound,
        duration: r.duration,
        errors: r.errors.slice(0, 5), // Limit errors shown
      })),
    };

    return NextResponse.json(summary);
  } catch (error) {
    console.error('Sync error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Sync failed' },
      { status: 500 }
    );
  }
}
