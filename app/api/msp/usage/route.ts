/**
 * MSP Usage & Billing API
 *
 * Endpoints for usage metrics and billing exports
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import {
  getTenantUsage,
  getAllTenantsUsage,
  generateBillingExport,
  billingExportToCSV,
  getUsageTrends,
} from '@/lib/msp/usage';

// GET /api/msp/usage - Get usage metrics
export async function GET(request: NextRequest) {
  try {
    const { userId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const searchParams = request.nextUrl.searchParams;
    const tenantId = searchParams.get('tenantId');
    const startDateStr = searchParams.get('startDate');
    const endDateStr = searchParams.get('endDate');
    const format = searchParams.get('format'); // 'json' | 'csv'
    const type = searchParams.get('type'); // 'usage' | 'billing' | 'trends'

    // Parse dates (default to last 30 days)
    const endDate = endDateStr ? new Date(endDateStr) : new Date();
    const startDate = startDateStr
      ? new Date(startDateStr)
      : new Date(endDate.getTime() - 30 * 24 * 60 * 60 * 1000);

    // Get user and their accessible tenants
    const userResult = await sql`
      SELECT is_msp_user, tenant_id FROM users WHERE clerk_user_id = ${userId}
    `;

    const user = userResult[0];
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    let accessibleTenantIds: string[];
    if (user.is_msp_user) {
      const tenantsResult = await sql`SELECT id FROM tenants WHERE status != 'deleted'`;
      accessibleTenantIds = tenantsResult.map((t: Record<string, unknown>) => t.id as string);
    } else if (user.tenant_id) {
      accessibleTenantIds = [user.tenant_id];
    } else {
      return NextResponse.json({
        usage: [],
        message: 'No tenants accessible',
      });
    }

    // If specific tenant requested, verify access
    if (tenantId && !accessibleTenantIds.includes(tenantId)) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const targetTenantIds = tenantId ? [tenantId] : accessibleTenantIds;

    // Handle different request types
    switch (type) {
      case 'billing': {
        const billing = await generateBillingExport(targetTenantIds, startDate, endDate);

        if (format === 'csv') {
          const csv = billingExportToCSV(billing);
          return new NextResponse(csv, {
            headers: {
              'Content-Type': 'text/csv',
              'Content-Disposition': `attachment; filename="billing-${startDate.toISOString().split('T')[0]}-${endDate.toISOString().split('T')[0]}.csv"`,
            },
          });
        }

        return NextResponse.json(billing);
      }

      case 'trends': {
        if (!tenantId) {
          return NextResponse.json(
            { error: 'tenantId required for trends' },
            { status: 400 }
          );
        }
        const days = parseInt(searchParams.get('days') || '30');
        const trends = await getUsageTrends(tenantId, days);
        return NextResponse.json({ trends });
      }

      default: {
        // Default: return usage metrics
        if (tenantId) {
          const usage = await getTenantUsage(tenantId, startDate, endDate);
          return NextResponse.json({ usage });
        } else {
          const usage = await getAllTenantsUsage(targetTenantIds, startDate, endDate);
          return NextResponse.json({
            usage,
            summary: {
              totalTenants: usage.length,
              totalEmails: usage.reduce((sum, u) => sum + u.emails.total, 0),
              totalThreats: usage.reduce((sum, u) => sum + u.emails.threats, 0),
              totalUsers: usage.reduce((sum, u) => sum + u.users.total, 0),
            },
          });
        }
      }
    }
  } catch (error) {
    console.error('Error fetching usage:', error);
    return NextResponse.json(
      { error: 'Failed to fetch usage data' },
      { status: 500 }
    );
  }
}
