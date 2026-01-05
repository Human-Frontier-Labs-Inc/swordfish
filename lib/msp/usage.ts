/**
 * MSP Usage Tracking & Billing
 *
 * Tracks usage metrics across tenants for billing and reporting
 */

import { sql } from '@/lib/db';

export interface UsageMetrics {
  tenantId: string;
  tenantName: string;
  period: {
    start: Date;
    end: Date;
  };
  emails: {
    total: number;
    scanned: number;
    threats: number;
    quarantined: number;
    delivered: number;
  };
  users: {
    total: number;
    active: number;
  };
  storage: {
    usedMB: number;
    limitMB: number;
  };
  api: {
    requests: number;
    errors: number;
  };
  features: {
    linkRewriting: boolean;
    bannerInjection: boolean;
    advancedAnalysis: boolean;
  };
}

export interface BillingExport {
  generatedAt: Date;
  period: {
    start: Date;
    end: Date;
  };
  tenants: TenantBilling[];
  totals: {
    totalEmails: number;
    totalUsers: number;
    totalThreats: number;
  };
}

export interface TenantBilling {
  tenantId: string;
  tenantName: string;
  domain: string | null;
  plan: string;
  status: string;
  metrics: {
    emailsProcessed: number;
    threatsBlocked: number;
    userCount: number;
    daysActive: number;
  };
  billing: {
    baseCharge: number;
    overage: number;
    total: number;
    currency: string;
  };
}

// Plan limits for billing calculations
const PLAN_LIMITS = {
  starter: {
    users: 25,
    emailsPerMonth: 10000,
    basePrice: 99,
    overagePerEmail: 0.001,
    overagePerUser: 2,
  },
  pro: {
    users: 250,
    emailsPerMonth: 100000,
    basePrice: 499,
    overagePerEmail: 0.0005,
    overagePerUser: 1.5,
  },
  enterprise: {
    users: Infinity,
    emailsPerMonth: Infinity,
    basePrice: 1999,
    overagePerEmail: 0,
    overagePerUser: 0,
  },
};

/**
 * Get usage metrics for a specific tenant
 */
export async function getTenantUsage(
  tenantId: string,
  startDate: Date,
  endDate: Date
): Promise<UsageMetrics | null> {
  try {
    // Get tenant info
    const tenantResult = await sql`
      SELECT id, name, plan, settings FROM tenants WHERE id = ${tenantId} LIMIT 1
    `;

    const tenant = tenantResult[0];
    if (!tenant) return null;

    // Get email stats
    const emailStats = await sql`
      SELECT
        COUNT(*)::int as total,
        COUNT(*) FILTER (WHERE verdict IN ('quarantine', 'block'))::int as threats,
        COUNT(*) FILTER (WHERE verdict = 'quarantine')::int as quarantined,
        COUNT(*) FILTER (WHERE verdict = 'pass')::int as delivered
      FROM email_verdicts
      WHERE tenant_id = ${tenantId}
        AND created_at >= ${startDate.toISOString()}
        AND created_at <= ${endDate.toISOString()}
    `;

    // Get user stats
    const userStats = await sql`
      SELECT COUNT(*)::int as total FROM users WHERE tenant_id = ${tenantId}
    `;

    // Get API activity from audit logs
    const apiStats = await sql`
      SELECT
        COUNT(*)::int as requests,
        COUNT(*) FILTER (WHERE action LIKE '%error%')::int as errors
      FROM audit_logs
      WHERE tenant_id = ${tenantId}
        AND created_at >= ${startDate.toISOString()}
        AND created_at <= ${endDate.toISOString()}
    `;

    // Get active users
    const activeUsers = await sql`
      SELECT COUNT(DISTINCT actor_id)::int as count
      FROM audit_logs
      WHERE tenant_id = ${tenantId}
        AND created_at >= ${startDate.toISOString()}
        AND created_at <= ${endDate.toISOString()}
    `;

    const settings = (tenant.settings as Record<string, unknown>) || {};
    const stats = emailStats[0] || { total: 0, threats: 0, quarantined: 0, delivered: 0 };
    const api = apiStats[0] || { requests: 0, errors: 0 };

    return {
      tenantId,
      tenantName: tenant.name,
      period: { start: startDate, end: endDate },
      emails: {
        total: stats.total,
        scanned: stats.total,
        threats: stats.threats,
        quarantined: stats.quarantined,
        delivered: stats.delivered,
      },
      users: {
        total: userStats[0]?.total || 0,
        active: activeUsers[0]?.count || 0,
      },
      storage: {
        usedMB: 0,
        limitMB: tenant.plan === 'enterprise' ? Infinity : 5000,
      },
      api: {
        requests: api.requests,
        errors: api.errors,
      },
      features: {
        linkRewriting: settings.linkRewritingEnabled !== false,
        bannerInjection: settings.bannerInjectionEnabled !== false,
        advancedAnalysis: tenant.plan !== 'starter',
      },
    };
  } catch (error) {
    console.error('Error getting tenant usage:', error);
    return null;
  }
}

/**
 * Get aggregated usage for all tenants (MSP view)
 */
export async function getAllTenantsUsage(
  tenantIds: string[],
  startDate: Date,
  endDate: Date
): Promise<UsageMetrics[]> {
  const results: UsageMetrics[] = [];

  for (const tenantId of tenantIds) {
    const usage = await getTenantUsage(tenantId, startDate, endDate);
    if (usage) results.push(usage);
  }

  return results;
}

/**
 * Generate billing export for a period
 */
export async function generateBillingExport(
  tenantIds: string[],
  startDate: Date,
  endDate: Date
): Promise<BillingExport> {
  const tenantBillings: TenantBilling[] = [];
  let totalEmails = 0;
  let totalUsers = 0;
  let totalThreats = 0;

  for (const tenantId of tenantIds) {
    const usage = await getTenantUsage(tenantId, startDate, endDate);
    if (!usage) continue;

    // Get tenant details
    const tenantResult = await sql`
      SELECT domain, plan, status, created_at FROM tenants WHERE id = ${tenantId} LIMIT 1
    `;

    const tenant = tenantResult[0];
    if (!tenant) continue;

    // Calculate billing
    const limits = PLAN_LIMITS[tenant.plan as keyof typeof PLAN_LIMITS] || PLAN_LIMITS.starter;
    const emailOverage = Math.max(0, usage.emails.total - limits.emailsPerMonth);
    const userOverage = Math.max(0, usage.users.total - limits.users);

    const overageCharge =
      (emailOverage * limits.overagePerEmail) +
      (userOverage * limits.overagePerUser);

    // Calculate days active in period
    const tenantStart = new Date(tenant.created_at);
    const periodStart = tenantStart > startDate ? tenantStart : startDate;
    const daysActive = Math.ceil((endDate.getTime() - periodStart.getTime()) / (1000 * 60 * 60 * 24));

    tenantBillings.push({
      tenantId,
      tenantName: usage.tenantName,
      domain: tenant.domain,
      plan: tenant.plan,
      status: tenant.status,
      metrics: {
        emailsProcessed: usage.emails.total,
        threatsBlocked: usage.emails.threats,
        userCount: usage.users.total,
        daysActive,
      },
      billing: {
        baseCharge: limits.basePrice,
        overage: Math.round(overageCharge * 100) / 100,
        total: Math.round((limits.basePrice + overageCharge) * 100) / 100,
        currency: 'USD',
      },
    });

    totalEmails += usage.emails.total;
    totalUsers += usage.users.total;
    totalThreats += usage.emails.threats;
  }

  return {
    generatedAt: new Date(),
    period: { start: startDate, end: endDate },
    tenants: tenantBillings,
    totals: {
      totalEmails,
      totalUsers,
      totalThreats,
    },
  };
}

/**
 * Export billing data as CSV
 */
export function billingExportToCSV(export_: BillingExport): string {
  const headers = [
    'Tenant ID',
    'Tenant Name',
    'Domain',
    'Plan',
    'Status',
    'Emails Processed',
    'Threats Blocked',
    'User Count',
    'Days Active',
    'Base Charge',
    'Overage',
    'Total',
    'Currency',
  ].join(',');

  const rows = export_.tenants.map(t => [
    t.tenantId,
    `"${t.tenantName}"`,
    t.domain || '',
    t.plan,
    t.status,
    t.metrics.emailsProcessed,
    t.metrics.threatsBlocked,
    t.metrics.userCount,
    t.metrics.daysActive,
    t.billing.baseCharge,
    t.billing.overage,
    t.billing.total,
    t.billing.currency,
  ].join(','));

  const footer = [
    'TOTALS',
    '',
    '',
    '',
    '',
    export_.totals.totalEmails,
    export_.totals.totalThreats,
    export_.totals.totalUsers,
    '',
    '',
    '',
    export_.tenants.reduce((sum, t) => sum + t.billing.total, 0).toFixed(2),
    'USD',
  ].join(',');

  return [
    `# Billing Export - ${export_.period.start.toISOString().split('T')[0]} to ${export_.period.end.toISOString().split('T')[0]}`,
    `# Generated: ${export_.generatedAt.toISOString()}`,
    '',
    headers,
    ...rows,
    '',
    footer,
  ].join('\n');
}

/**
 * Get usage trends over time for a tenant
 */
export async function getUsageTrends(
  tenantId: string,
  days: number = 30
): Promise<{ date: string; emails: number; threats: number }[]> {
  const results = await sql`
    SELECT
      DATE(created_at) as date,
      COUNT(*)::int as emails,
      COUNT(*) FILTER (WHERE verdict IN ('quarantine', 'block'))::int as threats
    FROM email_verdicts
    WHERE tenant_id = ${tenantId}
      AND created_at >= NOW() - INTERVAL '${days} days'
    GROUP BY DATE(created_at)
    ORDER BY date ASC
  `;

  return results.map((r: Record<string, unknown>) => ({
    date: (r.date as Date).toISOString().split('T')[0],
    emails: r.emails as number,
    threats: r.threats as number,
  }));
}
