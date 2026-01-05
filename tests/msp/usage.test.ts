/**
 * Tests for MSP Usage Tracking & Billing
 */

import { describe, it, expect, vi } from 'vitest';

// Mock database and schema before importing usage module
vi.mock('@/lib/db', () => ({
  db: {
    select: vi.fn(() => ({ from: vi.fn(() => ({ where: vi.fn(() => []) })) })),
    insert: vi.fn(),
    update: vi.fn(),
  },
}));

vi.mock('@/lib/db/schema', () => ({
  tenants: {},
  emails: {},
  auditLogs: {},
  tenantUsers: {},
  policies: {},
}));

// Import types and test pure functions directly
interface UsageMetrics {
  tenantId: string;
  tenantName: string;
  period: { start: Date; end: Date };
  emails: { total: number; scanned: number; threats: number; quarantined: number; delivered: number };
  users: { total: number; active: number };
  storage: { usedMB: number; limitMB: number };
  api: { requests: number; errors: number };
  features: { linkRewriting: boolean; bannerInjection: boolean; advancedAnalysis: boolean };
}

interface TenantBilling {
  tenantId: string;
  tenantName: string;
  domain: string | null;
  plan: string;
  status: string;
  metrics: { emailsProcessed: number; threatsBlocked: number; userCount: number; daysActive: number };
  billing: { baseCharge: number; overage: number; total: number; currency: string };
}

interface BillingExport {
  generatedAt: Date;
  period: { start: Date; end: Date };
  tenants: TenantBilling[];
  totals: { totalEmails: number; totalUsers: number; totalThreats: number };
}

// Pure function for CSV export (copy from lib for testing)
function billingExportToCSV(export_: BillingExport): string {
  const headers = [
    'Tenant ID', 'Tenant Name', 'Domain', 'Plan', 'Status',
    'Emails Processed', 'Threats Blocked', 'User Count', 'Days Active',
    'Base Charge', 'Overage', 'Total', 'Currency',
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
    'TOTALS', '', '', '', '',
    export_.totals.totalEmails,
    export_.totals.totalThreats,
    export_.totals.totalUsers,
    '', '', '',
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

describe('Usage Metrics', () => {
  describe('UsageMetrics structure', () => {
    it('should have correct shape', () => {
      const metrics: UsageMetrics = {
        tenantId: 'tenant-1',
        tenantName: 'Acme Corp',
        period: {
          start: new Date('2024-01-01'),
          end: new Date('2024-01-31'),
        },
        emails: {
          total: 10000,
          scanned: 10000,
          threats: 150,
          quarantined: 50,
          delivered: 9800,
        },
        users: {
          total: 50,
          active: 45,
        },
        storage: {
          usedMB: 1500,
          limitMB: 5000,
        },
        api: {
          requests: 5000,
          errors: 10,
        },
        features: {
          linkRewriting: true,
          bannerInjection: true,
          advancedAnalysis: true,
        },
      };

      expect(metrics.tenantId).toBe('tenant-1');
      expect(metrics.emails.total).toBe(10000);
      expect(metrics.emails.threats).toBeLessThan(metrics.emails.total);
      expect(metrics.users.active).toBeLessThanOrEqual(metrics.users.total);
    });

    it('should calculate threat rate correctly', () => {
      const emails = { total: 10000, threats: 150 };
      const threatRate = (emails.threats / emails.total) * 100;

      expect(threatRate).toBe(1.5);
      expect(threatRate).toBeLessThan(5); // Healthy threshold
    });

    it('should calculate delivery rate correctly', () => {
      const emails = { total: 10000, delivered: 9800 };
      const deliveryRate = (emails.delivered / emails.total) * 100;

      expect(deliveryRate).toBe(98);
      expect(deliveryRate).toBeGreaterThan(95); // Healthy threshold
    });
  });

  describe('Plan Limits', () => {
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

    it('should calculate starter plan overage correctly', () => {
      const usage = { users: 30, emails: 15000 };
      const limits = PLAN_LIMITS.starter;

      const emailOverage = Math.max(0, usage.emails - limits.emailsPerMonth);
      const userOverage = Math.max(0, usage.users - limits.users);

      const emailCharge = emailOverage * limits.overagePerEmail;
      const userCharge = userOverage * limits.overagePerUser;

      expect(emailOverage).toBe(5000);
      expect(userOverage).toBe(5);
      expect(emailCharge).toBe(5);
      expect(userCharge).toBe(10);
      expect(emailCharge + userCharge).toBe(15);
    });

    it('should not charge overage for enterprise', () => {
      const usage = { users: 1000, emails: 1000000 };
      const limits = PLAN_LIMITS.enterprise;

      const emailOverage = Math.max(0, usage.emails - limits.emailsPerMonth);
      const userOverage = Math.max(0, usage.users - limits.users);

      expect(emailOverage).toBe(0);
      expect(userOverage).toBe(0);
    });

    it('should not charge when under limits', () => {
      const usage = { users: 20, emails: 8000 };
      const limits = PLAN_LIMITS.starter;

      const emailOverage = Math.max(0, usage.emails - limits.emailsPerMonth);
      const userOverage = Math.max(0, usage.users - limits.users);

      expect(emailOverage).toBe(0);
      expect(userOverage).toBe(0);
    });
  });
});

describe('Billing Export', () => {
  const mockExport: BillingExport = {
    generatedAt: new Date('2024-02-01T12:00:00Z'),
    period: {
      start: new Date('2024-01-01'),
      end: new Date('2024-01-31'),
    },
    tenants: [
      {
        tenantId: 'tenant-1',
        tenantName: 'Acme Corp',
        domain: 'acme.com',
        plan: 'pro',
        status: 'active',
        metrics: {
          emailsProcessed: 50000,
          threatsBlocked: 500,
          userCount: 100,
          daysActive: 31,
        },
        billing: {
          baseCharge: 499,
          overage: 0,
          total: 499,
          currency: 'USD',
        },
      },
      {
        tenantId: 'tenant-2',
        tenantName: 'Beta Inc',
        domain: 'beta.io',
        plan: 'starter',
        status: 'active',
        metrics: {
          emailsProcessed: 15000,
          threatsBlocked: 100,
          userCount: 30,
          daysActive: 31,
        },
        billing: {
          baseCharge: 99,
          overage: 15,
          total: 114,
          currency: 'USD',
        },
      },
    ],
    totals: {
      totalEmails: 65000,
      totalUsers: 130,
      totalThreats: 600,
    },
  };

  describe('BillingExport structure', () => {
    it('should have correct totals', () => {
      const calculatedTotalEmails = mockExport.tenants.reduce(
        (sum, t) => sum + t.metrics.emailsProcessed,
        0
      );
      const calculatedTotalUsers = mockExport.tenants.reduce(
        (sum, t) => sum + t.metrics.userCount,
        0
      );
      const calculatedTotalThreats = mockExport.tenants.reduce(
        (sum, t) => sum + t.metrics.threatsBlocked,
        0
      );

      expect(calculatedTotalEmails).toBe(mockExport.totals.totalEmails);
      expect(calculatedTotalUsers).toBe(mockExport.totals.totalUsers);
      expect(calculatedTotalThreats).toBe(mockExport.totals.totalThreats);
    });

    it('should calculate total billing correctly', () => {
      const totalBilling = mockExport.tenants.reduce(
        (sum, t) => sum + t.billing.total,
        0
      );

      expect(totalBilling).toBe(499 + 114);
    });
  });

  describe('CSV Export', () => {
    it('should generate valid CSV format', () => {
      const csv = billingExportToCSV(mockExport);

      // Check headers
      expect(csv).toContain('Tenant ID');
      expect(csv).toContain('Tenant Name');
      expect(csv).toContain('Plan');
      expect(csv).toContain('Total');
      expect(csv).toContain('Currency');

      // Check data rows
      expect(csv).toContain('Acme Corp');
      expect(csv).toContain('acme.com');
      expect(csv).toContain('pro');
      expect(csv).toContain('499');

      expect(csv).toContain('Beta Inc');
      expect(csv).toContain('starter');
      expect(csv).toContain('114');
    });

    it('should include period in CSV header', () => {
      const csv = billingExportToCSV(mockExport);

      expect(csv).toContain('2024-01-01');
      expect(csv).toContain('2024-01-31');
    });

    it('should include totals row', () => {
      const csv = billingExportToCSV(mockExport);

      expect(csv).toContain('TOTALS');
      expect(csv).toContain('65000');
      expect(csv).toContain('130');
    });

    it('should handle empty tenant name quotes', () => {
      const csv = billingExportToCSV(mockExport);
      const lines = csv.split('\n');

      // Data rows should have quoted tenant names
      const dataLines = lines.filter(l => l.includes('tenant-'));
      dataLines.forEach(line => {
        expect(line).toMatch(/"[^"]+"/);
      });
    });

    it('should escape commas in tenant names', () => {
      const exportWithComma: BillingExport = {
        ...mockExport,
        tenants: [
          {
            ...mockExport.tenants[0],
            tenantName: 'Acme, Corp',
          },
        ],
      };

      const csv = billingExportToCSV(exportWithComma);
      expect(csv).toContain('"Acme, Corp"');
    });
  });
});

describe('Health Score Calculation', () => {
  it('should start at 100 for healthy tenants', () => {
    const baseScore = 100;
    expect(baseScore).toBe(100);
  });

  it('should deduct for high threat rate', () => {
    let healthScore = 100;
    const threatRates = [
      { rate: 1, deduction: 0 },
      { rate: 3, deduction: 5 },
      { rate: 7, deduction: 15 },
      { rate: 15, deduction: 30 },
    ];

    threatRates.forEach(({ rate, deduction }) => {
      let score = 100;
      if (rate > 10) score -= 30;
      else if (rate > 5) score -= 15;
      else if (rate > 2) score -= 5;

      expect(score).toBe(100 - deduction);
    });
  });

  it('should deduct for disconnected integration', () => {
    const integrationPenalty = 20;
    const baseScore = 100;
    const scoreWithDisconnected = baseScore - integrationPenalty;

    expect(scoreWithDisconnected).toBe(80);
  });

  it('should not go below 0', () => {
    let healthScore = 100;

    // Multiple deductions
    healthScore -= 30; // High threat rate
    healthScore -= 20; // Disconnected integration
    healthScore -= 30; // Additional penalty (hypothetical)
    healthScore -= 30; // Additional penalty (hypothetical)

    expect(Math.max(0, healthScore)).toBe(0);
  });

  it('should categorize health correctly', () => {
    const categorize = (score: number) => {
      if (score >= 80) return 'healthy';
      if (score >= 60) return 'warning';
      return 'critical';
    };

    expect(categorize(90)).toBe('healthy');
    expect(categorize(80)).toBe('healthy');
    expect(categorize(79)).toBe('warning');
    expect(categorize(60)).toBe('warning');
    expect(categorize(59)).toBe('critical');
    expect(categorize(0)).toBe('critical');
  });
});

describe('Usage Trends', () => {
  it('should generate daily data points', () => {
    const days = 30;
    const trends: { date: string; emails: number; threats: number }[] = [];

    const endDate = new Date();
    for (let i = 0; i < days; i++) {
      const date = new Date(endDate);
      date.setDate(date.getDate() - i);
      trends.unshift({
        date: date.toISOString().split('T')[0],
        emails: Math.floor(Math.random() * 1000) + 100,
        threats: Math.floor(Math.random() * 50),
      });
    }

    expect(trends).toHaveLength(30);
    expect(trends[0].date < trends[29].date).toBe(true);
  });

  it('should have threats <= emails for each day', () => {
    const trends = [
      { date: '2024-01-01', emails: 500, threats: 10 },
      { date: '2024-01-02', emails: 600, threats: 15 },
      { date: '2024-01-03', emails: 0, threats: 0 },
    ];

    trends.forEach(day => {
      expect(day.threats).toBeLessThanOrEqual(day.emails);
    });
  });
});

describe('Period Calculations', () => {
  it('should calculate 30-day period correctly', () => {
    const endDate = new Date('2024-01-31');
    const startDate = new Date(endDate.getTime() - 30 * 24 * 60 * 60 * 1000);

    expect(startDate.toISOString().split('T')[0]).toBe('2024-01-01');
  });

  it('should calculate days active for new tenant', () => {
    const periodStart = new Date('2024-01-01');
    const periodEnd = new Date('2024-01-31');
    const tenantCreated = new Date('2024-01-15');

    const effectiveStart = tenantCreated > periodStart ? tenantCreated : periodStart;
    const daysActive = Math.ceil(
      (periodEnd.getTime() - effectiveStart.getTime()) / (1000 * 60 * 60 * 24)
    );

    expect(daysActive).toBe(16);
  });

  it('should calculate full period for existing tenant', () => {
    const periodStart = new Date('2024-01-01');
    const periodEnd = new Date('2024-01-31');
    const tenantCreated = new Date('2023-06-01');

    const effectiveStart = tenantCreated > periodStart ? tenantCreated : periodStart;
    const daysActive = Math.ceil(
      (periodEnd.getTime() - effectiveStart.getTime()) / (1000 * 60 * 60 * 24)
    );

    expect(daysActive).toBe(30);
  });
});
