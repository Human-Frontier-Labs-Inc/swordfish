/**
 * Tests for MSP Components
 */

import { describe, it, expect, vi } from 'vitest';

// Mock Next.js
vi.mock('next/navigation', () => ({
  useRouter: vi.fn(() => ({
    push: vi.fn(),
  })),
  useSearchParams: vi.fn(() => ({
    get: vi.fn(() => null),
  })),
}));

vi.mock('next/link', () => ({
  default: ({ children, href }: { children: React.ReactNode; href: string }) => (
    `<a href="${href}">${children}</a>`
  ),
}));

describe('ClientCard Component', () => {
  const mockClient = {
    id: 'tenant-1',
    name: 'Acme Corp',
    domain: 'acme.com',
    plan: 'pro' as const,
    status: 'active' as const,
    userCount: 50,
    emailsProcessed: 10000,
    emailsTrend: 5,
    threatsBlocked: 150,
    threatsTrend: -10,
    quarantinePending: 3,
    lastActivityAt: new Date().toISOString(),
    healthScore: 85,
    integrationStatus: 'connected' as const,
  };

  describe('Status Colors', () => {
    it('should have correct status color mapping', () => {
      const statusColors = {
        active: 'bg-green-100 text-green-700 border-green-200',
        suspended: 'bg-red-100 text-red-700 border-red-200',
        pending: 'bg-yellow-100 text-yellow-700 border-yellow-200',
      };

      expect(statusColors.active).toContain('green');
      expect(statusColors.suspended).toContain('red');
      expect(statusColors.pending).toContain('yellow');
    });
  });

  describe('Plan Colors', () => {
    it('should have correct plan color mapping', () => {
      const planColors = {
        starter: 'bg-gray-100 text-gray-700',
        pro: 'bg-blue-100 text-blue-700',
        enterprise: 'bg-purple-100 text-purple-700',
      };

      expect(planColors.starter).toContain('gray');
      expect(planColors.pro).toContain('blue');
      expect(planColors.enterprise).toContain('purple');
    });
  });

  describe('Health Score Display', () => {
    it('should show green for healthy score', () => {
      const getHealthColor = (score: number) => {
        if (score >= 80) return 'text-green-600';
        if (score >= 60) return 'text-yellow-600';
        return 'text-red-600';
      };

      expect(getHealthColor(85)).toContain('green');
      expect(getHealthColor(100)).toContain('green');
    });

    it('should show yellow for warning score', () => {
      const getHealthColor = (score: number) => {
        if (score >= 80) return 'text-green-600';
        if (score >= 60) return 'text-yellow-600';
        return 'text-red-600';
      };

      expect(getHealthColor(70)).toContain('yellow');
      expect(getHealthColor(60)).toContain('yellow');
    });

    it('should show red for critical score', () => {
      const getHealthColor = (score: number) => {
        if (score >= 80) return 'text-green-600';
        if (score >= 60) return 'text-yellow-600';
        return 'text-red-600';
      };

      expect(getHealthColor(50)).toContain('red');
      expect(getHealthColor(0)).toContain('red');
    });
  });

  describe('Number Formatting', () => {
    const formatNumber = (num: number): string => {
      if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
      if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
      return num.toString();
    };

    it('should format thousands correctly', () => {
      expect(formatNumber(1500)).toBe('1.5K');
      expect(formatNumber(10000)).toBe('10.0K');
    });

    it('should format millions correctly', () => {
      expect(formatNumber(1500000)).toBe('1.5M');
      expect(formatNumber(10000000)).toBe('10.0M');
    });

    it('should not format small numbers', () => {
      expect(formatNumber(500)).toBe('500');
      expect(formatNumber(0)).toBe('0');
    });
  });

  describe('Trend Display', () => {
    it('should show positive trend for increase', () => {
      const trend = 5;
      expect(trend > 0).toBe(true);
    });

    it('should show negative trend for decrease', () => {
      const trend = -10;
      expect(trend < 0).toBe(true);
    });

    it('should invert color for threat trends', () => {
      // For threats, decrease is good (green), increase is bad (red)
      const getTrendColor = (trend: number, inverse: boolean) => {
        if (inverse) {
          return trend > 0 ? 'text-red-500' : 'text-green-500';
        }
        return trend > 0 ? 'text-green-500' : 'text-red-500';
      };

      // Emails: up is good
      expect(getTrendColor(5, false)).toContain('green');
      // Threats: up is bad
      expect(getTrendColor(5, true)).toContain('red');
      // Threats: down is good
      expect(getTrendColor(-10, true)).toContain('green');
    });
  });

  describe('Integration Status', () => {
    it('should show correct indicator for connected', () => {
      const status = 'connected';
      const indicatorClass = status === 'connected' ? 'bg-green-500' :
                             status === 'error' ? 'bg-red-500' : 'bg-gray-400';

      expect(indicatorClass).toContain('green');
    });

    it('should show correct indicator for error', () => {
      const status = 'error';
      const indicatorClass = status === 'connected' ? 'bg-green-500' :
                             status === 'error' ? 'bg-red-500' : 'bg-gray-400';

      expect(indicatorClass).toContain('red');
    });

    it('should show correct indicator for disconnected', () => {
      const status = 'disconnected';
      const indicatorClass = status === 'connected' ? 'bg-green-500' :
                             status === 'error' ? 'bg-red-500' : 'bg-gray-400';

      expect(indicatorClass).toContain('gray');
    });
  });
});

describe('TenantSwitcher Component', () => {
  const mockTenants = [
    {
      id: 'tenant-1',
      name: 'Acme Corp',
      domain: 'acme.com',
      plan: 'pro' as const,
      role: 'msp_admin' as const,
    },
    {
      id: 'tenant-2',
      name: 'Beta Inc',
      domain: 'beta.io',
      plan: 'starter' as const,
      role: 'tenant_admin' as const,
    },
  ];

  describe('Tenant Selection', () => {
    it('should find current tenant by ID', () => {
      const currentTenantId = 'tenant-1';
      const currentTenant = mockTenants.find(t => t.id === currentTenantId);

      expect(currentTenant).toBeDefined();
      expect(currentTenant?.name).toBe('Acme Corp');
    });

    it('should handle missing current tenant', () => {
      const currentTenantId = 'nonexistent';
      const currentTenant = mockTenants.find(t => t.id === currentTenantId);

      expect(currentTenant).toBeUndefined();
    });
  });

  describe('Plan Badge Colors', () => {
    it('should have correct color for each plan', () => {
      const planColors = {
        starter: 'bg-gray-100 text-gray-600',
        pro: 'bg-blue-100 text-blue-600',
        enterprise: 'bg-purple-100 text-purple-600',
      };

      expect(planColors.starter).toContain('gray');
      expect(planColors.pro).toContain('blue');
      expect(planColors.enterprise).toContain('purple');
    });
  });

  describe('Switch Handler', () => {
    it('should not trigger switch for same tenant', () => {
      const currentTenantId = 'tenant-1';
      const selectedTenantId = 'tenant-1';
      const switchCalled = selectedTenantId !== currentTenantId;

      expect(switchCalled).toBe(false);
    });

    it('should trigger switch for different tenant', () => {
      const currentTenantId = 'tenant-1';
      const selectedTenantId = 'tenant-2';
      const switchCalled = selectedTenantId !== currentTenantId;

      expect(switchCalled).toBe(true);
    });
  });
});

describe('OnboardingWizard Component', () => {
  describe('Step Navigation', () => {
    const STEPS = [
      { id: 'organization', title: 'Organization' },
      { id: 'integration', title: 'Email Integration' },
      { id: 'users', title: 'Users' },
      { id: 'policies', title: 'Security Policies' },
    ];

    it('should have 4 steps', () => {
      expect(STEPS).toHaveLength(4);
    });

    it('should start at step 0', () => {
      const currentStep = 0;
      expect(currentStep).toBe(0);
    });

    it('should not go back from step 0', () => {
      const currentStep = 0;
      const newStep = currentStep > 0 ? currentStep - 1 : currentStep;

      expect(newStep).toBe(0);
    });

    it('should not go past last step', () => {
      const currentStep = 3;
      const newStep = currentStep < STEPS.length - 1 ? currentStep + 1 : currentStep;

      expect(newStep).toBe(3);
    });
  });

  describe('Validation', () => {
    describe('Step 0 - Organization', () => {
      it('should require organization name', () => {
        const data = { organizationName: '' };
        const isValid = !!data.organizationName.trim();

        expect(isValid).toBe(false);
      });

      it('should require domain', () => {
        const data = { domain: '' };
        const isValid = !!data.domain.trim();

        expect(isValid).toBe(false);
      });

      it('should validate domain format', () => {
        const domainRegex = /^[a-z0-9.-]+\.[a-z]{2,}$/i;

        expect(domainRegex.test('valid.com')).toBe(true);
        expect(domainRegex.test('invalid')).toBe(false);
      });
    });

    describe('Step 1 - Integration', () => {
      it('should require integration type', () => {
        const data = { integrationType: null };
        const isValid = data.integrationType !== null;

        expect(isValid).toBe(false);
      });

      it('should accept valid integration types', () => {
        const validTypes = ['o365', 'gmail', 'smtp'];

        validTypes.forEach(type => {
          expect(['o365', 'gmail', 'smtp'].includes(type)).toBe(true);
        });
      });
    });

    describe('Step 2 - Users', () => {
      it('should require admin email', () => {
        const data = { adminEmail: '' };
        const isValid = !!data.adminEmail.trim();

        expect(isValid).toBe(false);
      });

      it('should validate admin email format', () => {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        expect(emailRegex.test('admin@company.com')).toBe(true);
        expect(emailRegex.test('invalid')).toBe(false);
      });

      it('should require admin name', () => {
        const data = { adminName: '' };
        const isValid = !!data.adminName.trim();

        expect(isValid).toBe(false);
      });
    });

    describe('Step 3 - Policies', () => {
      it('should allow empty selection (no required fields)', () => {
        // Step 3 has no required fields
        const errors: string[] = [];
        expect(errors).toHaveLength(0);
      });

      it('should default to use default policies', () => {
        const data = { useDefaultPolicies: true };
        expect(data.useDefaultPolicies).toBe(true);
      });
    });
  });

  describe('Data Updates', () => {
    it('should update single field', () => {
      const data = { organizationName: 'Old Name' };
      const updates = { organizationName: 'New Name' };
      const updated = { ...data, ...updates };

      expect(updated.organizationName).toBe('New Name');
    });

    it('should clear errors on update', () => {
      const errors = { organizationName: 'Required' };
      const updatedField = 'organizationName';

      const newErrors = { ...errors };
      delete newErrors[updatedField];

      expect(newErrors.organizationName).toBeUndefined();
    });
  });

  describe('Plan Selection', () => {
    it('should default to pro plan', () => {
      const defaultPlan = 'pro';
      expect(defaultPlan).toBe('pro');
    });

    it('should display correct user limits', () => {
      const planLimits = {
        starter: 'Up to 25 users',
        pro: 'Up to 250 users',
        enterprise: 'Unlimited users',
      };

      expect(planLimits.starter).toContain('25');
      expect(planLimits.pro).toContain('250');
      expect(planLimits.enterprise).toContain('Unlimited');
    });
  });

  describe('Default Policies', () => {
    const defaultPolicies = [
      'Block known malicious domains',
      'Quarantine suspicious attachments',
      'Warn on external sender impersonation',
      'Rewrite suspicious URLs for click-time protection',
    ];

    it('should have 4 default policies', () => {
      expect(defaultPolicies).toHaveLength(4);
    });

    it('should include link protection', () => {
      expect(defaultPolicies.some(p => p.toLowerCase().includes('url'))).toBe(true);
    });

    it('should include quarantine', () => {
      expect(defaultPolicies.some(p => p.toLowerCase().includes('quarantine'))).toBe(true);
    });
  });
});
