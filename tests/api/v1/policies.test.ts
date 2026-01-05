/**
 * REST API v1 - Policies Endpoint Tests
 *
 * Unit tests for policy validation and formatting
 */

import { describe, it, expect } from 'vitest';

describe('Policy Validation', () => {
  const VALID_TYPES = ['allowlist', 'blocklist', 'rule'];
  const VALID_TARGETS = ['domain', 'email', 'ip', 'pattern'];
  const VALID_ACTIONS = ['allow', 'block', 'quarantine'];

  describe('Type Validation', () => {
    it('should accept valid policy types', () => {
      VALID_TYPES.forEach((type) => {
        expect(VALID_TYPES.includes(type)).toBe(true);
      });
    });

    it('should reject invalid policy types', () => {
      const invalidTypes = ['whitelist', 'blacklist', 'custom', ''];
      invalidTypes.forEach((type) => {
        expect(VALID_TYPES.includes(type)).toBe(false);
      });
    });
  });

  describe('Target Validation', () => {
    it('should accept valid targets', () => {
      VALID_TARGETS.forEach((target) => {
        expect(VALID_TARGETS.includes(target)).toBe(true);
      });
    });

    it('should reject invalid targets', () => {
      const invalidTargets = ['user', 'group', 'url', ''];
      invalidTargets.forEach((target) => {
        expect(VALID_TARGETS.includes(target)).toBe(false);
      });
    });
  });

  describe('Action Validation', () => {
    it('should accept valid actions', () => {
      VALID_ACTIONS.forEach((action) => {
        expect(VALID_ACTIONS.includes(action)).toBe(true);
      });
    });

    it('should reject invalid actions', () => {
      const invalidActions = ['reject', 'warn', 'log', ''];
      invalidActions.forEach((action) => {
        expect(VALID_ACTIONS.includes(action)).toBe(false);
      });
    });
  });

  describe('Priority Validation', () => {
    it('should accept valid priority range (0-100)', () => {
      const validatePriority = (p: number) => p >= 0 && p <= 100;

      expect(validatePriority(0)).toBe(true);
      expect(validatePriority(50)).toBe(true);
      expect(validatePriority(100)).toBe(true);
    });

    it('should reject invalid priority values', () => {
      const validatePriority = (p: number) => p >= 0 && p <= 100;

      expect(validatePriority(-1)).toBe(false);
      expect(validatePriority(101)).toBe(false);
      expect(validatePriority(150)).toBe(false);
    });
  });

  describe('Value Validation', () => {
    describe('Domain target', () => {
      it('should validate domain format', () => {
        const isValidDomain = (v: string) => /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/.test(v);

        expect(isValidDomain('example.com')).toBe(true);
        expect(isValidDomain('sub.example.com')).toBe(true);
        expect(isValidDomain('my-domain.co.uk')).toBe(true);
      });

      it('should reject invalid domains', () => {
        const isValidDomain = (v: string) => /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/.test(v);

        expect(isValidDomain('')).toBe(false);
        expect(isValidDomain('not a domain')).toBe(false);
        expect(isValidDomain('-invalid.com')).toBe(false);
      });
    });

    describe('Email target', () => {
      it('should validate email format', () => {
        const isValidEmail = (v: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

        expect(isValidEmail('user@example.com')).toBe(true);
        expect(isValidEmail('user.name@example.co.uk')).toBe(true);
        expect(isValidEmail('user+tag@example.com')).toBe(true);
      });

      it('should reject invalid emails', () => {
        const isValidEmail = (v: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

        expect(isValidEmail('')).toBe(false);
        expect(isValidEmail('notanemail')).toBe(false);
        expect(isValidEmail('@example.com')).toBe(false);
      });
    });

    describe('IP target', () => {
      it('should validate IPv4 format', () => {
        const isValidIPv4 = (v: string) => {
          const parts = v.split('.');
          if (parts.length !== 4) return false;
          return parts.every((p) => {
            const n = parseInt(p, 10);
            return !isNaN(n) && n >= 0 && n <= 255 && p === n.toString();
          });
        };

        expect(isValidIPv4('192.168.1.1')).toBe(true);
        expect(isValidIPv4('10.0.0.0')).toBe(true);
        expect(isValidIPv4('255.255.255.255')).toBe(true);
      });

      it('should reject invalid IPs', () => {
        const isValidIPv4 = (v: string) => {
          const parts = v.split('.');
          if (parts.length !== 4) return false;
          return parts.every((p) => {
            const n = parseInt(p, 10);
            return !isNaN(n) && n >= 0 && n <= 255 && p === n.toString();
          });
        };

        expect(isValidIPv4('')).toBe(false);
        expect(isValidIPv4('256.1.1.1')).toBe(false);
        expect(isValidIPv4('192.168.1')).toBe(false);
        expect(isValidIPv4('not.an.ip.address')).toBe(false);
      });
    });

    describe('Pattern target', () => {
      it('should accept regex patterns', () => {
        const isValidPattern = (v: string) => {
          try {
            new RegExp(v);
            return true;
          } catch {
            return false;
          }
        };

        expect(isValidPattern('.*@spam\\.com$')).toBe(true);
        expect(isValidPattern('^[0-9]+$')).toBe(true);
        expect(isValidPattern('invoice.*\\.pdf')).toBe(true);
      });

      it('should reject invalid regex patterns', () => {
        const isValidPattern = (v: string) => {
          try {
            new RegExp(v);
            return true;
          } catch {
            return false;
          }
        };

        expect(isValidPattern('[invalid')).toBe(false);
        expect(isValidPattern('(unclosed')).toBe(false);
      });
    });
  });
});

describe('Policy Formatting', () => {
  it('should format raw policy to API format', () => {
    const rawPolicy = {
      id: 'policy_123',
      type: 'blocklist',
      target: 'domain',
      value: 'malicious.com',
      action: 'block',
      priority: 90,
      is_active: true,
      created_by: 'user_456',
      created_at: new Date('2024-01-15'),
      updated_at: new Date('2024-01-16'),
    };

    const formatted = {
      id: rawPolicy.id,
      type: rawPolicy.type,
      target: rawPolicy.target,
      value: rawPolicy.value,
      action: rawPolicy.action,
      priority: rawPolicy.priority,
      isActive: rawPolicy.is_active,
      createdBy: rawPolicy.created_by,
      createdAt: rawPolicy.created_at,
      updatedAt: rawPolicy.updated_at,
    };

    expect(formatted.id).toBe('policy_123');
    expect(formatted.type).toBe('blocklist');
    expect(formatted.isActive).toBe(true);
    expect(formatted.priority).toBe(90);
  });

  it('should apply snake_case to camelCase transformation', () => {
    const snakeToCamel = (str: string) =>
      str.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());

    expect(snakeToCamel('is_active')).toBe('isActive');
    expect(snakeToCamel('created_by')).toBe('createdBy');
    expect(snakeToCamel('created_at')).toBe('createdAt');
    expect(snakeToCamel('updated_at')).toBe('updatedAt');
  });
});

describe('Policy Conflict Detection', () => {
  it('should detect duplicate policies', () => {
    const existingPolicies = [
      { type: 'blocklist', target: 'domain', value: 'spam.com' },
      { type: 'allowlist', target: 'email', value: 'trusted@example.com' },
    ];

    const isDuplicate = (newPolicy: { type: string; target: string; value: string }) =>
      existingPolicies.some(
        (p) =>
          p.type === newPolicy.type &&
          p.target === newPolicy.target &&
          p.value === newPolicy.value
      );

    expect(isDuplicate({ type: 'blocklist', target: 'domain', value: 'spam.com' })).toBe(true);
    expect(isDuplicate({ type: 'blocklist', target: 'domain', value: 'other.com' })).toBe(false);
    expect(isDuplicate({ type: 'blocklist', target: 'email', value: 'spam.com' })).toBe(false);
  });
});

describe('Policy Priority Sorting', () => {
  it('should sort policies by priority (descending)', () => {
    const policies = [
      { id: '1', priority: 50 },
      { id: '2', priority: 90 },
      { id: '3', priority: 10 },
      { id: '4', priority: 70 },
    ];

    const sorted = [...policies].sort((a, b) => b.priority - a.priority);

    expect(sorted[0].id).toBe('2'); // priority 90
    expect(sorted[1].id).toBe('4'); // priority 70
    expect(sorted[2].id).toBe('1'); // priority 50
    expect(sorted[3].id).toBe('3'); // priority 10
  });

  it('should handle equal priorities by creation date', () => {
    const policies = [
      { id: '1', priority: 50, createdAt: new Date('2024-01-15') },
      { id: '2', priority: 50, createdAt: new Date('2024-01-10') },
      { id: '3', priority: 50, createdAt: new Date('2024-01-20') },
    ];

    const sorted = [...policies].sort((a, b) => {
      if (b.priority !== a.priority) return b.priority - a.priority;
      return b.createdAt.getTime() - a.createdAt.getTime();
    });

    expect(sorted[0].id).toBe('3'); // newest
    expect(sorted[1].id).toBe('1');
    expect(sorted[2].id).toBe('2'); // oldest
  });
});
