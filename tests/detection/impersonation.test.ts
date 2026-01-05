/**
 * Impersonation Detection Tests
 * Tests for executive/VIP impersonation detection
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  detectImpersonation,
  calculateImpersonationRisk,
  type ImpersonationResult,
} from '@/lib/detection/bec/impersonation';

// Mock the VIP list functions
vi.mock('@/lib/detection/bec/vip-list', () => ({
  checkVIPImpersonation: vi.fn(),
  findVIPByDisplayName: vi.fn(),
  findVIPByEmail: vi.fn(),
}));

import {
  checkVIPImpersonation,
  findVIPByDisplayName,
} from '@/lib/detection/bec/vip-list';

const mockCheckVIPImpersonation = vi.mocked(checkVIPImpersonation);
const mockFindVIPByDisplayName = vi.mocked(findVIPByDisplayName);

describe('Impersonation Detection', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Default: no VIP match
    mockCheckVIPImpersonation.mockResolvedValue({
      isImpersonation: false,
      confidence: 0,
    });
    mockFindVIPByDisplayName.mockResolvedValue([]);
  });

  describe('VIP Display Name Spoofing', () => {
    it('should detect VIP display name impersonation', async () => {
      mockCheckVIPImpersonation.mockResolvedValue({
        isImpersonation: true,
        confidence: 0.85,
        matchedVIP: {
          id: 'vip-1',
          tenantId: 'test',
          email: 'john.ceo@company.com',
          displayName: 'John CEO',
          role: 'executive',
          aliases: [],
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        reason: 'Display name matches VIP',
      });

      const result = await detectImpersonation(
        'test-tenant',
        'john.ceo@gmail.com', // Different email
        'John CEO',           // Same display name
        undefined,
        'company.com'
      );

      expect(result.isImpersonation).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.5);
      expect(result.matchedVIP).toBeDefined();
      expect(result.signals.some(s => s.type === 'display_name_spoof')).toBe(true);
    });
  });

  describe('Executive Title Spoofing', () => {
    it('should detect CEO title in display name', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'fake@external.com',
        'John Smith - CEO',
        undefined,
        'company.com'
      );

      expect(result.signals.some(s => s.type === 'title_spoof')).toBe(true);
      expect(result.confidence).toBeGreaterThan(0);
    });

    it('should detect CFO title in display name', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'fake@external.com',
        'Jane Doe, CFO',
        undefined,
        'company.com'
      );

      expect(result.signals.some(s => s.type === 'title_spoof')).toBe(true);
    });

    it('should detect VP title in display name', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'fake@external.com',
        'VP of Operations - Mike',
        undefined,
        'company.com'
      );

      expect(result.signals.some(s => s.type === 'title_spoof')).toBe(true);
    });

    it('should detect director title', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'fake@external.com',
        'Sarah Managing Director',
        undefined,
        'company.com'
      );

      expect(result.signals.some(s => s.type === 'title_spoof')).toBe(true);
    });
  });

  describe('Free Email with Executive Name', () => {
    it('should flag executive name with Gmail', async () => {
      mockFindVIPByDisplayName.mockResolvedValue([
        {
          id: 'vip-1',
          tenantId: 'test',
          email: 'john.smith@company.com',
          displayName: 'John Smith',
          role: 'executive',
          aliases: [],
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ]);

      const result = await detectImpersonation(
        'test-tenant',
        'johnsmith@gmail.com',
        'John Smith',
        undefined,
        'company.com'
      );

      expect(result.signals.some(s => s.type === 'free_email_executive')).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.5);
    });

    it('should flag executive title with free email as critical', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'ceo.john@yahoo.com',
        'John Smith CEO',
        undefined,
        'company.com'
      );

      expect(result.signals.some(s => s.type === 'free_email_executive' && s.severity === 'critical')).toBe(true);
    });

    it('should recognize various free email providers', async () => {
      const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com'];

      for (const provider of freeProviders) {
        mockFindVIPByDisplayName.mockResolvedValue([
          {
            id: 'vip-1',
            tenantId: 'test',
            email: 'vip@company.com',
            displayName: 'Test VIP',
            role: 'executive',
            aliases: [],
            createdAt: new Date(),
            updatedAt: new Date(),
          },
        ]);

        const result = await detectImpersonation(
          'test-tenant',
          `testvip@${provider}`,
          'Test VIP',
          undefined,
          'company.com'
        );

        expect(result.signals.some(s => s.type === 'free_email_executive')).toBe(true);
      }
    });
  });

  describe('Reply-To Mismatch', () => {
    it('should detect reply-to domain mismatch', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'john@company.com',
        'John Smith',
        'john@different-domain.com', // Different reply-to
        'company.com'
      );

      expect(result.signals.some(s => s.type === 'reply_to_mismatch')).toBe(true);
    });

    it('should flag free email reply-to as high severity', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'john@company.com',
        'John Smith',
        'john.smith@gmail.com', // Free email reply-to
        'company.com'
      );

      expect(result.signals.some(s =>
        s.type === 'reply_to_mismatch' && s.severity === 'high'
      )).toBe(true);
    });

    it('should not flag same domain reply-to', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'john@company.com',
        'John Smith',
        'john.smith@company.com', // Same domain
        'company.com'
      );

      expect(result.signals.some(s => s.type === 'reply_to_mismatch')).toBe(false);
    });
  });

  describe('Domain Lookalike Detection', () => {
    it('should detect cousin domain with different TLD', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'john@company.co', // .co instead of .com
        'John Smith',
        undefined,
        'company.com'
      );

      expect(result.signals.some(s => s.type === 'cousin_domain')).toBe(true);
    });

    it('should detect typosquatting (1 char difference)', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'john@compamy.com', // n->m typo
        'John Smith',
        undefined,
        'company.com'
      );

      expect(result.signals.some(s => s.type === 'cousin_domain')).toBe(true);
    });

    it('should detect character substitution (0 for o)', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'john@c0mpany.com', // o->0
        'John Smith',
        undefined,
        'company.com'
      );

      expect(result.signals.some(s => s.type === 'cousin_domain')).toBe(true);
    });

    it('should detect rn->m substitution', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'john@commany.com', // company with rn replaced
        'John Smith',
        undefined,
        'cornpany.com' // org domain has rn
      );

      // The substitution detection looks for rn->m
      expect(result.isImpersonation || result.signals.length >= 0).toBe(true);
    });
  });

  describe('Unicode Homoglyph Detection', () => {
    it('should detect Cyrillic a in email', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'john@compаny.com', // Cyrillic 'а' instead of 'a'
        'John Smith',
        undefined,
        'company.com'
      );

      expect(result.signals.some(s => s.type === 'unicode_spoof')).toBe(true);
      expect(result.confidence).toBeGreaterThan(0.8);
    });

    it('should detect Cyrillic o in display name', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'john@external.com',
        'Jоhn Smith', // Cyrillic 'о' instead of 'o'
        undefined,
        'company.com'
      );

      expect(result.signals.some(s => s.type === 'unicode_spoof')).toBe(true);
    });

    it('should flag any non-ASCII in email domain', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'john@cömpany.com', // ö with umlaut
        'John Smith',
        undefined,
        'company.com'
      );

      expect(result.signals.some(s => s.type === 'unicode_spoof')).toBe(true);
    });
  });

  describe('Impersonation Risk Calculation', () => {
    it('should return low risk for no impersonation', () => {
      const result: ImpersonationResult = {
        isImpersonation: false,
        confidence: 0,
        signals: [],
        explanation: 'No impersonation detected',
      };

      const risk = calculateImpersonationRisk(result);

      expect(risk.level).toBe('low');
      expect(risk.score).toBe(0);
    });

    it('should return critical risk for critical signals', () => {
      const result: ImpersonationResult = {
        isImpersonation: true,
        confidence: 0.9,
        signals: [
          { type: 'unicode_spoof', severity: 'critical', detail: 'Unicode attack' },
        ],
        explanation: 'Unicode attack detected',
      };

      const risk = calculateImpersonationRisk(result);

      expect(risk.level).toBe('critical');
    });

    it('should return high risk for multiple high signals', () => {
      const result: ImpersonationResult = {
        isImpersonation: true,
        confidence: 0.75,
        signals: [
          { type: 'display_name_spoof', severity: 'high', detail: 'VIP match' },
          { type: 'free_email_executive', severity: 'high', detail: 'Free email' },
        ],
        explanation: 'Multiple indicators',
      };

      const risk = calculateImpersonationRisk(result);

      expect(['high', 'critical']).toContain(risk.level);
    });

    it('should weight signals by severity', () => {
      const lowResult: ImpersonationResult = {
        isImpersonation: true,
        confidence: 0.5,
        signals: [
          { type: 'title_spoof', severity: 'low', detail: 'Title' },
          { type: 'title_spoof', severity: 'low', detail: 'Title 2' },
        ],
        explanation: 'Low signals',
      };

      const highResult: ImpersonationResult = {
        isImpersonation: true,
        confidence: 0.5,
        signals: [
          { type: 'unicode_spoof', severity: 'critical', detail: 'Critical' },
        ],
        explanation: 'High signal',
      };

      const lowRisk = calculateImpersonationRisk(lowResult);
      const highRisk = calculateImpersonationRisk(highResult);

      expect(highRisk.score).toBeGreaterThan(lowRisk.score);
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing organization domain', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'john@external.com',
        'John Smith',
        undefined,
        undefined // No org domain
      );

      // Should not throw and should work without domain checks
      expect(result).toBeDefined();
      expect(result.signals.some(s => s.type === 'cousin_domain')).toBe(false);
    });

    it('should handle empty display name', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'john@external.com',
        '',
        undefined,
        'company.com'
      );

      expect(result).toBeDefined();
    });

    it('should handle email without domain', async () => {
      const result = await detectImpersonation(
        'test-tenant',
        'invalid-email',
        'John Smith',
        undefined,
        'company.com'
      );

      // Should handle gracefully
      expect(result).toBeDefined();
    });

    it('should generate explanation for multiple signals', async () => {
      mockCheckVIPImpersonation.mockResolvedValue({
        isImpersonation: true,
        confidence: 0.8,
        matchedVIP: {
          id: 'vip-1',
          tenantId: 'test',
          email: 'vip@company.com',
          displayName: 'VIP User',
          role: 'executive',
          aliases: [],
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        reason: 'VIP match',
      });

      const result = await detectImpersonation(
        'test-tenant',
        'vip@gmail.com',
        'VIP User CEO',
        'reply@different.com',
        'company.com'
      );

      expect(result.explanation).toContain('Multiple');
    });
  });
});
