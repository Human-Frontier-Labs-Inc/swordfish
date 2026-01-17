/**
 * DMARC (Domain-based Message Authentication, Reporting & Conformance) Tests
 *
 * TDD tests for DMARC record parsing and policy evaluation
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { DMARCEvaluator } from '@/lib/email-auth/dmarc';
import { MockDNSResolver } from '@/lib/email-auth/dns-resolver';
import type {
  DMARCRecord,
  DMARCPolicy,
  DMARCResult,
  SPFResult,
  DKIMValidationResult
} from '@/lib/email-auth/types';

describe('DMARC Evaluator', () => {
  let mockDNS: MockDNSResolver;
  let evaluator: DMARCEvaluator;

  beforeEach(() => {
    mockDNS = new MockDNSResolver();
    evaluator = new DMARCEvaluator(mockDNS);
  });

  describe('DMARC Record Parsing', () => {
    it('should parse basic DMARC record from _dmarc.domain DNS', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', [
        'v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
      ]);

      const record = await evaluator.getRecord('example.com');

      expect(record).not.toBeNull();
      expect(record?.version).toBe('DMARC1');
      expect(record?.policy).toBe('reject');
      expect(record?.ruaAddresses).toContain('mailto:dmarc@example.com');
    });

    it('should parse DMARC record with all tags', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', [
        'v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:agg@example.com; ruf=mailto:forensic@example.com; adkim=s; aspf=r; fo=1; ri=86400',
      ]);

      const record = await evaluator.getRecord('example.com');

      expect(record?.policy).toBe('quarantine');
      expect(record?.subdomainPolicy).toBe('reject');
      expect(record?.percentage).toBe(50);
      expect(record?.ruaAddresses).toContain('mailto:agg@example.com');
      expect(record?.rufAddresses).toContain('mailto:forensic@example.com');
      expect(record?.adkim).toBe('strict');
      expect(record?.aspf).toBe('relaxed');
      expect(record?.failureOptions).toBe('1');
      expect(record?.reportInterval).toBe(86400);
    });

    it('should default adkim and aspf to relaxed', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', [
        'v=DMARC1; p=none',
      ]);

      const record = await evaluator.getRecord('example.com');

      expect(record?.adkim).toBe('relaxed');
      expect(record?.aspf).toBe('relaxed');
    });

    it('should default pct to 100', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', [
        'v=DMARC1; p=reject',
      ]);

      const record = await evaluator.getRecord('example.com');

      expect(record?.percentage).toBe(100);
    });

    it('should return null when no DMARC record exists', async () => {
      // No record set

      const record = await evaluator.getRecord('example.com');

      expect(record).toBeNull();
    });

    it('should throw for invalid DMARC version', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', [
        'v=DMARC2; p=reject',
      ]);

      await expect(evaluator.getRecord('example.com'))
        .rejects.toThrow('Invalid DMARC version');
    });

    it('should throw for missing policy tag', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', [
        'v=DMARC1; rua=mailto:dmarc@example.com',
      ]);

      await expect(evaluator.getRecord('example.com'))
        .rejects.toThrow('Missing required policy');
    });

    it('should parse multiple rua addresses', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', [
        'v=DMARC1; p=none; rua=mailto:dmarc1@example.com,mailto:dmarc2@example.com',
      ]);

      const record = await evaluator.getRecord('example.com');

      expect(record?.ruaAddresses).toHaveLength(2);
      expect(record?.ruaAddresses).toContain('mailto:dmarc1@example.com');
      expect(record?.ruaAddresses).toContain('mailto:dmarc2@example.com');
    });
  });

  describe('SPF Alignment Evaluation', () => {
    it('should pass strict SPF alignment when domains match exactly', () => {
      const headerFrom = 'sender@example.com';
      const mailFrom = 'bounce@example.com';

      const aligned = evaluator.checkSPFAlignment(headerFrom, mailFrom, 'strict');

      expect(aligned).toBe(true);
    });

    it('should fail strict SPF alignment for subdomain', () => {
      const headerFrom = 'sender@example.com';
      const mailFrom = 'bounce@mail.example.com';

      const aligned = evaluator.checkSPFAlignment(headerFrom, mailFrom, 'strict');

      expect(aligned).toBe(false);
    });

    it('should pass relaxed SPF alignment for subdomain', () => {
      const headerFrom = 'sender@example.com';
      const mailFrom = 'bounce@mail.example.com';

      const aligned = evaluator.checkSPFAlignment(headerFrom, mailFrom, 'relaxed');

      expect(aligned).toBe(true);
    });

    it('should pass relaxed SPF alignment when header domain is subdomain', () => {
      const headerFrom = 'sender@sub.example.com';
      const mailFrom = 'bounce@example.com';

      const aligned = evaluator.checkSPFAlignment(headerFrom, mailFrom, 'relaxed');

      expect(aligned).toBe(true);
    });

    it('should fail alignment for completely different domains', () => {
      const headerFrom = 'sender@example.com';
      const mailFrom = 'bounce@different.com';

      const strictAligned = evaluator.checkSPFAlignment(headerFrom, mailFrom, 'strict');
      const relaxedAligned = evaluator.checkSPFAlignment(headerFrom, mailFrom, 'relaxed');

      expect(strictAligned).toBe(false);
      expect(relaxedAligned).toBe(false);
    });
  });

  describe('DKIM Alignment Evaluation', () => {
    it('should pass strict DKIM alignment when domains match exactly', () => {
      const headerFrom = 'sender@example.com';
      const dkimDomain = 'example.com';

      const aligned = evaluator.checkDKIMAlignment(headerFrom, dkimDomain, 'strict');

      expect(aligned).toBe(true);
    });

    it('should fail strict DKIM alignment for subdomain', () => {
      const headerFrom = 'sender@example.com';
      const dkimDomain = 'mail.example.com';

      const aligned = evaluator.checkDKIMAlignment(headerFrom, dkimDomain, 'strict');

      expect(aligned).toBe(false);
    });

    it('should pass relaxed DKIM alignment for subdomain', () => {
      const headerFrom = 'sender@example.com';
      const dkimDomain = 'mail.example.com';

      const aligned = evaluator.checkDKIMAlignment(headerFrom, dkimDomain, 'relaxed');

      expect(aligned).toBe(true);
    });

    it('should pass relaxed DKIM alignment when header domain is subdomain', () => {
      const headerFrom = 'sender@sub.example.com';
      const dkimDomain = 'example.com';

      const aligned = evaluator.checkDKIMAlignment(headerFrom, dkimDomain, 'relaxed');

      expect(aligned).toBe(true);
    });

    it('should handle multiple DKIM signatures - pass if any aligns', () => {
      const headerFrom = 'sender@example.com';
      const dkimResults: DKIMValidationResult[] = [
        { result: 'fail', domain: 'other.com', selector: 's1' },
        { result: 'pass', domain: 'example.com', selector: 's2' },
      ];

      const aligned = evaluator.checkAnyDKIMAlignment(headerFrom, dkimResults, 'relaxed');

      expect(aligned).toBe(true);
    });

    it('should fail DKIM alignment if all signatures fail', () => {
      const headerFrom = 'sender@example.com';
      const dkimResults: DKIMValidationResult[] = [
        { result: 'fail', domain: 'other.com', selector: 's1' },
        { result: 'fail', domain: 'different.com', selector: 's2' },
      ];

      const aligned = evaluator.checkAnyDKIMAlignment(headerFrom, dkimResults, 'relaxed');

      expect(aligned).toBe(false);
    });
  });

  describe('Policy Application', () => {
    it('should apply none policy (monitor mode)', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', ['v=DMARC1; p=none']);

      const result = await evaluator.evaluate({
        headerFrom: 'sender@example.com',
        mailFrom: 'sender@different.com',
        spfResult: 'fail',
        dkimResults: [],
      });

      expect(result.result).toBe('fail');
      expect(result.appliedPolicy).toBe('none');
    });

    it('should apply quarantine policy', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', ['v=DMARC1; p=quarantine']);

      const result = await evaluator.evaluate({
        headerFrom: 'sender@example.com',
        mailFrom: 'sender@different.com',
        spfResult: 'fail',
        dkimResults: [],
      });

      expect(result.result).toBe('fail');
      expect(result.appliedPolicy).toBe('quarantine');
    });

    it('should apply reject policy', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', ['v=DMARC1; p=reject']);

      const result = await evaluator.evaluate({
        headerFrom: 'sender@example.com',
        mailFrom: 'sender@different.com',
        spfResult: 'fail',
        dkimResults: [],
      });

      expect(result.result).toBe('fail');
      expect(result.appliedPolicy).toBe('reject');
    });

    it('should pass when SPF passes and aligns', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', ['v=DMARC1; p=reject']);

      const result = await evaluator.evaluate({
        headerFrom: 'sender@example.com',
        mailFrom: 'bounce@example.com',
        spfResult: 'pass',
        dkimResults: [],
      });

      expect(result.result).toBe('pass');
      expect(result.spfAlignment).toBe(true);
    });

    it('should pass when DKIM passes and aligns', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', ['v=DMARC1; p=reject']);

      const result = await evaluator.evaluate({
        headerFrom: 'sender@example.com',
        mailFrom: 'sender@different.com',
        spfResult: 'fail',
        dkimResults: [
          { result: 'pass', domain: 'example.com', selector: 's1' },
        ],
      });

      expect(result.result).toBe('pass');
      expect(result.dkimAlignment).toBe(true);
    });
  });

  describe('Subdomain Policy (sp=)', () => {
    it('should apply subdomain policy for subdomains', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', ['v=DMARC1; p=none; sp=reject']);

      const result = await evaluator.evaluate({
        headerFrom: 'sender@sub.example.com',
        mailFrom: 'sender@different.com',
        spfResult: 'fail',
        dkimResults: [],
      });

      expect(result.appliedPolicy).toBe('reject');
    });

    it('should fall back to p= when sp= is not specified for subdomain', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', ['v=DMARC1; p=quarantine']);

      const result = await evaluator.evaluate({
        headerFrom: 'sender@sub.example.com',
        mailFrom: 'sender@different.com',
        spfResult: 'fail',
        dkimResults: [],
      });

      expect(result.appliedPolicy).toBe('quarantine');
    });

    it('should use organizational domain DMARC record for subdomains', async () => {
      // No DMARC record for subdomain
      mockDNS.setTxtRecord('_dmarc.example.com', ['v=DMARC1; p=reject']);

      const result = await evaluator.evaluate({
        headerFrom: 'sender@mail.sub.example.com',
        mailFrom: 'sender@different.com',
        spfResult: 'fail',
        dkimResults: [],
      });

      expect(result.policy).toBe('reject');
    });
  });

  describe('Percentage (pct=)', () => {
    it('should apply policy based on percentage', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', ['v=DMARC1; p=reject; pct=50']);

      const result = await evaluator.evaluate({
        headerFrom: 'sender@example.com',
        mailFrom: 'sender@different.com',
        spfResult: 'fail',
        dkimResults: [],
      });

      // Policy should still be reject but percentage is 50
      expect(result.percentage).toBe(50);
      expect(result.policy).toBe('reject');
    });

    it('should sample correctly at 0%', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', ['v=DMARC1; p=reject; pct=0']);

      const result = await evaluator.evaluate({
        headerFrom: 'sender@example.com',
        mailFrom: 'sender@different.com',
        spfResult: 'fail',
        dkimResults: [],
      });

      expect(result.percentage).toBe(0);
      // At 0%, policy effectively becomes none
      expect(result.appliedPolicy).toBe('none');
    });

    it('should respect 100% policy application', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', ['v=DMARC1; p=reject; pct=100']);

      const result = await evaluator.evaluate({
        headerFrom: 'sender@example.com',
        mailFrom: 'sender@different.com',
        spfResult: 'fail',
        dkimResults: [],
      });

      expect(result.percentage).toBe(100);
      expect(result.appliedPolicy).toBe('reject');
    });
  });

  describe('Edge Cases', () => {
    it('should handle no DMARC record (policy none)', async () => {
      // No DMARC record set

      const result = await evaluator.evaluate({
        headerFrom: 'sender@nodmarc.com',
        mailFrom: 'sender@different.com',
        spfResult: 'fail',
        dkimResults: [],
      });

      expect(result.result).toBe('none');
      expect(result.policy).toBe('none');
    });

    it('should handle DNS errors gracefully', async () => {
      mockDNS.setError('_dmarc.example.com', new Error('DNS timeout'));

      const result = await evaluator.evaluate({
        headerFrom: 'sender@example.com',
        mailFrom: 'sender@example.com',
        spfResult: 'pass',
        dkimResults: [],
      });

      // Should treat as no DMARC record
      expect(result.result).toBe('none');
    });

    it('should extract organizational domain correctly', () => {
      expect(evaluator.getOrganizationalDomain('sub.example.com')).toBe('example.com');
      expect(evaluator.getOrganizationalDomain('deep.sub.example.com')).toBe('example.com');
      expect(evaluator.getOrganizationalDomain('example.com')).toBe('example.com');
      expect(evaluator.getOrganizationalDomain('example.co.uk')).toBe('example.co.uk');
    });

    it('should handle both SPF and DKIM passing', async () => {
      mockDNS.setTxtRecord('_dmarc.example.com', ['v=DMARC1; p=reject']);

      const result = await evaluator.evaluate({
        headerFrom: 'sender@example.com',
        mailFrom: 'sender@example.com',
        spfResult: 'pass',
        dkimResults: [
          { result: 'pass', domain: 'example.com', selector: 's1' },
        ],
      });

      expect(result.result).toBe('pass');
      expect(result.spfAlignment).toBe(true);
      expect(result.dkimAlignment).toBe(true);
    });
  });
});
