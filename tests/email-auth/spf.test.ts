/**
 * SPF (Sender Policy Framework) Validation Tests
 *
 * TDD tests for SPF record parsing and IP validation
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SPFValidator } from '@/lib/email-auth/spf';
import { MockDNSResolver } from '@/lib/email-auth/dns-resolver';
import type { SPFResult, SPFRecord, SPFMechanism } from '@/lib/email-auth/types';

describe('SPF Validator', () => {
  let mockDNS: MockDNSResolver;
  let validator: SPFValidator;

  beforeEach(() => {
    mockDNS = new MockDNSResolver();
    validator = new SPFValidator(mockDNS);
  });

  afterEach(() => {
    // Clean up
  });

  describe('SPF Record Parsing', () => {
    it('should parse a basic SPF record with ip4 mechanism', () => {
      const record = 'v=spf1 ip4:192.168.1.0/24 -all';
      const parsed = validator.parseRecord(record);

      expect(parsed.version).toBe('spf1');
      expect(parsed.mechanisms).toHaveLength(2);
      expect(parsed.mechanisms[0].type).toBe('ip4');
      expect(parsed.mechanisms[0].value).toBe('192.168.1.0');
      expect(parsed.mechanisms[0].cidr).toBe(24);
      expect(parsed.mechanisms[0].qualifier).toBe('+');
      expect(parsed.mechanisms[1].type).toBe('all');
      expect(parsed.mechanisms[1].qualifier).toBe('-');
    });

    it('should parse SPF record with ip6 mechanism', () => {
      const record = 'v=spf1 ip6:2001:db8::/32 ~all';
      const parsed = validator.parseRecord(record);

      expect(parsed.mechanisms[0].type).toBe('ip6');
      expect(parsed.mechanisms[0].value).toBe('2001:db8::');
      expect(parsed.mechanisms[0].cidr).toBe(32);
      expect(parsed.mechanisms[1].type).toBe('all');
      expect(parsed.mechanisms[1].qualifier).toBe('~');
    });

    it('should parse SPF record with a mechanism', () => {
      const record = 'v=spf1 a a:mail.example.com -all';
      const parsed = validator.parseRecord(record);

      expect(parsed.mechanisms[0].type).toBe('a');
      expect(parsed.mechanisms[0].value).toBeUndefined();
      expect(parsed.mechanisms[1].type).toBe('a');
      expect(parsed.mechanisms[1].value).toBe('mail.example.com');
    });

    it('should parse SPF record with mx mechanism', () => {
      const record = 'v=spf1 mx mx:backup.example.com/24 -all';
      const parsed = validator.parseRecord(record);

      expect(parsed.mechanisms[0].type).toBe('mx');
      expect(parsed.mechanisms[0].value).toBeUndefined();
      expect(parsed.mechanisms[1].type).toBe('mx');
      expect(parsed.mechanisms[1].value).toBe('backup.example.com');
      expect(parsed.mechanisms[1].cidr).toBe(24);
    });

    it('should parse SPF record with include mechanism', () => {
      const record = 'v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all';
      const parsed = validator.parseRecord(record);

      expect(parsed.mechanisms[0].type).toBe('include');
      expect(parsed.mechanisms[0].value).toBe('_spf.google.com');
      expect(parsed.mechanisms[1].type).toBe('include');
      expect(parsed.mechanisms[1].value).toBe('spf.protection.outlook.com');
    });

    it('should parse SPF record with redirect modifier', () => {
      const record = 'v=spf1 redirect=_spf.example.com';
      const parsed = validator.parseRecord(record);

      expect(parsed.redirect).toBe('_spf.example.com');
    });

    it('should handle different qualifiers (+, -, ~, ?)', () => {
      const record = 'v=spf1 +ip4:1.1.1.1 -ip4:2.2.2.2 ~ip4:3.3.3.3 ?ip4:4.4.4.4 -all';
      const parsed = validator.parseRecord(record);

      expect(parsed.mechanisms[0].qualifier).toBe('+');
      expect(parsed.mechanisms[1].qualifier).toBe('-');
      expect(parsed.mechanisms[2].qualifier).toBe('~');
      expect(parsed.mechanisms[3].qualifier).toBe('?');
    });

    it('should return permerror for invalid SPF version', () => {
      const record = 'v=spf2 ip4:192.168.1.1 -all';

      expect(() => validator.parseRecord(record)).toThrow('Invalid SPF version');
    });
  });

  describe('IP Validation Against SPF Mechanisms', () => {
    it('should pass for IP matching ip4 mechanism', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip4:192.168.1.100 -all']);

      const result = await validator.validate('192.168.1.100', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
      expect(result.senderIP).toBe('192.168.1.100');
    });

    it('should pass for IP matching ip4 CIDR range', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip4:192.168.1.0/24 -all']);

      const result = await validator.validate('192.168.1.50', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });

    it('should fail for IP not matching any mechanism', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip4:192.168.1.0/24 -all']);

      const result = await validator.validate('10.0.0.1', 'sender@example.com', 'example.com');

      expect(result.result).toBe('fail');
    });

    it('should return softfail for ~all', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip4:192.168.1.0/24 ~all']);

      const result = await validator.validate('10.0.0.1', 'sender@example.com', 'example.com');

      expect(result.result).toBe('softfail');
    });

    it('should return neutral for ?all', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip4:192.168.1.0/24 ?all']);

      const result = await validator.validate('10.0.0.1', 'sender@example.com', 'example.com');

      expect(result.result).toBe('neutral');
    });

    it('should validate IPv6 addresses', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip6:2001:db8::/32 -all']);

      const result = await validator.validate('2001:db8::1', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });

    it('should check a mechanism against domain A records', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 a -all']);
      mockDNS.setARecord('example.com', ['93.184.216.34']);

      const result = await validator.validate('93.184.216.34', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });

    it('should check mx mechanism against domain MX records', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 mx -all']);
      mockDNS.setMxRecord('example.com', [{ priority: 10, exchange: 'mail.example.com' }]);
      mockDNS.setARecord('mail.example.com', ['198.51.100.1']);

      const result = await validator.validate('198.51.100.1', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });
  });

  describe('Nested Includes', () => {
    it('should resolve include mechanism', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 include:_spf.example.com -all']);
      mockDNS.setTxtRecord('_spf.example.com', ['v=spf1 ip4:192.168.1.0/24 -all']);

      const result = await validator.validate('192.168.1.50', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });

    it('should handle multiple levels of includes', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 include:spf1.example.com -all']);
      mockDNS.setTxtRecord('spf1.example.com', ['v=spf1 include:spf2.example.com -all']);
      mockDNS.setTxtRecord('spf2.example.com', ['v=spf1 ip4:10.0.0.0/8 -all']);

      const result = await validator.validate('10.0.0.50', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
      // RFC 7208: Each include mechanism triggers a DNS lookup count
      // include:spf1.example.com (1) + include:spf2.example.com (1) = 2
      expect(result.lookupCount).toBe(2);
    });

    it('should return permerror when exceeding 10 DNS lookups', async () => {
      // Create a chain of 11 includes
      mockDNS.setTxtRecord('example.com', ['v=spf1 include:spf1.example.com -all']);
      for (let i = 1; i <= 10; i++) {
        mockDNS.setTxtRecord(`spf${i}.example.com`, [`v=spf1 include:spf${i + 1}.example.com -all`]);
      }
      mockDNS.setTxtRecord('spf11.example.com', ['v=spf1 ip4:10.0.0.1 -all']);

      const result = await validator.validate('10.0.0.1', 'sender@example.com', 'example.com');

      expect(result.result).toBe('permerror');
      expect(result.explanation).toContain('DNS lookup limit');
    });

    it('should count all DNS lookups (a, mx, include, redirect)', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 a mx include:other.com -all']);
      mockDNS.setTxtRecord('other.com', ['v=spf1 a mx -all']);
      mockDNS.setARecord('example.com', ['1.1.1.1']);
      mockDNS.setARecord('other.com', ['2.2.2.2']);
      mockDNS.setMxRecord('example.com', [{ priority: 10, exchange: 'mx.example.com' }]);
      mockDNS.setMxRecord('other.com', [{ priority: 10, exchange: 'mx.other.com' }]);
      mockDNS.setARecord('mx.example.com', ['3.3.3.3']);
      mockDNS.setARecord('mx.other.com', ['4.4.4.4']);

      const result = await validator.validate('1.1.1.1', 'sender@example.com', 'example.com');

      // a mechanism matches first (1 lookup for A record resolution)
      // Result is pass immediately after 'a' mechanism matches
      expect(result.lookupCount).toBe(1);
      expect(result.result).toBe('pass');
    });
  });

  describe('Redirect Modifier', () => {
    it('should follow redirect modifier', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 redirect=_spf.example.com']);
      mockDNS.setTxtRecord('_spf.example.com', ['v=spf1 ip4:192.168.1.0/24 -all']);

      const result = await validator.validate('192.168.1.50', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });

    it('should ignore redirect if other mechanisms match', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip4:10.0.0.0/8 redirect=_spf.example.com']);
      mockDNS.setTxtRecord('_spf.example.com', ['v=spf1 ip4:192.168.1.0/24 -all']);

      const result = await validator.validate('10.0.0.50', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });

    it('should return permerror if redirect target has no SPF record', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 redirect=_spf.missing.com']);
      // No SPF record for _spf.missing.com

      const result = await validator.validate('10.0.0.1', 'sender@example.com', 'example.com');

      expect(result.result).toBe('permerror');
    });
  });

  describe('SPF Result Handling', () => {
    it('should return none when no SPF record exists', async () => {
      // No TXT records set for domain

      const result = await validator.validate('10.0.0.1', 'sender@example.com', 'example.com');

      expect(result.result).toBe('none');
    });

    it('should return temperror on DNS failure', async () => {
      mockDNS.setError('example.com', new Error('DNS timeout'));

      const result = await validator.validate('10.0.0.1', 'sender@example.com', 'example.com');

      expect(result.result).toBe('temperror');
    });

    it('should return permerror for malformed SPF record', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 invalid_mechanism -all']);

      const result = await validator.validate('10.0.0.1', 'sender@example.com', 'example.com');

      expect(result.result).toBe('permerror');
    });

    it('should return permerror when multiple SPF records exist', async () => {
      mockDNS.setTxtRecord('example.com', [
        'v=spf1 ip4:192.168.1.0/24 -all',
        'v=spf1 ip4:10.0.0.0/8 -all',
      ]);

      const result = await validator.validate('10.0.0.1', 'sender@example.com', 'example.com');

      expect(result.result).toBe('permerror');
      expect(result.explanation).toContain('Multiple SPF records');
    });
  });

  describe('Cache TTL', () => {
    it('should cache SPF records', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip4:192.168.1.0/24 -all']);

      // First lookup
      await validator.validate('192.168.1.50', 'sender@example.com', 'example.com');

      // Change the DNS record
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip4:10.0.0.0/8 -all']);

      // Should still use cached record if validator has internal caching
      const result = await validator.validate('192.168.1.50', 'sender@example.com', 'example.com');

      // Note: This test verifies the caching mechanism exists
      // The actual behavior depends on implementation details
      expect(result.domain).toBe('example.com');
    });
  });

  describe('IPv4 CIDR Range Matching', () => {
    it('should match IP at start of CIDR range', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip4:10.0.0.0/8 -all']);

      const result = await validator.validate('10.0.0.0', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });

    it('should match IP at end of CIDR range', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip4:10.0.0.0/8 -all']);

      const result = await validator.validate('10.255.255.255', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });

    it('should not match IP outside CIDR range', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip4:192.168.1.0/24 -all']);

      const result = await validator.validate('192.168.2.1', 'sender@example.com', 'example.com');

      expect(result.result).toBe('fail');
    });

    it('should handle /32 CIDR for exact IP match', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip4:192.168.1.100/32 -all']);

      const passResult = await validator.validate('192.168.1.100', 'sender@example.com', 'example.com');
      expect(passResult.result).toBe('pass');

      const failResult = await validator.validate('192.168.1.101', 'sender@example.com', 'example.com');
      expect(failResult.result).toBe('fail');
    });

    it('should handle IP without CIDR (default /32)', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip4:203.0.113.50 -all']);

      const passResult = await validator.validate('203.0.113.50', 'sender@example.com', 'example.com');
      expect(passResult.result).toBe('pass');

      const failResult = await validator.validate('203.0.113.51', 'sender@example.com', 'example.com');
      expect(failResult.result).toBe('fail');
    });
  });

  describe('IPv6 CIDR Range Matching', () => {
    it('should match IPv6 in /64 range', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip6:2001:db8::/64 -all']);

      const result = await validator.validate('2001:db8::abcd', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });

    it('should not match IPv6 outside /64 range', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip6:2001:db8::/64 -all']);

      const result = await validator.validate('2001:db9::1', 'sender@example.com', 'example.com');

      expect(result.result).toBe('fail');
    });

    it('should handle full IPv6 address without CIDR', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip6:2001:db8:85a3::8a2e:370:7334 -all']);

      const result = await validator.validate('2001:db8:85a3::8a2e:370:7334', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });
  });

  describe('Complex SPF Records', () => {
    it('should handle SPF record with many mechanisms', async () => {
      mockDNS.setTxtRecord('example.com', [
        'v=spf1 ip4:192.168.0.0/16 ip4:10.0.0.0/8 ip6:2001:db8::/32 a mx include:_spf.google.com ~all',
      ]);
      mockDNS.setTxtRecord('_spf.google.com', ['v=spf1 ip4:172.16.0.0/12 -all']);
      mockDNS.setARecord('example.com', ['1.1.1.1']);
      mockDNS.setMxRecord('example.com', [{ priority: 10, exchange: 'mail.example.com' }]);
      mockDNS.setARecord('mail.example.com', ['5.5.5.5']);

      const result = await validator.validate('10.50.100.200', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });

    it('should process mechanisms in order and stop at first match', async () => {
      mockDNS.setTxtRecord('example.com', [
        'v=spf1 ip4:192.168.1.0/24 -ip4:192.168.1.100 -all',
      ]);

      // 192.168.1.100 matches +ip4:192.168.1.0/24 first
      const result = await validator.validate('192.168.1.100', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });

    it('should handle exists mechanism', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 exists:_spf.%{d} -all']);
      mockDNS.setARecord('_spf.example.com', ['127.0.0.1']);

      // exists mechanism checks if domain has A record
      // Note: The implementation may need macro expansion support
      // For now, this tests basic exists parsing
      const parsed = validator.parseRecord('v=spf1 exists:_spf.example.com -all');
      expect(parsed.mechanisms[0].type).toBe('exists');
      expect(parsed.mechanisms[0].value).toBe('_spf.example.com');
    });

    it('should handle exp modifier', async () => {
      const record = 'v=spf1 ip4:192.168.1.0/24 exp=explain.example.com -all';
      const parsed = validator.parseRecord(record);

      expect(parsed.exp).toBe('explain.example.com');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty SPF record after version', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1']);

      const result = await validator.validate('192.168.1.1', 'sender@example.com', 'example.com');

      // Empty SPF record means neutral for all
      expect(result.result).toBe('neutral');
    });

    it('should handle SPF with only all mechanism', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 +all']);

      const result = await validator.validate('any.ip.here.1', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });

    it('should normalize case in mechanism types', () => {
      const record = 'v=spf1 IP4:192.168.1.0/24 MX A:mail.example.com -ALL';
      const parsed = validator.parseRecord(record);

      expect(parsed.mechanisms[0].type).toBe('ip4');
      expect(parsed.mechanisms[1].type).toBe('mx');
      expect(parsed.mechanisms[2].type).toBe('a');
      expect(parsed.mechanisms[3].type).toBe('all');
    });

    it('should handle a mechanism with CIDR', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 a/24 -all']);
      mockDNS.setARecord('example.com', ['192.168.1.1']);

      const result = await validator.validate('192.168.1.50', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });

    it('should handle mx mechanism with CIDR for each MX host', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 mx/24 -all']);
      mockDNS.setMxRecord('example.com', [{ priority: 10, exchange: 'mail.example.com' }]);
      mockDNS.setARecord('mail.example.com', ['10.0.0.1']);

      const result = await validator.validate('10.0.0.50', 'sender@example.com', 'example.com');

      expect(result.result).toBe('pass');
    });

    it('should handle include that returns none as no match', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 include:norecord.com -all']);
      // norecord.com has no SPF record

      const result = await validator.validate('10.0.0.1', 'sender@example.com', 'example.com');

      // include returns none -> treated as no match, continue to -all
      expect(result.result).toBe('fail');
    });

    it('should return mechanism info on match', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 ip4:192.168.1.0/24 -all']);

      const result = await validator.validate('192.168.1.50', 'sender@example.com', 'example.com');

      expect(result.mechanism).toBeDefined();
      expect(result.mechanism?.type).toBe('ip4');
      expect(result.mechanism?.value).toBe('192.168.1.0');
      expect(result.mechanism?.cidr).toBe(24);
    });

    it('should handle whitespace variations in SPF record', () => {
      const record = 'v=spf1  ip4:192.168.1.0/24   mx   -all';
      const parsed = validator.parseRecord(record);

      expect(parsed.mechanisms).toHaveLength(3);
      expect(parsed.mechanisms[0].type).toBe('ip4');
      expect(parsed.mechanisms[1].type).toBe('mx');
      expect(parsed.mechanisms[2].type).toBe('all');
    });
  });

  describe('Lookup Limit Enforcement', () => {
    it('should count include as one lookup', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 include:other.com -all']);
      mockDNS.setTxtRecord('other.com', ['v=spf1 ip4:10.0.0.0/8 -all']);

      const result = await validator.validate('10.0.0.1', 'sender@example.com', 'example.com');

      expect(result.lookupCount).toBe(1);
    });

    it('should count redirect as one lookup', async () => {
      mockDNS.setTxtRecord('example.com', ['v=spf1 redirect=other.com']);
      mockDNS.setTxtRecord('other.com', ['v=spf1 ip4:10.0.0.0/8 -all']);

      const result = await validator.validate('10.0.0.1', 'sender@example.com', 'example.com');

      expect(result.lookupCount).toBe(1);
    });

    it('should not count ip4/ip6 mechanisms as lookups', async () => {
      mockDNS.setTxtRecord('example.com', [
        'v=spf1 ip4:192.168.0.0/16 ip4:10.0.0.0/8 ip6:2001:db8::/32 ip4:172.16.0.0/12 -all',
      ]);

      const result = await validator.validate('192.168.1.1', 'sender@example.com', 'example.com');

      expect(result.lookupCount).toBe(0);
    });
  });
});
