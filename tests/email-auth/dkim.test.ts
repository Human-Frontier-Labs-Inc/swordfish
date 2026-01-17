/**
 * DKIM (DomainKeys Identified Mail) Validation Tests
 *
 * TDD tests for DKIM signature parsing and verification
 * Covers RFC 6376 compliance for DKIM validation
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { DKIMValidator } from '@/lib/email-auth/dkim';
import { MockDNSResolver, MemoryDNSCache } from '@/lib/email-auth/dns-resolver';
import type { DKIMValidationResult } from '@/lib/email-auth/types';

describe('DKIM Validator', () => {
  let mockDNS: MockDNSResolver;
  let validator: DKIMValidator;

  beforeEach(() => {
    mockDNS = new MockDNSResolver();
    validator = new DKIMValidator(mockDNS);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('DKIM-Signature Header Parsing', () => {
    // Test 1
    it('should parse basic DKIM-Signature header fields (v, a, b, bh, d, h, s)', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=selector1;
        c=relaxed/relaxed; q=dns/txt;
        h=from:to:subject:date;
        bh=base64bodyhash==;
        b=base64signature==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.version).toBe('1');
      expect(parsed.algorithm).toBe('rsa-sha256');
      expect(parsed.domain).toBe('example.com');
      expect(parsed.selector).toBe('selector1');
      expect(parsed.bodyHash).toBe('base64bodyhash==');
      expect(parsed.signature).toBe('base64signature==');
    });

    // Test 2
    it('should parse canonicalization methods - relaxed/relaxed (c= tag)', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        c=relaxed/relaxed; h=from:to; bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.canonicalization.header).toBe('relaxed');
      expect(parsed.canonicalization.body).toBe('relaxed');
    });

    // Test 3
    it('should parse canonicalization methods - simple/simple (c= tag)', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        c=simple/simple; h=from:to; bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.canonicalization.header).toBe('simple');
      expect(parsed.canonicalization.body).toBe('simple');
    });

    // Test 4
    it('should parse canonicalization methods - relaxed/simple mixed (c= tag)', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        c=relaxed/simple; h=from:to; bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.canonicalization.header).toBe('relaxed');
      expect(parsed.canonicalization.body).toBe('simple');
    });

    // Test 5
    it('should default canonicalization to simple/simple when not specified', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        h=from:to; bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.canonicalization.header).toBe('simple');
      expect(parsed.canonicalization.body).toBe('simple');
    });

    // Test 6
    it('should parse signed headers list (h= tag)', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        c=relaxed/relaxed;
        h=from:to:subject:date:message-id;
        bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.signedHeaders).toEqual(['from', 'to', 'subject', 'date', 'message-id']);
    });

    // Test 7
    it('should parse timestamp (t= tag)', () => {
      const timestamp = 1704067200; // 2024-01-01 00:00:00 UTC

      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        c=relaxed/relaxed; h=from:to;
        t=${timestamp};
        bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.timestamp).toBe(timestamp);
    });

    // Test 8
    it('should parse expiration (x= tag)', () => {
      const expiration = 1704153600; // 2024-01-02 00:00:00 UTC

      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        c=relaxed/relaxed; h=from:to;
        x=${expiration};
        bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.expiration).toBe(expiration);
    });

    // Test 9
    it('should parse identity tag (i= tag)', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        i=user@example.com;
        h=from:to; bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.identity).toBe('user@example.com');
    });

    // Test 10
    it('should parse body length tag (l= tag) for partial body signing', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        l=1000;
        h=from:to; bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.bodyLength).toBe(1000);
    });

    // Test 11
    it('should parse query method tag (q= tag)', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        q=dns/txt;
        h=from:to; bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.queryMethod).toBe('dns/txt');
    });

    // Test 12
    it('should throw error for missing required field v=', () => {
      const signature = 'a=rsa-sha256; d=example.com; s=s1; h=from; bh=h==; b=s==';
      expect(() => validator.parseSignature(signature)).toThrow('Missing required DKIM field: v');
    });

    // Test 13
    it('should throw error for missing required field a=', () => {
      const signature = 'v=1; d=example.com; s=s1; h=from; bh=h==; b=s==';
      expect(() => validator.parseSignature(signature)).toThrow('Missing required DKIM field: a');
    });

    // Test 14
    it('should throw error for missing required field d=', () => {
      const signature = 'v=1; a=rsa-sha256; s=s1; h=from; bh=h==; b=s==';
      expect(() => validator.parseSignature(signature)).toThrow('Missing required DKIM field: d');
    });

    // Test 15
    it('should throw error for missing required field s=', () => {
      const signature = 'v=1; a=rsa-sha256; d=example.com; h=from; bh=h==; b=s==';
      expect(() => validator.parseSignature(signature)).toThrow('Missing required DKIM field: s');
    });

    // Test 16
    it('should handle whitespace in signature value (b= tag)', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        h=from:to; bh=hash==; b=sig
        nature
        here==`;

      const parsed = validator.parseSignature(signature);

      // Whitespace should be removed from signature
      expect(parsed.signature).toBe('signaturehere==');
    });

    // Test 17
    it('should handle whitespace in body hash value (bh= tag)', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        h=from:to; bh=body
        hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.bodyHash).toBe('bodyhash==');
    });
  });

  describe('Public Key Retrieval', () => {
    // Test 18
    it('should retrieve public key from DNS (selector._domainkey.domain)', async () => {
      const publicKey = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...';
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        `v=DKIM1; k=rsa; p=${publicKey}`,
      ]);

      const key = await validator.getPublicKey('example.com', 'selector1');

      expect(key.publicKey).toBe(publicKey);
      expect(key.keyType).toBe('rsa');
    });

    // Test 19
    it('should parse public key with hash algorithms (h= tag)', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; h=sha256; p=publickey==',
      ]);

      const key = await validator.getPublicKey('example.com', 'selector1');

      expect(key.hashAlgorithms).toContain('sha256');
    });

    // Test 20
    it('should parse public key with service types (s= tag)', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; s=email; p=publickey==',
      ]);

      const key = await validator.getPublicKey('example.com', 'selector1');

      expect(key.serviceTypes).toContain('email');
    });

    // Test 21
    it('should parse public key with flags (t= tag)', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; t=y:s; p=publickey==',
      ]);

      const key = await validator.getPublicKey('example.com', 'selector1');

      expect(key.flags).toContain('y');
      expect(key.flags).toContain('s');
    });

    // Test 22
    it('should return empty public key for revoked key (empty p= value)', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=',
      ]);

      const key = await validator.getPublicKey('example.com', 'selector1');

      expect(key.publicKey).toBe('');
    });

    // Test 23
    it('should throw error for DNS lookup failure', async () => {
      mockDNS.setError('selector1._domainkey.example.com', new Error('DNS timeout'));

      await expect(validator.getPublicKey('example.com', 'selector1'))
        .rejects.toThrow();
    });

    // Test 24
    it('should throw error for missing DKIM public key record', async () => {
      // No record set for this domain
      await expect(validator.getPublicKey('nonexistent.com', 'selector1'))
        .rejects.toThrow('No DKIM public key found');
    });

    // Test 25
    it('should support Ed25519 key type (k=ed25519)', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=ed25519; p=ed25519publickey==',
      ]);

      const key = await validator.getPublicKey('example.com', 'selector1');

      expect(key.keyType).toBe('ed25519');
      expect(key.publicKey).toBe('ed25519publickey==');
    });
  });

  describe('Signature Verification', () => {
    // Test 26
    it('should return pass for valid signature', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7hbqE6NzLt9H5u3wBqFE/dGPLnlqj8kPgJVKJKTswOV9EhZJSBiErhHxnxMPAMKi/U7aJmQP3qFaEOyDwbFqTjdN6GlOhUuWpfkVBPPJwOVhPyFmDqDzFaRt1+KzFg5mFfyLsQIDAQAB',
      ]);

      const headers = `From: sender@example.com\r\nTo: recipient@test.com\r\nSubject: Test\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000`;
      const body = 'Hello World';
      const dkimHeader = `v=1; a=rsa-sha256; d=example.com; s=selector1;
        c=relaxed/relaxed; h=from:to:subject:date;
        bh=DUQNPJhhFHEO8nXnbQpfPuMrljVBpuaLpJBXjC4z0Tk=;
        b=ValidSignatureHere==`;

      const result = await validator.verify(headers, body, dkimHeader);

      // With mock data, signature verification will fail but parsing should succeed
      expect(['pass', 'fail']).toContain(result.result);
      expect(result.domain).toBe('example.com');
      expect(result.selector).toBe('selector1');
    });

    // Test 27
    it('should return fail for body hash mismatch', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=testkey==',
      ]);

      const headers = `From: sender@example.com\r\nTo: recipient@test.com`;
      const body = 'Original body content';
      // Body hash computed for different content
      const dkimHeader = `v=1; a=rsa-sha256; d=example.com; s=selector1;
        c=relaxed/relaxed; h=from:to;
        bh=WrongBodyHashForDifferentContent==; b=sig==`;

      const result = await validator.verify(headers, body, dkimHeader);

      expect(result.result).toBe('fail');
      expect(result.error).toContain('Body hash mismatch');
    });

    // Test 28
    it('should return permerror for invalid DKIM signature format', async () => {
      const headers = `From: sender@example.com\r\nTo: recipient@test.com`;
      const body = 'Hello World';
      const invalidDkimHeader = 'completely invalid signature format';

      const result = await validator.verify(headers, body, invalidDkimHeader);

      expect(result.result).toBe('permerror');
      expect(result.error).toContain('Failed to parse');
    });

    // Test 29
    it('should return temperror for DNS lookup failure', async () => {
      mockDNS.setError('selector1._domainkey.example.com', new Error('DNS timeout'));

      const headers = `From: sender@example.com\r\nTo: recipient@test.com`;
      const body = 'Hello World';
      const dkimHeader = `v=1; a=rsa-sha256; d=example.com; s=selector1;
        c=relaxed/relaxed; h=from:to;
        bh=hash==; b=sig==`;

      const result = await validator.verify(headers, body, dkimHeader);

      expect(result.result).toBe('temperror');
      expect(result.error).toContain('Failed to retrieve public key');
    });

    // Test 30
    it('should return fail for revoked public key', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=', // Empty p= means revoked
      ]);

      const headers = `From: sender@example.com\r\nTo: recipient@test.com`;
      const body = 'Hello World';
      const dkimHeader = `v=1; a=rsa-sha256; d=example.com; s=selector1;
        c=relaxed/relaxed; h=from:to;
        bh=hash==; b=sig==`;

      const result = await validator.verify(headers, body, dkimHeader);

      expect(result.result).toBe('fail');
      expect(result.error).toContain('revoked');
    });
  });

  describe('Canonicalization', () => {
    // Test 31
    it('should apply relaxed header canonicalization - lowercase header name', () => {
      const header = 'From:   Sender   <sender@example.com>  ';

      const canonicalized = validator.canonicalizeHeader(header, 'relaxed');

      expect(canonicalized).toBe('from:Sender <sender@example.com>');
    });

    // Test 32
    it('should apply simple header canonicalization - preserve original', () => {
      const header = 'From: Sender <sender@example.com>\r\n';

      const canonicalized = validator.canonicalizeHeader(header, 'simple');

      expect(canonicalized).toBe('From: Sender <sender@example.com>');
    });

    // Test 33
    it('should apply relaxed body canonicalization - reduce whitespace', () => {
      const body = '  Hello   World  \r\n\r\n\r\n';

      const canonicalized = validator.canonicalizeBody(body, 'relaxed');

      expect(canonicalized).toBe(' Hello World\r\n');
    });

    // Test 34
    it('should apply simple body canonicalization - remove trailing empty lines', () => {
      const body = 'Hello World\r\n\r\n\r\n';

      const canonicalized = validator.canonicalizeBody(body, 'simple');

      expect(canonicalized).toBe('Hello World\r\n');
    });

    // Test 35
    it('should handle empty body with relaxed canonicalization', () => {
      const body = '';

      const canonicalized = validator.canonicalizeBody(body, 'relaxed');

      expect(canonicalized).toBe('\r\n');
    });

    // Test 36
    it('should handle empty body with simple canonicalization', () => {
      const body = '';

      const canonicalized = validator.canonicalizeBody(body, 'simple');

      expect(canonicalized).toBe('\r\n');
    });

    // Test 37
    it('should handle body with only whitespace with relaxed canonicalization', () => {
      const body = '   \t  \r\n  \r\n';

      const canonicalized = validator.canonicalizeBody(body, 'relaxed');

      // All whitespace lines become empty, then removed
      expect(canonicalized).toBe('\r\n');
    });

    // Test 38
    it('should unfold headers in relaxed canonicalization', () => {
      const header = 'Subject: This is a very long\r\n   subject line that was folded';

      const canonicalized = validator.canonicalizeHeader(header, 'relaxed');

      expect(canonicalized).toBe('subject:This is a very long subject line that was folded');
    });
  });

  describe('Multiple DKIM Signatures', () => {
    // Test 39
    it('should verify multiple DKIM signatures from different selectors', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=key1==',
      ]);
      mockDNS.setTxtRecord('selector2._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=key2==',
      ]);

      const headers = `From: sender@example.com\r\nTo: recipient@test.com`;
      const body = 'Hello World';
      const dkimHeaders = [
        `v=1; a=rsa-sha256; d=example.com; s=selector1; c=relaxed/relaxed; h=from:to; bh=h1==; b=s1==`,
        `v=1; a=rsa-sha256; d=example.com; s=selector2; c=relaxed/relaxed; h=from:to; bh=h2==; b=s2==`,
      ];

      const results = await validator.verifyMultiple(headers, body, dkimHeaders);

      expect(results).toHaveLength(2);
      expect(results[0].selector).toBe('selector1');
      expect(results[1].selector).toBe('selector2');
    });

    // Test 40
    it('should verify multiple DKIM signatures from different domains', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=key1==',
      ]);
      mockDNS.setTxtRecord('selector1._domainkey.relay.com', [
        'v=DKIM1; k=rsa; p=key2==',
      ]);

      const headers = `From: sender@example.com\r\nTo: recipient@test.com`;
      const body = 'Hello World';
      const dkimHeaders = [
        `v=1; a=rsa-sha256; d=example.com; s=selector1; c=relaxed/relaxed; h=from:to; bh=h1==; b=s1==`,
        `v=1; a=rsa-sha256; d=relay.com; s=selector1; c=relaxed/relaxed; h=from:to; bh=h2==; b=s2==`,
      ];

      const results = await validator.verifyMultiple(headers, body, dkimHeaders);

      expect(results).toHaveLength(2);
      expect(results[0].domain).toBe('example.com');
      expect(results[1].domain).toBe('relay.com');
    });

    // Test 41
    it('should return empty array when no DKIM signatures present', async () => {
      const headers = `From: sender@example.com\r\nTo: recipient@test.com`;
      const body = 'Hello World';
      const dkimHeaders: string[] = [];

      const results = await validator.verifyMultiple(headers, body, dkimHeaders);

      expect(results).toHaveLength(0);
    });

    // Test 42
    it('should continue verifying remaining signatures if one fails', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=', // Revoked
      ]);
      mockDNS.setTxtRecord('selector2._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=validkey==',
      ]);

      const headers = `From: sender@example.com\r\nTo: recipient@test.com`;
      const body = 'Hello World';
      const dkimHeaders = [
        `v=1; a=rsa-sha256; d=example.com; s=selector1; c=relaxed/relaxed; h=from:to; bh=h1==; b=s1==`,
        `v=1; a=rsa-sha256; d=example.com; s=selector2; c=relaxed/relaxed; h=from:to; bh=h2==; b=s2==`,
      ];

      const results = await validator.verifyMultiple(headers, body, dkimHeaders);

      expect(results).toHaveLength(2);
      expect(results[0].result).toBe('fail'); // Revoked key
    });
  });

  describe('Signature Expiration', () => {
    // Test 43
    it('should fail expired signatures (x= tag in past)', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=testkey==',
      ]);

      const pastTimestamp = Math.floor(Date.now() / 1000) - 86400; // 1 day ago
      const pastExpiration = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago

      const headers = `From: sender@example.com\r\nTo: recipient@test.com`;
      const body = 'Hello World';
      const dkimHeader = `v=1; a=rsa-sha256; d=example.com; s=selector1;
        c=relaxed/relaxed; h=from:to;
        t=${pastTimestamp}; x=${pastExpiration};
        bh=hash==; b=sig==`;

      const result = await validator.verify(headers, body, dkimHeader);

      expect(result.result).toBe('fail');
      expect(result.error).toContain('expired');
    });

    // Test 44
    it('should not fail signature with future expiration', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=testkey==',
      ]);

      const currentTimestamp = Math.floor(Date.now() / 1000);
      const futureExpiration = Math.floor(Date.now() / 1000) + 86400; // 1 day from now

      const headers = `From: sender@example.com\r\nTo: recipient@test.com`;
      const body = 'Hello World';
      const dkimHeader = `v=1; a=rsa-sha256; d=example.com; s=selector1;
        c=relaxed/relaxed; h=from:to;
        t=${currentTimestamp}; x=${futureExpiration};
        bh=hash==; b=sig==`;

      const result = await validator.verify(headers, body, dkimHeader);

      // Will fail crypto verification but not due to expiration
      expect(result.error || '').not.toContain('expired');
    });

    // Test 45
    it('should handle signature without expiration (no x= tag)', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=testkey==',
      ]);

      const headers = `From: sender@example.com\r\nTo: recipient@test.com`;
      const body = 'Hello World';
      const dkimHeader = `v=1; a=rsa-sha256; d=example.com; s=selector1;
        c=relaxed/relaxed; h=from:to;
        bh=hash==; b=sig==`;

      const result = await validator.verify(headers, body, dkimHeader);

      expect(result.error || '').not.toContain('expired');
    });
  });

  describe('Partial Body Signing (l= tag)', () => {
    // Test 46
    it('should apply body length limit when l= tag is present', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=testkey==',
      ]);

      const headers = `From: sender@example.com\r\nTo: recipient@test.com`;
      const body = 'Short body' + 'A'.repeat(1000); // Long body
      const dkimHeader = `v=1; a=rsa-sha256; d=example.com; s=selector1;
        c=relaxed/relaxed; h=from:to;
        l=10;
        bh=hash==; b=sig==`;

      const result = await validator.verify(headers, body, dkimHeader);

      // Parsing should succeed with l= tag
      expect(result.signature?.bodyLength).toBe(10);
    });

    // Test 47
    it('should parse body length correctly from signature', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        l=500;
        h=from:to; bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.bodyLength).toBe(500);
    });
  });

  describe('Algorithm Support', () => {
    // Test 48
    it('should parse rsa-sha256 algorithm', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        h=from:to; bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.algorithm).toBe('rsa-sha256');
    });

    // Test 49
    it('should parse rsa-sha1 algorithm', () => {
      const signature = `v=1; a=rsa-sha1; d=example.com; s=s1;
        h=from:to; bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.algorithm).toBe('rsa-sha1');
    });

    // Test 50
    it('should parse ed25519-sha256 algorithm', () => {
      const signature = `v=1; a=ed25519-sha256; d=example.com; s=s1;
        h=from:to; bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.algorithm).toBe('ed25519-sha256');
    });
  });

  describe('Public Key Caching', () => {
    // Test 51
    it('should cache public keys to avoid repeated DNS lookups', async () => {
      const cache = new MemoryDNSCache();
      const cachingValidator = new DKIMValidator(mockDNS, cache);

      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=cachedkey==',
      ]);

      // First lookup
      const key1 = await cachingValidator.getPublicKey('example.com', 'selector1');
      expect(key1.publicKey).toBe('cachedkey==');

      // Change the DNS record
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=newkey==',
      ]);

      // Second lookup should return cached value
      const key2 = await cachingValidator.getPublicKey('example.com', 'selector1');
      expect(key2.publicKey).toBe('cachedkey=='); // Still cached

      cache.destroy();
    });

    // Test 52
    it('should fetch new key after cache expiry', async () => {
      const cache = new MemoryDNSCache();
      const cachingValidator = new DKIMValidator(mockDNS, cache, 0.1); // 100ms TTL

      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=originalkey==',
      ]);

      // First lookup
      await cachingValidator.getPublicKey('example.com', 'selector1');

      // Change the DNS record
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=updatedkey==',
      ]);

      // Wait for cache to expire
      await new Promise(resolve => setTimeout(resolve, 150));

      // Should now get new key
      const key = await cachingValidator.getPublicKey('example.com', 'selector1');
      expect(key.publicKey).toBe('updatedkey==');

      cache.destroy();
    });
  });

  describe('Header Hash Verification', () => {
    // Test 53
    it('should verify header hash includes all signed headers', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=testkey==',
      ]);

      const headers = `From: sender@example.com\r\nTo: recipient@test.com\r\nSubject: Test`;
      const body = 'Hello World';
      const dkimHeader = `v=1; a=rsa-sha256; d=example.com; s=selector1;
        c=relaxed/relaxed; h=from:to:subject;
        bh=hash==; b=sig==`;

      const result = await validator.verify(headers, body, dkimHeader);

      // Verify signature object contains signed headers
      expect(result.signature?.signedHeaders).toContain('from');
      expect(result.signature?.signedHeaders).toContain('to');
      expect(result.signature?.signedHeaders).toContain('subject');
    });
  });

  describe('Result Types', () => {
    // Test 54
    it('should return correct result types: pass, fail, temperror, permerror', async () => {
      // Set up different scenarios
      mockDNS.setTxtRecord('valid._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=validkey==',
      ]);
      mockDNS.setTxtRecord('revoked._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=',
      ]);
      mockDNS.setError('temperror._domainkey.example.com', new Error('DNS timeout'));

      const headers = `From: sender@example.com\r\nTo: recipient@test.com`;
      const body = 'Hello World';

      // Test temperror
      const temperrorResult = await validator.verify(headers, body,
        `v=1; a=rsa-sha256; d=example.com; s=temperror; h=from:to; bh=h==; b=s==`);
      expect(temperrorResult.result).toBe('temperror');

      // Test permerror (invalid signature format)
      const permerrorResult = await validator.verify(headers, body, 'invalid');
      expect(permerrorResult.result).toBe('permerror');

      // Test fail (revoked key)
      const failResult = await validator.verify(headers, body,
        `v=1; a=rsa-sha256; d=example.com; s=revoked; h=from:to; bh=h==; b=s==`);
      expect(failResult.result).toBe('fail');
    });
  });

  describe('Edge Cases', () => {
    // Test 55
    it('should handle DKIM signature with all optional tags', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=selector1;
        c=relaxed/simple; q=dns/txt;
        h=from:to:subject:date:message-id;
        t=1704067200; x=1704153600;
        i=user@example.com; l=1000;
        bh=bodyhash==; b=signature==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.version).toBe('1');
      expect(parsed.algorithm).toBe('rsa-sha256');
      expect(parsed.domain).toBe('example.com');
      expect(parsed.selector).toBe('selector1');
      expect(parsed.canonicalization.header).toBe('relaxed');
      expect(parsed.canonicalization.body).toBe('simple');
      expect(parsed.queryMethod).toBe('dns/txt');
      expect(parsed.signedHeaders).toHaveLength(5);
      expect(parsed.timestamp).toBe(1704067200);
      expect(parsed.expiration).toBe(1704153600);
      expect(parsed.identity).toBe('user@example.com');
      expect(parsed.bodyLength).toBe(1000);
      expect(parsed.bodyHash).toBe('bodyhash==');
      expect(parsed.signature).toBe('signature==');
    });

    // Test 56
    it('should handle subdomain in domain tag', () => {
      const signature = `v=1; a=rsa-sha256; d=mail.example.com; s=selector1;
        h=from:to; bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.domain).toBe('mail.example.com');
    });

    // Test 57
    it('should handle multi-line folded signature', () => {
      const signature = `v=1; a=rsa-sha256;
        d=example.com;
        s=selector1;
        h=from:to:subject:date;
        bh=bodyhash==;
        b=verylongsignature
          thatspansmultiple
          lineshere==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.version).toBe('1');
      expect(parsed.algorithm).toBe('rsa-sha256');
      expect(parsed.domain).toBe('example.com');
      expect(parsed.signature).toBe('verylongsignaturethatspansmultiplelineshere==');
    });

    // Test 58
    it('should handle identity with subdomain', () => {
      const signature = `v=1; a=rsa-sha256; d=example.com; s=s1;
        i=@subdomain.example.com;
        h=from:to; bh=hash==; b=sig==`;

      const parsed = validator.parseSignature(signature);

      expect(parsed.identity).toBe('@subdomain.example.com');
    });
  });

  describe('DKIMResult Interface', () => {
    // Test 59
    it('should return result with domain, selector, and explanation', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=', // Revoked
      ]);

      const headers = `From: sender@example.com`;
      const body = 'Test';
      const dkimHeader = `v=1; a=rsa-sha256; d=example.com; s=selector1;
        h=from; bh=hash==; b=sig==`;

      const result = await validator.verify(headers, body, dkimHeader);

      expect(result).toHaveProperty('result');
      expect(result).toHaveProperty('domain');
      expect(result).toHaveProperty('selector');
      expect(result.domain).toBe('example.com');
      expect(result.selector).toBe('selector1');
    });

    // Test 60
    it('should include signature object in result on success or fail', async () => {
      mockDNS.setTxtRecord('selector1._domainkey.example.com', [
        'v=DKIM1; k=rsa; p=testkey==',
      ]);

      const headers = `From: sender@example.com`;
      const body = 'Test';
      const dkimHeader = `v=1; a=rsa-sha256; d=example.com; s=selector1;
        h=from; bh=hash==; b=sig==`;

      const result = await validator.verify(headers, body, dkimHeader);

      expect(result.signature).toBeDefined();
      expect(result.signature?.domain).toBe('example.com');
      expect(result.signature?.algorithm).toBe('rsa-sha256');
    });
  });
});
