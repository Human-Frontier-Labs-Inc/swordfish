/**
 * Security Validation Tests
 *
 * TDD tests for input validation, sanitization, and security controls
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

import {
  validateEmail,
  validateDomain,
  validateUrl,
  sanitizeHtml,
  sanitizeInput,
  validateApiKey,
  validateTenantId,
  validateWebhookPayload,
  escapeForSql,
  validatePagination,
  ValidationError,
} from '@/lib/security/validation';

describe('Input Validation', () => {
  describe('Email Validation', () => {
    it('should accept valid email addresses', () => {
      const validEmails = [
        'user@example.com',
        'user.name@example.com',
        'user+tag@example.com',
        'user@subdomain.example.com',
      ];

      for (const email of validEmails) {
        expect(validateEmail(email)).toBe(true);
      }
    });

    it('should reject invalid email addresses', () => {
      const invalidEmails = [
        'notanemail',
        '@example.com',
        'user@',
        'user@.com',
        'user@example',
        '',
        'user@example..com',
      ];

      for (const email of invalidEmails) {
        expect(validateEmail(email)).toBe(false);
      }
    });

    it('should reject emails with dangerous characters', () => {
      const dangerousEmails = [
        'user<script>@example.com',
        'user"onclick=@example.com',
        "user'OR'1'='1@example.com",
      ];

      for (const email of dangerousEmails) {
        expect(validateEmail(email)).toBe(false);
      }
    });
  });

  describe('Domain Validation', () => {
    it('should accept valid domains', () => {
      const validDomains = [
        'example.com',
        'sub.example.com',
        'example.co.uk',
        'my-domain.com',
      ];

      for (const domain of validDomains) {
        expect(validateDomain(domain)).toBe(true);
      }
    });

    it('should reject invalid domains', () => {
      const invalidDomains = [
        'notadomain',
        '.com',
        'example.',
        '-example.com',
        'example-.com',
        'example..com',
        '',
      ];

      for (const domain of invalidDomains) {
        expect(validateDomain(domain)).toBe(false);
      }
    });
  });

  describe('URL Validation', () => {
    it('should accept valid URLs', () => {
      const validUrls = [
        'https://example.com',
        'http://example.com/path',
        'https://example.com/path?query=value',
        'https://sub.example.com:8080/path',
      ];

      for (const url of validUrls) {
        expect(validateUrl(url)).toBe(true);
      }
    });

    it('should reject dangerous URLs', () => {
      const dangerousUrls = [
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'vbscript:msgbox(1)',
        'file:///etc/passwd',
      ];

      for (const url of dangerousUrls) {
        expect(validateUrl(url)).toBe(false);
      }
    });

    it('should reject URLs with SSRF risk', () => {
      const ssrfUrls = [
        'http://localhost/admin',
        'http://127.0.0.1/internal',
        'http://169.254.169.254/latest/meta-data',
        'http://[::1]/admin',
        'http://0.0.0.0/admin',
      ];

      for (const url of ssrfUrls) {
        expect(validateUrl(url, { blockSSRF: true })).toBe(false);
      }
    });
  });

  describe('API Key Validation', () => {
    it('should validate API key format', () => {
      expect(validateApiKey('sk_live_abc123def456')).toBe(true);
      expect(validateApiKey('sk_test_abc123def456')).toBe(true);
      expect(validateApiKey('pk_live_abc123def456')).toBe(true);
    });

    it('should reject invalid API key formats', () => {
      expect(validateApiKey('invalid')).toBe(false);
      expect(validateApiKey('')).toBe(false);
      expect(validateApiKey('sk_')).toBe(false);
      expect(validateApiKey('abc123')).toBe(false);
    });
  });

  describe('Tenant ID Validation', () => {
    it('should accept valid tenant IDs', () => {
      expect(validateTenantId('tenant_abc123')).toBe(true);
      expect(validateTenantId('org_def456')).toBe(true);
      expect(validateTenantId('user_xyz789')).toBe(true);
    });

    it('should reject invalid tenant IDs', () => {
      expect(validateTenantId('')).toBe(false);
      expect(validateTenantId('invalid')).toBe(false);
      expect(validateTenantId('../etc/passwd')).toBe(false);
      expect(validateTenantId('tenant_<script>')).toBe(false);
    });
  });

  describe('Pagination Validation', () => {
    it('should validate pagination parameters', () => {
      expect(validatePagination({ page: 1, limit: 10 })).toEqual({ page: 1, limit: 10 });
      expect(validatePagination({ page: 5, limit: 50 })).toEqual({ page: 5, limit: 50 });
    });

    it('should enforce minimum values', () => {
      expect(validatePagination({ page: 0, limit: 0 })).toEqual({ page: 1, limit: 1 });
      expect(validatePagination({ page: -1, limit: -5 })).toEqual({ page: 1, limit: 1 });
    });

    it('should enforce maximum limit', () => {
      expect(validatePagination({ page: 1, limit: 1000 })).toEqual({ page: 1, limit: 100 });
    });
  });
});

describe('Input Sanitization', () => {
  describe('HTML Sanitization', () => {
    it('should remove script tags', () => {
      const input = '<p>Hello</p><script>alert(1)</script><p>World</p>';
      const sanitized = sanitizeHtml(input);

      expect(sanitized).not.toContain('<script>');
      expect(sanitized).not.toContain('alert');
      expect(sanitized).toContain('<p>Hello</p>');
    });

    it('should remove event handlers', () => {
      const input = '<img src="x" onerror="alert(1)">';
      const sanitized = sanitizeHtml(input);

      expect(sanitized).not.toContain('onerror');
      expect(sanitized).not.toContain('alert');
    });

    it('should remove javascript: URLs', () => {
      const input = '<a href="javascript:alert(1)">Click</a>';
      const sanitized = sanitizeHtml(input);

      expect(sanitized).not.toContain('javascript:');
    });

    it('should preserve safe HTML elements', () => {
      const input = '<p><strong>Bold</strong> and <em>italic</em></p>';
      const sanitized = sanitizeHtml(input);

      expect(sanitized).toContain('<p>');
      expect(sanitized).toContain('<strong>');
      expect(sanitized).toContain('<em>');
    });

    it('should handle encoded XSS attempts', () => {
      const inputs = [
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '&#60;script&#62;alert(1)&#60;/script&#62;',
      ];

      for (const input of inputs) {
        const sanitized = sanitizeHtml(input, { decodeEntities: true });
        expect(sanitized).not.toContain('<script>');
      }
    });
  });

  describe('General Input Sanitization', () => {
    it('should trim whitespace', () => {
      expect(sanitizeInput('  hello  ')).toBe('hello');
    });

    it('should remove null bytes', () => {
      expect(sanitizeInput('hello\x00world')).toBe('helloworld');
    });

    it('should limit string length', () => {
      const long = 'a'.repeat(10000);
      expect(sanitizeInput(long, { maxLength: 100 }).length).toBe(100);
    });

    it('should handle array inputs', () => {
      const input = ['  hello  ', '  world  '];
      expect(sanitizeInput(input)).toEqual(['hello', 'world']);
    });

    it('should handle object inputs', () => {
      const input = { name: '  John  ', email: '  john@example.com  ' };
      expect(sanitizeInput(input)).toEqual({ name: 'John', email: 'john@example.com' });
    });
  });

  describe('SQL Escape', () => {
    it('should escape SQL injection attempts', () => {
      const attacks = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "admin'--",
        "1; DELETE FROM emails;",
      ];

      for (const attack of attacks) {
        const escaped = escapeForSql(attack);
        expect(escaped).not.toContain("'");
        expect(escaped).not.toContain(';');
        expect(escaped).not.toContain('--');
      }
    });
  });
});

describe('Webhook Payload Validation', () => {
  it('should validate O365 webhook payload structure', () => {
    const validPayload = {
      value: [{
        subscriptionId: 'sub-123',
        clientState: 'secretToken',
        changeType: 'created',
        resource: 'messages/msg-123',
        tenantId: 'tenant-123',
      }],
    };

    expect(validateWebhookPayload(validPayload, 'o365')).toBe(true);
  });

  it('should validate Gmail webhook payload structure', () => {
    const validPayload = {
      message: {
        data: 'base64data',
        messageId: 'msg-123',
      },
      subscription: 'projects/xxx/subscriptions/gmail',
    };

    expect(validateWebhookPayload(validPayload, 'gmail')).toBe(true);
  });

  it('should reject malformed payloads', () => {
    const invalidPayloads = [
      null,
      undefined,
      {},
      { random: 'data' },
      { value: 'not an array' },
    ];

    for (const payload of invalidPayloads) {
      expect(validateWebhookPayload(payload as any, 'o365')).toBe(false);
    }
  });

  it('should reject payloads exceeding size limit', () => {
    const largePayload = {
      value: new Array(1000).fill({
        subscriptionId: 'a'.repeat(1000),
      }),
    };

    expect(() => validateWebhookPayload(largePayload, 'o365', { maxSize: 1000 }))
      .toThrow(ValidationError);
  });
});

describe('Validation Errors', () => {
  it('should throw ValidationError with details', () => {
    try {
      throw new ValidationError('Invalid input', {
        field: 'email',
        value: 'invalid',
        constraint: 'email_format',
      });
    } catch (error) {
      expect(error).toBeInstanceOf(ValidationError);
      expect((error as ValidationError).details.field).toBe('email');
    }
  });

  it('should serialize validation errors', () => {
    const error = new ValidationError('Invalid input', {
      field: 'email',
      value: 'invalid',
    });

    const serialized = error.toJSON();

    expect(serialized.message).toBe('Invalid input');
    expect(serialized.details.field).toBe('email');
  });
});
