/**
 * Security Test Suite
 * TDD: RED phase - Write failing tests first
 *
 * Comprehensive security testing including OWASP Top 10 checks,
 * input validation, authentication, and authorization tests.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  SecurityScanner,
  SecurityConfig,
  VulnerabilityReport,
  SecurityCheck,
  SecuritySeverity,
  InputValidator,
  ValidationResult,
  AuthenticationTester,
  AuthorizationTester,
  RateLimitTester,
  CsrfProtectionTester,
  XssSanitizer,
} from '../../lib/security/security-suite';

describe('Security Test Suite', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('SecurityScanner', () => {
    let scanner: SecurityScanner;

    beforeEach(() => {
      scanner = new SecurityScanner({
        strictMode: true,
        enableAllChecks: true,
      });
    });

    it('should accept security scanner configuration', () => {
      const config: SecurityConfig = {
        strictMode: true,
        enableAllChecks: true,
        customChecks: [],
      };

      scanner = new SecurityScanner(config);
      expect(scanner.getConfig()).toEqual(config);
    });

    it('should register custom security checks', () => {
      const customCheck: SecurityCheck = {
        name: 'custom-header-check',
        description: 'Check for custom security header',
        severity: SecuritySeverity.MEDIUM,
        check: vi.fn().mockResolvedValue({ passed: true }),
      };

      scanner.registerCheck(customCheck);

      const checks = scanner.getRegisteredChecks();
      expect(checks.some(c => c.name === 'custom-header-check')).toBe(true);
    });

    it('should run all security checks', async () => {
      const check1 = {
        name: 'check-1',
        description: 'Test check 1',
        severity: SecuritySeverity.HIGH,
        check: vi.fn().mockResolvedValue({ passed: true }),
      };

      const check2 = {
        name: 'check-2',
        description: 'Test check 2',
        severity: SecuritySeverity.MEDIUM,
        check: vi.fn().mockResolvedValue({ passed: false, message: 'Failed' }),
      };

      scanner.registerCheck(check1);
      scanner.registerCheck(check2);

      const report = await scanner.scan({});

      expect(check1.check).toHaveBeenCalled();
      expect(check2.check).toHaveBeenCalled();
      expect(report.vulnerabilities.length).toBeGreaterThan(0);
    });

    it('should categorize vulnerabilities by severity', async () => {
      scanner.registerCheck({
        name: 'critical-check',
        description: 'Critical vulnerability',
        severity: SecuritySeverity.CRITICAL,
        check: vi.fn().mockResolvedValue({ passed: false }),
      });

      scanner.registerCheck({
        name: 'low-check',
        description: 'Low vulnerability',
        severity: SecuritySeverity.LOW,
        check: vi.fn().mockResolvedValue({ passed: false }),
      });

      const report = await scanner.scan({});

      expect(report.bySeverity[SecuritySeverity.CRITICAL]).toBe(1);
      expect(report.bySeverity[SecuritySeverity.LOW]).toBe(1);
    });

    it('should generate security score', async () => {
      scanner.registerCheck({
        name: 'passing-check',
        description: 'Passes',
        severity: SecuritySeverity.HIGH,
        check: vi.fn().mockResolvedValue({ passed: true }),
      });

      scanner.registerCheck({
        name: 'failing-check',
        description: 'Fails',
        severity: SecuritySeverity.LOW,
        check: vi.fn().mockResolvedValue({ passed: false }),
      });

      const report = await scanner.scan({});

      // Score should be between 0 and 100
      expect(report.score).toBeGreaterThanOrEqual(0);
      expect(report.score).toBeLessThanOrEqual(100);
      expect(report.score).toBeGreaterThan(50); // High severity passed, only low failed
    });
  });

  describe('InputValidator', () => {
    let validator: InputValidator;

    beforeEach(() => {
      validator = new InputValidator();
    });

    describe('SQL Injection', () => {
      it('should detect SQL injection attempts', () => {
        const maliciousInputs = [
          "' OR '1'='1",
          "'; DROP TABLE users; --",
          "1; SELECT * FROM passwords",
          "admin'--",
          "1' UNION SELECT * FROM users--",
        ];

        for (const input of maliciousInputs) {
          const result = validator.validateInput(input, { checkSqlInjection: true });
          expect(result.isValid).toBe(false);
          expect(result.threats).toContain('sql_injection');
        }
      });

      it('should allow safe SQL-like strings', () => {
        const safeInputs = [
          'John O\'Brien',
          'SELECT a product',
          'user@email.com',
        ];

        for (const input of safeInputs) {
          const result = validator.validateInput(input, { checkSqlInjection: true });
          expect(result.isValid).toBe(true);
        }
      });
    });

    describe('XSS Prevention', () => {
      it('should detect XSS attempts', () => {
        const maliciousInputs = [
          '<script>alert("XSS")</script>',
          '<img src=x onerror=alert(1)>',
          'javascript:alert(1)',
          '<svg onload=alert(1)>',
          '"><script>alert(document.cookie)</script>',
        ];

        for (const input of maliciousInputs) {
          const result = validator.validateInput(input, { checkXss: true });
          expect(result.isValid).toBe(false);
          expect(result.threats).toContain('xss');
        }
      });

      it('should allow safe HTML-like strings', () => {
        const safeInputs = [
          'This is <b>bold</b> text',
          'Price is $50 < $100',
          'Use < for less than',
        ];

        for (const input of safeInputs) {
          const result = validator.validateInput(input, { checkXss: true, allowSafeHtml: true });
          expect(result.isValid).toBe(true);
        }
      });
    });

    describe('Command Injection', () => {
      it('should detect command injection attempts', () => {
        const maliciousInputs = [
          '; rm -rf /',
          '| cat /etc/passwd',
          '`whoami`',
          '$(id)',
          '&& curl malicious.com',
        ];

        for (const input of maliciousInputs) {
          const result = validator.validateInput(input, { checkCommandInjection: true });
          expect(result.isValid).toBe(false);
          expect(result.threats).toContain('command_injection');
        }
      });
    });

    describe('Path Traversal', () => {
      it('should detect path traversal attempts', () => {
        const maliciousInputs = [
          '../../../etc/passwd',
          '..\\..\\..\\windows\\system32',
          '/etc/passwd%00',
          '....//....//etc/passwd',
        ];

        for (const input of maliciousInputs) {
          const result = validator.validateInput(input, { checkPathTraversal: true });
          expect(result.isValid).toBe(false);
          expect(result.threats).toContain('path_traversal');
        }
      });
    });

    describe('Email Validation', () => {
      it('should validate email format', () => {
        const validEmails = [
          'user@example.com',
          'user.name@domain.org',
          'user+tag@company.co.uk',
        ];

        for (const email of validEmails) {
          const result = validator.validateEmail(email);
          expect(result.isValid).toBe(true);
        }
      });

      it('should reject invalid emails', () => {
        const invalidEmails = [
          'not-an-email',
          '@missing-local.com',
          'missing-at.com',
          'user@',
          '',
        ];

        for (const email of invalidEmails) {
          const result = validator.validateEmail(email);
          expect(result.isValid).toBe(false);
        }
      });
    });

    describe('URL Validation', () => {
      it('should validate URL format', () => {
        const validUrls = [
          'https://example.com',
          'http://localhost:3000',
          'https://sub.domain.com/path?query=value',
        ];

        for (const url of validUrls) {
          const result = validator.validateUrl(url);
          expect(result.isValid).toBe(true);
        }
      });

      it('should reject dangerous URLs', () => {
        const dangerousUrls = [
          'javascript:alert(1)',
          'data:text/html,<script>alert(1)</script>',
          'file:///etc/passwd',
        ];

        for (const url of dangerousUrls) {
          const result = validator.validateUrl(url, { allowedSchemes: ['http', 'https'] });
          expect(result.isValid).toBe(false);
        }
      });
    });
  });

  describe('AuthenticationTester', () => {
    let authTester: AuthenticationTester;
    let mockAuthFn: ReturnType<typeof vi.fn>;

    beforeEach(() => {
      mockAuthFn = vi.fn();
      authTester = new AuthenticationTester({
        authFunction: mockAuthFn,
      });
    });

    it('should test for broken authentication', async () => {
      mockAuthFn.mockResolvedValue({ success: true });

      const result = await authTester.testBrokenAuth();

      expect(result.vulnerable).toBe(true);
      expect(result.findings).toContain('Authentication accepts empty credentials');
    });

    it('should test for weak password policy', async () => {
      mockAuthFn
        .mockResolvedValueOnce({ success: true }) // weak password succeeds
        .mockResolvedValueOnce({ success: true }); // common password succeeds

      const result = await authTester.testPasswordPolicy();

      expect(result.weakPasswordsAllowed).toBe(true);
    });

    it('should test for session fixation', async () => {
      let sessionId = 'initial-session';
      const mockGetSession = vi.fn().mockImplementation(() => sessionId);
      const mockSetSession = vi.fn().mockImplementation((id) => { sessionId = id; });

      mockAuthFn.mockResolvedValue({ success: true });

      const result = await authTester.testSessionFixation({
        getSessionId: mockGetSession,
        setSessionId: mockSetSession,
      });

      // Should regenerate session after login
      expect(result.sessionRegenerated).toBe(true);
    });

    it('should test for brute force protection', async () => {
      mockAuthFn.mockResolvedValue({ success: false });

      const result = await authTester.testBruteForceProtection({
        attempts: 10,
        username: 'test-user',
      });

      expect(result.blocked).toBeDefined();
      // If not blocked after 10 attempts, it's vulnerable
    });

    it('should test password reset security', async () => {
      const mockResetFn = vi.fn().mockResolvedValue({ token: 'abc123' });

      const result = await authTester.testPasswordReset({
        resetFunction: mockResetFn,
        email: 'user@example.com',
      });

      expect(result.tokenSecure).toBeDefined();
      expect(result.findings).toBeDefined();
    });
  });

  describe('AuthorizationTester', () => {
    let authzTester: AuthorizationTester;

    beforeEach(() => {
      authzTester = new AuthorizationTester();
    });

    it('should test for horizontal privilege escalation', async () => {
      const mockAccess = vi.fn()
        .mockResolvedValueOnce({ allowed: true, data: 'user1-data' })
        .mockResolvedValueOnce({ allowed: true, data: 'user2-data' }); // Should be denied

      const result = await authzTester.testHorizontalPrivilegeEscalation({
        accessFunction: mockAccess,
        userId: 'user1',
        targetResourceId: 'user2-resource',
      });

      expect(result.vulnerable).toBe(true);
    });

    it('should test for vertical privilege escalation', async () => {
      const mockAdminAction = vi.fn().mockResolvedValue({ success: true });

      const result = await authzTester.testVerticalPrivilegeEscalation({
        adminAction: mockAdminAction,
        userRole: 'user',
      });

      expect(result.vulnerable).toBe(true);
    });

    it('should test for IDOR vulnerabilities', async () => {
      const mockFetch = vi.fn()
        .mockResolvedValueOnce({ id: 1, secret: 'data' }) // Own resource
        .mockResolvedValueOnce({ id: 2, secret: 'other-data' }); // Other user's resource

      const result = await authzTester.testIdor({
        fetchResource: mockFetch,
        ownResourceId: '1',
        otherResourceId: '2',
      });

      expect(result.vulnerable).toBe(true);
    });

    it('should test tenant isolation', async () => {
      const mockQuery = vi.fn().mockResolvedValue([
        { id: 1, tenantId: 'tenant-a' },
        { id: 2, tenantId: 'tenant-b' }, // Should not be visible
      ]);

      const result = await authzTester.testTenantIsolation({
        queryFunction: mockQuery,
        currentTenantId: 'tenant-a',
      });

      expect(result.isolated).toBe(false);
      expect(result.leakedTenants).toContain('tenant-b');
    });
  });

  describe('RateLimitTester', () => {
    let rateLimitTester: RateLimitTester;

    beforeEach(() => {
      rateLimitTester = new RateLimitTester();
    });

    it('should test rate limiting effectiveness', async () => {
      let requestCount = 0;
      const mockEndpoint = vi.fn().mockImplementation(async () => {
        requestCount++;
        if (requestCount > 100) {
          return { status: 429 };
        }
        return { status: 200 };
      });

      const result = await rateLimitTester.testRateLimit({
        endpoint: mockEndpoint,
        requestsPerSecond: 50,
        duration: 5000,
      });

      expect(result.rateLimitApplied).toBe(true);
      expect(result.limitThreshold).toBeLessThanOrEqual(100);
    });

    it('should test for rate limit bypass attempts', async () => {
      const mockEndpoint = vi.fn().mockResolvedValue({ status: 200 });

      const result = await rateLimitTester.testBypassAttempts({
        endpoint: mockEndpoint,
        bypassTechniques: ['ip-rotation', 'header-manipulation'],
      });

      expect(result.bypassable).toBeDefined();
    });
  });

  describe('CsrfProtectionTester', () => {
    let csrfTester: CsrfProtectionTester;

    beforeEach(() => {
      csrfTester = new CsrfProtectionTester();
    });

    it('should test for missing CSRF tokens', async () => {
      const mockSubmit = vi.fn().mockResolvedValue({ success: true });

      const result = await csrfTester.testMissingToken({
        submitFunction: mockSubmit,
      });

      expect(result.vulnerable).toBe(true);
    });

    it('should test for token validation', async () => {
      const mockSubmit = vi.fn()
        .mockImplementation(async (token) => {
          if (token === 'valid-token') {
            return { success: true };
          }
          return { success: false, error: 'Invalid token' };
        });

      const result = await csrfTester.testTokenValidation({
        submitFunction: mockSubmit,
        validToken: 'valid-token',
      });

      expect(result.tokensValidated).toBe(true);
    });

    it('should test for same-site cookie configuration', () => {
      const result = csrfTester.testSameSiteCookie({
        cookies: [
          { name: 'session', sameSite: 'Strict', secure: true, httpOnly: true },
        ],
      });

      expect(result.properlyConfigured).toBe(true);
    });
  });

  describe('XssSanitizer', () => {
    let sanitizer: XssSanitizer;

    beforeEach(() => {
      sanitizer = new XssSanitizer();
    });

    it('should sanitize script tags', () => {
      const input = '<script>alert("XSS")</script>';
      const sanitized = sanitizer.sanitize(input);

      expect(sanitized).not.toContain('<script');
      expect(sanitized).not.toContain('alert');
    });

    it('should sanitize event handlers', () => {
      const input = '<img src="x" onerror="alert(1)">';
      const sanitized = sanitizer.sanitize(input);

      expect(sanitized).not.toContain('onerror');
    });

    it('should sanitize javascript: URLs', () => {
      const input = '<a href="javascript:alert(1)">Click</a>';
      const sanitized = sanitizer.sanitize(input);

      expect(sanitized).not.toContain('javascript:');
    });

    it('should preserve safe content', () => {
      const input = 'Hello <b>World</b>!';
      const sanitized = sanitizer.sanitize(input, { allowedTags: ['b'] });

      expect(sanitized).toContain('<b>World</b>');
    });

    it('should escape special characters', () => {
      const input = '<>&"\'';
      const escaped = sanitizer.escapeHtml(input);

      expect(escaped).toBe('&lt;&gt;&amp;&quot;&#39;');
    });
  });

  describe('Integration', () => {
    it('should run comprehensive security scan', async () => {
      const scanner = new SecurityScanner({
        strictMode: true,
        enableAllChecks: true,
      });

      const mockRequest = {
        method: 'POST',
        path: '/api/users',
        headers: { 'Content-Type': 'application/json' },
        body: { username: 'test' },
      };

      const report = await scanner.fullScan(mockRequest);

      expect(report.summary).toBeDefined();
      expect(report.score).toBeDefined();
      expect(report.recommendations).toBeInstanceOf(Array);
    });

    it('should generate security report', async () => {
      const scanner = new SecurityScanner({ enableAllChecks: true });

      scanner.registerCheck({
        name: 'test-check',
        description: 'Test',
        severity: SecuritySeverity.MEDIUM,
        check: vi.fn().mockResolvedValue({ passed: false, message: 'Test failed' }),
      });

      const report = await scanner.scan({});
      const formatted = scanner.formatReport(report);

      expect(formatted).toContain('Security Report');
      expect(formatted).toContain('test-check');
    });
  });
});
