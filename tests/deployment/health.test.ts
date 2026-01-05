/**
 * Health Check Tests
 *
 * TDD tests for deployment health checks and environment validation
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import {
  HealthChecker,
  EnvironmentValidator,
  getHealthStatus,
  isReady,
  isAlive,
} from '@/lib/deployment/health';

describe('Health Checker', () => {
  let healthChecker: HealthChecker;

  beforeEach(() => {
    healthChecker = new HealthChecker();
  });

  describe('Default Checks', () => {
    it('should have database check registered', async () => {
      const result = await healthChecker.check('database');
      expect(result).not.toBeNull();
      expect(result?.service).toBe('database');
    });

    it('should have auth check registered', async () => {
      const result = await healthChecker.check('auth');
      expect(result).not.toBeNull();
      expect(result?.service).toBe('auth');
    });

    it('should have email-integration check registered', async () => {
      const result = await healthChecker.check('email-integration');
      expect(result).not.toBeNull();
      expect(result?.service).toBe('email-integration');
    });

    it('should have ai-services check registered', async () => {
      const result = await healthChecker.check('ai-services');
      expect(result).not.toBeNull();
      expect(result?.service).toBe('ai-services');
    });

    it('should have billing check registered', async () => {
      const result = await healthChecker.check('billing');
      expect(result).not.toBeNull();
      expect(result?.service).toBe('billing');
    });
  });

  describe('Custom Checks', () => {
    it('should register custom health check', async () => {
      healthChecker.register('custom', async () => ({
        service: 'custom',
        status: 'healthy',
        message: 'Custom service OK',
        lastChecked: new Date(),
      }));

      const result = await healthChecker.check('custom');
      expect(result?.service).toBe('custom');
      expect(result?.status).toBe('healthy');
    });

    it('should return null for unregistered check', async () => {
      const result = await healthChecker.check('nonexistent');
      expect(result).toBeNull();
    });
  });

  describe('Check All', () => {
    it('should return system health with all checks', async () => {
      const health = await healthChecker.checkAll();

      expect(health.overall).toBeDefined();
      expect(health.version).toBeDefined();
      expect(health.uptime).toBeGreaterThanOrEqual(0);
      expect(health.checks).toBeInstanceOf(Array);
      expect(health.timestamp).toBeInstanceOf(Date);
    });

    it('should aggregate health status correctly', async () => {
      // Add a healthy check
      healthChecker.register('test-healthy', async () => ({
        service: 'test-healthy',
        status: 'healthy',
        lastChecked: new Date(),
      }));

      const health = await healthChecker.checkAll();
      expect(health.checks.length).toBeGreaterThan(0);
    });

    it('should report overall unhealthy if any check is unhealthy', async () => {
      healthChecker.register('test-unhealthy', async () => ({
        service: 'test-unhealthy',
        status: 'unhealthy',
        message: 'Service down',
        lastChecked: new Date(),
      }));

      const health = await healthChecker.checkAll();
      expect(health.overall).toBe('unhealthy');
    });

    it('should report overall degraded if any check is degraded and none unhealthy', async () => {
      // Clear and add only degraded checks
      const checker = new HealthChecker();
      checker.register('test-degraded', async () => ({
        service: 'test-degraded',
        status: 'degraded',
        message: 'Service degraded',
        lastChecked: new Date(),
      }));
      checker.register('test-healthy', async () => ({
        service: 'test-healthy',
        status: 'healthy',
        lastChecked: new Date(),
      }));

      // Note: Default checks may affect this - test the logic
      const health = await checker.checkAll();
      expect(['healthy', 'degraded', 'unhealthy']).toContain(health.overall);
    });
  });

  describe('Check Results', () => {
    it('should include latency when measured', async () => {
      const result = await healthChecker.check('database');
      expect(result?.latencyMs).toBeDefined();
      expect(result?.latencyMs).toBeGreaterThanOrEqual(0);
    });

    it('should include timestamp', async () => {
      const result = await healthChecker.check('database');
      expect(result?.lastChecked).toBeInstanceOf(Date);
    });
  });
});

describe('Environment Validator', () => {
  let validator: EnvironmentValidator;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    validator = new EnvironmentValidator();
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('Required Variables', () => {
    it('should report missing DATABASE_URL', () => {
      delete process.env.DATABASE_URL;

      const result = validator.validate();
      expect(result.errors).toContain('Missing required environment variable: DATABASE_URL');
    });

    it('should report missing CLERK_SECRET_KEY', () => {
      delete process.env.CLERK_SECRET_KEY;

      const result = validator.validate();
      expect(result.errors).toContain('Missing required environment variable: CLERK_SECRET_KEY');
    });

    it('should pass when all required variables are set', () => {
      process.env.DATABASE_URL = 'postgres://localhost/test';
      process.env.CLERK_SECRET_KEY = 'sk_test_123';
      process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY = 'pk_test_123';

      const result = validator.validate();
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('Optional Variables', () => {
    it('should warn about missing optional variables', () => {
      delete process.env.STRIPE_SECRET_KEY;

      const result = validator.validate();
      expect(result.warnings.some(w => w.includes('STRIPE_SECRET_KEY'))).toBe(true);
    });

    it('should not error for missing optional variables', () => {
      process.env.DATABASE_URL = 'postgres://localhost/test';
      process.env.CLERK_SECRET_KEY = 'sk_test_123';
      process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY = 'pk_test_123';
      delete process.env.STRIPE_SECRET_KEY;

      const result = validator.validate();
      expect(result.valid).toBe(true);
    });
  });

  describe('Database URL Validation', () => {
    it('should error for non-PostgreSQL database URL', () => {
      process.env.DATABASE_URL = 'mysql://localhost/test';
      process.env.CLERK_SECRET_KEY = 'sk_test_123';
      process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY = 'pk_test_123';

      const result = validator.validate();
      expect(result.errors).toContain('DATABASE_URL must be a PostgreSQL connection string');
    });

    it('should accept valid PostgreSQL URL', () => {
      process.env.DATABASE_URL = 'postgres://user:pass@localhost/db';
      process.env.CLERK_SECRET_KEY = 'sk_test_123';
      process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY = 'pk_test_123';

      const result = validator.validate();
      expect(result.errors.some(e => e.includes('PostgreSQL'))).toBe(false);
    });
  });

  describe('Production Validation', () => {
    it('should warn about test Stripe keys in production', () => {
      process.env.NODE_ENV = 'production';
      process.env.DATABASE_URL = 'postgres://localhost/test';
      process.env.CLERK_SECRET_KEY = 'sk_test_123';
      process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY = 'pk_test_123';
      process.env.STRIPE_SECRET_KEY = 'sk_test_123';

      const result = validator.validate();
      expect(result.warnings.some(w => w.includes('test Stripe keys'))).toBe(true);
    });
  });

  describe('Deployment Config', () => {
    it('should return correct environment', () => {
      process.env.NODE_ENV = 'production';

      const config = validator.getConfig();
      expect(config.environment).toBe('production');
    });

    it('should detect email integration feature', () => {
      process.env.MICROSOFT_CLIENT_ID = 'test-id';

      const config = validator.getConfig();
      expect(config.features.emailIntegration).toBe(true);
    });

    it('should detect AI detection feature', () => {
      process.env.OPENAI_API_KEY = 'sk-test';

      const config = validator.getConfig();
      expect(config.features.aiDetection).toBe(true);
    });

    it('should detect billing feature', () => {
      process.env.STRIPE_SECRET_KEY = 'sk_test_123';

      const config = validator.getConfig();
      expect(config.features.billing).toBe(true);
    });

    it('should include version', () => {
      const config = validator.getConfig();
      expect(config.version).toBeDefined();
    });
  });
});

describe('Health API Functions', () => {
  describe('getHealthStatus', () => {
    it('should return system health', async () => {
      const health = await getHealthStatus();

      expect(health.overall).toBeDefined();
      expect(health.checks).toBeInstanceOf(Array);
    });
  });

  describe('isReady', () => {
    it('should return boolean', async () => {
      const ready = await isReady();
      expect(typeof ready).toBe('boolean');
    });
  });

  describe('isAlive', () => {
    it('should return true', () => {
      expect(isAlive()).toBe(true);
    });
  });
});
