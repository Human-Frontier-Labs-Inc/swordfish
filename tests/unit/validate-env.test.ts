/**
 * Unit tests for environment variable validation
 * Tests that validateEnvironment logs correctly for missing/present vars
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// We need to re-import the module fresh for each test since it reads process.env
// at call time. We use dynamic imports after setting up env vars.

describe('validateEnvironment', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.restoreAllMocks();
    // Clear all relevant env vars
    delete process.env.DATABASE_URL;
    delete process.env.CLERK_SECRET_KEY;
    delete process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.STRIPE_SECRET_KEY;
    delete process.env.UPSTASH_REDIS_REST_URL;
  });

  afterEach(() => {
    // Restore original env
    process.env = { ...originalEnv };
  });

  it('should log errors when required env vars are missing', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    // Use fresh import to avoid module cache issues
    const { validateEnvironment } = await import('@/lib/config/validate-env');
    validateEnvironment();

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Missing required environment variables')
    );
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('DATABASE_URL')
    );
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('CLERK_SECRET_KEY')
    );
  });

  it('should log warnings when optional env vars are missing', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});

    // Set required vars so only optional warnings appear
    process.env.DATABASE_URL = 'postgres://test';
    process.env.CLERK_SECRET_KEY = 'sk_test_123';
    process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY = 'pk_test_123';

    const { validateEnvironment } = await import('@/lib/config/validate-env');
    validateEnvironment();

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('Missing optional environment variables')
    );
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('ANTHROPIC_API_KEY')
    );
  });

  it('should log success when all env vars are present', async () => {
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    // Set all env vars
    process.env.DATABASE_URL = 'postgres://test';
    process.env.CLERK_SECRET_KEY = 'sk_test_123';
    process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY = 'pk_test_123';
    process.env.ANTHROPIC_API_KEY = 'sk-ant-123';
    process.env.STRIPE_SECRET_KEY = 'sk_test_stripe';
    process.env.UPSTASH_REDIS_REST_URL = 'https://redis.upstash.com';

    const { validateEnvironment } = await import('@/lib/config/validate-env');
    validateEnvironment();

    expect(infoSpy).toHaveBeenCalledWith(
      expect.stringContaining('All environment variables validated successfully')
    );
    expect(errorSpy).not.toHaveBeenCalled();
    expect(warnSpy).not.toHaveBeenCalled();
  });
});
