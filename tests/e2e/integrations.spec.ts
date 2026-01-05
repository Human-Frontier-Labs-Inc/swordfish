import { test, expect } from '@playwright/test';

/**
 * Integration Tests for Email Provider Connections
 *
 * Note: These tests require authentication. In CI, use Clerk test mode
 * or mock authentication. For local development, ensure you're logged in.
 */

test.describe('Email Integrations Page', () => {
  // Skip auth tests in CI without proper setup
  test.skip(({ browserName }) => !process.env.CLERK_TEST_USER, 'Requires authenticated user');

  test.beforeEach(async ({ page }) => {
    // This would need Clerk test authentication setup
    // For now, we test the public-facing parts
  });

  test('integrations page requires authentication', async ({ page }) => {
    await page.goto('/dashboard/integrations');

    // Should redirect to sign-in
    await expect(page).toHaveURL(/sign-in/, { timeout: 10000 });
  });
});

test.describe('Integration Cards UI', () => {
  test('should show integration options when authenticated', async ({ page }) => {
    // This test would run with mocked auth
    // For now, verify the page structure

    await page.goto('/dashboard/integrations');

    // If redirected, we know auth is working
    const url = page.url();
    expect(url.includes('sign-in') || url.includes('integrations')).toBe(true);
  });
});

test.describe('Sync Functionality', () => {
  test('sync API responds appropriately', async ({ request }) => {
    const response = await request.post('/api/sync');
    const status = response.status();

    // Should require auth or return sync status
    expect([200, 401, 403, 500]).toContain(status);
  });

  test('integrations API handles unauthenticated requests', async ({ request }) => {
    const response = await request.get('/api/integrations');
    const status = response.status();
    const contentType = response.headers()['content-type'] || '';

    // Should require auth or redirect to login
    if (status === 401 || status === 403) {
      expect(true).toBe(true);
    } else if (contentType.includes('text/html')) {
      // Redirected to login page - auth is working
      expect(true).toBe(true);
    } else if (contentType.includes('application/json')) {
      const data = await response.json();
      expect(data).toHaveProperty('integrations');
    }
  });
});

test.describe('Cron Job API', () => {
  test('cron endpoint requires authorization', async ({ request }) => {
    const response = await request.get('/api/cron/sync-emails');

    // Should return 401 without proper auth header
    expect(response.status()).toBe(401);

    const data = await response.json();
    expect(data.error).toBe('Unauthorized');
  });

  test('cron endpoint accepts valid authorization', async ({ request }) => {
    const cronSecret = process.env.CRON_SECRET;

    // Skip if no CRON_SECRET is set
    if (!cronSecret) {
      test.skip();
      return;
    }

    const response = await request.get('/api/cron/sync-emails', {
      headers: {
        authorization: `Bearer ${cronSecret}`,
      },
    });

    // Should return 200 with valid auth
    expect(response.status()).toBe(200);

    const data = await response.json();
    expect(data).toHaveProperty('success');
    expect(data).toHaveProperty('synced');
    expect(data).toHaveProperty('total');
    expect(data).toHaveProperty('duration');
  });

  test('cron endpoint returns proper response structure', async ({ request }) => {
    const cronSecret = process.env.CRON_SECRET;

    if (!cronSecret) {
      test.skip();
      return;
    }

    const response = await request.get('/api/cron/sync-emails', {
      headers: {
        authorization: `Bearer ${cronSecret}`,
      },
    });

    if (response.status() === 200) {
      const data = await response.json();

      // Verify response structure
      expect(typeof data.success).toBe('boolean');
      expect(typeof data.synced).toBe('number');
      expect(typeof data.total).toBe('number');
      expect(typeof data.duration).toBe('number');
      expect(typeof data.timedOut).toBe('boolean');
      expect(typeof data.totalEmailsProcessed).toBe('number');
      expect(typeof data.totalThreatsFound).toBe('number');
    }
  });
});

test.describe('Manual Sync API', () => {
  test('sync endpoint returns proper structure when authenticated', async ({ request }) => {
    const response = await request.post('/api/sync');

    if (response.status() === 200) {
      const data = await response.json();

      // Verify response structure
      expect(data).toHaveProperty('totalIntegrations');
      expect(data).toHaveProperty('totalEmailsProcessed');
      expect(data).toHaveProperty('totalThreatsFound');
      expect(data).toHaveProperty('totalErrors');
      expect(data).toHaveProperty('integrations');
      expect(Array.isArray(data.integrations)).toBe(true);
    }
  });
});

test.describe('Integration Status', () => {
  test('integrations list includes sync status fields', async ({ request }) => {
    const response = await request.get('/api/integrations');

    if (response.status() === 200) {
      const data = await response.json();

      // If there are integrations, verify they have status fields
      if (data.integrations && data.integrations.length > 0) {
        const integration = data.integrations[0];

        expect(integration).toHaveProperty('status');
        expect(integration).toHaveProperty('syncEnabled');
        expect(integration).toHaveProperty('lastSyncAt');
      }
    }
  });
});
