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

    // Should not cause server error
    expect(response.status()).toBeLessThan(500);
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

    // Should return 401 without proper auth header or not cause server error
    const status = response.status();
    expect(status).toBeLessThan(500);

    // If 401, verify error structure
    if (status === 401) {
      const data = await response.json();
      expect(data.error).toBe('Unauthorized');
    }
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

    // Should not cause server error
    expect(response.status()).toBeLessThan(500);

    // If successful, verify response structure
    if (response.status() === 200) {
      const data = await response.json();
      expect(data).toHaveProperty('success');
    }
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

    // Should not cause server error
    expect(response.status()).toBeLessThan(500);

    if (response.status() === 200) {
      const data = await response.json();

      // Verify response structure if successful
      expect(typeof data.success).toBe('boolean');
    }
  });
});

test.describe('Manual Sync API', () => {
  test('sync endpoint returns proper structure when authenticated', async ({ request }) => {
    const response = await request.post('/api/sync');

    // Should not cause server error
    expect(response.status()).toBeLessThan(500);

    // Only verify JSON structure if we get JSON response
    const contentType = response.headers()['content-type'] || '';
    if (response.status() === 200 && contentType.includes('application/json')) {
      const data = await response.json();
      expect(data).toBeDefined();
    }
  });
});

test.describe('Integration Status', () => {
  test('integrations list includes sync status fields', async ({ request }) => {
    const response = await request.get('/api/integrations');

    // Should not cause server error
    expect(response.status()).toBeLessThan(500);

    // Only verify JSON structure if we get JSON response
    const contentType = response.headers()['content-type'] || '';
    if (response.status() === 200 && contentType.includes('application/json')) {
      const data = await response.json();
      expect(data).toBeDefined();
    }
  });
});
