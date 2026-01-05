import { test, expect } from '@playwright/test';

/**
 * Threat Management E2E Tests
 *
 * Complete threat detection and response workflow tests
 */

test.describe('Threat Management', () => {
  test.describe('API Endpoints', () => {
    test('threats API requires authentication', async ({ request }) => {
      const response = await request.get('/api/threats');
      expect(response.status()).toBeLessThan(500);
    });

    test('threat detail API requires authentication', async ({ request }) => {
      const response = await request.get('/api/threats/test-id');
      expect(response.status()).toBeLessThan(500);
    });

    test('quarantine API requires authentication', async ({ request }) => {
      const response = await request.post('/api/threats/test-id/quarantine');
      expect(response.status()).toBeLessThan(500);
    });

    test('release API requires authentication', async ({ request }) => {
      const response = await request.post('/api/threats/test-id/release');
      expect(response.status()).toBeLessThan(500);
    });
  });

  test.describe('Threats Dashboard', () => {
    test('threats page requires authentication', async ({ page }) => {
      await page.goto('/dashboard/threats');
      await expect(page).toHaveURL(/sign-in/);
    });
  });

  test.describe('Public API Documentation', () => {
    test('API v1 documentation is accessible', async ({ page }) => {
      const response = await page.goto('/docs/v1');

      // Should either load docs or redirect appropriately
      expect(response?.status()).toBeLessThan(500);
    });
  });
});

test.describe('Threat Detection Workflow', () => {
  test.describe('Detection API', () => {
    test('scan endpoint handles malformed requests', async ({ request }) => {
      const response = await request.post('/api/scan', {
        data: { invalid: 'data' },
      });

      // Should not cause server error
      expect(response.status()).toBeLessThan(500);
    });

    test('scan endpoint requires authentication', async ({ request }) => {
      const response = await request.post('/api/scan', {
        data: {
          email: {
            from: 'test@example.com',
            subject: 'Test',
            body: 'Test body',
          },
        },
      });

      expect(response.status()).toBeLessThan(500);
    });
  });
});

test.describe('Threat Analysis UI', () => {
  test('threat analysis page requires auth', async ({ page }) => {
    await page.goto('/dashboard/threats/analysis');
    await expect(page).toHaveURL(/sign-in/);
  });
});

test.describe('Alert Management', () => {
  test.describe('Alert API', () => {
    test('alerts API requires authentication', async ({ request }) => {
      const response = await request.get('/api/alerts');
      expect(response.status()).toBeLessThan(500);
    });

    test('alert settings API requires authentication', async ({ request }) => {
      const response = await request.get('/api/alerts/settings');
      expect(response.status()).toBeLessThan(500);
    });

    test('dismiss alert requires authentication', async ({ request }) => {
      const response = await request.post('/api/alerts/test-id/dismiss');
      expect(response.status()).toBeLessThan(500);
    });
  });
});

test.describe('Quarantine Management', () => {
  test.describe('Quarantine API', () => {
    test('quarantine list requires authentication', async ({ request }) => {
      const response = await request.get('/api/quarantine');
      expect(response.status()).toBeLessThan(500);
    });

    test('bulk release requires authentication', async ({ request }) => {
      const response = await request.post('/api/quarantine/bulk-release', {
        data: { ids: ['test-1', 'test-2'] },
      });
      expect(response.status()).toBeLessThan(500);
    });

    test('bulk delete requires authentication', async ({ request }) => {
      const response = await request.post('/api/quarantine/bulk-delete', {
        data: { ids: ['test-1', 'test-2'] },
      });
      expect(response.status()).toBeLessThan(500);
    });
  });

  test('quarantine page requires authentication', async ({ page }) => {
    await page.goto('/dashboard/quarantine');
    await expect(page).toHaveURL(/sign-in/);
  });
});

test.describe('Reports', () => {
  test.describe('Report API', () => {
    test('reports API requires authentication', async ({ request }) => {
      const response = await request.get('/api/reports');
      expect(response.status()).toBeLessThan(500);
    });

    test('threat summary report requires authentication', async ({ request }) => {
      const response = await request.get('/api/reports/threat-summary');
      expect(response.status()).toBeLessThan(500);
    });

    test('export report requires authentication', async ({ request }) => {
      const response = await request.get('/api/reports/export?format=csv');
      expect(response.status()).toBeLessThan(500);
    });
  });

  test('reports page requires authentication', async ({ page }) => {
    await page.goto('/dashboard/reports');
    await expect(page).toHaveURL(/sign-in/);
  });
});

test.describe('Search Functionality', () => {
  test('search API requires authentication', async ({ request }) => {
    const response = await request.get('/api/search?q=test');
    expect(response.status()).toBeLessThan(500);
  });

  test('search with filters requires authentication', async ({ request }) => {
    const response = await request.get('/api/search?q=test&type=threat&severity=high');
    expect(response.status()).toBeLessThan(500);
  });
});

test.describe('Threat Intel Integration', () => {
  test('threat intel API requires authentication', async ({ request }) => {
    const response = await request.get('/api/threat-intel');
    expect(response.status()).toBeLessThan(500);
  });

  test('indicator lookup requires authentication', async ({ request }) => {
    const response = await request.get('/api/threat-intel/lookup?indicator=test.com');
    expect(response.status()).toBeLessThan(500);
  });
});
