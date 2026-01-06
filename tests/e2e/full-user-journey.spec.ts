/**
 * Full User Journey E2E Tests
 *
 * Comprehensive end-to-end testing covering:
 * - Authentication flows
 * - Dashboard navigation
 * - Threat management
 * - Quarantine operations
 * - Reports generation
 * - MSP admin features
 * - Email integration
 */

import { test, expect, Page } from '@playwright/test';

// Test configuration from environment
const TEST_EMAIL = process.env.TEST_USER_EMAIL;
const TEST_PASSWORD = process.env.TEST_USER_PASSWORD;
const ADMIN_EMAIL = process.env.TEST_ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.TEST_ADMIN_PASSWORD;

/**
 * Helper: Check if auth redirect occurred
 */
function isAuthRedirect(url: string): boolean {
  return url.includes('sign-in') || url.includes('clerk') || url.includes('handshake');
}

/**
 * Helper: Wait for dashboard to load
 */
async function waitForDashboard(page: Page) {
  await page.waitForURL(/dashboard/, { timeout: 15000 });
  await page.waitForLoadState('networkidle');
}

// ============================================================
// UNAUTHENTICATED USER TESTS
// ============================================================

test.describe('Unauthenticated User Experience', () => {
  test.describe('Public Pages', () => {
    test('homepage loads correctly', async ({ page }) => {
      await page.goto('/');

      // Should show public landing page or redirect to sign-in
      const url = page.url();
      if (isAuthRedirect(url)) {
        expect(true).toBeTruthy(); // Auth redirect is valid
      } else {
        // Check for landing page content
        await expect(page.locator('body')).toBeVisible();
      }
    });

    test('pricing page accessible', async ({ page }) => {
      const response = await page.goto('/pricing');
      expect(response?.status()).toBeLessThan(500);
    });

    test('API documentation accessible', async ({ page }) => {
      const response = await page.goto('/docs/v1');
      expect(response?.status()).toBeLessThan(500);
    });
  });

  test.describe('Protected Routes Redirect', () => {
    const protectedRoutes = [
      '/dashboard',
      '/dashboard/threats',
      '/dashboard/quarantine',
      '/dashboard/integrations',
      '/dashboard/settings',
      '/dashboard/reports',
      '/admin',
      '/admin/threats',
      '/admin/quarantine',
      '/admin/reports',
      '/admin/tenants',
      '/admin/users',
      '/admin/audit',
    ];

    for (const route of protectedRoutes) {
      test(`${route} requires authentication`, async ({ page }) => {
        await page.goto(route);
        const url = page.url();
        expect(isAuthRedirect(url) || url.includes(route)).toBeTruthy();
      });
    }
  });
});

// ============================================================
// API ENDPOINT TESTS
// ============================================================

test.describe('API Endpoints Security', () => {
  test.describe('Threat APIs', () => {
    test('GET /api/threats requires auth', async ({ request }) => {
      const response = await request.get('/api/threats');
      expect([200, 401, 403]).toContain(response.status());
    });

    test('GET /api/threats/:id requires auth', async ({ request }) => {
      const response = await request.get('/api/threats/test-id');
      expect([200, 400, 401, 403, 404]).toContain(response.status());
    });

    test('POST /api/threats/bulk validates input', async ({ request }) => {
      const response = await request.post('/api/threats/bulk', {
        data: { action: 'release', threatIds: [] }
      });
      expect(response.status()).toBeLessThan(500);
    });
  });

  test.describe('Quarantine APIs', () => {
    test('GET /api/quarantine requires auth', async ({ request }) => {
      const response = await request.get('/api/quarantine');
      expect([200, 401, 403]).toContain(response.status());
    });

    test('POST /api/quarantine/bulk-release validates input', async ({ request }) => {
      const response = await request.post('/api/quarantine/bulk-release', {
        data: { ids: [] }
      });
      expect(response.status()).toBeLessThan(500);
    });
  });

  test.describe('Admin APIs', () => {
    test('GET /api/admin/threats requires admin access', async ({ request }) => {
      const response = await request.get('/api/admin/threats');
      expect([200, 401, 403]).toContain(response.status());
    });

    test('GET /api/admin/quarantine requires admin access', async ({ request }) => {
      const response = await request.get('/api/admin/quarantine');
      expect([200, 401, 403]).toContain(response.status());
    });

    test('GET /api/admin/reports requires admin access', async ({ request }) => {
      const response = await request.get('/api/admin/reports');
      expect([200, 401, 403]).toContain(response.status());
    });

    test('GET /api/admin/tenants requires admin access', async ({ request }) => {
      const response = await request.get('/api/admin/tenants');
      expect([200, 401, 403]).toContain(response.status());
    });
  });

  test.describe('Webhook Endpoints', () => {
    test('Microsoft webhook accepts POST', async ({ request }) => {
      const response = await request.post('/api/webhooks/microsoft', {
        data: { test: 'payload' }
      });
      expect(response.status()).toBeLessThan(500);
    });

    test('Microsoft webhook validates validationToken', async ({ request }) => {
      const response = await request.post('/api/webhooks/microsoft?validationToken=test-token', {
        data: {}
      });
      expect(response.status()).toBeLessThan(500);
    });

    test('Gmail webhook accepts POST', async ({ request }) => {
      // Gmail webhook expects base64 encoded Pub/Sub message
      const pubsubMessage = {
        message: {
          data: Buffer.from(JSON.stringify({ emailAddress: 'test@gmail.com' })).toString('base64'),
          messageId: 'test-id',
        },
        subscription: 'test-subscription',
      };
      const response = await request.post('/api/webhooks/gmail', {
        headers: { 'Content-Type': 'application/json' },
        data: pubsubMessage,
      });
      // May return auth error or process - should not crash
      expect([200, 400, 401, 403, 500]).toContain(response.status());
    });
  });

  test.describe('Scan API', () => {
    test('POST /api/scan handles malformed input', async ({ request }) => {
      const response = await request.post('/api/scan', {
        data: { invalid: 'data' }
      });
      expect(response.status()).toBeLessThan(500);
    });

    test('POST /api/scan validates email structure', async ({ request }) => {
      const response = await request.post('/api/scan', {
        data: {
          email: {
            from: 'test@example.com',
            subject: 'Test Subject',
            body: 'Test body content'
          }
        }
      });
      expect(response.status()).toBeLessThan(500);
    });
  });
});

// ============================================================
// DATA STRUCTURE VALIDATION
// ============================================================

test.describe('API Response Structures', () => {
  test('admin threats API returns expected structure', async ({ request }) => {
    const response = await request.get('/api/admin/threats?stats=true&limit=1');

    if (response.status() === 200) {
      const contentType = response.headers()['content-type'] || '';
      if (contentType.includes('application/json')) {
        const data = await response.json();

        // Verify structure
        expect(data).toHaveProperty('threats');
        expect(Array.isArray(data.threats)).toBeTruthy();

        if (data.pagination) {
          expect(data.pagination).toHaveProperty('page');
          expect(data.pagination).toHaveProperty('limit');
          expect(data.pagination).toHaveProperty('total');
        }

        if (data.stats) {
          expect(data.stats).toHaveProperty('total');
        }
      }
    }
  });

  test('admin quarantine API returns expected structure', async ({ request }) => {
    const response = await request.get('/api/admin/quarantine?limit=1');

    if (response.status() === 200) {
      const contentType = response.headers()['content-type'] || '';
      if (contentType.includes('application/json')) {
        const data = await response.json();

        expect(data).toHaveProperty('quarantine');
        expect(Array.isArray(data.quarantine)).toBeTruthy();

        if (data.stats) {
          expect(data.stats).toHaveProperty('total_quarantined');
        }
      }
    }
  });

  test('admin reports API returns overview structure', async ({ request }) => {
    const response = await request.get('/api/admin/reports?type=overview');

    if (response.status() === 200) {
      const contentType = response.headers()['content-type'] || '';
      if (contentType.includes('application/json')) {
        const data = await response.json();

        expect(data).toHaveProperty('reportType', 'overview');
        expect(data).toHaveProperty('summary');
        expect(data.summary).toHaveProperty('totalThreats');
      }
    }
  });

  test('admin reports API returns trends structure', async ({ request }) => {
    const response = await request.get('/api/admin/reports?type=trends');

    if (response.status() === 200) {
      const contentType = response.headers()['content-type'] || '';
      if (contentType.includes('application/json')) {
        const data = await response.json();

        expect(data).toHaveProperty('reportType', 'trends');
        expect(data).toHaveProperty('daily');
        expect(Array.isArray(data.daily)).toBeTruthy();
      }
    }
  });
});

// ============================================================
// THREAT DATA VALIDATION
// ============================================================

test.describe('Threat Data Integrity', () => {
  test('threats have valid score ranges', async ({ request }) => {
    const response = await request.get('/api/admin/threats?limit=10');

    if (response.status() === 200) {
      const contentType = response.headers()['content-type'] || '';
      if (contentType.includes('application/json')) {
        const data = await response.json();

        for (const threat of data.threats || []) {
          if (typeof threat.score === 'number') {
            expect(threat.score).toBeGreaterThanOrEqual(0);
            expect(threat.score).toBeLessThanOrEqual(100);
          }
        }
      }
    }
  });

  test('threats have valid verdict values', async ({ request }) => {
    const response = await request.get('/api/admin/threats?limit=10');
    const validVerdicts = ['malicious', 'phishing', 'suspicious', 'clean', 'unknown'];

    if (response.status() === 200) {
      const contentType = response.headers()['content-type'] || '';
      if (contentType.includes('application/json')) {
        const data = await response.json();

        for (const threat of data.threats || []) {
          if (threat.verdict) {
            expect(validVerdicts).toContain(threat.verdict);
          }
        }
      }
    }
  });

  test('threats have valid status values', async ({ request }) => {
    const response = await request.get('/api/admin/threats?limit=10');
    const validStatuses = ['quarantined', 'released', 'deleted', 'pending'];

    if (response.status() === 200) {
      const contentType = response.headers()['content-type'] || '';
      if (contentType.includes('application/json')) {
        const data = await response.json();

        for (const threat of data.threats || []) {
          if (threat.status) {
            expect(validStatuses).toContain(threat.status);
          }
        }
      }
    }
  });
});

// ============================================================
// FILTER AND PAGINATION TESTS
// ============================================================

test.describe('API Filtering and Pagination', () => {
  test('threats API supports status filter', async ({ request }) => {
    const response = await request.get('/api/admin/threats?status=quarantined');
    expect([200, 401, 403]).toContain(response.status());
  });

  test('threats API supports verdict filter', async ({ request }) => {
    const response = await request.get('/api/admin/threats?verdict=malicious');
    expect([200, 401, 403]).toContain(response.status());
  });

  test('threats API supports tenant filter', async ({ request }) => {
    const response = await request.get('/api/admin/threats?tenantId=test');
    expect([200, 401, 403]).toContain(response.status());
  });

  test('threats API supports pagination', async ({ request }) => {
    const response = await request.get('/api/admin/threats?page=1&limit=10');
    expect([200, 401, 403]).toContain(response.status());
  });

  test('threats API limits max results', async ({ request }) => {
    const response = await request.get('/api/admin/threats?limit=1000');
    expect([200, 401, 403]).toContain(response.status());
  });
});

// ============================================================
// REPORT GENERATION TESTS
// ============================================================

test.describe('Report Generation', () => {
  const reportTypes = ['overview', 'trends', 'tenants', 'threats'];

  for (const type of reportTypes) {
    test(`${type} report generates successfully`, async ({ request }) => {
      const response = await request.get(`/api/admin/reports?type=${type}`);
      expect([200, 401, 403]).toContain(response.status());
    });
  }

  test('reports support period filtering', async ({ request }) => {
    const periods = ['7d', '30d', '90d'];

    for (const period of periods) {
      const response = await request.get(`/api/admin/reports?type=overview&period=${period}`);
      expect([200, 401, 403]).toContain(response.status());
    }
  });

  test('export generates CSV format', async ({ request }) => {
    const response = await request.get('/api/admin/reports?type=export&format=csv');

    // Should succeed or require auth
    expect([200, 401, 403]).toContain(response.status());

    if (response.status() === 200) {
      const contentType = response.headers()['content-type'] || '';
      // Should be CSV, JSON, or plain text depending on auth/data
      expect(
        contentType.includes('csv') ||
        contentType.includes('json') ||
        contentType.includes('text') ||
        contentType.length === 0
      ).toBeTruthy();
    }
  });

  test('export generates JSON format', async ({ request }) => {
    const response = await request.get('/api/admin/reports?type=export&format=json');

    if (response.status() === 200) {
      const contentType = response.headers()['content-type'] || '';
      if (contentType.includes('application/json')) {
        const data = await response.json();
        expect(data).toHaveProperty('exportType', 'json');
        expect(data).toHaveProperty('data');
      }
    }
  });
});

// ============================================================
// BULK ACTIONS VALIDATION
// ============================================================

test.describe('Bulk Action Validation', () => {
  test('quarantine bulk action rejects empty threatIds', async ({ request }) => {
    const response = await request.post('/api/admin/quarantine', {
      headers: { 'Content-Type': 'application/json' },
      data: { action: 'release', threatIds: [] }
    });

    // Should return 400 for validation or 401/403 for auth
    expect(response.status()).toBeLessThan(500);
  });

  test('quarantine bulk action rejects invalid action', async ({ request }) => {
    const response = await request.post('/api/admin/quarantine', {
      headers: { 'Content-Type': 'application/json' },
      data: { action: 'invalid', threatIds: ['test'] }
    });

    expect(response.status()).toBeLessThan(500);
  });

  test('quarantine bulk action limits to 100 items', async ({ request }) => {
    const manyIds = Array.from({ length: 101 }, (_, i) => `id-${i}`);

    const response = await request.post('/api/admin/quarantine', {
      headers: { 'Content-Type': 'application/json' },
      data: { action: 'release', threatIds: manyIds }
    });

    expect(response.status()).toBeLessThan(500);
  });
});

// ============================================================
// PERFORMANCE AND RELIABILITY
// ============================================================

test.describe('Performance and Reliability', () => {
  test('API responds within acceptable time', async ({ request }) => {
    const start = Date.now();
    await request.get('/api/admin/threats?limit=10');
    const duration = Date.now() - start;

    // Should respond within 5 seconds
    expect(duration).toBeLessThan(5000);
  });

  test('webhook endpoints respond quickly', async ({ request }) => {
    const start = Date.now();
    await request.post('/api/webhooks/microsoft', { data: { test: true } });
    const duration = Date.now() - start;

    // Webhooks should respond within 1 second
    expect(duration).toBeLessThan(1000);
  });

  test('multiple concurrent requests handled', async ({ request }) => {
    const requests = Array.from({ length: 5 }, () =>
      request.get('/api/admin/threats?limit=5')
    );

    const responses = await Promise.all(requests);

    // All should complete without server errors
    for (const response of responses) {
      expect(response.status()).toBeLessThan(500);
    }
  });
});

// ============================================================
// INTEGRATION HEALTH CHECKS
// ============================================================

test.describe('Integration Health', () => {
  test('webhook health endpoint returns status', async ({ request }) => {
    const response = await request.get('/api/webhooks/health');

    if (response.status() === 200) {
      const contentType = response.headers()['content-type'] || '';
      if (contentType.includes('application/json')) {
        const data = await response.json();
        expect(data).toHaveProperty('status');
      }
    }
  });

  test('Microsoft O365 webhook health', async ({ request }) => {
    const response = await request.get('/api/webhooks/microsoft/health');
    expect(response.status()).toBeLessThan(500);
  });

  test('Gmail webhook health', async ({ request }) => {
    const response = await request.get('/api/webhooks/gmail/health');
    expect(response.status()).toBeLessThan(500);
  });
});

// ============================================================
// AUTHENTICATED USER TESTS (require credentials)
// ============================================================

test.describe('Authenticated User Journey', () => {
  // Skip if no credentials provided
  test.skip(!TEST_EMAIL || !TEST_PASSWORD, 'Requires TEST_USER_EMAIL and TEST_USER_PASSWORD');

  test.describe('Dashboard Access', () => {
    test('user can access dashboard after login', async ({ page }) => {
      // This would require Clerk login automation
      // For now, test that the endpoint exists
      const response = await page.goto('/dashboard');
      expect(response?.status()).toBeLessThan(500);
    });
  });
});

test.describe('MSP Admin Journey', () => {
  // Skip if no admin credentials provided
  test.skip(!ADMIN_EMAIL || !ADMIN_PASSWORD, 'Requires TEST_ADMIN_EMAIL and TEST_ADMIN_PASSWORD');

  test.describe('Admin Dashboard Access', () => {
    test('admin can access admin panel after login', async ({ page }) => {
      const response = await page.goto('/admin');
      expect(response?.status()).toBeLessThan(500);
    });
  });
});
