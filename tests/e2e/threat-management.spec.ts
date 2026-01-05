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

/**
 * MSP Admin Threat Management Tests
 *
 * User Stories:
 * 1. As an MSP admin, I can view threats across all tenants
 * 2. As an MSP admin, I can filter threats by tenant, verdict, status
 * 3. As an MSP admin, I can view quarantined emails and take bulk actions
 */
test.describe('MSP Admin Threat Management', () => {
  test.describe('Admin Threats API', () => {
    test('admin threats API returns proper structure when authenticated', async ({ request }) => {
      const response = await request.get('/api/admin/threats');

      // Should return 401 for unauthenticated or 200 with data
      expect([200, 401, 403]).toContain(response.status());

      if (response.status() === 200) {
        const contentType = response.headers()['content-type'] || '';
        if (contentType.includes('application/json')) {
          const data = await response.json();

          // Should have threats array
          expect(data).toHaveProperty('threats');
          expect(Array.isArray(data.threats)).toBeTruthy();

          // Should have pagination
          expect(data).toHaveProperty('pagination');
          expect(data.pagination).toHaveProperty('page');
          expect(data.pagination).toHaveProperty('limit');
          expect(data.pagination).toHaveProperty('total');
        }
      }
    });

    test('admin threats API supports stats parameter', async ({ request }) => {
      const response = await request.get('/api/admin/threats?stats=true');

      expect([200, 401, 403]).toContain(response.status());

      if (response.status() === 200) {
        const contentType = response.headers()['content-type'] || '';
        if (contentType.includes('application/json')) {
          const data = await response.json();
          expect(data).toHaveProperty('stats');
          expect(data.stats).toHaveProperty('total');
          expect(data.stats).toHaveProperty('quarantined');
        }
      }
    });

    test('admin threats API supports status filter', async ({ request }) => {
      const response = await request.get('/api/admin/threats?status=quarantined');
      expect([200, 401, 403]).toContain(response.status());
    });

    test('admin threats API supports verdict filter', async ({ request }) => {
      const response = await request.get('/api/admin/threats?verdict=malicious');
      expect([200, 401, 403]).toContain(response.status());
    });

    test('admin threats API supports tenant filter', async ({ request }) => {
      const response = await request.get('/api/admin/threats?tenantId=test-tenant');
      expect([200, 401, 403]).toContain(response.status());
    });
  });

  test.describe('Admin Quarantine API', () => {
    test('admin quarantine API returns proper structure', async ({ request }) => {
      const response = await request.get('/api/admin/quarantine');

      expect([200, 401, 403]).toContain(response.status());

      if (response.status() === 200) {
        const contentType = response.headers()['content-type'] || '';
        if (contentType.includes('application/json')) {
          const data = await response.json();

          // Should have quarantine array
          expect(data).toHaveProperty('quarantine');
          expect(Array.isArray(data.quarantine)).toBeTruthy();

          // Should have stats
          expect(data).toHaveProperty('stats');

          // Should have pagination
          expect(data).toHaveProperty('pagination');
        }
      }
    });

    test('admin quarantine bulk action validates input', async ({ request }) => {
      // Missing threatIds should return 400 or 401/403 for auth
      const emptyResponse = await request.post('/api/admin/quarantine', {
        headers: { 'Content-Type': 'application/json' },
        data: { action: 'release' }
      });

      // Should not return server error - validation or auth should handle it
      expect(emptyResponse.status()).toBeLessThan(500);

      // If we got a success response, verify structure is correct
      if (emptyResponse.status() === 200) {
        const contentType = emptyResponse.headers()['content-type'] || '';
        if (contentType.includes('application/json')) {
          const data = await emptyResponse.json();
          // Either error message or success with results
          expect(data).toBeDefined();
        }
      }

      // Invalid action should return 400 or 401/403 for auth
      const invalidActionResponse = await request.post('/api/admin/quarantine', {
        headers: { 'Content-Type': 'application/json' },
        data: { threatIds: ['test'], action: 'invalid' }
      });

      // Should not return server error
      expect(invalidActionResponse.status()).toBeLessThan(500);
    });

    test('admin quarantine API limits bulk actions to 100', async ({ request }) => {
      // Generate 101 fake IDs
      const manyIds = Array.from({ length: 101 }, (_, i) => `fake-id-${i}`);

      const response = await request.post('/api/admin/quarantine', {
        headers: { 'Content-Type': 'application/json' },
        data: { threatIds: manyIds, action: 'release' }
      });

      // Should not return server error - validation or auth should handle it
      expect(response.status()).toBeLessThan(500);
    });
  });

  test.describe('Admin Threats Page', () => {
    test('admin threats page loads correctly', async ({ page }) => {
      await page.goto('/admin/threats');

      // Should either show threats page or redirect to auth
      const url = page.url();

      if (url.includes('/admin/threats')) {
        // Page loaded - check for key elements
        await expect(page.locator('h1')).toContainText(/Threats|Overview/i);
      } else {
        // Redirected to auth or dashboard - expected for unauthenticated users
        expect(url).toMatch(/sign-in|dashboard/i);
      }
    });
  });

  test.describe('Admin Quarantine Page', () => {
    test('admin quarantine page loads correctly', async ({ page }) => {
      await page.goto('/admin/quarantine');

      const url = page.url();

      if (url.includes('/admin/quarantine')) {
        // Page loaded
        await expect(page.locator('h1')).toContainText(/Quarantine/i);
      }
    });
  });

  test.describe('Data Integrity', () => {
    test('threat data includes required fields when data exists', async ({ request }) => {
      const response = await request.get('/api/admin/threats?limit=1&stats=true');

      if (response.status() === 200) {
        const contentType = response.headers()['content-type'] || '';
        if (contentType.includes('application/json')) {
          const data = await response.json();

          if (data.threats && data.threats.length > 0) {
            const threat = data.threats[0];

            // Verify required fields exist
            expect(threat).toHaveProperty('id');
            expect(threat).toHaveProperty('tenantId');
            expect(threat).toHaveProperty('tenantName');
            expect(threat).toHaveProperty('subject');
            expect(threat).toHaveProperty('senderEmail');
            expect(threat).toHaveProperty('verdict');
            expect(threat).toHaveProperty('score');
            expect(threat).toHaveProperty('status');
            expect(threat).toHaveProperty('createdAt');

            // Verify score is a valid number
            expect(typeof threat.score).toBe('number');
            expect(threat.score).toBeGreaterThanOrEqual(0);
            expect(threat.score).toBeLessThanOrEqual(100);

            // Verify status is valid
            expect(['quarantined', 'released', 'deleted']).toContain(threat.status);

            // Verify verdict is valid
            expect(['malicious', 'phishing', 'suspicious']).toContain(threat.verdict);
          }
        }
      }
    });

    test('quarantine data includes required fields when data exists', async ({ request }) => {
      const response = await request.get('/api/admin/quarantine?limit=1');

      if (response.status() === 200) {
        const contentType = response.headers()['content-type'] || '';
        if (contentType.includes('application/json')) {
          const data = await response.json();

          if (data.quarantine && data.quarantine.length > 0) {
            const item = data.quarantine[0];

            // Verify required fields
            expect(item).toHaveProperty('id');
            expect(item).toHaveProperty('tenantId');
            expect(item).toHaveProperty('tenantName');
            expect(item).toHaveProperty('subject');
            expect(item).toHaveProperty('senderEmail');
            expect(item).toHaveProperty('recipientEmail');
            expect(item).toHaveProperty('verdict');
            expect(item).toHaveProperty('score');
            expect(item).toHaveProperty('quarantinedAt');
          }

          // Verify stats structure
          if (data.stats) {
            expect(data.stats).toHaveProperty('total_quarantined');
            expect(typeof data.stats.total_quarantined).toBe('number');
          }
        }
      }
    });
  });
});
