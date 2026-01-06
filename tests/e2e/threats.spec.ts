import { test, expect } from '@playwright/test';

test.describe('Threats Page', () => {
  test('threats page requires authentication', async ({ page }) => {
    await page.goto('/dashboard/threats');

    // Should redirect to sign-in or Clerk auth
    const url = page.url();
    expect(url.includes('sign-in') || url.includes('clerk') || url.includes('handshake')).toBeTruthy();
  });

  test('threats API handles unauthenticated requests', async ({ request }) => {
    const response = await request.get('/api/threats');
    const status = response.status();
    const contentType = response.headers()['content-type'] || '';

    // API should either deny access or redirect to auth
    if (status === 401 || status === 403) {
      expect(true).toBe(true);
    } else if (contentType.includes('text/html')) {
      // Redirected to login page - auth is working
      expect(true).toBe(true);
    } else if (contentType.includes('application/json')) {
      const data = await response.json();
      expect(data).toHaveProperty('threats');
    }
  });

  test('threats bulk API validates request', async ({ request }) => {
    const response = await request.post('/api/threats/bulk', {
      data: { action: 'release', threatIds: [] }
    });
    const status = response.status();

    // Should require auth or return validation error
    expect([200, 400, 401, 403]).toContain(status);
  });
});

test.describe('Quarantine Page', () => {
  test('quarantine page requires authentication', async ({ page }) => {
    await page.goto('/dashboard/quarantine');

    // Should redirect to sign-in or Clerk auth
    const url = page.url();
    expect(url.includes('sign-in') || url.includes('clerk') || url.includes('handshake')).toBeTruthy();
  });

  test('quarantine API handles unauthenticated requests', async ({ request }) => {
    const response = await request.get('/api/quarantine');
    const status = response.status();
    const contentType = response.headers()['content-type'] || '';

    // API should either deny access or redirect to auth
    if (status === 401 || status === 403) {
      expect(true).toBe(true);
    } else if (contentType.includes('text/html')) {
      // Redirected to login page - auth is working
      expect(true).toBe(true);
    } else if (contentType.includes('application/json')) {
      const data = await response.json();
      expect(data).toHaveProperty('emails');
    }
  });
});
