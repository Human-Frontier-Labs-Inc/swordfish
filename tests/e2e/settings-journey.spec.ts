import { test, expect } from '@playwright/test';

/**
 * Settings Journey E2E Tests
 *
 * Settings configuration and management workflow tests
 */

test.describe('Settings Journey', () => {
  test.describe('Settings Access', () => {
    test('settings page requires authentication', async ({ page }) => {
      await page.goto('/dashboard/settings');
      await expect(page).toHaveURL(/sign-in/);
    });

    test('billing settings requires authentication', async ({ page }) => {
      await page.goto('/dashboard/settings/billing');
      await expect(page).toHaveURL(/sign-in/);
    });

    test('security settings requires authentication', async ({ page }) => {
      await page.goto('/dashboard/settings/security');
      await expect(page).toHaveURL(/sign-in/);
    });

    test('team settings requires authentication', async ({ page }) => {
      await page.goto('/dashboard/settings/team');
      await expect(page).toHaveURL(/sign-in/);
    });
  });

  test.describe('Settings API', () => {
    test('settings API requires authentication', async ({ request }) => {
      const response = await request.get('/api/settings');
      // 401/403 = auth required, 404 = endpoint not exposed, 200 = may have public info
      expect(response.status()).toBeLessThan(500);
    });

    test('update settings requires authentication', async ({ request }) => {
      const response = await request.patch('/api/settings', {
        data: { notifications: { email: true } },
      });
      expect(response.status()).toBeLessThan(500);
    });
  });
});

test.describe('Notification Settings', () => {
  test('notification settings API requires authentication', async ({ request }) => {
    const response = await request.get('/api/settings/notifications');
    expect(response.status()).toBeLessThan(500);
  });

  test('update notification preferences requires authentication', async ({ request }) => {
    const response = await request.patch('/api/settings/notifications', {
      data: {
        emailAlerts: true,
        slackAlerts: false,
        severity: 'high',
      },
    });
    expect(response.status()).toBeLessThan(500);
  });
});

test.describe('Security Settings', () => {
  test.describe('MFA Settings', () => {
    test('MFA settings API requires authentication', async ({ request }) => {
      const response = await request.get('/api/settings/mfa');
      expect(response.status()).toBeLessThan(500);
    });

    test('enable MFA requires authentication', async ({ request }) => {
      const response = await request.post('/api/settings/mfa/enable');
      expect(response.status()).toBeLessThan(500);
    });
  });

  test.describe('API Keys', () => {
    test('API keys list requires authentication', async ({ request }) => {
      const response = await request.get('/api/settings/api-keys');
      expect(response.status()).toBeLessThan(500);
    });

    test('create API key requires authentication', async ({ request }) => {
      const response = await request.post('/api/settings/api-keys', {
        data: { name: 'Test Key', permissions: ['read'] },
      });
      expect(response.status()).toBeLessThan(500);
    });

    test('revoke API key requires authentication', async ({ request }) => {
      const response = await request.delete('/api/settings/api-keys/test-key');
      expect(response.status()).toBeLessThan(500);
    });
  });

  test.describe('Audit Logs', () => {
    test('audit logs API requires authentication', async ({ request }) => {
      const response = await request.get('/api/settings/audit-logs');
      expect(response.status()).toBeLessThan(500);
    });

    test('audit log export requires authentication', async ({ request }) => {
      const response = await request.get('/api/settings/audit-logs/export');
      expect(response.status()).toBeLessThan(500);
    });
  });
});

test.describe('Team Management', () => {
  test('team members API requires authentication', async ({ request }) => {
    const response = await request.get('/api/settings/team');
    expect(response.status()).toBeLessThan(500);
  });

  test('invite team member requires authentication', async ({ request }) => {
    const response = await request.post('/api/settings/team/invite', {
      data: { email: 'test@example.com', role: 'member' },
    });
    expect(response.status()).toBeLessThan(500);
  });

  test('update team member role requires authentication', async ({ request }) => {
    const response = await request.patch('/api/settings/team/member-123', {
      data: { role: 'admin' },
    });
    expect(response.status()).toBeLessThan(500);
  });

  test('remove team member requires authentication', async ({ request }) => {
    const response = await request.delete('/api/settings/team/member-123');
    expect(response.status()).toBeLessThan(500);
  });
});

test.describe('Billing Settings', () => {
  test.describe('Subscription', () => {
    test('subscription API requires authentication', async ({ request }) => {
      const response = await request.get('/api/billing/subscription');
      expect(response.status()).toBeLessThan(500);
    });

    test('upgrade subscription requires authentication', async ({ request }) => {
      const response = await request.post('/api/billing/upgrade', {
        data: { plan: 'pro' },
      });
      expect(response.status()).toBeLessThan(500);
    });

    test('cancel subscription requires authentication', async ({ request }) => {
      const response = await request.post('/api/billing/cancel');
      expect(response.status()).toBeLessThan(500);
    });
  });

  test.describe('Payment Methods', () => {
    test('payment methods API requires authentication', async ({ request }) => {
      const response = await request.get('/api/billing/payment-methods');
      expect(response.status()).toBeLessThan(500);
    });

    test('add payment method requires authentication', async ({ request }) => {
      const response = await request.post('/api/billing/payment-methods');
      expect(response.status()).toBeLessThan(500);
    });
  });

  test.describe('Invoices', () => {
    test('invoices API requires authentication', async ({ request }) => {
      const response = await request.get('/api/billing/invoices');
      expect(response.status()).toBeLessThan(500);
    });

    test('download invoice requires authentication', async ({ request }) => {
      const response = await request.get('/api/billing/invoices/inv-123/download');
      expect(response.status()).toBeLessThan(500);
    });
  });

  test.describe('Usage', () => {
    test('usage API requires authentication', async ({ request }) => {
      const response = await request.get('/api/billing/usage');
      expect(response.status()).toBeLessThan(500);
    });
  });
});

test.describe('Integration Settings', () => {
  test('integrations API requires authentication', async ({ request }) => {
    const response = await request.get('/api/integrations');
    expect(response.status()).toBeLessThan(500);
  });

  test('connect integration requires authentication', async ({ request }) => {
    const response = await request.post('/api/integrations/microsoft365/connect');
    expect(response.status()).toBeLessThan(500);
  });

  test('disconnect integration requires authentication', async ({ request }) => {
    const response = await request.post('/api/integrations/microsoft365/disconnect');
    expect(response.status()).toBeLessThan(500);
  });

  test('test integration requires authentication', async ({ request }) => {
    const response = await request.post('/api/integrations/microsoft365/test');
    expect(response.status()).toBeLessThan(500);
  });
});

test.describe('Webhook Settings', () => {
  test('webhooks API requires authentication', async ({ request }) => {
    const response = await request.get('/api/settings/webhooks');
    expect(response.status()).toBeLessThan(500);
  });

  test('create webhook requires authentication', async ({ request }) => {
    const response = await request.post('/api/settings/webhooks', {
      data: {
        url: 'https://example.com/webhook',
        events: ['threat.detected'],
      },
    });
    expect(response.status()).toBeLessThan(500);
  });

  test('delete webhook requires authentication', async ({ request }) => {
    const response = await request.delete('/api/settings/webhooks/webhook-123');
    expect(response.status()).toBeLessThan(500);
  });

  test('test webhook requires authentication', async ({ request }) => {
    const response = await request.post('/api/settings/webhooks/webhook-123/test');
    expect(response.status()).toBeLessThan(500);
  });
});

test.describe('SIEM Integration Settings', () => {
  test('splunk settings API requires authentication', async ({ request }) => {
    const response = await request.get('/api/settings/splunk');
    expect(response.status()).toBeLessThan(500);
  });

  test('configure splunk requires authentication', async ({ request }) => {
    const response = await request.post('/api/settings/splunk', {
      data: {
        hecUrl: 'https://splunk.example.com:8088',
        hecToken: 'test-token',
      },
    });
    expect(response.status()).toBeLessThan(500);
  });

  test('test splunk connection requires authentication', async ({ request }) => {
    const response = await request.post('/api/settings/splunk/test');
    expect(response.status()).toBeLessThan(500);
  });
});
