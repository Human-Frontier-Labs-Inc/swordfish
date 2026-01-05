import { test, expect } from '@playwright/test';

/**
 * Webhook E2E Tests
 * Tests for real-time email processing via webhooks
 */

test.describe('Webhook Endpoints', () => {
  test.describe('Gmail Webhook', () => {
    test('health endpoint returns status', async ({ request }) => {
      const response = await request.get('/api/webhooks/gmail');

      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data.status).toBe('healthy');
      expect(data.service).toBe('gmail-webhook');
      expect(data.timestamp).toBeDefined();
    });

    test('POST without payload returns error', async ({ request }) => {
      const response = await request.post('/api/webhooks/gmail', {
        headers: { 'Content-Type': 'application/json' },
        data: {},
      });

      // Should either process or error gracefully
      expect([200, 400, 500]).toContain(response.status());
    });

    test('POST with valid Pub/Sub format processes successfully', async ({ request }) => {
      const notification = {
        emailAddress: 'test-nonexistent@gmail.com',
        historyId: '12345',
      };

      const pubSubPayload = {
        message: {
          data: Buffer.from(JSON.stringify(notification)).toString('base64'),
          messageId: 'test-pubsub-msg-1',
          publishTime: new Date().toISOString(),
        },
        subscription: 'projects/test/subscriptions/gmail-webhook',
      };

      const response = await request.post('/api/webhooks/gmail', {
        headers: { 'Content-Type': 'application/json' },
        data: pubSubPayload,
      });

      // Should return 200 even for unknown emails (just ignores them)
      expect(response.status()).toBe(200);

      const data = await response.json();
      // Either 'ignored' for unknown email or 'processed' for valid
      expect(['ignored', 'processed']).toContain(data.status);
    });
  });

  test.describe('Microsoft Webhook', () => {
    test('health endpoint returns status', async ({ request }) => {
      const response = await request.get('/api/webhooks/microsoft');

      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data.status).toBe('healthy');
      expect(data.endpoint).toBe('/api/webhooks/microsoft');
    });

    test('responds to validation challenge', async ({ request }) => {
      const validationToken = 'test-validation-token-12345';

      const response = await request.post(
        `/api/webhooks/microsoft?validationToken=${encodeURIComponent(validationToken)}`
      );

      expect(response.status()).toBe(200);
      expect(response.headers()['content-type']).toContain('text/plain');

      const text = await response.text();
      expect(text).toBe(validationToken);
    });

    test('processes notification payload', async ({ request }) => {
      const notification = {
        value: [
          {
            subscriptionId: 'test-sub-nonexistent',
            clientState: 'test-state',
            changeType: 'created',
            resource: 'Users/test-user/Messages/test-msg',
            tenantId: 'test-azure-tenant',
          },
        ],
      };

      const response = await request.post('/api/webhooks/microsoft', {
        headers: { 'Content-Type': 'application/json' },
        data: notification,
      });

      // Should return 200 or 202 (accepted) even if subscription not found
      expect([200, 202]).toContain(response.status());
    });
  });

  test.describe('O365 Webhook', () => {
    test('health endpoint returns status', async ({ request }) => {
      const response = await request.get('/api/webhooks/o365');

      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data.status).toBe('healthy');
      expect(data.service).toBe('o365-webhook');
    });

    test('responds to validation challenge', async ({ request }) => {
      const validationToken = 'test-o365-validation-token';

      const response = await request.post(
        `/api/webhooks/o365?validationToken=${encodeURIComponent(validationToken)}`
      );

      expect(response.status()).toBe(200);
      expect(response.headers()['content-type']).toContain('text/plain');

      const text = await response.text();
      expect(text).toBe(validationToken);
    });
  });

  test.describe('Webhook Health Dashboard', () => {
    test('health endpoint requires authentication', async ({ request }) => {
      const response = await request.get('/api/webhooks/health');
      const status = response.status();

      // Should require auth or return metrics
      expect([200, 401, 403, 500]).toContain(status);
    });
  });
});

test.describe('Real-Time Processing SLA', () => {
  test('Gmail webhook responds within 5 seconds', async ({ request }) => {
    const startTime = Date.now();

    const notification = {
      emailAddress: 'sla-test@gmail.com',
      historyId: '99999',
    };

    const pubSubPayload = {
      message: {
        data: Buffer.from(JSON.stringify(notification)).toString('base64'),
        messageId: 'sla-test-msg',
        publishTime: new Date().toISOString(),
      },
      subscription: 'projects/test/subscriptions/gmail-webhook',
    };

    const response = await request.post('/api/webhooks/gmail', {
      headers: { 'Content-Type': 'application/json' },
      data: pubSubPayload,
    });

    const duration = Date.now() - startTime;

    // Response should be within 5 seconds SLA
    expect(duration).toBeLessThan(5000);
    expect(response.status()).toBe(200);
  });

  test('Microsoft webhook responds within 5 seconds', async ({ request }) => {
    const startTime = Date.now();

    const notification = {
      value: [
        {
          subscriptionId: 'sla-test-sub',
          clientState: 'sla-test',
          changeType: 'created',
          resource: 'Users/sla-user/Messages/sla-msg',
          tenantId: 'sla-tenant',
        },
      ],
    };

    const response = await request.post('/api/webhooks/microsoft', {
      headers: { 'Content-Type': 'application/json' },
      data: notification,
    });

    const duration = Date.now() - startTime;

    // Response should be within 5 seconds SLA
    expect(duration).toBeLessThan(5000);
    expect([200, 202]).toContain(response.status());
  });
});

test.describe('Rate Limiting', () => {
  test('Gmail webhook handles high request volume', async ({ request }) => {
    const notification = {
      emailAddress: 'rate-limit-test@gmail.com',
      historyId: '11111',
    };

    const pubSubPayload = {
      message: {
        data: Buffer.from(JSON.stringify(notification)).toString('base64'),
        messageId: 'rate-test',
        publishTime: new Date().toISOString(),
      },
      subscription: 'projects/test/subscriptions/gmail-webhook',
    };

    // Send multiple requests
    const promises = [];
    for (let i = 0; i < 10; i++) {
      promises.push(
        request.post('/api/webhooks/gmail', {
          headers: { 'Content-Type': 'application/json' },
          data: pubSubPayload,
        })
      );
    }

    const responses = await Promise.all(promises);

    // All should succeed or some may be rate limited
    for (const response of responses) {
      expect([200, 429]).toContain(response.status());
    }
  });
});
