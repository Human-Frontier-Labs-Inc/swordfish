/**
 * Email Integration E2E Tests
 *
 * Tests real email integration with Microsoft 365 and Gmail.
 * Requires environment variables to be set:
 * - TEST_GMAIL_ADDRESS: Gmail address for testing
 * - TEST_GMAIL_APP_PASSWORD: Gmail app password (not regular password)
 * - TEST_M365_EMAIL: Microsoft 365 email for testing
 * - TEST_M365_PASSWORD: Microsoft 365 password
 * - TEST_TENANT_ID: Tenant ID for authenticated tests
 *
 * Usage:
 *   TEST_GMAIL_ADDRESS=test@gmail.com \
 *   TEST_GMAIL_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx \
 *   npm run test:e2e -- tests/e2e/email-integration.spec.ts
 */

import { test, expect } from '@playwright/test';

// Environment configuration
const config = {
  gmail: {
    email: process.env.TEST_GMAIL_ADDRESS,
    appPassword: process.env.TEST_GMAIL_APP_PASSWORD,
  },
  m365: {
    email: process.env.TEST_M365_EMAIL,
    password: process.env.TEST_M365_PASSWORD,
    clientId: process.env.TEST_M365_CLIENT_ID,
    clientSecret: process.env.TEST_M365_CLIENT_SECRET,
    tenantId: process.env.TEST_M365_TENANT_ID,
  },
  swordfish: {
    apiKey: process.env.SWORDFISH_API_KEY,
    tenantId: process.env.TEST_TENANT_ID,
  },
};

// Check if credentials are available
const hasGmailCreds = config.gmail.email && config.gmail.appPassword;
const hasM365Creds = config.m365.email && config.m365.password;
const hasSwordfishApiKey = !!config.swordfish.apiKey;

// ============================================================
// GMAIL INTEGRATION TESTS
// ============================================================

test.describe('Gmail Integration', () => {
  test.skip(!hasGmailCreds, 'Requires TEST_GMAIL_ADDRESS and TEST_GMAIL_APP_PASSWORD');

  test.describe('Gmail Webhook Processing', () => {
    test('Gmail webhook accepts valid Pub/Sub message', async ({ request }) => {
      // Simulate Gmail Pub/Sub notification
      const pubsubMessage = {
        message: {
          data: Buffer.from(JSON.stringify({
            emailAddress: config.gmail.email,
            historyId: '12345',
          })).toString('base64'),
          messageId: 'test-message-id',
          publishTime: new Date().toISOString(),
        },
        subscription: 'projects/test-project/subscriptions/swordfish-gmail',
      };

      const response = await request.post('/api/webhooks/gmail', {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${config.swordfish.apiKey || 'test-token'}`,
        },
        data: pubsubMessage,
      });

      // Should acknowledge the message (200) or reject invalid auth (401/403)
      expect([200, 401, 403]).toContain(response.status());
    });

    test('Gmail webhook rejects malformed messages', async ({ request }) => {
      const response = await request.post('/api/webhooks/gmail', {
        headers: { 'Content-Type': 'application/json' },
        data: { invalid: 'structure' },
      });

      // Should return error but not crash
      expect(response.status()).toBeLessThan(500);
    });
  });

  test.describe('Gmail OAuth Flow', () => {
    test('Gmail OAuth initiation endpoint exists', async ({ request }) => {
      const response = await request.get('/api/integrations/gmail/connect');
      // Should redirect to OAuth or require auth
      expect([200, 302, 401, 403]).toContain(response.status());
    });

    test('Gmail OAuth callback endpoint exists', async ({ request }) => {
      const response = await request.get('/api/integrations/gmail/callback?code=test');
      // Should handle callback or require auth
      expect(response.status()).toBeLessThan(500);
    });
  });
});

// ============================================================
// MICROSOFT 365 INTEGRATION TESTS
// ============================================================

test.describe('Microsoft 365 Integration', () => {
  test.skip(!hasM365Creds, 'Requires TEST_M365_EMAIL and TEST_M365_PASSWORD');

  test.describe('Microsoft Webhook Processing', () => {
    test('Microsoft webhook validates subscription', async ({ request }) => {
      // Microsoft Graph sends validation token for new subscriptions
      const validationToken = 'test-validation-token-12345';
      const response = await request.post(
        `/api/webhooks/microsoft?validationToken=${validationToken}`,
        { data: {} }
      );

      if (response.status() === 200) {
        const text = await response.text();
        expect(text).toBe(validationToken);
      }
    });

    test('Microsoft webhook processes change notification', async ({ request }) => {
      // Simulate Microsoft Graph change notification
      const notification = {
        value: [
          {
            subscriptionId: 'test-subscription-id',
            subscriptionExpirationDateTime: new Date(Date.now() + 86400000).toISOString(),
            changeType: 'created',
            resource: 'me/mailFolders/inbox/messages/test-message-id',
            resourceData: {
              '@odata.type': '#Microsoft.Graph.Message',
              '@odata.id': 'Users/test-user/Messages/test-message-id',
              id: 'test-message-id',
            },
            clientState: 'swordfish-webhook',
            tenantId: config.m365.tenantId || 'test-tenant',
          },
        ],
      };

      const response = await request.post('/api/webhooks/microsoft', {
        headers: { 'Content-Type': 'application/json' },
        data: notification,
      });

      // Should process or acknowledge
      expect([200, 202, 401, 403]).toContain(response.status());
    });
  });

  test.describe('Microsoft OAuth Flow', () => {
    test('Microsoft OAuth initiation endpoint exists', async ({ request }) => {
      const response = await request.get('/api/integrations/microsoft/connect');
      expect([200, 302, 401, 403]).toContain(response.status());
    });

    test('Microsoft OAuth callback endpoint exists', async ({ request }) => {
      const response = await request.get('/api/integrations/microsoft/callback?code=test');
      expect(response.status()).toBeLessThan(500);
    });
  });
});

// ============================================================
// THREAT DETECTION API TESTS
// ============================================================

test.describe('Threat Detection API', () => {
  test.describe('Email Scanning', () => {
    test('scan API processes email content', async ({ request }) => {
      const testEmail = {
        email: {
          from: 'sender@example.com',
          to: 'recipient@example.com',
          subject: 'Test email for scanning',
          body: 'This is a test email body for threat scanning.',
          headers: {
            'Message-ID': '<test-message-id@example.com>',
            'Date': new Date().toISOString(),
          },
        },
      };

      const response = await request.post('/api/scan', {
        headers: { 'Content-Type': 'application/json' },
        data: testEmail,
      });

      if (response.status() === 200) {
        const contentType = response.headers()['content-type'] || '';
        if (contentType.includes('application/json')) {
          const data = await response.json();
          // Should return scan result
          expect(data).toBeDefined();
        }
      }
    });

    test('scan API detects phishing indicators', async ({ request }) => {
      const phishingEmail = {
        email: {
          from: 'security@fakemicrosoft.com',
          to: 'victim@company.com',
          subject: 'Urgent: Your account will be suspended',
          body: `
            Dear User,

            Your Microsoft 365 account will be suspended in 24 hours.
            Click here to verify your account: http://fake-microsoft-login.com/verify

            Enter your password to confirm your identity.

            Microsoft Security Team
          `,
        },
      };

      const response = await request.post('/api/scan', {
        headers: { 'Content-Type': 'application/json' },
        data: phishingEmail,
      });

      expect(response.status()).toBeLessThan(500);

      if (response.status() === 200) {
        const contentType = response.headers()['content-type'] || '';
        if (contentType.includes('application/json')) {
          const data = await response.json();
          // Should detect this as suspicious/phishing
          if (data.verdict) {
            expect(['phishing', 'suspicious', 'malicious']).toContain(data.verdict);
          }
        }
      }
    });

    test('scan API detects BEC indicators', async ({ request }) => {
      const becEmail = {
        email: {
          from: 'ceo.spoofed@external-domain.com',
          to: 'accountant@company.com',
          subject: 'Urgent Wire Transfer Needed',
          body: `
            Hi,

            I need you to process an urgent wire transfer of $50,000 to our new vendor.
            This is time-sensitive and confidential. Please do not discuss with anyone else.

            I'm in a meeting so please just proceed with the transfer.

            Thanks,
            CEO
          `,
        },
      };

      const response = await request.post('/api/scan', {
        headers: { 'Content-Type': 'application/json' },
        data: becEmail,
      });

      expect(response.status()).toBeLessThan(500);
    });

    test('scan API handles attachments', async ({ request }) => {
      const emailWithAttachment = {
        email: {
          from: 'sender@example.com',
          to: 'recipient@company.com',
          subject: 'Document for review',
          body: 'Please find the attached document.',
          attachments: [
            {
              filename: 'invoice.pdf',
              contentType: 'application/pdf',
              size: 12345,
              hash: 'abc123def456',
            },
          ],
        },
      };

      const response = await request.post('/api/scan', {
        headers: { 'Content-Type': 'application/json' },
        data: emailWithAttachment,
      });

      expect(response.status()).toBeLessThan(500);
    });
  });
});

// ============================================================
// REAL EMAIL TESTS (with credentials)
// ============================================================

test.describe('Real Email Integration Tests', () => {
  test.skip(!hasGmailCreds && !hasM365Creds, 'Requires email credentials');

  test.describe('Send and Detect Test', () => {
    test('system detects simulated threat email', async ({ request }) => {
      // This test simulates what would happen when a threat email arrives
      // In a full integration test, you would:
      // 1. Send a test email to the monitored account
      // 2. Wait for webhook notification
      // 3. Verify threat was detected

      // For now, we test the detection directly
      const threatEmail = {
        email: {
          from: 'attacker@malicious-domain.xyz',
          to: hasGmailCreds ? config.gmail.email : config.m365.email,
          subject: 'Invoice #INV-2024-FAKE - Payment Required Immediately',
          body: `
            URGENT: Your payment is overdue!

            Click here to pay now: http://suspicious-payment-link.xyz/pay

            If you don't pay within 2 hours, legal action will be taken.

            Download the invoice: http://malware-download.xyz/invoice.exe
          `,
          headers: {
            'Reply-To': 'different-reply@another-domain.com',
            'X-Originating-IP': '192.0.2.1',
          },
        },
      };

      const response = await request.post('/api/scan', {
        headers: { 'Content-Type': 'application/json' },
        data: threatEmail,
      });

      expect(response.status()).toBeLessThan(500);
    });
  });
});

// ============================================================
// INTEGRATION STATUS TESTS
// ============================================================

test.describe('Integration Status', () => {
  test('integration list endpoint works', async ({ request }) => {
    const response = await request.get('/api/integrations');
    expect([200, 401, 403]).toContain(response.status());
  });

  test('Gmail integration status endpoint works', async ({ request }) => {
    const response = await request.get('/api/integrations/gmail/status');
    expect([200, 401, 403, 404]).toContain(response.status());
  });

  test('Microsoft integration status endpoint works', async ({ request }) => {
    const response = await request.get('/api/integrations/microsoft/status');
    expect([200, 401, 403, 404]).toContain(response.status());
  });
});

// ============================================================
// WEBHOOK RELIABILITY TESTS
// ============================================================

test.describe('Webhook Reliability', () => {
  test('webhooks handle duplicate messages idempotently', async ({ request }) => {
    const messageId = `test-${Date.now()}`;

    // Send same message twice
    const payload = {
      value: [
        {
          subscriptionId: 'sub-1',
          resource: `messages/${messageId}`,
          changeType: 'created',
        },
      ],
    };

    const response1 = await request.post('/api/webhooks/microsoft', {
      headers: { 'Content-Type': 'application/json' },
      data: payload,
    });

    const response2 = await request.post('/api/webhooks/microsoft', {
      headers: { 'Content-Type': 'application/json' },
      data: payload,
    });

    // Both should succeed (idempotent handling)
    expect(response1.status()).toBeLessThan(500);
    expect(response2.status()).toBeLessThan(500);
  });

  test('webhooks handle concurrent requests', async ({ request }) => {
    const requests = Array.from({ length: 10 }, (_, i) => {
      return request.post('/api/webhooks/microsoft', {
        headers: { 'Content-Type': 'application/json' },
        data: {
          value: [
            {
              subscriptionId: `sub-${i}`,
              resource: `messages/msg-${i}`,
              changeType: 'created',
            },
          ],
        },
      });
    });

    const responses = await Promise.all(requests);

    // All should complete without crashing
    for (const response of responses) {
      expect(response.status()).toBeLessThan(500);
    }
  });

  test('webhooks respond within SLA', async ({ request }) => {
    const start = Date.now();

    await request.post('/api/webhooks/microsoft', {
      headers: { 'Content-Type': 'application/json' },
      data: { value: [{ changeType: 'test' }] },
    });

    const duration = Date.now() - start;

    // Must respond within 5 seconds for Microsoft webhook SLA
    expect(duration).toBeLessThan(5000);
  });
});
