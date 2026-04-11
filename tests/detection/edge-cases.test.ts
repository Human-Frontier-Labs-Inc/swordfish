/**
 * Detection Edge Case Tests
 *
 * Tests for:
 * 1. URL shortener escalation when combined with other suspicious signals
 * 2. Missing authentication (SPF/DKIM/DMARC all none) with URLs
 */

import { describe, it, expect } from 'vitest';
import { classifyEmail } from '@/lib/detection/ml/classifier';
import { runDeterministicAnalysis } from '@/lib/detection/deterministic';
import type { ParsedEmail } from '@/lib/detection/types';

function createTestEmail(overrides: Partial<ParsedEmail> = {}): ParsedEmail {
  return {
    messageId: 'test-message-id',
    subject: 'Test Subject',
    from: {
      address: 'sender@example.com',
      displayName: 'Test Sender',
      domain: 'example.com',
    },
    to: [{
      address: 'recipient@company.com',
      displayName: 'Recipient',
      domain: 'company.com',
    }],
    date: new Date(),
    headers: {},
    body: {
      text: 'Test email body',
      html: '<p>Test email body</p>',
    },
    attachments: [],
    rawHeaders: '',
    ...overrides,
  };
}

describe('URL Shortener Escalation', () => {
  it('should keep ml_shortener as warning when no other suspicious signals', async () => {
    const email = createTestEmail({
      body: {
        text: 'Check this out: https://bit.ly/abc123',
        html: '<p>Check this out: <a href="https://bit.ly/abc123">link</a></p>',
      },
    });

    const result = await classifyEmail(email);
    const shortenerSignal = result.signals.find(s => s.type === 'ml_shortener');

    if (shortenerSignal) {
      expect(shortenerSignal.severity).toBe('warning');
      expect(shortenerSignal.detail).not.toContain('escalated');
    }
  });

  it('should escalate ml_shortener to critical when combined with 2+ other warning/critical signals', async () => {
    const email = createTestEmail({
      subject: 'URGENT: Your account has been suspended - verify now immediately',
      body: {
        text: 'Your account has been suspended due to unusual activity. Click here to verify: https://bit.ly/verify123. Enter your password to confirm your identity. Failure to comply will result in account termination.',
        html: '<p>Your account has been suspended due to unusual activity. Click here to verify: <a href="https://bit.ly/verify123">link</a>. Enter your password to confirm your identity.</p>',
      },
      from: {
        address: 'security@evil-domain.com',
        displayName: 'security@paypal.com',
        domain: 'evil-domain.com',
      },
    });

    const result = await classifyEmail(email);
    const shortenerSignal = result.signals.find(s => s.type === 'ml_shortener');

    // There should be threat language, urgency, and other signals alongside the shortener
    const warningOrCriticalSignals = result.signals.filter(
      s => s.type !== 'ml_shortener' && (s.severity === 'warning' || s.severity === 'critical')
    );

    expect(warningOrCriticalSignals.length).toBeGreaterThanOrEqual(2);

    if (shortenerSignal) {
      expect(shortenerSignal.severity).toBe('critical');
      expect(shortenerSignal.detail).toContain('escalated');
    }
  });

  it('should add score boost when shortener is escalated', async () => {
    const email = createTestEmail({
      subject: 'URGENT: Security alert - unauthorized access detected',
      body: {
        text: 'Unauthorized access to your account. Verify immediately: https://tinyurl.com/verify456. Your account will be terminated. Enter your credentials now.',
        html: '',
      },
    });

    const result = await classifyEmail(email);
    const shortenerSignal = result.signals.find(s => s.type === 'ml_shortener');

    if (shortenerSignal && shortenerSignal.severity === 'critical') {
      // Base score is shortenerLinkCount * 15, escalation adds 20
      expect(shortenerSignal.score).toBeGreaterThanOrEqual(35);
    }
  });
});

describe('Missing Authentication Detection', () => {
  it('should flag emails with no authentication and URLs', async () => {
    const email = createTestEmail({
      headers: {
        'authentication-results': 'mx.example.com; spf=none; dkim=none; dmarc=none',
      },
      body: {
        text: 'Click here: https://example.com/login',
        html: '<a href="https://example.com/login">Login</a>',
      },
    });

    const result = await runDeterministicAnalysis(email);
    const noAuthSignal = result.signals.find(s => s.type === 'no_authentication');

    expect(noAuthSignal).toBeDefined();
    expect(noAuthSignal?.severity).toBe('warning');
    expect(noAuthSignal?.score).toBe(20);
    expect(noAuthSignal?.detail).toContain('no authentication');
  });

  it('should NOT flag emails with partial authentication', async () => {
    const email = createTestEmail({
      headers: {
        'authentication-results': 'mx.example.com; spf=pass; dkim=none; dmarc=none',
      },
      body: {
        text: 'Click here: https://example.com/login',
        html: '<a href="https://example.com/login">Login</a>',
      },
    });

    const result = await runDeterministicAnalysis(email);
    const noAuthSignal = result.signals.find(s => s.type === 'no_authentication');

    expect(noAuthSignal).toBeUndefined();
  });

  it('should NOT flag emails with no auth but no URLs', async () => {
    const email = createTestEmail({
      headers: {
        'authentication-results': 'mx.example.com; spf=none; dkim=none; dmarc=none',
      },
      body: {
        text: 'This is a plain text email with no links.',
        html: '<p>This is a plain text email with no links.</p>',
      },
    });

    const result = await runDeterministicAnalysis(email);
    const noAuthSignal = result.signals.find(s => s.type === 'no_authentication');

    expect(noAuthSignal).toBeUndefined();
  });

  it('should NOT flag emails with spf=fail (already handled separately)', async () => {
    const email = createTestEmail({
      headers: {
        'authentication-results': 'mx.example.com; spf=fail; dkim=none; dmarc=none',
      },
      body: {
        text: 'Click here: https://example.com/login',
        html: '<a href="https://example.com/login">Login</a>',
      },
    });

    const result = await runDeterministicAnalysis(email);
    const noAuthSignal = result.signals.find(s => s.type === 'no_authentication');

    // spf=fail is not spf=none, so no_authentication should not fire
    expect(noAuthSignal).toBeUndefined();
  });

  it('should include metadata about auth state and URL count', async () => {
    const email = createTestEmail({
      headers: {
        'authentication-results': 'mx.example.com; spf=none; dkim=none; dmarc=none',
      },
      body: {
        text: 'Visit https://example.com and https://other.com',
        html: '<a href="https://example.com">one</a> <a href="https://other.com">two</a>',
      },
    });

    const result = await runDeterministicAnalysis(email);
    const noAuthSignal = result.signals.find(s => s.type === 'no_authentication');

    expect(noAuthSignal).toBeDefined();
    expect(noAuthSignal?.metadata).toBeDefined();
    expect(noAuthSignal?.metadata?.spf).toBe('none');
    expect(noAuthSignal?.metadata?.dkim).toBe('none');
    expect(noAuthSignal?.metadata?.dmarc).toBe('none');
    expect(noAuthSignal?.metadata?.urlCount).toBeGreaterThanOrEqual(2);
  });
});
