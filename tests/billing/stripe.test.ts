/**
 * Stripe Billing Integration Tests
 *
 * TDD tests for subscription management, usage tracking, and payments
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Create mock stripe instance using vi.hoisted
const { mockStripeInstance } = vi.hoisted(() => {
  return {
    mockStripeInstance: {
      customers: {
        create: vi.fn(),
        retrieve: vi.fn(),
        update: vi.fn(),
      },
      subscriptions: {
        create: vi.fn(),
        retrieve: vi.fn(),
        update: vi.fn(),
        cancel: vi.fn(),
        list: vi.fn(),
      },
      subscriptionItems: {
        createUsageRecord: vi.fn(),
      },
      billing: {
        meterEvents: {
          create: vi.fn(),
        },
      },
      checkout: {
        sessions: {
          create: vi.fn(),
        },
      },
      billingPortal: {
        sessions: {
          create: vi.fn(),
        },
      },
      prices: {
        list: vi.fn(),
      },
      invoices: {
        list: vi.fn(),
        retrieve: vi.fn(),
      },
      paymentMethods: {
        list: vi.fn(),
      },
      webhooks: {
        constructEvent: vi.fn(),
      },
    },
  };
});

// Mock Stripe constructor
vi.mock('stripe', () => ({
  default: vi.fn(() => mockStripeInstance),
}));

import {
  BillingService,
  UsageTracker,
  PlanFeatures,
} from '@/lib/billing/stripe';

describe('Billing Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Customer Management', () => {
    it('should create a new Stripe customer', async () => {
      mockStripeInstance.customers.create.mockResolvedValueOnce({
        id: 'cus_test123',
        email: 'user@example.com',
        metadata: { tenantId: 'tenant-1' },
      });

      const billing = new BillingService();
      const customer = await billing.createCustomer({
        email: 'user@example.com',
        tenantId: 'tenant-1',
        name: 'Test User',
      });

      expect(customer.id).toBe('cus_test123');
      expect(mockStripeInstance.customers.create).toHaveBeenCalledWith({
        email: 'user@example.com',
        name: 'Test User',
        metadata: { tenantId: 'tenant-1' },
      });
    });

    it('should retrieve existing customer', async () => {
      mockStripeInstance.customers.retrieve.mockResolvedValueOnce({
        id: 'cus_test123',
        email: 'user@example.com',
        subscriptions: { data: [] },
      });

      const billing = new BillingService();
      const customer = await billing.getCustomer('cus_test123');

      expect(customer.id).toBe('cus_test123');
    });

    it('should update customer billing info', async () => {
      mockStripeInstance.customers.update.mockResolvedValueOnce({
        id: 'cus_test123',
        email: 'newemail@example.com',
      });

      const billing = new BillingService();
      const updated = await billing.updateCustomer('cus_test123', {
        email: 'newemail@example.com',
      });

      expect(updated.email).toBe('newemail@example.com');
    });
  });

  describe('Subscription Management', () => {
    it('should create a subscription', async () => {
      mockStripeInstance.subscriptions.create.mockResolvedValueOnce({
        id: 'sub_test123',
        status: 'active',
        current_period_end: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
        items: {
          data: [{ id: 'si_test123', price: { id: 'price_pro' } }],
        },
      });

      const billing = new BillingService();
      const subscription = await billing.createSubscription({
        customerId: 'cus_test123',
        priceId: 'price_pro',
        tier: 'pro',
      });

      expect(subscription.id).toBe('sub_test123');
      expect(subscription.status).toBe('active');
    });

    it('should upgrade subscription tier', async () => {
      mockStripeInstance.subscriptions.retrieve.mockResolvedValueOnce({
        id: 'sub_test123',
        items: { data: [{ id: 'si_test123' }] },
      });

      mockStripeInstance.subscriptions.update.mockResolvedValueOnce({
        id: 'sub_test123',
        status: 'active',
        items: {
          data: [{ price: { id: 'price_enterprise' } }],
        },
      });

      const billing = new BillingService();
      await billing.upgradeSubscription('sub_test123', 'enterprise');

      expect(mockStripeInstance.subscriptions.update).toHaveBeenCalled();
    });

    it('should downgrade subscription tier', async () => {
      mockStripeInstance.subscriptions.retrieve.mockResolvedValueOnce({
        id: 'sub_test123',
        items: { data: [{ id: 'si_test123' }] },
      });

      mockStripeInstance.subscriptions.update.mockResolvedValueOnce({
        id: 'sub_test123',
        status: 'active',
      });

      const billing = new BillingService();
      await billing.downgradeSubscription('sub_test123', 'pro');

      expect(mockStripeInstance.subscriptions.update).toHaveBeenCalledWith(
        'sub_test123',
        expect.objectContaining({
          proration_behavior: 'create_prorations',
        })
      );
    });

    it('should cancel subscription at period end', async () => {
      mockStripeInstance.subscriptions.update.mockResolvedValueOnce({
        id: 'sub_test123',
        cancel_at_period_end: true,
      });

      const billing = new BillingService();
      const cancelled = await billing.cancelSubscription('sub_test123', {
        atPeriodEnd: true,
      });

      expect(cancelled.cancel_at_period_end).toBe(true);
    });

    it('should immediately cancel subscription', async () => {
      mockStripeInstance.subscriptions.cancel.mockResolvedValueOnce({
        id: 'sub_test123',
        status: 'canceled',
      });

      const billing = new BillingService();
      const cancelled = await billing.cancelSubscription('sub_test123', {
        immediately: true,
      });

      expect(cancelled.status).toBe('canceled');
    });

    it('should resume cancelled subscription', async () => {
      mockStripeInstance.subscriptions.update.mockResolvedValueOnce({
        id: 'sub_test123',
        cancel_at_period_end: false,
        status: 'active',
      });

      const billing = new BillingService();
      const resumed = await billing.resumeSubscription('sub_test123');

      expect(resumed.cancel_at_period_end).toBe(false);
    });
  });

  describe('Checkout Sessions', () => {
    it('should create checkout session for new subscription', async () => {
      mockStripeInstance.checkout.sessions.create.mockResolvedValueOnce({
        id: 'cs_test123',
        url: 'https://checkout.stripe.com/pay/cs_test123',
      });

      const billing = new BillingService();
      const session = await billing.createCheckoutSession({
        customerId: 'cus_test123',
        priceId: 'price_pro',
        successUrl: 'https://app.swordfish.com/success',
        cancelUrl: 'https://app.swordfish.com/cancel',
      });

      expect(session.url).toContain('checkout.stripe.com');
    });

    it('should create billing portal session', async () => {
      mockStripeInstance.billingPortal.sessions.create.mockResolvedValueOnce({
        id: 'bps_test123',
        url: 'https://billing.stripe.com/session/bps_test123',
      });

      const billing = new BillingService();
      const session = await billing.createBillingPortalSession({
        customerId: 'cus_test123',
        returnUrl: 'https://app.swordfish.com/settings',
      });

      expect(session.url).toContain('billing.stripe.com');
    });
  });

  describe('Plan Features', () => {
    it('should return features for free tier', () => {
      const features = PlanFeatures.getFeatures('free');

      expect(features.emailsPerMonth).toBe(1000);
      expect(features.users).toBe(1);
      expect(features.retentionDays).toBe(30);
      expect(features.advancedThreats).toBe(false);
    });

    it('should return features for pro tier', () => {
      const features = PlanFeatures.getFeatures('pro');

      expect(features.emailsPerMonth).toBe(50000);
      expect(features.users).toBe(10);
      expect(features.retentionDays).toBe(90);
      expect(features.advancedThreats).toBe(true);
    });

    it('should return features for enterprise tier', () => {
      const features = PlanFeatures.getFeatures('enterprise');

      expect(features.emailsPerMonth).toBe(-1); // Unlimited
      expect(features.users).toBe(-1); // Unlimited
      expect(features.retentionDays).toBe(365);
      expect(features.sso).toBe(true);
      expect(features.customIntegrations).toBe(true);
    });

    it('should check if feature is available', () => {
      expect(PlanFeatures.hasFeature('free', 'advancedThreats')).toBe(false);
      expect(PlanFeatures.hasFeature('pro', 'advancedThreats')).toBe(true);
      expect(PlanFeatures.hasFeature('pro', 'sso')).toBe(false);
      expect(PlanFeatures.hasFeature('enterprise', 'sso')).toBe(true);
    });
  });
});

describe('Usage Tracking', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Email Usage', () => {
    it('should track email scans', async () => {
      const tracker = new UsageTracker();

      await tracker.recordUsage({
        tenantId: 'tenant-1',
        type: 'email_scan',
        quantity: 1,
      });

      const usage = await tracker.getUsage('tenant-1', 'email_scan');
      expect(usage.total).toBe(1);
    });

    it('should aggregate usage by period', async () => {
      const tracker = new UsageTracker();

      // Record multiple usages
      for (let i = 0; i < 10; i++) {
        await tracker.recordUsage({
          tenantId: 'tenant-1',
          type: 'email_scan',
          quantity: 1,
        });
      }

      const usage = await tracker.getUsage('tenant-1', 'email_scan', {
        period: 'month',
      });

      expect(usage.total).toBe(10);
    });

    it('should check usage limits', async () => {
      const tracker = new UsageTracker();

      // Set limit
      tracker.setLimit('tenant-1', 'email_scan', 100);

      // Record usage near limit
      for (let i = 0; i < 95; i++) {
        await tracker.recordUsage({
          tenantId: 'tenant-1',
          type: 'email_scan',
          quantity: 1,
        });
      }

      const status = await tracker.checkLimit('tenant-1', 'email_scan');

      expect(status.current).toBe(95);
      expect(status.limit).toBe(100);
      expect(status.remaining).toBe(5);
      expect(status.percentUsed).toBe(95);
    });

    it('should block usage when limit exceeded', async () => {
      const tracker = new UsageTracker();

      tracker.setLimit('tenant-1', 'email_scan', 10);

      for (let i = 0; i < 10; i++) {
        await tracker.recordUsage({
          tenantId: 'tenant-1',
          type: 'email_scan',
          quantity: 1,
        });
      }

      const canUse = await tracker.canUse('tenant-1', 'email_scan', 1);
      expect(canUse).toBe(false);
    });
  });

  describe('Metered Billing', () => {
    it('should report usage to Stripe', async () => {
      mockStripeInstance.billing.meterEvents.create.mockResolvedValueOnce({
        id: 'mev_test123',
      });

      const tracker = new UsageTracker();

      // Record usage
      for (let i = 0; i < 100; i++) {
        await tracker.recordUsage({
          tenantId: 'tenant-1',
          type: 'email_scan',
          quantity: 1,
        });
      }

      const reported = await tracker.reportToStripe({
        tenantId: 'tenant-1',
        subscriptionItemId: 'si_test123',
        usageType: 'email_scan',
      });

      expect(reported.quantity).toBe(100);
      expect(mockStripeInstance.billing.meterEvents.create).toHaveBeenCalled();
    });
  });
});

describe('Invoice Management', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should list customer invoices', async () => {
    mockStripeInstance.invoices.list.mockResolvedValueOnce({
      data: [
        { id: 'in_1', amount_paid: 9900, status: 'paid', created: Date.now() / 1000 },
        { id: 'in_2', amount_paid: 9900, status: 'paid', created: Date.now() / 1000 },
      ],
    });

    const billing = new BillingService();
    const invoices = await billing.listInvoices('cus_test123');

    expect(invoices.length).toBe(2);
    expect(invoices[0].status).toBe('paid');
  });

  it('should retrieve specific invoice', async () => {
    mockStripeInstance.invoices.retrieve.mockResolvedValueOnce({
      id: 'in_test123',
      amount_paid: 9900,
      status: 'paid',
      invoice_pdf: 'https://stripe.com/invoice.pdf',
    });

    const billing = new BillingService();
    const invoice = await billing.getInvoice('in_test123');

    expect(invoice.invoice_pdf).toContain('invoice.pdf');
  });
});

describe('Webhook Handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should handle subscription created event', async () => {
    const billing = new BillingService();

    const result = await billing.handleWebhook({
      type: 'customer.subscription.created',
      data: {
        object: {
          id: 'sub_test123',
          customer: 'cus_test123',
          status: 'active',
          metadata: { tenantId: 'tenant-1' },
        },
      },
    });

    expect(result.handled).toBe(true);
    expect(result.action).toBe('subscription_created');
  });

  it('should handle subscription updated event', async () => {
    const billing = new BillingService();

    const result = await billing.handleWebhook({
      type: 'customer.subscription.updated',
      data: {
        object: {
          id: 'sub_test123',
          status: 'active',
          metadata: { tenantId: 'tenant-1' },
        },
      },
    });

    expect(result.handled).toBe(true);
  });

  it('should handle subscription cancelled event', async () => {
    const billing = new BillingService();

    const result = await billing.handleWebhook({
      type: 'customer.subscription.deleted',
      data: {
        object: {
          id: 'sub_test123',
          status: 'canceled',
          metadata: { tenantId: 'tenant-1' },
        },
      },
    });

    expect(result.handled).toBe(true);
    expect(result.action).toBe('subscription_cancelled');
  });

  it('should handle payment succeeded event', async () => {
    const billing = new BillingService();

    const result = await billing.handleWebhook({
      type: 'invoice.payment_succeeded',
      data: {
        object: {
          id: 'in_test123',
          customer: 'cus_test123',
          amount_paid: 9900,
        },
      },
    });

    expect(result.handled).toBe(true);
  });

  it('should handle payment failed event', async () => {
    const billing = new BillingService();

    const result = await billing.handleWebhook({
      type: 'invoice.payment_failed',
      data: {
        object: {
          id: 'in_test123',
          customer: 'cus_test123',
          attempt_count: 3,
        },
      },
    });

    expect(result.handled).toBe(true);
    expect(result.action).toBe('payment_failed');
  });
});

describe('Pricing', () => {
  it('should return pricing information', () => {
    const pricing = BillingService.getPricing();

    expect(pricing.free.monthly).toBe(0);
    expect(pricing.pro.monthly).toBeGreaterThan(0);
    expect(pricing.enterprise.monthly).toBeGreaterThan(pricing.pro.monthly);
  });

  it('should calculate annual discount', () => {
    const pricing = BillingService.getPricing();

    const monthlyTotal = pricing.pro.monthly * 12;
    const annualTotal = pricing.pro.annual;

    expect(annualTotal).toBeLessThan(monthlyTotal);
  });
});
