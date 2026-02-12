/**
 * Stripe Billing Service
 *
 * Subscription management, usage tracking, and payment handling
 */

import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder', {
  apiVersion: '2025-12-15.clover',
});

export type SubscriptionTier = 'free' | 'pro' | 'enterprise';
export type BillingPeriod = 'month' | 'year';

// Price IDs from Stripe Dashboard (per-user pricing)
const PRICE_IDS: Record<SubscriptionTier, { monthly: string; annual: string }> = {
  free: { monthly: 'price_free', annual: 'price_free' },
  pro: { monthly: 'price_pro_monthly_per_user', annual: 'price_pro_annual_per_user' },
  enterprise: { monthly: 'price_enterprise_monthly_per_user', annual: 'price_enterprise_annual_per_user' },
};

// Per-user pricing in cents (65% margin targeting)
// Pro: ~$40 cost/user/yr → $120/user/yr (~$10/mo)
// Enterprise: ~$60 cost/user/yr → $180/user/yr (~$15/mo)
const PRICING_PER_USER: Record<SubscriptionTier, { monthly: number; annual: number }> = {
  free: { monthly: 0, annual: 0 },
  pro: { monthly: 1000, annual: 12000 }, // $10/user/month or $120/user/year
  enterprise: { monthly: 1500, annual: 18000 }, // $15/user/month or $180/user/year
};

// Volume discount tiers (percentage off base price)
interface VolumeDiscount {
  minUsers: number;
  maxUsers: number;
  discountPercent: number;
}

const VOLUME_DISCOUNTS: VolumeDiscount[] = [
  { minUsers: 1, maxUsers: 50, discountPercent: 0 },
  { minUsers: 51, maxUsers: 250, discountPercent: 17 }, // ~$100/$150 per user/yr
  { minUsers: 251, maxUsers: 1000, discountPercent: 29 }, // ~$85/$130 per user/yr
  { minUsers: 1001, maxUsers: Infinity, discountPercent: 35 }, // Custom pricing baseline
];

/**
 * Calculate per-user price with volume discounts
 */
export function calculatePerUserPrice(
  tier: SubscriptionTier,
  userCount: number,
  period: BillingPeriod = 'year'
): { pricePerUser: number; totalPrice: number; discountPercent: number } {
  const basePrice = period === 'year' 
    ? PRICING_PER_USER[tier].annual 
    : PRICING_PER_USER[tier].monthly;
  
  const discount = VOLUME_DISCOUNTS.find(
    d => userCount >= d.minUsers && userCount <= d.maxUsers
  ) || VOLUME_DISCOUNTS[0];
  
  const discountedPrice = Math.round(basePrice * (1 - discount.discountPercent / 100));
  
  return {
    pricePerUser: discountedPrice,
    totalPrice: discountedPrice * userCount,
    discountPercent: discount.discountPercent,
  };
}

// Legacy flat pricing export (deprecated, use calculatePerUserPrice)
const PRICING = PRICING_PER_USER;

interface TierFeatures {
  retentionDays: number;
  advancedThreats: boolean;
  aiPoweredDetection: boolean;
  sso?: boolean;
  customIntegrations?: boolean;
  prioritySupport?: boolean;
  dedicatedAccount?: boolean;
  apiAccess?: boolean;
  customRules?: boolean;
}

const TIER_FEATURES: Record<SubscriptionTier, TierFeatures> = {
  free: {
    retentionDays: 30,
    advancedThreats: false,
    aiPoweredDetection: false,
  },
  pro: {
    retentionDays: 90,
    advancedThreats: true,
    aiPoweredDetection: true,
    prioritySupport: true,
    apiAccess: true,
    customRules: true,
  },
  enterprise: {
    retentionDays: 365,
    advancedThreats: true,
    aiPoweredDetection: true,
    sso: true,
    customIntegrations: true,
    prioritySupport: true,
    dedicatedAccount: true,
    apiAccess: true,
    customRules: true,
  },
};

export class PlanFeatures {
  static getFeatures(tier: SubscriptionTier): TierFeatures {
    return TIER_FEATURES[tier];
  }

  static hasFeature(tier: SubscriptionTier, feature: keyof TierFeatures): boolean {
    const features = TIER_FEATURES[tier];
    return !!features[feature];
  }
}

interface WebhookResult {
  handled: boolean;
  action?: string;
  data?: unknown;
}

export class BillingService {
  /**
   * Create a new Stripe customer
   */
  async createCustomer(params: {
    email: string;
    tenantId: string;
    name?: string;
  }): Promise<Stripe.Customer> {
    return stripe.customers.create({
      email: params.email,
      name: params.name,
      metadata: { tenantId: params.tenantId },
    });
  }

  /**
   * Get customer by ID
   */
  async getCustomer(customerId: string): Promise<Stripe.Customer> {
    return stripe.customers.retrieve(customerId) as Promise<Stripe.Customer>;
  }

  /**
   * Update customer information
   */
  async updateCustomer(
    customerId: string,
    params: Partial<{ email: string; name: string }>
  ): Promise<Stripe.Customer> {
    return stripe.customers.update(customerId, params);
  }

  /**
   * Create a subscription
   */
  async createSubscription(params: {
    customerId: string;
    priceId: string;
    tier: SubscriptionTier;
    period?: BillingPeriod;
  }): Promise<Stripe.Subscription> {
    return stripe.subscriptions.create({
      customer: params.customerId,
      items: [{ price: params.priceId }],
      metadata: { tier: params.tier },
    });
  }

  /**
   * Upgrade subscription to higher tier
   */
  async upgradeSubscription(
    subscriptionId: string,
    newTier: SubscriptionTier,
    period: BillingPeriod = 'month'
  ): Promise<Stripe.Subscription> {
    const subscription = await stripe.subscriptions.retrieve(subscriptionId);
    const itemId = subscription.items.data[0].id;
    const priceId = PRICE_IDS[newTier][period === 'month' ? 'monthly' : 'annual'];

    return stripe.subscriptions.update(subscriptionId, {
      items: [{ id: itemId, price: priceId }],
      proration_behavior: 'create_prorations',
      metadata: { tier: newTier },
    });
  }

  /**
   * Downgrade subscription to lower tier
   */
  async downgradeSubscription(
    subscriptionId: string,
    newTier: SubscriptionTier,
    period: BillingPeriod = 'month'
  ): Promise<Stripe.Subscription> {
    const subscription = await stripe.subscriptions.retrieve(subscriptionId);
    const itemId = subscription.items.data[0].id;
    const priceId = PRICE_IDS[newTier][period === 'month' ? 'monthly' : 'annual'];

    return stripe.subscriptions.update(subscriptionId, {
      items: [{ id: itemId, price: priceId }],
      proration_behavior: 'create_prorations',
      metadata: { tier: newTier },
    });
  }

  /**
   * Cancel subscription
   */
  async cancelSubscription(
    subscriptionId: string,
    options: { atPeriodEnd?: boolean; immediately?: boolean }
  ): Promise<Stripe.Subscription> {
    if (options.immediately) {
      return stripe.subscriptions.cancel(subscriptionId);
    }

    return stripe.subscriptions.update(subscriptionId, {
      cancel_at_period_end: true,
    });
  }

  /**
   * Resume a cancelled subscription
   */
  async resumeSubscription(subscriptionId: string): Promise<Stripe.Subscription> {
    return stripe.subscriptions.update(subscriptionId, {
      cancel_at_period_end: false,
    });
  }

  /**
   * Create checkout session for new subscription
   */
  async createCheckoutSession(params: {
    customerId: string;
    priceId: string;
    successUrl: string;
    cancelUrl: string;
  }): Promise<Stripe.Checkout.Session> {
    return stripe.checkout.sessions.create({
      customer: params.customerId,
      mode: 'subscription',
      line_items: [{ price: params.priceId, quantity: 1 }],
      success_url: params.successUrl,
      cancel_url: params.cancelUrl,
    });
  }

  /**
   * Create billing portal session
   */
  async createBillingPortalSession(params: {
    customerId: string;
    returnUrl: string;
  }): Promise<Stripe.BillingPortal.Session> {
    return stripe.billingPortal.sessions.create({
      customer: params.customerId,
      return_url: params.returnUrl,
    });
  }

  /**
   * List customer invoices
   */
  async listInvoices(customerId: string): Promise<Stripe.Invoice[]> {
    const result = await stripe.invoices.list({ customer: customerId });
    return result.data;
  }

  /**
   * Get specific invoice
   */
  async getInvoice(invoiceId: string): Promise<Stripe.Invoice> {
    return stripe.invoices.retrieve(invoiceId);
  }

  /**
   * Handle Stripe webhook events
   */
  async handleWebhook(event: {
    type: string;
    data: { object: Record<string, unknown> };
  }): Promise<WebhookResult> {
    switch (event.type) {
      case 'customer.subscription.created':
        return {
          handled: true,
          action: 'subscription_created',
          data: event.data.object,
        };

      case 'customer.subscription.updated':
        return {
          handled: true,
          action: 'subscription_updated',
          data: event.data.object,
        };

      case 'customer.subscription.deleted':
        return {
          handled: true,
          action: 'subscription_cancelled',
          data: event.data.object,
        };

      case 'invoice.payment_succeeded':
        return {
          handled: true,
          action: 'payment_succeeded',
          data: event.data.object,
        };

      case 'invoice.payment_failed':
        return {
          handled: true,
          action: 'payment_failed',
          data: event.data.object,
        };

      default:
        return { handled: false };
    }
  }

  /**
   * Get base per-user pricing (before volume discounts)
   */
  static getPricing(): Record<SubscriptionTier, { monthly: number; annual: number }> {
    return PRICING_PER_USER;
  }

  /**
   * Get pricing quote for a specific user count
   */
  static getQuote(
    tier: SubscriptionTier,
    userCount: number,
    period: BillingPeriod = 'year'
  ): {
    tier: SubscriptionTier;
    userCount: number;
    period: BillingPeriod;
    pricePerUser: number;
    totalPrice: number;
    discountPercent: number;
    annualTotal: number;
  } {
    const quote = calculatePerUserPrice(tier, userCount, period);
    return {
      tier,
      userCount,
      period,
      ...quote,
      annualTotal: period === 'year' ? quote.totalPrice : quote.totalPrice * 12,
    };
  }

  /**
   * Get volume discount tiers
   */
  static getVolumeDiscounts(): VolumeDiscount[] {
    return VOLUME_DISCOUNTS;
  }
}

// Usage tracking types
interface UsageRecord {
  tenantId: string;
  type: string;
  quantity: number;
  timestamp: Date;
}

interface UsageLimit {
  tenantId: string;
  type: string;
  limit: number;
}

interface UsageStatus {
  current: number;
  limit: number;
  remaining: number;
  percentUsed: number;
}

export class UsageTracker {
  private usage: UsageRecord[] = [];
  private limits: Map<string, UsageLimit> = new Map();

  /**
   * Record usage
   */
  async recordUsage(params: {
    tenantId: string;
    type: string;
    quantity: number;
  }): Promise<void> {
    this.usage.push({
      tenantId: params.tenantId,
      type: params.type,
      quantity: params.quantity,
      timestamp: new Date(),
    });
  }

  /**
   * Get usage for tenant
   */
  async getUsage(
    tenantId: string,
    type: string,
    options: { period?: 'day' | 'week' | 'month' } = {}
  ): Promise<{ total: number }> {
    const now = new Date();
    let startDate: Date;

    switch (options.period) {
      case 'day':
        startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case 'week':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case 'month':
      default:
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
    }

    const filtered = this.usage.filter(
      u => u.tenantId === tenantId && u.type === type && u.timestamp >= startDate
    );

    const total = filtered.reduce((sum, u) => sum + u.quantity, 0);
    return { total };
  }

  /**
   * Set usage limit
   */
  setLimit(tenantId: string, type: string, limit: number): void {
    this.limits.set(`${tenantId}:${type}`, { tenantId, type, limit });
  }

  /**
   * Check usage against limit
   */
  async checkLimit(tenantId: string, type: string): Promise<UsageStatus> {
    const usage = await this.getUsage(tenantId, type);
    const limitRecord = this.limits.get(`${tenantId}:${type}`);
    const limit = limitRecord?.limit || Infinity;

    return {
      current: usage.total,
      limit,
      remaining: Math.max(0, limit - usage.total),
      percentUsed: limit === Infinity ? 0 : Math.round((usage.total / limit) * 100),
    };
  }

  /**
   * Check if can use more
   */
  async canUse(tenantId: string, type: string, quantity: number): Promise<boolean> {
    const status = await this.checkLimit(tenantId, type);
    return status.remaining >= quantity;
  }

  /**
   * Report usage to Stripe for metered billing
   */
  async reportToStripe(params: {
    tenantId: string;
    subscriptionItemId: string;
    usageType: string;
  }): Promise<{ quantity: number }> {
    const usage = await this.getUsage(params.tenantId, params.usageType);

    // Use billing meter events for usage-based billing in newer Stripe API
    await stripe.billing.meterEvents.create({
      event_name: params.usageType,
      payload: {
        value: String(usage.total),
        stripe_customer_id: params.subscriptionItemId,
      },
    });

    return { quantity: usage.total };
  }

  /**
   * Reset usage for new billing period
   */
  resetUsage(tenantId: string, type?: string): void {
    this.usage = this.usage.filter(
      u => u.tenantId !== tenantId || (type && u.type !== type)
    );
  }
}
