/**
 * Billing Checkout API
 * POST - Create a Stripe Checkout Session for plan upgrades
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth, currentUser } from '@clerk/nextjs/server';
import { BillingService, stripe } from '@/lib/billing/stripe';

const billingService = new BillingService();

// Allowed price IDs to prevent arbitrary price injection
const ALLOWED_PRICE_IDS = new Set([
  process.env.STRIPE_STARTER_PRICE_ID || 'price_1TL60cGjNblFEnhd5HGhlZsm',
  process.env.STRIPE_PRO_PRICE_ID || 'price_1TL60dGjNblFEnhdQk8bIcuk',
  process.env.STRIPE_ENTERPRISE_PRICE_ID || 'price_1TL60eGjNblFEnhd8Nq0QCcM',
]);

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json() as { priceId?: string };
    const { priceId } = body;

    if (!priceId || typeof priceId !== 'string') {
      return NextResponse.json(
        { error: 'Missing required field: priceId' },
        { status: 400 }
      );
    }

    // Validate the price ID is one we recognize
    if (!ALLOWED_PRICE_IDS.has(priceId)) {
      return NextResponse.json(
        { error: 'Invalid price ID' },
        { status: 400 }
      );
    }

    const user = await currentUser();
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const email = user.emailAddresses[0]?.emailAddress;

    // Get or create Stripe customer
    // Check Clerk public metadata first for a stored customer ID
    let customerId = (user.publicMetadata as Record<string, unknown>)?.stripeCustomerId as string | undefined;

    if (!customerId) {
      // Search Stripe for existing customer by email
      const existingCustomers = await stripe.customers.list({
        email: email,
        limit: 1,
      });

      if (existingCustomers.data.length > 0) {
        customerId = existingCustomers.data[0].id;
      } else {
        // Create new customer
        const customer = await billingService.createCustomer({
          email: email || '',
          tenantId,
          name: `${user.firstName || ''} ${user.lastName || ''}`.trim() || undefined,
        });
        customerId = customer.id;
      }
    }

    const origin = request.nextUrl.origin;
    const session = await billingService.createCheckoutSession({
      customerId,
      priceId,
      successUrl: `${origin}/dashboard/billing?session_id={CHECKOUT_SESSION_ID}&status=success`,
      cancelUrl: `${origin}/dashboard/billing?status=cancelled`,
    });

    if (!session.url) {
      return NextResponse.json(
        { error: 'Failed to create checkout session' },
        { status: 500 }
      );
    }

    return NextResponse.json({ url: session.url });
  } catch (error) {
    console.error('Checkout session error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
