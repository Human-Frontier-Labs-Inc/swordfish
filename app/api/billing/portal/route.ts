/**
 * Billing Portal API
 * POST - Create a Stripe Billing Portal session for subscription management
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth, currentUser } from '@clerk/nextjs/server';
import { BillingService, stripe, STRIPE_PORTAL_CONFIG_ID } from '@/lib/billing/stripe';

const billingService = new BillingService();

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const user = await currentUser();
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const email = user.emailAddresses[0]?.emailAddress;

    // Get or create Stripe customer
    let customerId = (user.publicMetadata as Record<string, unknown>)?.stripeCustomerId as string | undefined;

    if (!customerId) {
      const existingCustomers = await stripe.customers.list({
        email: email,
        limit: 1,
      });

      if (existingCustomers.data.length > 0) {
        customerId = existingCustomers.data[0].id;
      } else {
        const customer = await billingService.createCustomer({
          email: email || '',
          tenantId,
          name: `${user.firstName || ''} ${user.lastName || ''}`.trim() || undefined,
        });
        customerId = customer.id;
      }
    }

    const origin = request.nextUrl.origin;
    const session = await billingService.createBillingPortalSession({
      customerId,
      returnUrl: `${origin}/dashboard/billing`,
      configurationId: STRIPE_PORTAL_CONFIG_ID,
    });

    return NextResponse.json({ url: session.url });
  } catch (error) {
    console.error('Billing portal session error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
