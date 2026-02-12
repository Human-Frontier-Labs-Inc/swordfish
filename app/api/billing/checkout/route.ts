/**
 * Create Stripe Checkout Session
 * POST /api/billing/checkout
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import Stripe from 'stripe';
import { sql } from '@/lib/db';
import { BillingService, calculatePerUserPrice, SubscriptionTier } from '@/lib/billing';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || '', {
  apiVersion: '2025-12-15.clover',
});

const billingService = new BillingService();

export async function POST(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();
    
    if (!userId || !orgId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const body = await request.json();
    const { tier, userCount, period = 'year' } = body as {
      tier: SubscriptionTier;
      userCount: number;
      period?: 'month' | 'year';
    };

    if (!tier || !userCount || userCount < 1) {
      return NextResponse.json(
        { error: 'Missing required fields: tier, userCount' },
        { status: 400 }
      );
    }

    if (!['pro', 'enterprise'].includes(tier)) {
      return NextResponse.json(
        { error: 'Invalid tier. Must be pro or enterprise.' },
        { status: 400 }
      );
    }

    // Get tenant
    const tenantResult = await sql`
      SELECT id, stripe_customer_id, name
      FROM tenants 
      WHERE clerk_org_id = ${orgId} 
      LIMIT 1
    `;

    if (tenantResult.length === 0) {
      return NextResponse.json(
        { error: 'Tenant not found' },
        { status: 404 }
      );
    }

    const tenant = tenantResult[0];
    let customerId = tenant.stripe_customer_id;

    // Create Stripe customer if doesn't exist
    if (!customerId) {
      // Get user email
      const userResult = await sql`
        SELECT email FROM users WHERE clerk_user_id = ${userId} LIMIT 1
      `;
      
      const email = userResult[0]?.email || `${orgId}@swordphish.io`;
      
      const customer = await billingService.createCustomer({
        email,
        tenantId: tenant.id,
        name: tenant.name,
      });

      customerId = customer.id;

      // Save customer ID
      await sql`
        UPDATE tenants
        SET stripe_customer_id = ${customerId}, updated_at = NOW()
        WHERE id = ${tenant.id}::uuid
      `;
    }

    // Calculate pricing
    const quote = calculatePerUserPrice(tier, userCount, period);
    
    // Get or create price in Stripe
    // For now, use line_items with unit_amount for flexibility
    const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';
    
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: `SwordPhish ${tier.charAt(0).toUpperCase() + tier.slice(1)}`,
              description: `${userCount} users - ${period}ly billing`,
            },
            unit_amount: quote.pricePerUser,
            recurring: {
              interval: period === 'year' ? 'year' : 'month',
            },
          },
          quantity: userCount,
        },
      ],
      subscription_data: {
        metadata: {
          tier,
          userCount: String(userCount),
          tenantId: tenant.id,
        },
      },
      success_url: `${baseUrl}/dashboard/settings?billing=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${baseUrl}/dashboard/settings?billing=canceled`,
      metadata: {
        tenantId: tenant.id,
        tier,
        userCount: String(userCount),
      },
    });

    return NextResponse.json({
      sessionId: session.id,
      url: session.url,
      quote: {
        tier,
        userCount,
        period,
        pricePerUser: quote.pricePerUser / 100, // Convert to dollars
        totalPrice: quote.totalPrice / 100,
        discountPercent: quote.discountPercent,
      },
    });
  } catch (error) {
    console.error('Checkout session error:', error);
    return NextResponse.json(
      { error: 'Failed to create checkout session' },
      { status: 500 }
    );
  }
}
