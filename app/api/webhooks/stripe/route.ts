/**
 * Stripe Webhook Handler
 * Handles subscription lifecycle and payment events
 *
 * Setup instructions:
 * 1. Go to Stripe Dashboard > Developers > Webhooks
 * 2. Add endpoint: https://your-domain.com/api/webhooks/stripe
 * 3. Subscribe to: customer.subscription.*, invoice.payment_*, checkout.session.completed
 * 4. Copy the webhook signing secret to STRIPE_WEBHOOK_SECRET env var
 */

import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';
import Stripe from 'stripe';
import { sql } from '@/lib/db';
import { logAuditEvent } from '@/lib/db/audit';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || '', {
  apiVersion: '2025-12-15.clover',
});

export async function POST(request: NextRequest) {
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!webhookSecret) {
    console.error('STRIPE_WEBHOOK_SECRET not configured');
    return NextResponse.json(
      { error: 'Webhook not configured' },
      { status: 500 }
    );
  }

  const body = await request.text();
  const headerPayload = await headers();
  const signature = headerPayload.get('stripe-signature');

  if (!signature) {
    return NextResponse.json(
      { error: 'Missing stripe-signature header' },
      { status: 400 }
    );
  }

  let event: Stripe.Event;

  try {
    event = stripe.webhooks.constructEvent(body, signature, webhookSecret);
  } catch (err) {
    console.error('Stripe webhook verification failed:', err);
    return NextResponse.json(
      { error: 'Invalid signature' },
      { status: 400 }
    );
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed':
        await handleCheckoutCompleted(event.data.object as Stripe.Checkout.Session);
        break;

      case 'customer.subscription.created':
        await handleSubscriptionCreated(event.data.object as Stripe.Subscription);
        break;

      case 'customer.subscription.updated':
        await handleSubscriptionUpdated(event.data.object as Stripe.Subscription);
        break;

      case 'customer.subscription.deleted':
        await handleSubscriptionDeleted(event.data.object as Stripe.Subscription);
        break;

      case 'invoice.payment_succeeded':
        await handlePaymentSucceeded(event.data.object as Stripe.Invoice);
        break;

      case 'invoice.payment_failed':
        await handlePaymentFailed(event.data.object as Stripe.Invoice);
        break;

      default:
        console.log(`Unhandled Stripe event: ${event.type}`);
    }

    return NextResponse.json({ received: true });
  } catch (error) {
    console.error('Stripe webhook processing error:', error);
    return NextResponse.json(
      { error: 'Processing failed' },
      { status: 500 }
    );
  }
}

/**
 * Handle checkout.session.completed
 * Creates/updates tenant subscription after successful checkout
 */
async function handleCheckoutCompleted(session: Stripe.Checkout.Session) {
  const customerId = session.customer as string;
  const subscriptionId = session.subscription as string;

  if (!customerId || !subscriptionId) {
    console.log('Checkout session missing customer or subscription');
    return;
  }

  // Find tenant by Stripe customer ID
  const tenantResult = await sql`
    SELECT id, clerk_org_id FROM tenants 
    WHERE stripe_customer_id = ${customerId} 
    LIMIT 1
  `;

  if (tenantResult.length === 0) {
    console.error(`No tenant found for Stripe customer: ${customerId}`);
    return;
  }

  const tenant = tenantResult[0];

  // Update tenant with subscription ID
  await sql`
    UPDATE tenants
    SET 
      stripe_subscription_id = ${subscriptionId},
      subscription_status = 'active',
      updated_at = NOW()
    WHERE id = ${tenant.id}::uuid
  `;

  await logAuditEvent({
    tenantId: tenant.clerk_org_id,
    actorId: 'stripe_webhook',
    actorEmail: 'system',
    action: 'subscription.checkout_completed',
    resourceType: 'subscription',
    resourceId: subscriptionId,
    afterState: {
      customerId,
      subscriptionId,
      sessionId: session.id,
    },
  });

  console.log(`Checkout completed for tenant ${tenant.id}, subscription: ${subscriptionId}`);
}

/**
 * Handle customer.subscription.created
 */
async function handleSubscriptionCreated(subscription: Stripe.Subscription) {
  const customerId = typeof subscription.customer === 'string' 
    ? subscription.customer 
    : subscription.customer?.id;
  const tier = (subscription.metadata?.tier as string) || 'standard';
  const userCount = parseInt(subscription.metadata?.userCount || '1', 10);
  
  // Get period end from the subscription object (cast through unknown for newer Stripe API versions)
  const periodEnd = (subscription as unknown as { current_period_end?: number }).current_period_end;

  // Update tenant subscription info
  await sql`
    UPDATE tenants
    SET 
      stripe_subscription_id = ${subscription.id},
      subscription_status = ${subscription.status},
      subscription_tier = ${tier},
      subscription_user_count = ${userCount},
      subscription_period_end = ${periodEnd ? `to_timestamp(${periodEnd})` : null},
      updated_at = NOW()
    WHERE stripe_customer_id = ${customerId}
  `;

  console.log(`Subscription created: ${subscription.id} (${tier}, ${userCount} users)`);
}

/**
 * Handle customer.subscription.updated
 * Handles upgrades, downgrades, and quantity changes
 */
async function handleSubscriptionUpdated(subscription: Stripe.Subscription) {
  const customerId = typeof subscription.customer === 'string' 
    ? subscription.customer 
    : subscription.customer?.id;
  const tier = (subscription.metadata?.tier as string) || 'standard';
  const userCount = parseInt(subscription.metadata?.userCount || '1', 10);
  
  // Get period end from the subscription object (cast through unknown for newer Stripe API versions)
  const periodEnd = (subscription as unknown as { current_period_end?: number }).current_period_end;

  // Find tenant
  const tenantResult = await sql`
    SELECT id, clerk_org_id, subscription_tier, subscription_user_count
    FROM tenants 
    WHERE stripe_customer_id = ${customerId} 
    LIMIT 1
  `;

  if (tenantResult.length === 0) {
    console.error(`No tenant found for Stripe customer: ${customerId}`);
    return;
  }

  const tenant = tenantResult[0];
  const previousTier = tenant.subscription_tier;
  const previousUserCount = tenant.subscription_user_count;

  // Update tenant subscription info
  await sql`
    UPDATE tenants
    SET 
      subscription_status = ${subscription.status},
      subscription_tier = ${tier},
      subscription_user_count = ${userCount},
      subscription_period_end = ${periodEnd ? `to_timestamp(${periodEnd})` : null},
      updated_at = NOW()
    WHERE id = ${tenant.id}::uuid
  `;

  // Determine what changed
  let action = 'subscription.updated';
  if (tier !== previousTier) {
    action = tier === 'enterprise' ? 'subscription.upgraded' : 'subscription.downgraded';
  } else if (userCount !== previousUserCount) {
    action = userCount > previousUserCount ? 'subscription.seats_added' : 'subscription.seats_removed';
  }

  await logAuditEvent({
    tenantId: tenant.clerk_org_id,
    actorId: 'stripe_webhook',
    actorEmail: 'system',
    action,
    resourceType: 'subscription',
    resourceId: subscription.id,
    beforeState: { tier: previousTier, userCount: previousUserCount },
    afterState: { tier, userCount, status: subscription.status },
  });

  console.log(`Subscription updated: ${subscription.id} (${previousTier} → ${tier}, ${previousUserCount} → ${userCount} users)`);
}

/**
 * Handle customer.subscription.deleted
 * Downgrades tenant to free tier
 */
async function handleSubscriptionDeleted(subscription: Stripe.Subscription) {
  const customerId = typeof subscription.customer === 'string' 
    ? subscription.customer 
    : subscription.customer?.id;

  const tenantResult = await sql`
    SELECT id, clerk_org_id FROM tenants 
    WHERE stripe_customer_id = ${customerId} 
    LIMIT 1
  `;

  if (tenantResult.length === 0) {
    console.error(`No tenant found for Stripe customer: ${customerId}`);
    return;
  }

  const tenant = tenantResult[0];

  // Downgrade to free tier
  await sql`
    UPDATE tenants
    SET 
      subscription_status = 'canceled',
      subscription_tier = 'free',
      subscription_user_count = 1,
      stripe_subscription_id = NULL,
      updated_at = NOW()
    WHERE id = ${tenant.id}::uuid
  `;

  await logAuditEvent({
    tenantId: tenant.clerk_org_id,
    actorId: 'stripe_webhook',
    actorEmail: 'system',
    action: 'subscription.canceled',
    resourceType: 'subscription',
    resourceId: subscription.id,
    afterState: { tier: 'free', status: 'canceled' },
  });

  console.log(`Subscription canceled for tenant ${tenant.id}, downgraded to free tier`);
}

/**
 * Handle invoice.payment_succeeded
 */
async function handlePaymentSucceeded(invoice: Stripe.Invoice) {
  const customerId = typeof invoice.customer === 'string' 
    ? invoice.customer 
    : invoice.customer?.id;
  
  // Get subscription ID - may be string or object depending on expansion
  const invoiceAny = invoice as unknown as Record<string, unknown>;
  const subscriptionId = typeof invoiceAny.subscription === 'string'
    ? invoiceAny.subscription
    : (invoiceAny.subscription as { id?: string } | null)?.id;

  if (!subscriptionId) {
    // One-time payment, not subscription
    return;
  }

  // Ensure subscription is active
  await sql`
    UPDATE tenants
    SET 
      subscription_status = 'active',
      updated_at = NOW()
    WHERE stripe_customer_id = ${customerId}
      AND stripe_subscription_id = ${subscriptionId}
  `;

  console.log(`Payment succeeded for subscription: ${subscriptionId}`);
}

/**
 * Handle invoice.payment_failed
 * Marks subscription as past_due
 */
async function handlePaymentFailed(invoice: Stripe.Invoice) {
  const customerId = typeof invoice.customer === 'string' 
    ? invoice.customer 
    : invoice.customer?.id;
  
  // Get subscription ID - may be string or object depending on expansion
  const invoiceAny = invoice as unknown as Record<string, unknown>;
  const subscriptionId = typeof invoiceAny.subscription === 'string'
    ? invoiceAny.subscription
    : (invoiceAny.subscription as { id?: string } | null)?.id;

  if (!subscriptionId) {
    return;
  }

  const tenantResult = await sql`
    SELECT id, clerk_org_id FROM tenants 
    WHERE stripe_customer_id = ${customerId} 
    LIMIT 1
  `;

  if (tenantResult.length === 0) {
    return;
  }

  const tenant = tenantResult[0];

  // Mark subscription as past_due
  await sql`
    UPDATE tenants
    SET 
      subscription_status = 'past_due',
      updated_at = NOW()
    WHERE id = ${tenant.id}::uuid
  `;

  await logAuditEvent({
    tenantId: tenant.clerk_org_id,
    actorId: 'stripe_webhook',
    actorEmail: 'system',
    action: 'subscription.payment_failed',
    resourceType: 'subscription',
    resourceId: subscriptionId,
    afterState: {
      invoiceId: invoice.id,
      amountDue: invoice.amount_due,
      attemptCount: invoice.attempt_count,
    },
  });

  console.log(`Payment failed for subscription: ${subscriptionId} (attempt ${invoice.attempt_count})`);
}
