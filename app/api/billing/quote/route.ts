/**
 * Get Pricing Quote
 * GET /api/billing/quote?tier=pro&userCount=100&period=year
 */

import { NextRequest, NextResponse } from 'next/server';
import { BillingService, calculatePerUserPrice, SubscriptionTier, BillingPeriod } from '@/lib/billing';

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const tier = searchParams.get('tier') as SubscriptionTier;
  const userCount = parseInt(searchParams.get('userCount') || '1', 10);
  const period = (searchParams.get('period') || 'year') as BillingPeriod;

  if (!tier || !['free', 'standard', 'enterprise'].includes(tier)) {
    return NextResponse.json(
      { error: 'Invalid tier. Must be free, standard, or enterprise.' },
      { status: 400 }
    );
  }

  if (userCount < 1 || userCount > 100000) {
    return NextResponse.json(
      { error: 'Invalid userCount. Must be between 1 and 100000.' },
      { status: 400 }
    );
  }

  // Get quote
  const quote = calculatePerUserPrice(tier, userCount, period);
  
  // Get volume discount tiers for reference
  const volumeDiscounts = BillingService.getVolumeDiscounts();

  return NextResponse.json({
    tier,
    userCount,
    period,
    pricePerUser: quote.pricePerUser / 100, // Convert cents to dollars
    totalPrice: quote.totalPrice / 100,
    annualTotal: period === 'year' 
      ? quote.totalPrice / 100 
      : (quote.totalPrice * 12) / 100,
    discountPercent: quote.discountPercent,
    volumeDiscounts: volumeDiscounts.map(d => ({
      range: d.maxUsers === Infinity 
        ? `${d.minUsers}+` 
        : `${d.minUsers}-${d.maxUsers}`,
      discountPercent: d.discountPercent,
    })),
    features: BillingService.getQuote(tier, userCount, period),
  });
}
