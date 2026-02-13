'use client';

import Link from 'next/link';
import { useState, useMemo } from 'react';
import { SignedIn, SignedOut } from '@clerk/nextjs';

// Volume discount tiers matching lib/billing/stripe.ts
const VOLUME_TIERS = [
  { min: 1, max: 99, price: 200, discount: 0 },
  { min: 100, max: 499, price: 176, discount: 12 },
  { min: 500, max: 999, price: 150, discount: 25 },
  { min: 1000, max: 4999, price: 126, discount: 37 },
  { min: 5000, max: Infinity, price: 100, discount: 50 },
];

function getPrice(userCount: number): { pricePerUser: number; discount: number } {
  const tier = VOLUME_TIERS.find(t => userCount >= t.min && userCount <= t.max) || VOLUME_TIERS[0];
  return { pricePerUser: tier.price, discount: tier.discount };
}

function formatCurrency(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function PricingPage() {
  const [userCount, setUserCount] = useState(100);
  const [billingPeriod, setBillingPeriod] = useState<'month' | 'year'>('year');

  const pricing = useMemo(() => {
    const { pricePerUser, discount } = getPrice(userCount);
    const monthlyPerUser = pricePerUser;
    const annualPerUser = pricePerUser * 12;
    const monthlyTotal = monthlyPerUser * userCount;
    const annualTotal = annualPerUser * userCount;
    
    // 17% discount for annual billing
    const annualDiscount = 17;
    const annualDiscountedTotal = Math.round(annualTotal * 0.83);
    const annualDiscountedPerUser = Math.round(annualPerUser * 0.83);

    return {
      userCount,
      volumeDiscount: discount,
      monthly: {
        perUser: monthlyPerUser,
        total: monthlyTotal,
      },
      annual: {
        perUser: annualDiscountedPerUser,
        total: annualDiscountedTotal,
        savings: annualTotal - annualDiscountedTotal,
      },
    };
  }, [userCount]);

  const displayPrice = billingPeriod === 'year' ? pricing.annual : pricing.monthly;

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-800">
      {/* Navigation */}
      <nav className="border-b border-slate-700/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <Link href="/" className="flex items-center gap-2">
              <svg className="w-8 h-8 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              <span className="text-xl font-bold text-white">Swordfish</span>
            </Link>
            <div className="flex items-center gap-4">
              <SignedOut>
                <Link href="/sign-in" className="text-slate-300 hover:text-white transition-colors">
                  Sign In
                </Link>
                <Link
                  href="/sign-up"
                  className="bg-cyan-500 hover:bg-cyan-400 text-white px-4 py-2 rounded-lg font-medium transition-colors"
                >
                  Get Started
                </Link>
              </SignedOut>
              <SignedIn>
                <Link
                  href="/dashboard"
                  className="bg-cyan-500 hover:bg-cyan-400 text-white px-4 py-2 rounded-lg font-medium transition-colors"
                >
                  Dashboard
                </Link>
              </SignedIn>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        {/* Hero */}
        <div className="text-center mb-16">
          <h1 className="text-4xl sm:text-5xl font-bold text-white mb-4">
            Enterprise Security.
            <span className="text-cyan-400"> Startup Pricing.</span>
          </h1>
          <p className="text-xl text-slate-300 max-w-2xl mx-auto">
            All security features included. No upsells on protection.
            The more you grow, the more you save.
          </p>
        </div>

        {/* Pricing Calculator */}
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-2xl p-8 mb-16">
          <div className="flex flex-col lg:flex-row gap-8">
            {/* Left: User Count Slider */}
            <div className="flex-1">
              <label className="block text-slate-300 text-sm font-medium mb-4">
                How many users do you need to protect?
              </label>
              <div className="mb-6">
                <input
                  type="range"
                  min="1"
                  max="5000"
                  value={userCount}
                  onChange={(e) => setUserCount(parseInt(e.target.value, 10))}
                  className="w-full h-2 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-cyan-500"
                />
                <div className="flex justify-between text-xs text-slate-500 mt-2">
                  <span>1</span>
                  <span>100</span>
                  <span>500</span>
                  <span>1,000</span>
                  <span>5,000+</span>
                </div>
              </div>
              <div className="flex items-center gap-4 mb-6">
                <input
                  type="number"
                  min="1"
                  max="100000"
                  value={userCount}
                  onChange={(e) => setUserCount(Math.max(1, parseInt(e.target.value, 10) || 1))}
                  className="w-32 px-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white text-center focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
                <span className="text-slate-400">users</span>
              </div>

              {/* Billing Toggle */}
              <div className="flex items-center gap-4">
                <span className={`text-sm ${billingPeriod === 'month' ? 'text-white' : 'text-slate-500'}`}>
                  Monthly
                </span>
                <button
                  onClick={() => setBillingPeriod(billingPeriod === 'month' ? 'year' : 'month')}
                  className={`relative w-14 h-7 rounded-full transition-colors ${
                    billingPeriod === 'year' ? 'bg-cyan-500' : 'bg-slate-600'
                  }`}
                >
                  <div
                    className={`absolute top-1 w-5 h-5 bg-white rounded-full transition-transform ${
                      billingPeriod === 'year' ? 'translate-x-8' : 'translate-x-1'
                    }`}
                  />
                </button>
                <span className={`text-sm ${billingPeriod === 'year' ? 'text-white' : 'text-slate-500'}`}>
                  Annual
                  <span className="ml-2 text-xs text-emerald-400 font-medium">Save 17%</span>
                </span>
              </div>
            </div>

            {/* Right: Price Display */}
            <div className="lg:w-80 bg-slate-900/50 rounded-xl p-6 text-center">
              {pricing.volumeDiscount > 0 && (
                <div className="inline-block bg-emerald-500/10 text-emerald-400 text-xs font-medium px-3 py-1 rounded-full mb-4">
                  {pricing.volumeDiscount}% volume discount applied
                </div>
              )}
              <div className="text-5xl font-bold text-white mb-2">
                {formatCurrency(displayPrice.perUser)}
                <span className="text-lg text-slate-400 font-normal">
                  /user/{billingPeriod === 'year' ? 'year' : 'month'}
                </span>
              </div>
              <div className="text-slate-400 mb-6">
                {formatCurrency(displayPrice.total)} total {billingPeriod === 'year' ? 'per year' : 'per month'}
              </div>
              {billingPeriod === 'year' && pricing.annual.savings > 0 && (
                <div className="text-emerald-400 text-sm mb-6">
                  You save {formatCurrency(pricing.annual.savings)}/year
                </div>
              )}
              <Link
                href="/sign-up"
                className="block w-full bg-cyan-500 hover:bg-cyan-400 text-white py-3 rounded-lg font-semibold transition-colors"
              >
                Start Free Trial
              </Link>
              <p className="text-slate-500 text-xs mt-3">14-day free trial. No credit card required.</p>
            </div>
          </div>
        </div>

        {/* Volume Discount Table */}
        <div className="mb-16">
          <h2 className="text-2xl font-bold text-white text-center mb-8">
            Volume Discounts
          </h2>
          <div className="grid sm:grid-cols-5 gap-4">
            {VOLUME_TIERS.map((tier, i) => (
              <div
                key={i}
                className={`bg-slate-800/50 border rounded-xl p-4 text-center transition-all ${
                  userCount >= tier.min && userCount <= tier.max
                    ? 'border-cyan-500 ring-2 ring-cyan-500/20'
                    : 'border-slate-700/50'
                }`}
              >
                <div className="text-slate-400 text-sm mb-2">
                  {tier.max === Infinity ? `${tier.min.toLocaleString()}+` : `${tier.min.toLocaleString()}-${tier.max.toLocaleString()}`}
                </div>
                <div className="text-2xl font-bold text-white">
                  {formatCurrency(tier.price)}
                </div>
                <div className="text-slate-500 text-xs">/user/month</div>
                {tier.discount > 0 && (
                  <div className="text-emerald-400 text-xs mt-2">
                    {tier.discount}% off
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Plan Comparison */}
        <div className="mb-16">
          <h2 className="text-2xl font-bold text-white text-center mb-8">
            Standard vs Enterprise
          </h2>
          <div className="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
            {/* Standard */}
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-2xl p-8">
              <div className="text-cyan-400 font-medium mb-2">Standard</div>
              <div className="text-3xl font-bold text-white mb-4">
                $2<span className="text-lg text-slate-400 font-normal">/user/month</span>
              </div>
              <p className="text-slate-400 text-sm mb-6">
                Everything you need to protect your organization from email threats.
              </p>
              <ul className="space-y-3 mb-8">
                {[
                  'AI-powered threat detection',
                  'Phishing & BEC protection',
                  'QR code attack detection',
                  'Malware & ransomware blocking',
                  'Real-time quarantine',
                  'Microsoft 365 & Google Workspace',
                  'API access',
                  'Custom detection rules',
                  '90-day retention',
                  'Email support',
                ].map((feature, i) => (
                  <li key={i} className="flex items-center gap-3 text-slate-300">
                    <svg className="w-5 h-5 text-emerald-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    {feature}
                  </li>
                ))}
              </ul>
              <Link
                href="/sign-up"
                className="block w-full text-center border border-cyan-500 text-cyan-400 hover:bg-cyan-500/10 py-3 rounded-lg font-semibold transition-colors"
              >
                Start Free Trial
              </Link>
            </div>

            {/* Enterprise */}
            <div className="bg-slate-800/50 border border-cyan-500/50 rounded-2xl p-8 relative">
              <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-cyan-500 text-white text-xs font-medium px-3 py-1 rounded-full">
                Recommended for 500+ users
              </div>
              <div className="text-cyan-400 font-medium mb-2">Enterprise</div>
              <div className="text-3xl font-bold text-white mb-4">
                $2.50<span className="text-lg text-slate-400 font-normal">/user/month</span>
              </div>
              <p className="text-slate-400 text-sm mb-6">
                Everything in Standard, plus enterprise-grade support and compliance.
              </p>
              <ul className="space-y-3 mb-8">
                {[
                  'Everything in Standard',
                  'SSO / SAML integration',
                  'Custom SIEM integrations',
                  'Dedicated account manager',
                  '99.9% SLA guarantee',
                  'Priority support (4hr response)',
                  'Custom webhooks',
                  '365-day retention',
                  'SOC 2 Type II report',
                  'Custom training & onboarding',
                ].map((feature, i) => (
                  <li key={i} className="flex items-center gap-3 text-slate-300">
                    <svg className="w-5 h-5 text-emerald-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    {feature}
                  </li>
                ))}
              </ul>
              <Link
                href="/sign-up?plan=enterprise"
                className="block w-full text-center bg-cyan-500 hover:bg-cyan-400 text-white py-3 rounded-lg font-semibold transition-colors"
              >
                Contact Sales
              </Link>
            </div>
          </div>
        </div>

        {/* Competitor Comparison */}
        <div className="bg-gradient-to-r from-cyan-500/10 to-purple-500/10 border border-cyan-500/20 rounded-2xl p-8 mb-16 text-center">
          <h2 className="text-2xl font-bold text-white mb-4">
            Why pay more for the same protection?
          </h2>
          <div className="flex flex-col sm:flex-row justify-center items-center gap-8 mb-6">
            <div className="text-center">
              <div className="text-slate-400 text-sm mb-1">Competitors</div>
              <div className="text-3xl font-bold text-slate-500 line-through">$3.00</div>
              <div className="text-slate-500 text-sm">/user/month</div>
            </div>
            <div className="text-4xl text-cyan-400">→</div>
            <div className="text-center">
              <div className="text-cyan-400 text-sm mb-1">Swordfish</div>
              <div className="text-3xl font-bold text-white">$1.26</div>
              <div className="text-slate-400 text-sm">/user/month at 1,000+ users</div>
            </div>
          </div>
          <p className="text-slate-300 max-w-xl mx-auto">
            Same AI-powered protection. Same advanced threat detection. 
            <span className="text-emerald-400 font-medium"> 58% less cost.</span>
          </p>
        </div>

        {/* FAQ */}
        <div className="max-w-3xl mx-auto mb-16">
          <h2 className="text-2xl font-bold text-white text-center mb-8">
            Frequently Asked Questions
          </h2>
          <div className="space-y-6">
            {[
              {
                q: 'Is there a free trial?',
                a: 'Yes! Every plan includes a 14-day free trial with full access to all features. No credit card required to start.',
              },
              {
                q: 'What counts as a user?',
                a: 'A user is any email address/mailbox being protected. Shared mailboxes and distribution lists are not counted.',
              },
              {
                q: 'Can I change my plan later?',
                a: 'Absolutely. You can upgrade, downgrade, or adjust user count at any time. Changes are prorated.',
              },
              {
                q: 'What email platforms do you support?',
                a: 'We support Microsoft 365 (Exchange Online) and Google Workspace. Setup takes less than 5 minutes.',
              },
              {
                q: 'Is my data secure?',
                a: 'Yes. We use end-to-end encryption, SOC 2 Type II compliant infrastructure, and never store email content permanently. Emails are analyzed in real-time and only metadata is retained.',
              },
              {
                q: 'Do you offer MSP/partner pricing?',
                a: 'Yes! MSPs and resellers get additional volume discounts and multi-tenant management tools. Contact us for partner pricing.',
              },
            ].map((faq, i) => (
              <div key={i} className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
                <h3 className="text-white font-medium mb-2">{faq.q}</h3>
                <p className="text-slate-400 text-sm">{faq.a}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Final CTA */}
        <div className="text-center">
          <h2 className="text-3xl font-bold text-white mb-4">
            Ready to protect your organization?
          </h2>
          <p className="text-slate-300 mb-8">
            Start your free trial today. Setup takes less than 5 minutes.
          </p>
          <div className="flex flex-col sm:flex-row justify-center gap-4">
            <Link
              href="/sign-up"
              className="bg-cyan-500 hover:bg-cyan-400 text-white px-8 py-3 rounded-lg font-semibold transition-colors"
            >
              Start Free Trial
            </Link>
            <Link
              href="/sign-up?demo=true"
              className="border border-slate-600 hover:border-slate-500 text-slate-300 hover:text-white px-8 py-3 rounded-lg font-semibold transition-colors"
            >
              Request Demo
            </Link>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-700/50 py-8 mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2">
              <svg className="w-6 h-6 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              <span className="text-slate-400">Swordfish</span>
            </div>
            <p className="text-slate-500 text-sm">
              &copy; 2026 Swordfish. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
