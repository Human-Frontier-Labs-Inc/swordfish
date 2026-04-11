'use client';

import { useState } from 'react';
import { useTenant } from '@/lib/auth/tenant-context';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

type PlanTier = 'starter' | 'pro' | 'enterprise';

interface PlanFeature {
  label: string;
  starter: string | boolean;
  pro: string | boolean;
  enterprise: string | boolean;
}

const PLAN_FEATURES: PlanFeature[] = [
  { label: 'Emails scanned / month', starter: '1,000', pro: '50,000', enterprise: 'Unlimited' },
  { label: 'Users', starter: '1', pro: '10', enterprise: 'Unlimited' },
  { label: 'Data retention', starter: '30 days', pro: '90 days', enterprise: '365 days' },
  { label: 'Advanced threat detection', starter: false, pro: true, enterprise: true },
  { label: 'Priority support', starter: false, pro: true, enterprise: true },
  { label: 'SSO / SAML', starter: false, pro: false, enterprise: true },
  { label: 'Custom integrations', starter: false, pro: false, enterprise: true },
  { label: 'Dedicated account manager', starter: false, pro: false, enterprise: true },
];

const PLAN_PRICING: Record<PlanTier, { monthly: number; label: string }> = {
  starter: { monthly: 0, label: 'Free' },
  pro: { monthly: 49, label: '$49/mo' },
  enterprise: { monthly: 199, label: '$199/mo' },
};

const PLAN_DESCRIPTIONS: Record<PlanTier, string> = {
  starter: 'For individuals and small teams getting started with email security.',
  pro: 'For growing teams that need advanced threat detection and more capacity.',
  enterprise: 'For organizations that require full-scale protection and dedicated support.',
};

// Map plan tiers to Stripe price IDs (env vars set server-side, these are the test-mode IDs)
const PLAN_PRICE_IDS: Record<PlanTier, string> = {
  starter: 'price_1TL60cGjNblFEnhd5HGhlZsm',
  pro: 'price_1TL60dGjNblFEnhdQk8bIcuk',
  enterprise: 'price_1TL60eGjNblFEnhd8Nq0QCcM',
};

function FeatureCheck({ included }: { included: boolean }) {
  if (included) {
    return (
      <svg className="h-5 w-5 text-green-500 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
      </svg>
    );
  }
  return (
    <svg className="h-5 w-5 text-gray-300 dark:text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}

function PlanCard({
  tier,
  currentPlan,
  loadingTier,
  managingPortal,
  onUpgrade,
  onManage,
}: {
  tier: PlanTier;
  currentPlan: PlanTier;
  loadingTier: PlanTier | null;
  managingPortal: boolean;
  onUpgrade: (tier: PlanTier) => void;
  onManage: () => void;
}) {
  const isCurrent = tier === currentPlan;
  const isUpgrade = getPlanRank(tier) > getPlanRank(currentPlan);
  const pricing = PLAN_PRICING[tier];
  const description = PLAN_DESCRIPTIONS[tier];
  const isLoading = loadingTier === tier;
  const isDisabled = loadingTier !== null || managingPortal;

  return (
    <Card
      className={`relative flex flex-col ${
        isCurrent
          ? 'border-blue-500 ring-2 ring-blue-500/20 dark:border-blue-400 dark:ring-blue-400/20'
          : 'border-gray-200 dark:border-gray-700'
      }`}
    >
      {isCurrent && (
        <div className="absolute -top-3 left-1/2 -translate-x-1/2">
          <Badge className="bg-blue-600 text-white dark:bg-blue-500">Current Plan</Badge>
        </div>
      )}
      {tier === 'pro' && !isCurrent && (
        <div className="absolute -top-3 left-1/2 -translate-x-1/2">
          <Badge className="bg-purple-600 text-white dark:bg-purple-500">Popular</Badge>
        </div>
      )}

      <CardHeader className="pb-4 pt-6 text-center">
        <CardTitle className="text-lg font-semibold text-gray-900 dark:text-white">
          {tier.charAt(0).toUpperCase() + tier.slice(1)}
        </CardTitle>
        <div className="mt-2">
          {pricing.monthly === 0 ? (
            <span className="text-3xl font-bold text-gray-900 dark:text-white">Free</span>
          ) : (
            <>
              <span className="text-3xl font-bold text-gray-900 dark:text-white">
                ${pricing.monthly}
              </span>
              <span className="text-sm text-gray-500 dark:text-gray-400">/month</span>
            </>
          )}
        </div>
        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">{description}</p>
      </CardHeader>

      <CardContent className="flex flex-1 flex-col justify-between gap-6">
        <ul className="space-y-3">
          {PLAN_FEATURES.map((feature) => {
            const value = feature[tier];
            return (
              <li key={feature.label} className="flex items-center gap-3 text-sm">
                {typeof value === 'boolean' ? (
                  <FeatureCheck included={value} />
                ) : (
                  <FeatureCheck included={true} />
                )}
                <span className="text-gray-700 dark:text-gray-300">
                  {typeof value === 'string' ? `${value} ${feature.label.toLowerCase()}` : feature.label}
                </span>
              </li>
            );
          })}
        </ul>

        <div className="pt-2">
          {isCurrent ? (
            <Button
              onClick={onManage}
              variant="outline"
              className="w-full"
              disabled={isDisabled}
            >
              {managingPortal ? (
                <span className="flex items-center gap-2">
                  <LoadingSpinner />
                  Opening portal...
                </span>
              ) : (
                'Manage Subscription'
              )}
            </Button>
          ) : isUpgrade ? (
            <Button
              onClick={() => onUpgrade(tier)}
              className="w-full bg-blue-600 text-white hover:bg-blue-700 dark:bg-blue-500 dark:hover:bg-blue-600"
              disabled={isDisabled}
            >
              {isLoading ? (
                <span className="flex items-center gap-2">
                  <LoadingSpinner />
                  Redirecting...
                </span>
              ) : (
                `Upgrade to ${tier.charAt(0).toUpperCase() + tier.slice(1)}`
              )}
            </Button>
          ) : (
            <Button
              variant="outline"
              className="w-full"
              disabled
            >
              Included in your plan
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function LoadingSpinner() {
  return (
    <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}

function getPlanRank(plan: PlanTier): number {
  const ranks: Record<PlanTier, number> = { starter: 0, pro: 1, enterprise: 2 };
  return ranks[plan];
}

export default function BillingPage() {
  const { currentTenant } = useTenant();
  const currentPlan: PlanTier = currentTenant?.plan ?? 'starter';

  const [loadingTier, setLoadingTier] = useState<PlanTier | null>(null);
  const [managingPortal, setManagingPortal] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleUpgrade(tier: PlanTier): Promise<void> {
    if (tier === 'enterprise') {
      window.open('mailto:sales@swordphish.io?subject=Enterprise%20Plan%20Inquiry', '_blank');
      return;
    }

    setError(null);
    setLoadingTier(tier);

    try {
      const priceId = PLAN_PRICE_IDS[tier];
      const response = await fetch('/api/billing/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ priceId }),
      });

      if (!response.ok) {
        const data = await response.json() as { error?: string };
        throw new Error(data.error || 'Failed to create checkout session');
      }

      const { url } = await response.json() as { url: string };
      window.location.href = url;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Something went wrong';
      setError(message);
      setLoadingTier(null);
    }
  }

  async function handleManage(): Promise<void> {
    setError(null);
    setManagingPortal(true);

    try {
      const response = await fetch('/api/billing/portal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });

      if (!response.ok) {
        const data = await response.json() as { error?: string };
        throw new Error(data.error || 'Failed to open billing portal');
      }

      const { url } = await response.json() as { url: string };
      window.location.href = url;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Something went wrong';
      setError(message);
      setManagingPortal(false);
    }
  }

  return (
    <div className="space-y-8">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Billing</h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Manage your subscription and view plan details.
        </p>
      </div>

      {/* Error banner */}
      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-900/20">
          <div className="flex items-start gap-3">
            <svg className="mt-0.5 h-5 w-5 flex-shrink-0 text-red-600 dark:text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
            </svg>
            <div>
              <p className="text-sm font-medium text-red-800 dark:text-red-200">
                Billing error
              </p>
              <p className="mt-1 text-sm text-red-700 dark:text-red-300">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Current plan summary */}
      <Card className="border-gray-200 dark:border-gray-700">
        <CardHeader>
          <CardTitle className="text-base font-medium text-gray-900 dark:text-white">
            Current Plan
          </CardTitle>
        </CardHeader>
        <CardContent className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-blue-100 dark:bg-blue-900/40">
              <svg className="h-6 w-6 text-blue-600 dark:text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <div>
              <p className="font-semibold text-gray-900 dark:text-white">
                {currentPlan.charAt(0).toUpperCase() + currentPlan.slice(1)} Plan
              </p>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {PLAN_PRICING[currentPlan].monthly === 0
                  ? 'Free forever'
                  : `${PLAN_PRICING[currentPlan].label} billed monthly`}
              </p>
            </div>
          </div>
          {currentPlan !== 'enterprise' && (
            <Badge variant="secondary" className="bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300">
              {currentPlan === 'starter' ? 'Upgrade available' : 'Enterprise upgrade available'}
            </Badge>
          )}
        </CardContent>
      </Card>

      {/* Plan comparison */}
      <div>
        <h2 className="mb-4 text-lg font-semibold text-gray-900 dark:text-white">
          Compare Plans
        </h2>
        <div className="grid gap-6 md:grid-cols-3">
          {(['starter', 'pro', 'enterprise'] as const).map((tier) => (
            <PlanCard
              key={tier}
              tier={tier}
              currentPlan={currentPlan}
              loadingTier={loadingTier}
              managingPortal={managingPortal}
              onUpgrade={handleUpgrade}
              onManage={handleManage}
            />
          ))}
        </div>
      </div>

      {/* Enterprise CTA */}
      <Card className="border-gray-200 bg-gradient-to-r from-gray-50 to-blue-50 dark:border-gray-700 dark:from-gray-800 dark:to-blue-900/20">
        <CardContent className="flex flex-col items-center gap-4 py-8 text-center sm:flex-row sm:text-left">
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Need a custom plan?
            </h3>
            <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
              We offer tailored solutions for large organizations, MSPs, and teams with specific compliance requirements.
            </p>
          </div>
          <Button
            onClick={() =>
              window.open(
                'mailto:sales@swordphish.io?subject=Custom%20Plan%20Inquiry',
                '_blank'
              )
            }
            variant="outline"
            className="shrink-0"
          >
            Contact Sales
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
