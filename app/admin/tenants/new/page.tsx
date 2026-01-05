'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { ArrowLeft } from 'lucide-react';
import Link from 'next/link';

import { Button } from '@/components/ui/button';
import { OnboardingWizard } from '@/components/msp/OnboardingWizard';

export default function NewTenantPage() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  const handleComplete = async (data: {
    organizationName: string;
    domain: string;
    plan: 'starter' | 'pro' | 'enterprise';
    integrationType: 'o365' | 'gmail' | 'smtp' | null;
    adminEmail: string;
    adminName: string;
    additionalUsers: Array<{ email: string; role: string }>;
    useDefaultPolicies: boolean;
    selectedPolicyTemplates: string[];
  }) => {
    try {
      const response = await fetch('/api/msp/tenants', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to create tenant');
      }

      const result = await response.json();

      // Redirect to the new tenant's detail page
      router.push(`/admin/tenants/${result.tenant.id}?onboarding=success`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
      throw err; // Re-throw so wizard shows error state
    }
  };

  const handleCancel = () => {
    router.push('/admin/tenants');
  };

  return (
    <div className="container mx-auto py-8 px-4">
      {/* Header */}
      <div className="mb-8">
        <Link href="/admin/tenants" className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground mb-4">
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Clients
        </Link>
        <h1 className="text-3xl font-bold">Add New Client</h1>
        <p className="text-muted-foreground mt-2">
          Set up a new client organization in the Swordfish platform
        </p>
      </div>

      {/* Global error display */}
      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-red-700">{error}</p>
          <Button
            variant="ghost"
            size="sm"
            className="mt-2 text-red-700"
            onClick={() => setError(null)}
          >
            Dismiss
          </Button>
        </div>
      )}

      {/* Onboarding Wizard */}
      <OnboardingWizard onComplete={handleComplete} onCancel={handleCancel} />
    </div>
  );
}
