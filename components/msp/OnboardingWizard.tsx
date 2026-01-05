'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Building2,
  Mail,
  Users,
  Shield,
  Check,
  ChevronRight,
  ChevronLeft,
  Loader2,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';

interface OnboardingData {
  // Step 1: Organization
  organizationName: string;
  domain: string;
  plan: 'starter' | 'pro' | 'enterprise';

  // Step 2: Integration
  integrationType: 'o365' | 'gmail' | 'smtp' | null;

  // Step 3: Users
  adminEmail: string;
  adminName: string;
  additionalUsers: Array<{ email: string; role: string }>;

  // Step 4: Policies
  useDefaultPolicies: boolean;
  selectedPolicyTemplates: string[];
}

const INITIAL_DATA: OnboardingData = {
  organizationName: '',
  domain: '',
  plan: 'pro',
  integrationType: null,
  adminEmail: '',
  adminName: '',
  additionalUsers: [],
  useDefaultPolicies: true,
  selectedPolicyTemplates: [],
};

const STEPS = [
  { id: 'organization', title: 'Organization', icon: Building2 },
  { id: 'integration', title: 'Email Integration', icon: Mail },
  { id: 'users', title: 'Users', icon: Users },
  { id: 'policies', title: 'Security Policies', icon: Shield },
];

interface OnboardingWizardProps {
  onComplete: (data: OnboardingData) => Promise<void>;
  onCancel: () => void;
}

export function OnboardingWizard({ onComplete, onCancel }: OnboardingWizardProps) {
  const [currentStep, setCurrentStep] = useState(0);
  const [data, setData] = useState<OnboardingData>(INITIAL_DATA);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  const updateData = (updates: Partial<OnboardingData>) => {
    setData((prev) => ({ ...prev, ...updates }));
    // Clear errors for updated fields
    const errorKeys = Object.keys(updates);
    setErrors((prev) => {
      const next = { ...prev };
      errorKeys.forEach((key) => delete next[key]);
      return next;
    });
  };

  const validateStep = (step: number): boolean => {
    const newErrors: Record<string, string> = {};

    switch (step) {
      case 0: // Organization
        if (!data.organizationName.trim()) {
          newErrors.organizationName = 'Organization name is required';
        }
        if (!data.domain.trim()) {
          newErrors.domain = 'Domain is required';
        } else if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(data.domain)) {
          newErrors.domain = 'Please enter a valid domain';
        }
        break;

      case 1: // Integration
        if (!data.integrationType) {
          newErrors.integrationType = 'Please select an email integration';
        }
        break;

      case 2: // Users
        if (!data.adminEmail.trim()) {
          newErrors.adminEmail = 'Admin email is required';
        } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.adminEmail)) {
          newErrors.adminEmail = 'Please enter a valid email';
        }
        if (!data.adminName.trim()) {
          newErrors.adminName = 'Admin name is required';
        }
        break;

      case 3: // Policies
        // No required fields
        break;
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleNext = () => {
    if (validateStep(currentStep)) {
      if (currentStep < STEPS.length - 1) {
        setCurrentStep((prev) => prev + 1);
      }
    }
  };

  const handleBack = () => {
    if (currentStep > 0) {
      setCurrentStep((prev) => prev - 1);
    }
  };

  const handleSubmit = async () => {
    if (!validateStep(currentStep)) return;

    setIsSubmitting(true);
    try {
      await onComplete(data);
    } catch (error) {
      setErrors({ submit: 'Failed to create client. Please try again.' });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto">
      {/* Progress Steps */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          {STEPS.map((step, index) => {
            const StepIcon = step.icon;
            const isComplete = index < currentStep;
            const isCurrent = index === currentStep;

            return (
              <div
                key={step.id}
                className={`flex items-center ${
                  index < STEPS.length - 1 ? 'flex-1' : ''
                }`}
              >
                <div className="flex flex-col items-center">
                  <div
                    className={`w-10 h-10 rounded-full flex items-center justify-center border-2 transition-colors ${
                      isComplete
                        ? 'bg-green-500 border-green-500 text-white'
                        : isCurrent
                        ? 'bg-blue-500 border-blue-500 text-white'
                        : 'bg-white border-gray-300 text-gray-400'
                    }`}
                  >
                    {isComplete ? (
                      <Check className="h-5 w-5" />
                    ) : (
                      <StepIcon className="h-5 w-5" />
                    )}
                  </div>
                  <span
                    className={`mt-2 text-sm font-medium ${
                      isCurrent ? 'text-blue-600' : 'text-gray-500'
                    }`}
                  >
                    {step.title}
                  </span>
                </div>
                {index < STEPS.length - 1 && (
                  <div
                    className={`flex-1 h-0.5 mx-4 ${
                      index < currentStep ? 'bg-green-500' : 'bg-gray-200'
                    }`}
                  />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Step Content */}
      <Card>
        <CardHeader>
          <CardTitle>{STEPS[currentStep].title}</CardTitle>
          <CardDescription>
            {currentStep === 0 && 'Enter the basic information for the new client organization.'}
            {currentStep === 1 && 'Choose how to connect their email system.'}
            {currentStep === 2 && 'Set up the initial admin user and invite team members.'}
            {currentStep === 3 && 'Configure security policies for the organization.'}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Step 1: Organization */}
          {currentStep === 0 && (
            <>
              <div className="space-y-2">
                <label className="text-sm font-medium">Organization Name *</label>
                <Input
                  value={data.organizationName}
                  onChange={(e) => updateData({ organizationName: e.target.value })}
                  placeholder="Acme Corporation"
                />
                {errors.organizationName && (
                  <p className="text-sm text-red-500">{errors.organizationName}</p>
                )}
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">Primary Domain *</label>
                <Input
                  value={data.domain}
                  onChange={(e) => updateData({ domain: e.target.value.toLowerCase() })}
                  placeholder="acme.com"
                />
                {errors.domain && (
                  <p className="text-sm text-red-500">{errors.domain}</p>
                )}
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">Plan</label>
                <div className="grid grid-cols-3 gap-4">
                  {(['starter', 'pro', 'enterprise'] as const).map((plan) => (
                    <div
                      key={plan}
                      onClick={() => updateData({ plan })}
                      className={`p-4 border rounded-lg cursor-pointer transition-colors ${
                        data.plan === plan
                          ? 'border-blue-500 bg-blue-50'
                          : 'border-gray-200 hover:border-gray-300'
                      }`}
                    >
                      <p className="font-medium capitalize">{plan}</p>
                      <p className="text-sm text-muted-foreground">
                        {plan === 'starter' && 'Up to 25 users'}
                        {plan === 'pro' && 'Up to 250 users'}
                        {plan === 'enterprise' && 'Unlimited users'}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}

          {/* Step 2: Integration */}
          {currentStep === 1 && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <IntegrationOption
                  type="o365"
                  title="Microsoft 365"
                  description="Connect via Microsoft Graph API"
                  selected={data.integrationType === 'o365'}
                  onSelect={() => updateData({ integrationType: 'o365' })}
                />
                <IntegrationOption
                  type="gmail"
                  title="Google Workspace"
                  description="Connect via Gmail API"
                  selected={data.integrationType === 'gmail'}
                  onSelect={() => updateData({ integrationType: 'gmail' })}
                />
                <IntegrationOption
                  type="smtp"
                  title="SMTP Gateway"
                  description="Generic SMTP integration"
                  selected={data.integrationType === 'smtp'}
                  onSelect={() => updateData({ integrationType: 'smtp' })}
                />
              </div>
              {errors.integrationType && (
                <p className="text-sm text-red-500">{errors.integrationType}</p>
              )}
              <p className="text-sm text-muted-foreground">
                You&apos;ll complete the OAuth connection after creating the client.
              </p>
            </>
          )}

          {/* Step 3: Users */}
          {currentStep === 2 && (
            <>
              <div className="space-y-4">
                <h3 className="font-medium">Primary Administrator</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Name *</label>
                    <Input
                      value={data.adminName}
                      onChange={(e) => updateData({ adminName: e.target.value })}
                      placeholder="John Smith"
                    />
                    {errors.adminName && (
                      <p className="text-sm text-red-500">{errors.adminName}</p>
                    )}
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Email *</label>
                    <Input
                      type="email"
                      value={data.adminEmail}
                      onChange={(e) => updateData({ adminEmail: e.target.value })}
                      placeholder="john@acme.com"
                    />
                    {errors.adminEmail && (
                      <p className="text-sm text-red-500">{errors.adminEmail}</p>
                    )}
                  </div>
                </div>
              </div>

              <div className="p-4 bg-blue-50 rounded-lg border border-blue-200">
                <p className="text-sm text-blue-800">
                  An invitation email will be sent to the admin after setup.
                  They&apos;ll be able to invite additional team members.
                </p>
              </div>
            </>
          )}

          {/* Step 4: Policies */}
          {currentStep === 3 && (
            <>
              <div className="space-y-4">
                <div
                  onClick={() => updateData({ useDefaultPolicies: true })}
                  className={`p-4 border rounded-lg cursor-pointer ${
                    data.useDefaultPolicies
                      ? 'border-blue-500 bg-blue-50'
                      : 'border-gray-200'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-medium">Use Default Policies</p>
                      <p className="text-sm text-muted-foreground">
                        Apply our recommended security policies
                      </p>
                    </div>
                    <Badge>Recommended</Badge>
                  </div>
                </div>

                <div
                  onClick={() => updateData({ useDefaultPolicies: false })}
                  className={`p-4 border rounded-lg cursor-pointer ${
                    !data.useDefaultPolicies
                      ? 'border-blue-500 bg-blue-50'
                      : 'border-gray-200'
                  }`}
                >
                  <p className="font-medium">Custom Setup</p>
                  <p className="text-sm text-muted-foreground">
                    Configure policies manually after creation
                  </p>
                </div>
              </div>

              {data.useDefaultPolicies && (
                <div className="p-4 bg-gray-50 rounded-lg">
                  <h4 className="font-medium mb-2">Default policies include:</h4>
                  <ul className="text-sm space-y-1 text-muted-foreground">
                    <li>• Block known malicious domains</li>
                    <li>• Quarantine suspicious attachments</li>
                    <li>• Warn on external sender impersonation</li>
                    <li>• Rewrite suspicious URLs for click-time protection</li>
                  </ul>
                </div>
              )}
            </>
          )}

          {errors.submit && (
            <p className="text-sm text-red-500 text-center">{errors.submit}</p>
          )}
        </CardContent>
      </Card>

      {/* Navigation Buttons */}
      <div className="flex justify-between mt-6">
        <Button variant="outline" onClick={currentStep === 0 ? onCancel : handleBack}>
          <ChevronLeft className="h-4 w-4 mr-2" />
          {currentStep === 0 ? 'Cancel' : 'Back'}
        </Button>

        {currentStep < STEPS.length - 1 ? (
          <Button onClick={handleNext}>
            Next
            <ChevronRight className="h-4 w-4 ml-2" />
          </Button>
        ) : (
          <Button onClick={handleSubmit} disabled={isSubmitting}>
            {isSubmitting ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Creating...
              </>
            ) : (
              <>
                Create Client
                <Check className="h-4 w-4 ml-2" />
              </>
            )}
          </Button>
        )}
      </div>
    </div>
  );
}

function IntegrationOption({
  type,
  title,
  description,
  selected,
  onSelect,
}: {
  type: string;
  title: string;
  description: string;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <div
      onClick={onSelect}
      className={`p-4 border rounded-lg cursor-pointer text-center transition-colors ${
        selected
          ? 'border-blue-500 bg-blue-50'
          : 'border-gray-200 hover:border-gray-300'
      }`}
    >
      <div className="w-12 h-12 mx-auto mb-3 bg-gray-100 rounded-lg flex items-center justify-center">
        {type === 'o365' && <span className="text-2xl">M</span>}
        {type === 'gmail' && <span className="text-2xl">G</span>}
        {type === 'smtp' && <Mail className="h-6 w-6 text-gray-600" />}
      </div>
      <p className="font-medium">{title}</p>
      <p className="text-sm text-muted-foreground">{description}</p>
    </div>
  );
}

export default OnboardingWizard;
