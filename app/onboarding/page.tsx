'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useUser, useOrganization, useOrganizationList } from '@clerk/nextjs';
import { Building2, Users, Shield, Mail, Check } from 'lucide-react';

interface OnboardingStep {
  id: number;
  title: string;
  description: string;
  completed: boolean;
}

const ONBOARDING_STEPS: Omit<OnboardingStep, 'completed'>[] = [
  {
    id: 1,
    title: 'Welcome to Swordfish',
    description: 'Protect your organization from email threats with AI-powered detection.',
  },
  {
    id: 2,
    title: 'Choose Account Type',
    description: 'Select how you will use Swordfish.',
  },
  {
    id: 3,
    title: 'Connect Email Provider',
    description: 'Link your Microsoft 365 or Google Workspace account.',
  },
  {
    id: 4,
    title: 'Configure Detection',
    description: 'Set your security thresholds and policies.',
  },
  {
    id: 5,
    title: 'Setup Notifications',
    description: 'Choose how you want to be alerted about threats.',
  },
  {
    id: 6,
    title: 'You\'re All Set!',
    description: 'Start monitoring your email security.',
  },
];

type AccountType = 'single' | 'msp' | null;

export default function OnboardingPage() {
  const router = useRouter();
  const { user, isLoaded: userLoaded } = useUser();
  const { organization } = useOrganization();
  const { createOrganization } = useOrganizationList();

  const [currentStep, setCurrentStep] = useState(1);
  const [steps, setSteps] = useState<OnboardingStep[]>(
    ONBOARDING_STEPS.map(s => ({ ...s, completed: false }))
  );
  const [loading, setLoading] = useState(false);
  const [accountType, setAccountType] = useState<AccountType>(null);
  const [orgName, setOrgName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [settings, setSettings] = useState({
    detection: {
      suspiciousThreshold: 30,
      quarantineThreshold: 60,
      blockThreshold: 80,
    },
    notifications: {
      emailEnabled: true,
      slackEnabled: false,
    },
  });

  useEffect(() => {
    if (userLoaded && !user) {
      router.push('/sign-in');
    }
  }, [userLoaded, user, router]);

  useEffect(() => {
    // Check existing onboarding progress
    fetch('/api/onboarding')
      .then(res => res.json())
      .then(data => {
        if (data.completed) {
          // Check if MSP and route accordingly
          if (data.isMsp) {
            router.push('/admin');
          } else {
            router.push('/dashboard');
          }
        } else if (data.currentStep) {
          setCurrentStep(data.currentStep);
          if (data.accountType) {
            setAccountType(data.accountType);
          }
          setSteps(prev => prev.map(s => ({
            ...s,
            completed: data.completedSteps?.includes(s.id) || false,
          })));
        }
      })
      .catch(() => {
        // First time user, start fresh
      });
  }, [router]);

  const handleAccountTypeSelect = async (type: AccountType) => {
    setAccountType(type);
    setError(null);
  };

  const handleCreateOrganization = async () => {
    if (!orgName.trim()) {
      setError('Please enter an organization name');
      return false;
    }

    setLoading(true);
    setError(null);

    try {
      // Create organization via Clerk
      if (createOrganization) {
        const org = await createOrganization({ name: orgName });

        // Set isMsp metadata via our API
        const response = await fetch('/api/onboarding/setup-account', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            organizationId: org.id,
            accountType: accountType,
            organizationName: orgName,
          }),
        });

        if (!response.ok) {
          const data = await response.json();
          throw new Error(data.error || 'Failed to setup account');
        }
      }

      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create organization');
      return false;
    } finally {
      setLoading(false);
    }
  };

  const handleNext = async () => {
    setLoading(true);
    setError(null);

    try {
      // Special handling for account type step
      if (currentStep === 2) {
        if (!accountType) {
          setError('Please select an account type');
          setLoading(false);
          return;
        }

        // If user doesn't have an org, create one
        if (!organization && orgName) {
          const success = await handleCreateOrganization();
          if (!success) {
            setLoading(false);
            return;
          }
        } else if (!organization && !orgName) {
          setError('Please enter an organization name');
          setLoading(false);
          return;
        } else if (organization) {
          // Update existing org with account type
          const response = await fetch('/api/onboarding/setup-account', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              organizationId: organization.id,
              accountType: accountType,
            }),
          });

          if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to setup account');
          }
        }
      }

      // Mark current step as completed
      await fetch('/api/onboarding', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          currentStep: currentStep + 1,
          completedStep: currentStep,
          accountType: accountType,
        }),
      });

      setSteps(prev => prev.map(s =>
        s.id === currentStep ? { ...s, completed: true } : s
      ));

      if (currentStep === ONBOARDING_STEPS.length) {
        // Save settings and complete onboarding
        await fetch('/api/settings', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ settings }),
        });

        await fetch('/api/onboarding', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ completed: true, accountType }),
        });

        // Route based on account type
        if (accountType === 'msp') {
          router.push('/admin');
        } else {
          router.push('/dashboard');
        }
      } else {
        setCurrentStep(prev => prev + 1);
      }
    } catch (err) {
      console.error('Onboarding error:', err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleSkip = async () => {
    setLoading(true);

    try {
      await fetch('/api/onboarding', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          currentStep: currentStep + 1,
          skippedStep: currentStep,
        }),
      });

      if (currentStep === ONBOARDING_STEPS.length) {
        if (accountType === 'msp') {
          router.push('/admin');
        } else {
          router.push('/dashboard');
        }
      } else {
        setCurrentStep(prev => prev + 1);
      }
    } catch (err) {
      console.error('Skip error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleConnectMicrosoft = () => {
    window.location.href = '/api/auth/microsoft';
  };

  const handleConnectGoogle = () => {
    window.location.href = '/api/auth/google';
  };

  const renderStepContent = () => {
    switch (currentStep) {
      case 1:
        return (
          <div className="text-center">
            <div className="text-6xl mb-6">
              <Shield className="w-16 h-16 mx-auto text-blue-600" />
            </div>
            <h2 className="text-2xl font-bold mb-4">Welcome to Swordfish</h2>
            <p className="text-gray-600 mb-6">
              Your AI-powered email security platform. We&apos;ll help you set up protection
              against phishing, BEC, malware, and spam in just a few minutes.
            </p>
            <div className="grid grid-cols-2 gap-4 text-left max-w-md mx-auto">
              <div className="flex items-center gap-2">
                <Check className="w-5 h-5 text-green-500" />
                <span>Phishing Detection</span>
              </div>
              <div className="flex items-center gap-2">
                <Check className="w-5 h-5 text-green-500" />
                <span>BEC Prevention</span>
              </div>
              <div className="flex items-center gap-2">
                <Check className="w-5 h-5 text-green-500" />
                <span>Malware Scanning</span>
              </div>
              <div className="flex items-center gap-2">
                <Check className="w-5 h-5 text-green-500" />
                <span>Spam Filtering</span>
              </div>
            </div>
          </div>
        );

      case 2:
        return (
          <div className="text-center">
            <h2 className="text-2xl font-bold mb-4">How will you use Swordfish?</h2>
            <p className="text-gray-600 mb-8">
              Select the option that best describes your organization.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-2xl mx-auto mb-8">
              {/* Single Company Option */}
              <div
                onClick={() => handleAccountTypeSelect('single')}
                className={`p-6 border-2 rounded-xl cursor-pointer transition-all ${
                  accountType === 'single'
                    ? 'border-blue-500 bg-blue-50 shadow-md'
                    : 'border-gray-200 hover:border-gray-300 hover:shadow'
                }`}
              >
                <div className={`w-16 h-16 mx-auto mb-4 rounded-full flex items-center justify-center ${
                  accountType === 'single' ? 'bg-blue-500' : 'bg-gray-100'
                }`}>
                  <Building2 className={`w-8 h-8 ${
                    accountType === 'single' ? 'text-white' : 'text-gray-600'
                  }`} />
                </div>
                <h3 className="text-lg font-semibold mb-2">Single Company</h3>
                <p className="text-sm text-gray-500">
                  I want to protect my own organization&apos;s email
                </p>
                <ul className="mt-4 text-sm text-left space-y-2">
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-500" />
                    <span>Dashboard for your team</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-500" />
                    <span>Email threat detection</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-500" />
                    <span>Quarantine management</span>
                  </li>
                </ul>
              </div>

              {/* MSP Option */}
              <div
                onClick={() => handleAccountTypeSelect('msp')}
                className={`p-6 border-2 rounded-xl cursor-pointer transition-all ${
                  accountType === 'msp'
                    ? 'border-purple-500 bg-purple-50 shadow-md'
                    : 'border-gray-200 hover:border-gray-300 hover:shadow'
                }`}
              >
                <div className={`w-16 h-16 mx-auto mb-4 rounded-full flex items-center justify-center ${
                  accountType === 'msp' ? 'bg-purple-500' : 'bg-gray-100'
                }`}>
                  <Users className={`w-8 h-8 ${
                    accountType === 'msp' ? 'text-white' : 'text-gray-600'
                  }`} />
                </div>
                <h3 className="text-lg font-semibold mb-2">Managed Service Provider</h3>
                <p className="text-sm text-gray-500">
                  I manage email security for multiple clients
                </p>
                <ul className="mt-4 text-sm text-left space-y-2">
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-500" />
                    <span>Multi-tenant dashboard</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-500" />
                    <span>Client onboarding wizard</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-500" />
                    <span>Cross-client analytics</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-500" />
                    <span>Usage & billing reports</span>
                  </li>
                </ul>
              </div>
            </div>

            {/* Organization Name Input */}
            {accountType && !organization && (
              <div className="max-w-md mx-auto">
                <label className="block text-sm font-medium text-gray-700 mb-2 text-left">
                  {accountType === 'msp' ? 'Your MSP Company Name' : 'Your Organization Name'}
                </label>
                <input
                  type="text"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  placeholder={accountType === 'msp' ? 'e.g., SecureTech Solutions' : 'e.g., Acme Corporation'}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
            )}

            {error && (
              <p className="mt-4 text-sm text-red-600">{error}</p>
            )}
          </div>
        );

      case 3:
        return (
          <div className="text-center">
            <h2 className="text-2xl font-bold mb-4">Connect Your Email Provider</h2>
            <p className="text-gray-600 mb-8">
              {accountType === 'msp'
                ? 'Connect your MSP\'s email or skip to set up client connections later.'
                : 'Link your email system to start monitoring for threats.'
              }
            </p>
            <div className="flex flex-col gap-4 max-w-sm mx-auto">
              <button
                onClick={handleConnectMicrosoft}
                className="flex items-center justify-center gap-3 p-4 border-2 rounded-lg hover:border-blue-500 hover:bg-blue-50 transition-colors"
              >
                <svg className="w-6 h-6" viewBox="0 0 23 23" fill="none">
                  <path fill="#f35325" d="M1 1h10v10H1z"/>
                  <path fill="#81bc06" d="M12 1h10v10H12z"/>
                  <path fill="#05a6f0" d="M1 12h10v10H1z"/>
                  <path fill="#ffba08" d="M12 12h10v10H12z"/>
                </svg>
                <span className="font-medium">Connect Microsoft 365</span>
              </button>
              <button
                onClick={handleConnectGoogle}
                className="flex items-center justify-center gap-3 p-4 border-2 rounded-lg hover:border-red-500 hover:bg-red-50 transition-colors"
              >
                <svg className="w-6 h-6" viewBox="0 0 24 24">
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
                <span className="font-medium">Connect Google Workspace</span>
              </button>
            </div>
          </div>
        );

      case 4:
        return (
          <div>
            <h2 className="text-2xl font-bold mb-4 text-center">Configure Detection Thresholds</h2>
            <p className="text-gray-600 mb-8 text-center">
              Customize how aggressively threats are detected and handled.
            </p>
            <div className="max-w-md mx-auto space-y-6">
              <div>
                <div className="flex justify-between mb-2">
                  <label className="font-medium">Suspicious Threshold</label>
                  <span className="text-gray-500">{settings.detection.suspiciousThreshold}%</span>
                </div>
                <input
                  type="range"
                  min="10"
                  max="50"
                  value={settings.detection.suspiciousThreshold}
                  onChange={(e) => setSettings(prev => ({
                    ...prev,
                    detection: { ...prev.detection, suspiciousThreshold: parseInt(e.target.value) },
                  }))}
                  className="w-full accent-yellow-500"
                />
                <p className="text-sm text-gray-500 mt-1">
                  Emails above this score are flagged for review
                </p>
              </div>
              <div>
                <div className="flex justify-between mb-2">
                  <label className="font-medium">Quarantine Threshold</label>
                  <span className="text-gray-500">{settings.detection.quarantineThreshold}%</span>
                </div>
                <input
                  type="range"
                  min="40"
                  max="80"
                  value={settings.detection.quarantineThreshold}
                  onChange={(e) => setSettings(prev => ({
                    ...prev,
                    detection: { ...prev.detection, quarantineThreshold: parseInt(e.target.value) },
                  }))}
                  className="w-full accent-orange-500"
                />
                <p className="text-sm text-gray-500 mt-1">
                  Emails above this score are held for admin review
                </p>
              </div>
              <div>
                <div className="flex justify-between mb-2">
                  <label className="font-medium">Block Threshold</label>
                  <span className="text-gray-500">{settings.detection.blockThreshold}%</span>
                </div>
                <input
                  type="range"
                  min="60"
                  max="95"
                  value={settings.detection.blockThreshold}
                  onChange={(e) => setSettings(prev => ({
                    ...prev,
                    detection: { ...prev.detection, blockThreshold: parseInt(e.target.value) },
                  }))}
                  className="w-full accent-red-500"
                />
                <p className="text-sm text-gray-500 mt-1">
                  Emails above this score are automatically blocked
                </p>
              </div>
            </div>
          </div>
        );

      case 5:
        return (
          <div>
            <h2 className="text-2xl font-bold mb-4 text-center">Setup Notifications</h2>
            <p className="text-gray-600 mb-8 text-center">
              Choose how you want to be notified about threats.
            </p>
            <div className="max-w-md mx-auto space-y-4">
              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div className="flex items-center gap-3">
                  <Mail className="w-6 h-6 text-gray-600" />
                  <div>
                    <div className="font-medium">Email Notifications</div>
                    <div className="text-sm text-gray-500">Get alerts via email</div>
                  </div>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={settings.notifications.emailEnabled}
                    onChange={(e) => setSettings(prev => ({
                      ...prev,
                      notifications: { ...prev.notifications, emailEnabled: e.target.checked },
                    }))}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                </label>
              </div>
              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div className="flex items-center gap-3">
                  <svg className="w-6 h-6" viewBox="0 0 24 24" fill="#4A154B">
                    <path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"/>
                  </svg>
                  <div>
                    <div className="font-medium">Slack Notifications</div>
                    <div className="text-sm text-gray-500">Get alerts in Slack</div>
                  </div>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={settings.notifications.slackEnabled}
                    onChange={(e) => setSettings(prev => ({
                      ...prev,
                      notifications: { ...prev.notifications, slackEnabled: e.target.checked },
                    }))}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                </label>
              </div>
            </div>
          </div>
        );

      case 6:
        return (
          <div className="text-center">
            <div className="text-6xl mb-6">
              <Check className="w-16 h-16 mx-auto text-green-500" />
            </div>
            <h2 className="text-2xl font-bold mb-4">You&apos;re All Set!</h2>
            <p className="text-gray-600 mb-6">
              {accountType === 'msp'
                ? 'Your MSP dashboard is ready. Start onboarding your clients!'
                : `Swordfish is now protecting your ${organization?.name || 'organization'}'s email.`
              }
            </p>
            <div className="bg-gray-50 rounded-lg p-6 max-w-md mx-auto text-left">
              <h3 className="font-semibold mb-3">What&apos;s Next?</h3>
              {accountType === 'msp' ? (
                <ul className="space-y-2 text-sm">
                  <li className="flex items-center gap-2">
                    <span className="text-purple-500">→</span>
                    Access your MSP admin dashboard
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-purple-500">→</span>
                    Add your first client organization
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-purple-500">→</span>
                    Configure default security policies
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-purple-500">→</span>
                    View cross-client analytics
                  </li>
                </ul>
              ) : (
                <ul className="space-y-2 text-sm">
                  <li className="flex items-center gap-2">
                    <span className="text-blue-500">→</span>
                    View your security dashboard
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-blue-500">→</span>
                    Review detected threats
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-blue-500">→</span>
                    Configure advanced policies
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-blue-500">→</span>
                    Add team members
                  </li>
                </ul>
              )}
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  if (!userLoaded) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Progress indicator */}
      <div className="bg-white border-b px-6 py-4">
        <div className="max-w-3xl mx-auto">
          <div className="flex items-center justify-between mb-2">
            {steps.map((step, index) => (
              <div key={step.id} className="flex items-center">
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                    step.completed
                      ? 'bg-green-500 text-white'
                      : step.id === currentStep
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-200 text-gray-500'
                  }`}
                >
                  {step.completed ? <Check className="w-4 h-4" /> : step.id}
                </div>
                {index < steps.length - 1 && (
                  <div
                    className={`w-12 h-1 mx-1 ${
                      step.completed ? 'bg-green-500' : 'bg-gray-200'
                    }`}
                  />
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="bg-white rounded-xl shadow-lg p-8 max-w-2xl w-full">
          {renderStepContent()}

          {/* Navigation */}
          <div className="flex justify-between mt-8 pt-6 border-t">
            {currentStep > 1 ? (
              <button
                onClick={() => setCurrentStep(prev => prev - 1)}
                className="px-6 py-2 text-gray-600 hover:text-gray-900"
                disabled={loading}
              >
                Back
              </button>
            ) : (
              <div />
            )}
            <div className="flex gap-3">
              {currentStep !== 1 && currentStep !== 2 && currentStep !== ONBOARDING_STEPS.length && (
                <button
                  onClick={handleSkip}
                  className="px-6 py-2 text-gray-500 hover:text-gray-700"
                  disabled={loading}
                >
                  Skip
                </button>
              )}
              <button
                onClick={handleNext}
                disabled={loading || (currentStep === 2 && !accountType)}
                className={`px-6 py-2 text-white rounded-lg disabled:opacity-50 ${
                  accountType === 'msp' && currentStep === 2
                    ? 'bg-purple-600 hover:bg-purple-700'
                    : 'bg-blue-600 hover:bg-blue-700'
                }`}
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <span className="animate-spin">⟳</span>
                    {currentStep === 2 ? 'Setting up...' : 'Saving...'}
                  </span>
                ) : currentStep === ONBOARDING_STEPS.length ? (
                  accountType === 'msp' ? 'Go to MSP Dashboard' : 'Go to Dashboard'
                ) : (
                  'Continue'
                )}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
