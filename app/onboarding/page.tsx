'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useUser, useOrganization } from '@clerk/nextjs';

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
    title: 'Connect Email Provider',
    description: 'Link your Microsoft 365 or Google Workspace account.',
  },
  {
    id: 3,
    title: 'Configure Detection',
    description: 'Set your security thresholds and policies.',
  },
  {
    id: 4,
    title: 'Setup Notifications',
    description: 'Choose how you want to be alerted about threats.',
  },
  {
    id: 5,
    title: 'You\'re All Set!',
    description: 'Start monitoring your email security.',
  },
];

export default function OnboardingPage() {
  const router = useRouter();
  const { user, isLoaded: userLoaded } = useUser();
  const { organization } = useOrganization();

  const [currentStep, setCurrentStep] = useState(1);
  const [steps, setSteps] = useState<OnboardingStep[]>(
    ONBOARDING_STEPS.map(s => ({ ...s, completed: false }))
  );
  const [loading, setLoading] = useState(false);
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
          router.push('/dashboard');
        } else if (data.currentStep) {
          setCurrentStep(data.currentStep);
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

  const handleNext = async () => {
    setLoading(true);

    try {
      // Mark current step as completed
      await fetch('/api/onboarding', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          currentStep: currentStep + 1,
          completedStep: currentStep,
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
          body: JSON.stringify({ completed: true }),
        });

        router.push('/dashboard');
      } else {
        setCurrentStep(prev => prev + 1);
      }
    } catch (error) {
      console.error('Onboarding error:', error);
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
        router.push('/dashboard');
      } else {
        setCurrentStep(prev => prev + 1);
      }
    } catch (error) {
      console.error('Skip error:', error);
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
            <div className="text-6xl mb-6">🛡️</div>
            <h2 className="text-2xl font-bold mb-4">Welcome to Swordfish</h2>
            <p className="text-gray-600 mb-6">
              Your AI-powered email security platform. We'll help you set up protection
              against phishing, BEC, malware, and spam in just a few minutes.
            </p>
            <div className="grid grid-cols-2 gap-4 text-left max-w-md mx-auto">
              <div className="flex items-center gap-2">
                <span className="text-green-500">✓</span>
                <span>Phishing Detection</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-green-500">✓</span>
                <span>BEC Prevention</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-green-500">✓</span>
                <span>Malware Scanning</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-green-500">✓</span>
                <span>Spam Filtering</span>
              </div>
            </div>
          </div>
        );

      case 2:
        return (
          <div className="text-center">
            <h2 className="text-2xl font-bold mb-4">Connect Your Email Provider</h2>
            <p className="text-gray-600 mb-8">
              Link your email system to start monitoring for threats.
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

      case 3:
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

      case 4:
        return (
          <div>
            <h2 className="text-2xl font-bold mb-4 text-center">Setup Notifications</h2>
            <p className="text-gray-600 mb-8 text-center">
              Choose how you want to be notified about threats.
            </p>
            <div className="max-w-md mx-auto space-y-4">
              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div className="flex items-center gap-3">
                  <span className="text-2xl">📧</span>
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
                  <span className="text-2xl">💬</span>
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

      case 5:
        return (
          <div className="text-center">
            <div className="text-6xl mb-6">🎉</div>
            <h2 className="text-2xl font-bold mb-4">You're All Set!</h2>
            <p className="text-gray-600 mb-6">
              Swordfish is now protecting your {organization?.name || 'organization'}'s email.
              Head to your dashboard to monitor threats and manage security.
            </p>
            <div className="bg-gray-50 rounded-lg p-6 max-w-md mx-auto text-left">
              <h3 className="font-semibold mb-3">What's Next?</h3>
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
                  {step.completed ? '✓' : step.id}
                </div>
                {index < steps.length - 1 && (
                  <div
                    className={`w-16 h-1 mx-2 ${
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
              {currentStep !== 1 && currentStep !== ONBOARDING_STEPS.length && (
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
                disabled={loading}
                className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <span className="animate-spin">⟳</span>
                    Saving...
                  </span>
                ) : currentStep === ONBOARDING_STEPS.length ? (
                  'Go to Dashboard'
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
