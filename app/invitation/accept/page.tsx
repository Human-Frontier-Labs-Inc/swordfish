'use client';

import { useEffect, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { useAuth, useUser, SignIn, SignUp } from '@clerk/nextjs';
import Link from 'next/link';

interface InvitationDetails {
  id: string;
  email: string;
  role: string;
  tenantId: string;
  tenantName: string;
  expiresAt: string;
  invitedBy: string;
}

type ViewState = 'loading' | 'sign-in' | 'sign-up' | 'processing' | 'success' | 'error';

export default function AcceptInvitationPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const { isSignedIn, isLoaded: authLoaded } = useAuth();
  const { user } = useUser();

  const token = searchParams.get('token');

  const [viewState, setViewState] = useState<ViewState>('loading');
  const [invitation, setInvitation] = useState<InvitationDetails | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [authMode, setAuthMode] = useState<'sign-in' | 'sign-up'>('sign-up');

  // Fetch invitation details
  useEffect(() => {
    if (!token) {
      setError('Invalid invitation link. No token provided.');
      setViewState('error');
      return;
    }

    fetchInvitation();
  }, [token]);

  // Auto-accept when user is signed in
  useEffect(() => {
    if (authLoaded && isSignedIn && invitation && viewState !== 'processing' && viewState !== 'success') {
      acceptInvitation();
    }
  }, [authLoaded, isSignedIn, invitation]);

  async function fetchInvitation() {
    try {
      const response = await fetch(`/api/invitation/details?token=${token}`);
      const data = await response.json();

      if (!response.ok) {
        setError(data.error || 'Failed to load invitation');
        setViewState('error');
        return;
      }

      setInvitation(data.invitation);

      // Check if already signed in
      if (authLoaded && isSignedIn) {
        acceptInvitation();
      } else {
        setViewState('sign-up');
      }
    } catch (err) {
      setError('Failed to load invitation details');
      setViewState('error');
    }
  }

  async function acceptInvitation() {
    if (!token || !invitation) return;

    setViewState('processing');

    try {
      const response = await fetch('/api/invitation/accept', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || 'Failed to accept invitation');
        setViewState('error');
        return;
      }

      setViewState('success');

      // Redirect to dashboard after short delay
      setTimeout(() => {
        router.push('/dashboard');
      }, 2000);
    } catch (err) {
      setError('Failed to accept invitation');
      setViewState('error');
    }
  }

  // Loading state
  if (viewState === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto" />
          <p className="mt-4 text-gray-600">Loading invitation...</p>
        </div>
      </div>
    );
  }

  // Error state
  if (viewState === 'error') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="max-w-md w-full mx-4">
          <div className="bg-white rounded-lg shadow-lg p-8 text-center">
            <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <XIcon className="w-8 h-8 text-red-600" />
            </div>
            <h1 className="text-2xl font-bold text-gray-900 mb-2">Invalid Invitation</h1>
            <p className="text-gray-600 mb-6">{error}</p>
            <Link
              href="/"
              className="inline-block bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700"
            >
              Go to Homepage
            </Link>
          </div>
        </div>
      </div>
    );
  }

  // Success state
  if (viewState === 'success') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="max-w-md w-full mx-4">
          <div className="bg-white rounded-lg shadow-lg p-8 text-center">
            <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <CheckIcon className="w-8 h-8 text-green-600" />
            </div>
            <h1 className="text-2xl font-bold text-gray-900 mb-2">Welcome to Swordfish!</h1>
            <p className="text-gray-600 mb-2">
              You've joined <strong>{invitation?.tenantName}</strong> as a{' '}
              <span className="capitalize">{invitation?.role?.replace('_', ' ')}</span>.
            </p>
            <p className="text-sm text-gray-500 mb-6">Redirecting to dashboard...</p>
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600 mx-auto" />
          </div>
        </div>
      </div>
    );
  }

  // Processing state
  if (viewState === 'processing') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="max-w-md w-full mx-4">
          <div className="bg-white rounded-lg shadow-lg p-8 text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4" />
            <h1 className="text-2xl font-bold text-gray-900 mb-2">Setting up your account...</h1>
            <p className="text-gray-600">Please wait while we configure your access.</p>
          </div>
        </div>
      </div>
    );
  }

  // Sign-in / Sign-up state
  return (
    <div className="min-h-screen bg-gray-50 py-12 px-4">
      <div className="max-w-md mx-auto">
        {/* Invitation details card */}
        {invitation && (
          <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
            <div className="flex items-center gap-4 mb-4">
              <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
                <EnvelopeIcon className="w-6 h-6 text-blue-600" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">You're Invited!</h1>
                <p className="text-sm text-gray-500">Join {invitation.tenantName}</p>
              </div>
            </div>

            <div className="border-t pt-4 space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500">Email:</span>
                <span className="font-medium">{invitation.email}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Role:</span>
                <span className="font-medium capitalize">
                  {invitation.role?.replace('_', ' ')}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Expires:</span>
                <span className="font-medium">
                  {new Date(invitation.expiresAt).toLocaleDateString()}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Auth toggle */}
        <div className="flex rounded-lg bg-gray-200 p-1 mb-6">
          <button
            onClick={() => setAuthMode('sign-up')}
            className={`flex-1 py-2 text-sm font-medium rounded-md transition ${
              authMode === 'sign-up'
                ? 'bg-white text-gray-900 shadow'
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            Create Account
          </button>
          <button
            onClick={() => setAuthMode('sign-in')}
            className={`flex-1 py-2 text-sm font-medium rounded-md transition ${
              authMode === 'sign-in'
                ? 'bg-white text-gray-900 shadow'
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            Sign In
          </button>
        </div>

        {/* Clerk auth component */}
        <div className="bg-white rounded-lg shadow-lg overflow-hidden">
          {authMode === 'sign-up' ? (
            <SignUp
              appearance={{
                elements: {
                  rootBox: 'w-full',
                  card: 'shadow-none border-0',
                },
              }}
              redirectUrl={`/invitation/accept?token=${token}`}
              signInUrl={`/invitation/accept?token=${token}`}
            />
          ) : (
            <SignIn
              appearance={{
                elements: {
                  rootBox: 'w-full',
                  card: 'shadow-none border-0',
                },
              }}
              redirectUrl={`/invitation/accept?token=${token}`}
              signUpUrl={`/invitation/accept?token=${token}`}
            />
          )}
        </div>
      </div>
    </div>
  );
}

// Icons
function CheckIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
    </svg>
  );
}

function XIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}

function EnvelopeIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
    </svg>
  );
}
