import { Suspense } from 'react';
import AcceptInvitationClient from './client';

// Force dynamic rendering - this page uses useSearchParams which requires request-time data
export const dynamic = 'force-dynamic';

// Loading fallback for Suspense
function LoadingFallback() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto" />
        <p className="mt-4 text-gray-600">Loading invitation...</p>
      </div>
    </div>
  );
}

// Server component page that wraps client component in Suspense
export default function AcceptInvitationPage() {
  return (
    <Suspense fallback={<LoadingFallback />}>
      <AcceptInvitationClient />
    </Suspense>
  );
}
