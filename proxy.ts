import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';
import { NextResponse } from 'next/server';

// Define public routes that don't require authentication
const isPublicRoute = createRouteMatcher([
  '/',
  '/sign-in(.*)',
  '/sign-up(.*)',
  '/api/webhooks(.*)',
  '/api/health',
  '/api/cron(.*)',
  '/click(.*)',
]);

// Define onboarding routes
const isOnboardingRoute = createRouteMatcher(['/onboarding(.*)']);

// Define protected routes with specific requirements
const isDashboardRoute = createRouteMatcher(['/dashboard(.*)']);
const isAdminRoute = createRouteMatcher(['/admin(.*)']);
const isApiRoute = createRouteMatcher(['/api(.*)']);

export default clerkMiddleware(async (auth, request) => {
  const { userId, orgId, orgRole, sessionClaims } = await auth();

  // Allow public routes
  if (isPublicRoute(request)) {
    return NextResponse.next();
  }

  // Redirect unauthenticated users to sign-in
  if (!userId) {
    const signInUrl = new URL('/sign-in', request.url);
    signInUrl.searchParams.set('redirect_url', request.url);
    return NextResponse.redirect(signInUrl);
  }

  // Allow API calls needed during onboarding
  if (request.nextUrl.pathname.startsWith('/api/onboarding')) {
    return NextResponse.next();
  }
  if (request.nextUrl.pathname.startsWith('/api/settings')) {
    return NextResponse.next();
  }
  if (request.nextUrl.pathname.startsWith('/api/auth')) {
    return NextResponse.next();
  }

  // Check if user has completed onboarding via public metadata
  const publicMetadata = sessionClaims?.publicMetadata as { onboardingCompleted?: boolean } | undefined;
  const hasCompletedOnboarding = publicMetadata?.onboardingCompleted === true;

  // If user hasn't completed onboarding and isn't on onboarding page, redirect there
  if (!hasCompletedOnboarding && !isOnboardingRoute(request)) {
    return NextResponse.redirect(new URL('/onboarding', request.url));
  }

  // Create headers with user context for downstream use
  const headers = new Headers(request.headers);
  headers.set('x-user-id', userId);
  if (orgId) headers.set('x-org-id', orgId);
  if (orgRole) headers.set('x-org-role', orgRole);

  // Dashboard routes
  if (isDashboardRoute(request)) {
    return NextResponse.next({
      request: { headers },
    });
  }

  // Admin routes
  if (isAdminRoute(request)) {
    return NextResponse.next({
      request: { headers },
    });
  }

  // API routes - add auth context
  if (isApiRoute(request)) {
    return NextResponse.next({
      request: { headers },
    });
  }

  return NextResponse.next({
    request: { headers },
  });
});

export const config = {
  matcher: [
    // Skip static files and Next.js internals
    '/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)',
    // Always run for API routes
    '/(api|trpc)(.*)',
  ],
};
