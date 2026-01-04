import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';
import { NextResponse } from 'next/server';

// Define public routes that don't require authentication
const isPublicRoute = createRouteMatcher([
  '/',
  '/sign-in(.*)',
  '/sign-up(.*)',
  '/api/webhooks(.*)',
]);

// Define protected routes with specific requirements
const isDashboardRoute = createRouteMatcher(['/dashboard(.*)']);
const isApiRoute = createRouteMatcher(['/api(.*)']);

export default clerkMiddleware(async (auth, request) => {
  const { userId, orgId, orgRole } = await auth();

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

  // Dashboard routes require authentication (handled above)
  if (isDashboardRoute(request)) {
    // Add user context to headers for downstream use
    const headers = new Headers(request.headers);
    headers.set('x-user-id', userId);
    if (orgId) headers.set('x-org-id', orgId);
    if (orgRole) headers.set('x-org-role', orgRole);

    return NextResponse.next({
      request: { headers },
    });
  }

  // API routes - add auth context
  if (isApiRoute(request)) {
    const headers = new Headers(request.headers);
    headers.set('x-user-id', userId);
    if (orgId) headers.set('x-org-id', orgId);
    if (orgRole) headers.set('x-org-role', orgRole);

    return NextResponse.next({
      request: { headers },
    });
  }

  return NextResponse.next();
});

export const config = {
  matcher: [
    // Skip static files and Next.js internals
    '/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)',
    // Always run for API routes
    '/(api|trpc)(.*)',
  ],
};
