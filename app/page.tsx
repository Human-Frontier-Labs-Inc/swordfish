import Link from "next/link";
import { SignedIn, SignedOut } from "@clerk/nextjs";

export default function Home() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-800">
      {/* Navigation */}
      <nav className="border-b border-slate-700/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-2">
              <svg className="w-8 h-8 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              <span className="text-xl font-bold text-white">Swordfish</span>
            </div>
            <div className="flex items-center gap-4">
              <SignedOut>
                <Link
                  href="/sign-in"
                  className="text-slate-300 hover:text-white transition-colors"
                >
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

      {/* Hero Section */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-32">
        <div className="text-center">
          <h1 className="text-5xl sm:text-6xl font-bold text-white mb-6">
            AI-Powered Email
            <span className="text-cyan-400"> Security</span>
          </h1>
          <p className="text-xl text-slate-300 max-w-2xl mx-auto mb-10">
            Protect your organization from phishing, malware, and advanced email threats
            with intelligent real-time analysis powered by Claude AI.
          </p>
          <div className="flex justify-center gap-4">
            <SignedOut>
              <Link
                href="/sign-up"
                className="bg-cyan-500 hover:bg-cyan-400 text-white px-8 py-3 rounded-lg font-semibold text-lg transition-colors"
              >
                Start Free Trial
              </Link>
              <Link
                href="/sign-in"
                className="border border-slate-600 hover:border-slate-500 text-slate-300 hover:text-white px-8 py-3 rounded-lg font-semibold text-lg transition-colors"
              >
                Sign In
              </Link>
            </SignedOut>
            <SignedIn>
              <Link
                href="/dashboard"
                className="bg-cyan-500 hover:bg-cyan-400 text-white px-8 py-3 rounded-lg font-semibold text-lg transition-colors"
              >
                Go to Dashboard
              </Link>
            </SignedIn>
          </div>
        </div>

        {/* Features Grid */}
        <div className="mt-24 grid md:grid-cols-3 gap-8">
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
            <div className="w-12 h-12 bg-cyan-500/10 rounded-lg flex items-center justify-center mb-4">
              <svg className="w-6 h-6 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
              </svg>
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">AI Threat Detection</h3>
            <p className="text-slate-400">
              Claude AI analyzes email content, attachments, and sender behavior to identify sophisticated threats.
            </p>
          </div>

          <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
            <div className="w-12 h-12 bg-cyan-500/10 rounded-lg flex items-center justify-center mb-4">
              <svg className="w-6 h-6 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">Quarantine & Control</h3>
            <p className="text-slate-400">
              Automatically quarantine suspicious emails with one-click release or permanent deletion options.
            </p>
          </div>

          <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
            <div className="w-12 h-12 bg-cyan-500/10 rounded-lg flex items-center justify-center mb-4">
              <svg className="w-6 h-6 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">Real-Time Analytics</h3>
            <p className="text-slate-400">
              Comprehensive dashboards showing threat trends, blocked attacks, and security posture.
            </p>
          </div>
        </div>

        {/* Integration Logos */}
        <div className="mt-24 text-center">
          <p className="text-slate-500 text-sm uppercase tracking-wider mb-8">Integrates with</p>
          <div className="flex justify-center items-center gap-12">
            <div className="text-slate-400 flex items-center gap-2">
              <svg className="w-8 h-8" viewBox="0 0 24 24" fill="currentColor">
                <path d="M11.5 3v8.5H3V3h8.5zm0 18H3v-8.5h8.5V21zM21 3v8.5h-8.5V3H21zm0 18h-8.5v-8.5H21V21z"/>
              </svg>
              <span className="font-medium">Microsoft 365</span>
            </div>
            <div className="text-slate-400 flex items-center gap-2">
              <svg className="w-8 h-8" viewBox="0 0 24 24" fill="currentColor">
                <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
              </svg>
              <span className="font-medium">Google Workspace</span>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-700/50 py-8">
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
