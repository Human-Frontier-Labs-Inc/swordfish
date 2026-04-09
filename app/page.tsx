import Link from "next/link";
import { SignedIn, SignedOut } from "@clerk/nextjs";

export default function Home() {
  return (
    <div className="min-h-screen bg-slate-950 text-white overflow-hidden">
      {/* Animated background grid */}
      <div className="fixed inset-0 pointer-events-none">
        <div
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(59,130,246,0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,0.5) 1px, transparent 1px)",
            backgroundSize: "64px 64px",
          }}
        />
        {/* Radial gradient glow behind hero */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[900px] h-[600px] rounded-full bg-blue-600/10 blur-[120px]" />
        <div className="absolute top-40 right-0 w-[400px] h-[400px] rounded-full bg-cyan-500/8 blur-[100px]" />
      </div>

      {/* Navigation */}
      <nav className="relative z-10 border-b border-white/5">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-2">
              <svg
                className="w-8 h-8 text-blue-500"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
              <span className="text-xl font-bold tracking-tight">
                Sword<span className="text-blue-400">Phish</span>
              </span>
            </div>
            <div className="flex items-center gap-4">
              <SignedOut>
                <Link
                  href="/sign-in"
                  className="text-slate-400 hover:text-white text-sm font-medium transition-colors"
                >
                  Sign In
                </Link>
                <Link
                  href="/sign-up"
                  className="relative bg-blue-600 hover:bg-blue-500 text-white px-5 py-2 rounded-lg text-sm font-semibold transition-all shadow-lg shadow-blue-600/25 hover:shadow-blue-500/40"
                >
                  Get Started
                </Link>
              </SignedOut>
              <SignedIn>
                <Link
                  href="/dashboard"
                  className="relative bg-blue-600 hover:bg-blue-500 text-white px-5 py-2 rounded-lg text-sm font-semibold transition-all shadow-lg shadow-blue-600/25 hover:shadow-blue-500/40"
                >
                  Dashboard
                </Link>
              </SignedIn>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <main className="relative z-10">
        <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-24 sm:pt-32 pb-20">
          <div className="text-center animate-[fadeInUp_0.8s_ease-out_both]">
            {/* Badge */}
            <div className="inline-flex items-center gap-2 rounded-full border border-blue-500/20 bg-blue-500/10 px-4 py-1.5 text-sm text-blue-300 mb-8">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500" />
              </span>
              AI-Powered Email Threat Detection
            </div>

            <h1 className="text-5xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight leading-[1.1] mb-6">
              Stop Phishing Attacks
              <br />
              <span className="bg-gradient-to-r from-blue-400 via-cyan-400 to-blue-500 bg-clip-text text-transparent">
                Before They Strike
              </span>
            </h1>
            <p className="text-lg sm:text-xl text-slate-400 max-w-2xl mx-auto mb-12 leading-relaxed">
              Protect your organization from phishing, BEC, and advanced email
              threats with real-time AI analysis powered by Claude.
            </p>

            <div className="flex flex-col items-center gap-5">
              <SignedOut>
                <div className="flex flex-col sm:flex-row gap-4">
                  <Link
                    href="/sign-up"
                    className="relative group bg-blue-600 hover:bg-blue-500 text-white px-8 py-3.5 rounded-lg font-semibold text-lg transition-all shadow-lg shadow-blue-600/25 hover:shadow-blue-500/40 hover:scale-[1.02] active:scale-[0.98]"
                  >
                    <span className="absolute inset-0 rounded-lg bg-blue-400/20 opacity-0 group-hover:opacity-100 animate-[pulse_2s_ease-in-out_infinite] transition-opacity" />
                    <span className="relative">Start Free Trial</span>
                  </Link>
                  <Link
                    href="/sign-in"
                    className="border border-slate-700 hover:border-slate-500 text-slate-300 hover:text-white px-8 py-3.5 rounded-lg font-semibold text-lg transition-all hover:bg-white/5"
                  >
                    Sign In
                  </Link>
                </div>
                <Link
                  href="/sign-up"
                  className="text-blue-400 hover:text-blue-300 text-sm font-medium transition-colors"
                >
                  MSP / Partner? Sign up to manage multiple clients &rarr;
                </Link>
              </SignedOut>
              <SignedIn>
                <Link
                  href="/dashboard"
                  className="relative group bg-blue-600 hover:bg-blue-500 text-white px-8 py-3.5 rounded-lg font-semibold text-lg transition-all shadow-lg shadow-blue-600/25 hover:shadow-blue-500/40 hover:scale-[1.02] active:scale-[0.98]"
                >
                  <span className="absolute inset-0 rounded-lg bg-blue-400/20 opacity-0 group-hover:opacity-100 animate-[pulse_2s_ease-in-out_infinite] transition-opacity" />
                  <span className="relative">Go to Dashboard</span>
                </Link>
              </SignedIn>
            </div>
          </div>
        </section>

        {/* Stats Bar */}
        <section className="border-y border-white/5 bg-white/[0.02] animate-[fadeInUp_0.8s_ease-out_0.2s_both]">
          <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
              <div>
                <div className="text-3xl font-bold text-white">99.7%</div>
                <div className="text-sm text-slate-500 mt-1">Detection Rate</div>
              </div>
              <div>
                <div className="text-3xl font-bold text-white">&lt;200ms</div>
                <div className="text-sm text-slate-500 mt-1">Analysis Time</div>
              </div>
              <div>
                <div className="text-3xl font-bold text-white">0</div>
                <div className="text-sm text-slate-500 mt-1">False Negatives</div>
              </div>
              <div>
                <div className="text-3xl font-bold text-white">24/7</div>
                <div className="text-sm text-slate-500 mt-1">Monitoring</div>
              </div>
            </div>
          </div>
        </section>

        {/* Features Grid */}
        <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 animate-[fadeInUp_0.8s_ease-out_0.4s_both]">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">
              Enterprise-Grade Email Security
            </h2>
            <p className="text-slate-400 max-w-2xl mx-auto">
              SwordPhish combines advanced AI with real-time threat
              intelligence to protect every inbox in your organization.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            <div className="group relative bg-slate-900/50 border border-slate-800 hover:border-blue-500/30 rounded-xl p-6 transition-all duration-300 hover:bg-slate-900/80">
              <div className="absolute inset-0 rounded-xl bg-gradient-to-b from-blue-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="relative">
                <div className="w-12 h-12 bg-blue-500/10 border border-blue-500/20 rounded-lg flex items-center justify-center mb-4">
                  <svg
                    className="w-6 h-6 text-blue-400"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"
                    />
                  </svg>
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">
                  AI Threat Detection
                </h3>
                <p className="text-slate-400 text-sm leading-relaxed">
                  Claude AI analyzes email content, attachments, and sender
                  behavior to identify sophisticated phishing and BEC attacks in
                  real time.
                </p>
              </div>
            </div>

            <div className="group relative bg-slate-900/50 border border-slate-800 hover:border-blue-500/30 rounded-xl p-6 transition-all duration-300 hover:bg-slate-900/80">
              <div className="absolute inset-0 rounded-xl bg-gradient-to-b from-blue-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="relative">
                <div className="w-12 h-12 bg-blue-500/10 border border-blue-500/20 rounded-lg flex items-center justify-center mb-4">
                  <svg
                    className="w-6 h-6 text-blue-400"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                    />
                  </svg>
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">
                  Quarantine &amp; Control
                </h3>
                <p className="text-slate-400 text-sm leading-relaxed">
                  Automatically quarantine suspicious emails with one-click
                  release or permanent deletion. Full audit trail for compliance.
                </p>
              </div>
            </div>

            <div className="group relative bg-slate-900/50 border border-slate-800 hover:border-blue-500/30 rounded-xl p-6 transition-all duration-300 hover:bg-slate-900/80">
              <div className="absolute inset-0 rounded-xl bg-gradient-to-b from-blue-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="relative">
                <div className="w-12 h-12 bg-blue-500/10 border border-blue-500/20 rounded-lg flex items-center justify-center mb-4">
                  <svg
                    className="w-6 h-6 text-blue-400"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
                    />
                  </svg>
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">
                  Real-Time Analytics
                </h3>
                <p className="text-slate-400 text-sm leading-relaxed">
                  Comprehensive dashboards showing threat trends, blocked
                  attacks, and your organization&apos;s security posture at a
                  glance.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Integration Logos */}
        <section className="border-t border-white/5 animate-[fadeInUp_0.8s_ease-out_0.6s_both]">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 text-center">
            <p className="text-slate-600 text-xs uppercase tracking-[0.2em] font-medium mb-8">
              Integrates with your email platform
            </p>
            <div className="flex justify-center items-center gap-16">
              <div className="text-slate-500 flex items-center gap-3 hover:text-slate-300 transition-colors">
                <svg className="w-7 h-7" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M11.5 3v8.5H3V3h8.5zm0 18H3v-8.5h8.5V21zM21 3v8.5h-8.5V3H21zm0 18h-8.5v-8.5H21V21z" />
                </svg>
                <span className="font-medium text-sm">Microsoft 365</span>
              </div>
              <div className="text-slate-500 flex items-center gap-3 hover:text-slate-300 transition-colors">
                <svg className="w-7 h-7" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                  <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                  <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                  <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                </svg>
                <span className="font-medium text-sm">Google Workspace</span>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="relative z-10 border-t border-white/5 py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2">
              <svg
                className="w-5 h-5 text-blue-500"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
              <span className="text-slate-500 text-sm font-medium">
                Sword<span className="text-blue-500">Phish</span>
              </span>
            </div>
            <p className="text-slate-600 text-sm">
              &copy; 2026 SwordPhish. All rights reserved.
            </p>
          </div>
        </div>
      </footer>

      {/* Global animation keyframes */}
      <style>{`
        @keyframes fadeInUp {
          from {
            opacity: 0;
            transform: translateY(24px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
      `}</style>
    </div>
  );
}
