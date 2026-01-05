import { SignUp } from "@clerk/nextjs";

export default function Page() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-800 flex flex-col items-center justify-center py-12 px-4">
      {/* Header */}
      <div className="mb-8 text-center">
        <div className="flex items-center justify-center gap-2 mb-4">
          <svg className="w-10 h-10 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <span className="text-2xl font-bold text-white">Swordfish</span>
        </div>
        <h1 className="text-xl font-semibold text-white mb-2">Create your account</h1>
        <p className="text-slate-400">AI-powered email security for your organization</p>
      </div>

      {/* Clerk Sign Up Component */}
      <SignUp
        afterSignUpUrl="/onboarding"
        signInUrl="/sign-in"
      />

      {/* Account Type Info */}
      <div className="mt-8 max-w-md text-center">
        <p className="text-sm text-slate-400 mb-4">
          After signing up, you&apos;ll choose your account type:
        </p>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <div className="font-medium text-white mb-1">Single Company</div>
            <p className="text-slate-400 text-xs">Protect your organization</p>
          </div>
          <div className="bg-slate-800/50 border border-purple-700/50 rounded-lg p-4">
            <div className="font-medium text-purple-300 mb-1">MSP / Partner</div>
            <p className="text-slate-400 text-xs">Manage multiple clients</p>
          </div>
        </div>
      </div>
    </div>
  );
}
