'use client';

import { useTenant } from '@/lib/auth/tenant-context';
import { useDashboardData } from '@/lib/hooks/use-dashboard-data';
import { StatCard } from '@/components/dashboard/stat-card';
import { IntegrationStatus } from '@/components/dashboard/integration-status';
import { RecentThreats } from '@/components/dashboard/recent-threats';

// Mock integrations - will be replaced when integrations are built
const mockIntegrations = [
  {
    id: '1',
    type: 'o365' as const,
    name: 'Microsoft 365',
    status: 'disconnected' as const,
    lastSync: undefined,
  },
];

// Demo threats to show when no real data exists yet
const demoThreats = [
  {
    id: 'demo-1',
    subject: 'Urgent: Verify your account immediately',
    from: 'security@paypa1-verify.com',
    verdict: 'block' as const,
    signals: ['Homoglyph domain', 'SPF fail', 'Urgency language'],
    timestamp: new Date(Date.now() - 1000 * 60 * 30),
  },
  {
    id: 'demo-2',
    subject: 'Invoice #INV-2024-001 attached',
    from: 'accounting@supplier-invoice.net',
    verdict: 'quarantine' as const,
    signals: ['New domain', 'Suspicious attachment'],
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2),
  },
  {
    id: 'demo-3',
    subject: 'Request for wire transfer',
    from: '"CEO John Smith" <ceo.john@gmail.com>',
    verdict: 'block' as const,
    signals: ['Display name spoof', 'BEC pattern', 'Free email provider'],
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 5),
  },
];

export default function DashboardPage() {
  const { currentTenant } = useTenant();
  const { stats, threats, isLoading } = useDashboardData();

  // Use real stats if available, otherwise show zeros with demo message
  const displayStats = {
    threatsBlocked: stats?.threatsBlocked || 0,
    quarantined: stats?.quarantined || 0,
    emailsScanned: stats?.emailsScanned || 0,
    detectionRate: stats?.detectionRate || 0,
  };

  // Demo mode is only when no emails have been scanned at all
  const isDemo = (stats?.emailsScanned || 0) === 0 && threats.length === 0;

  // Show demo threats only in demo mode, otherwise show real threats (or empty if no threats)
  const displayThreats = threats.length > 0
    ? threats.map(t => ({
        id: t.id,
        subject: t.subject || 'Unknown Subject',
        from: t.sender || 'Unknown Sender',
        verdict: t.verdict as 'block' | 'quarantine' | 'suspicious',
        signals: [t.detail],
        timestamp: new Date(t.timestamp),
      }))
    : isDemo ? demoThreats : [];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="mt-1 text-sm text-gray-500">
          Overview of your email security status for {currentTenant?.name || 'your organization'}
        </p>
      </div>

      {/* Demo Banner */}
      {isDemo && !isLoading && (
        <div className="rounded-lg bg-blue-50 border border-blue-200 p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <InfoIcon className="h-5 w-5 text-blue-400" />
            </div>
            <div className="ml-3">
              <p className="text-sm text-blue-700">
                <strong>Demo Mode:</strong> No emails have been scanned yet. Connect an email integration to start protecting your inbox, or use the API to analyze emails.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Threats Blocked (7d)"
          value={displayStats.threatsBlocked}
          icon={ShieldIcon}
          color="red"
          testId="threat-count-24h"
        />
        <StatCard
          title="Quarantine Pending"
          value={displayStats.quarantined}
          icon={InboxIcon}
          color="yellow"
          testId="quarantine-pending"
        />
        <StatCard
          title="Emails Scanned"
          value={displayStats.emailsScanned.toLocaleString()}
          icon={MailIcon}
          color="blue"
        />
        <StatCard
          title="Detection Rate"
          value={displayStats.emailsScanned > 0 ? `${displayStats.detectionRate}%` : '--'}
          icon={ChartIcon}
          color="green"
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Recent Threats - 2 columns */}
        <div className="lg:col-span-2">
          <RecentThreats threats={displayThreats} isDemo={isDemo} />
        </div>

        {/* Integration Status - 1 column */}
        <div>
          <IntegrationStatus integrations={mockIntegrations} />
        </div>
      </div>

      {/* Quick Actions */}
      <div className="rounded-lg bg-white p-6 shadow">
        <h3 className="text-lg font-medium text-gray-900">Quick Actions</h3>
        <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <QuickAction
            title="Review Quarantine"
            description={`${displayStats.quarantined} emails pending`}
            href="/dashboard/quarantine"
            icon={InboxIcon}
          />
          <QuickAction
            title="Add Policy"
            description="Create allow/block rules"
            href="/dashboard/policies/new"
            icon={PlusIcon}
          />
          <QuickAction
            title="View Reports"
            description="Download security reports"
            href="/dashboard/reports"
            icon={DocumentIcon}
          />
          <QuickAction
            title="Connect Integration"
            description="Add email provider"
            href="/dashboard/integrations"
            icon={PlugIcon}
          />
        </div>
      </div>
    </div>
  );
}

// Quick Action Component
function QuickAction({
  title,
  description,
  href,
  icon: Icon,
}: {
  title: string;
  description: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
}) {
  return (
    <a
      href={href}
      className="group relative flex items-center gap-4 rounded-lg border border-gray-200 p-4 hover:border-blue-500 hover:bg-blue-50 transition-colors"
    >
      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gray-100 group-hover:bg-blue-100">
        <Icon className="h-5 w-5 text-gray-600 group-hover:text-blue-600" />
      </div>
      <div>
        <p className="font-medium text-gray-900 group-hover:text-blue-900">{title}</p>
        <p className="text-sm text-gray-500 group-hover:text-blue-600">{description}</p>
      </div>
    </a>
  );
}

// Icons
function ShieldIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
    </svg>
  );
}

function InboxIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 13.5h3.86a2.25 2.25 0 012.012 1.244l.256.512a2.25 2.25 0 002.013 1.244h3.218a2.25 2.25 0 002.013-1.244l.256-.512a2.25 2.25 0 012.013-1.244h3.859m-19.5.338V18a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18v-4.162c0-.224-.034-.447-.1-.661L19.24 5.338a2.25 2.25 0 00-2.15-1.588H6.911a2.25 2.25 0 00-2.15 1.588L2.35 13.177a2.25 2.25 0 00-.1.661z" />
    </svg>
  );
}

function MailIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
    </svg>
  );
}

function ChartIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
    </svg>
  );
}

function PlusIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
    </svg>
  );
}

function DocumentIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
    </svg>
  );
}

function PlugIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
    </svg>
  );
}

function InfoIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" />
    </svg>
  );
}
