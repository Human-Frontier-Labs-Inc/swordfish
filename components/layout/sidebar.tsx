'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useTenant } from '@/lib/auth/tenant-context';
import clsx from 'clsx';

// Navigation items
const navigation = [
  { name: 'Overview', href: '/dashboard', icon: HomeIcon },
  { name: 'Emails', href: '/dashboard/emails', icon: EnvelopeIcon },
  { name: 'Threats', href: '/dashboard/threats', icon: ShieldIcon },
  { name: 'Quarantine', href: '/dashboard/quarantine', icon: InboxIcon },
  { name: 'Policies', href: '/dashboard/policies', icon: DocumentIcon },
  { name: 'Integrations', href: '/dashboard/integrations', icon: PlugIcon },
  { name: 'Reports', href: '/dashboard/reports', icon: ChartIcon },
];

const adminNavigation = [
  { name: 'Settings', href: '/dashboard/settings', icon: CogIcon },
];

interface SidebarProps {
  onNavigate?: () => void;
}

export function Sidebar({ onNavigate }: SidebarProps) {
  const pathname = usePathname();
  const { currentTenant, canManageTenant, isMspUser } = useTenant();

  return (
    <div className="relative flex h-full w-64 flex-col bg-slate-900 overflow-hidden">
      {/* Subtle background pattern */}
      <div className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: 'radial-gradient(circle at 1px 1px, rgba(148,163,184,0.8) 1px, transparent 0)',
          backgroundSize: '24px 24px',
        }}
      />
      {/* Gradient overlay on sidebar */}
      <div className="absolute inset-0 bg-gradient-to-b from-blue-900/20 via-transparent to-slate-900" />

      {/* Logo */}
      <div className="relative flex h-16 items-center px-6">
        <Link href="/dashboard" className="flex items-center gap-2.5 group" onClick={onNavigate}>
          <SwordfishLogo className="h-8 w-8 text-blue-400 transition-transform duration-200 group-hover:scale-110" />
          <span className="text-xl font-bold text-white tracking-tight">
            Sword<span className="text-cyan-400">Phish</span>
          </span>
        </Link>
      </div>

      {/* MSP Dashboard Link */}
      {isMspUser && (
        <div className="relative mx-4 mb-2">
          <Link
            href="/msp"
            className={clsx(
              'flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-all duration-200',
              pathname.startsWith('/msp')
                ? 'bg-purple-600 text-white shadow-lg shadow-purple-600/20'
                : 'bg-purple-900/50 text-purple-200 hover:bg-purple-800 hover:text-white'
            )}
            onClick={onNavigate}
          >
            <BuildingIcon className="h-5 w-5" />
            MSP Dashboard
          </Link>
        </div>
      )}

      {/* Current Tenant */}
      {currentTenant && (
        <div className="relative mx-4 mb-4 rounded-lg bg-slate-800/80 border border-slate-700/50 p-3 backdrop-blur-sm">
          <div className="text-xs font-medium uppercase tracking-wider text-slate-400">
            Current Tenant
          </div>
          <div className="mt-1 truncate font-medium text-white">
            {currentTenant.name}
          </div>
          <div className="mt-0.5 text-xs text-slate-400">
            {currentTenant.plan.charAt(0).toUpperCase() + currentTenant.plan.slice(1)} Plan
          </div>
        </div>
      )}

      {/* Main Navigation */}
      <nav className="relative flex-1 space-y-0.5 px-3" role="navigation" aria-label="Main navigation">
        {navigation.map((item) => {
          const isActive = pathname === item.href ||
            (item.href !== '/dashboard' && pathname.startsWith(item.href));

          return (
            <Link
              key={item.name}
              href={item.href}
              onClick={onNavigate}
              className={clsx(
                'group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all duration-200',
                isActive
                  ? 'bg-blue-600/90 text-white shadow-lg shadow-blue-600/20 border-l-2 border-cyan-400 pl-[10px]'
                  : 'text-slate-300 hover:bg-slate-800/80 hover:text-white hover:pl-4'
              )}
            >
              <item.icon
                className={clsx(
                  'h-5 w-5 flex-shrink-0 transition-colors duration-200',
                  isActive ? 'text-cyan-300' : 'text-slate-400 group-hover:text-blue-400'
                )}
              />
              {item.name}
            </Link>
          );
        })}

        {/* Admin section */}
        {canManageTenant && (
          <>
            <div className="my-4 border-t border-slate-700/50" />
            <div className="px-3 py-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
              Administration
            </div>
            {adminNavigation.map((item) => {
              const isActive = pathname === item.href || pathname.startsWith(item.href);

              return (
                <Link
                  key={item.name}
                  href={item.href}
                  onClick={onNavigate}
                  className={clsx(
                    'group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all duration-200',
                    isActive
                      ? 'bg-blue-600/90 text-white shadow-lg shadow-blue-600/20 border-l-2 border-cyan-400 pl-[10px]'
                      : 'text-slate-300 hover:bg-slate-800/80 hover:text-white hover:pl-4'
                  )}
                >
                  <item.icon
                    className={clsx(
                      'h-5 w-5 flex-shrink-0 transition-colors duration-200',
                      isActive ? 'text-cyan-300' : 'text-slate-400 group-hover:text-blue-400'
                    )}
                  />
                  {item.name}
                </Link>
              );
            })}
          </>
        )}
      </nav>

      {/* Bottom section */}
      <div className="relative border-t border-slate-700/50 p-4" />
    </div>
  );
}

// Icons (inline SVG components)
function SwordfishLogo({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
    </svg>
  );
}

function HomeIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25" />
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

function DocumentIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
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

function ChartIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
    </svg>
  );
}

function CogIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.24-.438.613-.431.992a6.759 6.759 0 010 .255c-.007.378.138.75.43.99l1.005.828c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.02-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 010-.255c.007-.378-.138-.75-.43-.99l-1.004-.828a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  );
}

function BuildingIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21" />
    </svg>
  );
}
