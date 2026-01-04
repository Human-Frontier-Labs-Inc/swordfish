'use client';

import clsx from 'clsx';

interface Integration {
  id: string;
  type: 'o365' | 'gmail' | 'smtp';
  name: string;
  status: 'connected' | 'pending' | 'error' | 'disconnected';
  lastSync?: Date;
  errorMessage?: string;
}

interface IntegrationStatusProps {
  integrations: Integration[];
}

const integrationMeta = {
  o365: {
    name: 'Microsoft 365',
    icon: MicrosoftIcon,
    color: 'blue',
  },
  gmail: {
    name: 'Google Workspace',
    icon: GoogleIcon,
    color: 'red',
  },
  smtp: {
    name: 'SMTP Gateway',
    icon: MailIcon,
    color: 'gray',
  },
};

const statusConfig = {
  connected: {
    label: 'Connected',
    color: 'green',
    dotClass: 'bg-green-500',
    textClass: 'text-green-700',
    bgClass: 'bg-green-50',
  },
  pending: {
    label: 'Pending',
    color: 'yellow',
    dotClass: 'bg-yellow-500',
    textClass: 'text-yellow-700',
    bgClass: 'bg-yellow-50',
  },
  error: {
    label: 'Error',
    color: 'red',
    dotClass: 'bg-red-500',
    textClass: 'text-red-700',
    bgClass: 'bg-red-50',
  },
  disconnected: {
    label: 'Disconnected',
    color: 'gray',
    dotClass: 'bg-gray-400',
    textClass: 'text-gray-600',
    bgClass: 'bg-gray-50',
  },
};

export function IntegrationStatus({ integrations }: IntegrationStatusProps) {
  return (
    <div className="overflow-hidden rounded-lg bg-white shadow">
      <div className="border-b border-gray-200 px-5 py-4">
        <h3 className="text-lg font-medium text-gray-900">Integrations</h3>
      </div>
      <ul className="divide-y divide-gray-200">
        {integrations.length === 0 ? (
          <li className="px-5 py-8 text-center">
            <PlugIcon className="mx-auto h-12 w-12 text-gray-300" />
            <p className="mt-2 text-sm text-gray-500">No integrations configured</p>
            <a
              href="/dashboard/integrations"
              className="mt-3 inline-flex items-center text-sm font-medium text-blue-600 hover:text-blue-500"
            >
              Connect an integration
              <ArrowRightIcon className="ml-1 h-4 w-4" />
            </a>
          </li>
        ) : (
          integrations.map((integration) => {
            const meta = integrationMeta[integration.type];
            const status = statusConfig[integration.status];
            const Icon = meta.icon;

            return (
              <li key={integration.id} className="px-5 py-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gray-100">
                      <Icon className="h-6 w-6 text-gray-600" />
                    </div>
                    <div>
                      <p className="font-medium text-gray-900">{meta.name}</p>
                      {integration.lastSync && (
                        <p className="text-xs text-gray-500">
                          Last synced: {formatRelativeTime(integration.lastSync)}
                        </p>
                      )}
                    </div>
                  </div>
                  <div
                    className={clsx(
                      'flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium',
                      status.bgClass,
                      status.textClass
                    )}
                    data-testid={`integration-${integration.type}`}
                  >
                    <span className={clsx('h-1.5 w-1.5 rounded-full', status.dotClass)} />
                    {status.label}
                  </div>
                </div>
                {integration.status === 'error' && integration.errorMessage && (
                  <div className="mt-2 rounded-md bg-red-50 p-2">
                    <p className="text-xs text-red-700">{integration.errorMessage}</p>
                  </div>
                )}
              </li>
            );
          })
        )}
      </ul>
      <div className="border-t border-gray-200 bg-gray-50 px-5 py-3">
        <a
          href="/dashboard/integrations"
          className="text-sm font-medium text-blue-600 hover:text-blue-500"
        >
          Manage integrations →
        </a>
      </div>
    </div>
  );
}

function formatRelativeTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
}

// Icons
function MicrosoftIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor">
      <path d="M11.4 24H0V12.6h11.4V24zM24 24H12.6V12.6H24V24zM11.4 11.4H0V0h11.4v11.4zm12.6 0H12.6V0H24v11.4z" />
    </svg>
  );
}

function GoogleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor">
      <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
      <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
      <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
      <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
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

function PlugIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
    </svg>
  );
}

function ArrowRightIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
    </svg>
  );
}
