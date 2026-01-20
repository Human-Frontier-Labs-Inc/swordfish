'use client';

import { useState, useEffect, useCallback } from 'react';
import { useTenant } from '@/lib/auth/tenant-context';
import Link from 'next/link';

interface DomainConfig {
  id: string;
  status: 'pending' | 'active' | 'error' | 'disabled';
  errorMessage: string | null;
  totalUsers: number;
  activeUsers: number;
  lastUserSync: string | null;
  lastEmailSync: string | null;
  // Google specific
  serviceAccountEmail?: string;
  adminEmail?: string;
  // Microsoft specific
  azureTenantId?: string;
  clientId?: string;
}

interface ConfigState {
  google_workspace: DomainConfig | null;
  microsoft_365: DomainConfig | null;
}

export default function DomainWidePage() {
  const { currentTenant, canManageTenant } = useTenant();
  const [configs, setConfigs] = useState<ConfigState>({ google_workspace: null, microsoft_365: null });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [syncing, setSyncing] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Form state for Google Workspace
  const [googleForm, setGoogleForm] = useState({
    serviceAccountKey: '',
    adminEmail: '',
  });

  // Form state for Microsoft 365
  const [microsoftForm, setMicrosoftForm] = useState({
    azureTenantId: '',
    clientId: '',
    clientSecret: '',
  });

  const fetchConfigs = useCallback(async () => {
    if (!currentTenant) return;

    try {
      const response = await fetch('/api/integrations/domain-wide');
      if (response.ok) {
        const data = await response.json();
        setConfigs(data);
      }
    } catch (err) {
      console.error('Failed to fetch configs:', err);
    } finally {
      setLoading(false);
    }
  }, [currentTenant]);

  useEffect(() => {
    fetchConfigs();
  }, [fetchConfigs]);

  const handleGoogleSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    setSuccess(null);

    try {
      const response = await fetch('/api/integrations/domain-wide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: 'google_workspace',
          serviceAccountKey: googleForm.serviceAccountKey,
          adminEmail: googleForm.adminEmail,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error);
      } else {
        setSuccess('Google Workspace domain-wide monitoring configured successfully!');
        setGoogleForm({ serviceAccountKey: '', adminEmail: '' });
        fetchConfigs();
      }
    } catch (err) {
      setError('Failed to configure Google Workspace');
    } finally {
      setSaving(false);
    }
  };

  const handleMicrosoftSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    setSuccess(null);

    try {
      const response = await fetch('/api/integrations/domain-wide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: 'microsoft_365',
          azureTenantId: microsoftForm.azureTenantId,
          clientId: microsoftForm.clientId,
          clientSecret: microsoftForm.clientSecret,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error);
      } else {
        setSuccess('Microsoft 365 domain-wide monitoring configured successfully!');
        setMicrosoftForm({ azureTenantId: '', clientId: '', clientSecret: '' });
        fetchConfigs();
      }
    } catch (err) {
      setError('Failed to configure Microsoft 365');
    } finally {
      setSaving(false);
    }
  };

  const handleSync = async (provider: 'google_workspace' | 'microsoft_365') => {
    setSyncing(provider);
    setError(null);

    try {
      const response = await fetch('/api/integrations/domain-wide/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, setupWebhooks: true }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error);
      } else {
        setSuccess(`Synced ${data.sync?.usersDiscovered || 0} users`);
        fetchConfigs();
      }
    } catch (err) {
      setError('Failed to sync users');
    } finally {
      setSyncing(null);
    }
  };

  if (!canManageTenant) {
    return (
      <div className="p-8 text-center">
        <h2 className="text-xl font-bold text-gray-900">Access Denied</h2>
        <p className="mt-2 text-gray-600">You need admin permissions to configure domain-wide monitoring.</p>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Domain-Wide Email Monitoring</h1>
          <p className="mt-1 text-sm text-gray-500">
            Monitor all emails across your organization without requiring individual user consent
          </p>
        </div>
        <Link
          href="/dashboard/integrations"
          className="text-sm text-blue-600 hover:text-blue-800"
        >
          Back to Integrations
        </Link>
      </div>

      {/* Alerts */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <p className="text-red-800">{error}</p>
        </div>
      )}
      {success && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
          <p className="text-green-800">{success}</p>
        </div>
      )}

      {/* Google Workspace Section */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center gap-3">
            <GoogleIcon className="h-8 w-8" />
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Google Workspace</h2>
              <p className="text-sm text-gray-500">Domain-wide delegation via service account</p>
            </div>
            {configs.google_workspace && (
              <StatusBadge status={configs.google_workspace.status} />
            )}
          </div>
        </div>

        <div className="p-6">
          {configs.google_workspace?.status === 'active' ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <StatCard label="Total Users" value={configs.google_workspace.totalUsers} />
                <StatCard label="Active Users" value={configs.google_workspace.activeUsers} />
                <StatCard
                  label="Last User Sync"
                  value={configs.google_workspace.lastUserSync
                    ? new Date(configs.google_workspace.lastUserSync).toLocaleString()
                    : 'Never'}
                />
                <StatCard
                  label="Last Email Sync"
                  value={configs.google_workspace.lastEmailSync
                    ? new Date(configs.google_workspace.lastEmailSync).toLocaleString()
                    : 'Never'}
                />
              </div>
              <div className="pt-4 border-t">
                <p className="text-sm text-gray-600 mb-2">
                  Service Account: {configs.google_workspace.serviceAccountEmail}
                </p>
                <p className="text-sm text-gray-600 mb-4">
                  Admin Email: {configs.google_workspace.adminEmail}
                </p>
                <button
                  onClick={() => handleSync('google_workspace')}
                  disabled={syncing === 'google_workspace'}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                  {syncing === 'google_workspace' ? 'Syncing...' : 'Sync Users Now'}
                </button>
              </div>
            </div>
          ) : (
            <form onSubmit={handleGoogleSetup} className="space-y-4">
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-sm">
                <h3 className="font-medium text-blue-900 mb-2">Setup Requirements:</h3>
                <ol className="list-decimal list-inside space-y-1 text-blue-800">
                  <li>Create a service account in Google Cloud Console</li>
                  <li>Enable the Admin SDK API and Gmail API</li>
                  <li>Download the JSON key file</li>
                  <li>In Google Admin Console, enable domain-wide delegation</li>
                  <li>Grant the service account these OAuth scopes:
                    <ul className="ml-6 mt-1 text-xs">
                      <li>• https://www.googleapis.com/auth/admin.directory.user.readonly</li>
                      <li>• https://www.googleapis.com/auth/gmail.readonly</li>
                      <li>• https://www.googleapis.com/auth/gmail.modify</li>
                    </ul>
                  </li>
                </ol>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Service Account Key (JSON)
                </label>
                <textarea
                  value={googleForm.serviceAccountKey}
                  onChange={(e) => setGoogleForm({ ...googleForm, serviceAccountKey: e.target.value })}
                  rows={6}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg font-mono text-sm"
                  placeholder='{"type": "service_account", "project_id": "...", ...}'
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Admin Email (for impersonation)
                </label>
                <input
                  type="email"
                  value={googleForm.adminEmail}
                  onChange={(e) => setGoogleForm({ ...googleForm, adminEmail: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                  placeholder="admin@yourdomain.com"
                  required
                />
                <p className="mt-1 text-xs text-gray-500">
                  This must be a Google Workspace super admin account
                </p>
              </div>

              <button
                type="submit"
                disabled={saving}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {saving ? 'Configuring...' : 'Configure Google Workspace'}
              </button>
            </form>
          )}

          {configs.google_workspace?.status === 'error' && (
            <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
              <p className="text-red-800">{configs.google_workspace.errorMessage}</p>
            </div>
          )}
        </div>
      </div>

      {/* Microsoft 365 Section */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center gap-3">
            <MicrosoftIcon className="h-8 w-8" />
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Microsoft 365</h2>
              <p className="text-sm text-gray-500">Application permissions with admin consent</p>
            </div>
            {configs.microsoft_365 && (
              <StatusBadge status={configs.microsoft_365.status} />
            )}
          </div>
        </div>

        <div className="p-6">
          {configs.microsoft_365?.status === 'active' ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <StatCard label="Total Users" value={configs.microsoft_365.totalUsers} />
                <StatCard label="Active Users" value={configs.microsoft_365.activeUsers} />
                <StatCard
                  label="Last User Sync"
                  value={configs.microsoft_365.lastUserSync
                    ? new Date(configs.microsoft_365.lastUserSync).toLocaleString()
                    : 'Never'}
                />
                <StatCard
                  label="Last Email Sync"
                  value={configs.microsoft_365.lastEmailSync
                    ? new Date(configs.microsoft_365.lastEmailSync).toLocaleString()
                    : 'Never'}
                />
              </div>
              <div className="pt-4 border-t">
                <p className="text-sm text-gray-600 mb-2">
                  Azure Tenant ID: {configs.microsoft_365.azureTenantId}
                </p>
                <p className="text-sm text-gray-600 mb-4">
                  Client ID: {configs.microsoft_365.clientId}
                </p>
                <button
                  onClick={() => handleSync('microsoft_365')}
                  disabled={syncing === 'microsoft_365'}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                  {syncing === 'microsoft_365' ? 'Syncing...' : 'Sync Users Now'}
                </button>
              </div>
            </div>
          ) : (
            <form onSubmit={handleMicrosoftSetup} className="space-y-4">
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-sm">
                <h3 className="font-medium text-blue-900 mb-2">Setup Requirements:</h3>
                <ol className="list-decimal list-inside space-y-1 text-blue-800">
                  <li>Create an app registration in Azure Portal</li>
                  <li>Add API permissions: Microsoft Graph → Application permissions
                    <ul className="ml-6 mt-1 text-xs">
                      <li>• User.Read.All (to list users)</li>
                      <li>• Mail.Read (to read all mailboxes)</li>
                    </ul>
                  </li>
                  <li>Grant admin consent for your organization</li>
                  <li>Create a client secret</li>
                </ol>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Azure Tenant ID
                </label>
                <input
                  type="text"
                  value={microsoftForm.azureTenantId}
                  onChange={(e) => setMicrosoftForm({ ...microsoftForm, azureTenantId: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Application (Client) ID
                </label>
                <input
                  type="text"
                  value={microsoftForm.clientId}
                  onChange={(e) => setMicrosoftForm({ ...microsoftForm, clientId: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Client Secret
                </label>
                <input
                  type="password"
                  value={microsoftForm.clientSecret}
                  onChange={(e) => setMicrosoftForm({ ...microsoftForm, clientSecret: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg"
                  placeholder="Enter client secret"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={saving}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {saving ? 'Configuring...' : 'Configure Microsoft 365'}
              </button>
            </form>
          )}

          {configs.microsoft_365?.status === 'error' && (
            <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
              <p className="text-red-800">{configs.microsoft_365.errorMessage}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    active: 'bg-green-100 text-green-800',
    pending: 'bg-yellow-100 text-yellow-800',
    error: 'bg-red-100 text-red-800',
    disabled: 'bg-gray-100 text-gray-800',
  };

  return (
    <span className={`ml-auto px-2 py-1 text-xs font-medium rounded-full ${colors[status] || colors.disabled}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="bg-gray-50 rounded-lg p-3">
      <p className="text-xs font-medium text-gray-500 uppercase">{label}</p>
      <p className="mt-1 text-lg font-semibold text-gray-900">{value}</p>
    </div>
  );
}

function GoogleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24">
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
    </svg>
  );
}

function MicrosoftIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24">
      <path fill="#F25022" d="M1 1h10v10H1z"/>
      <path fill="#00A4EF" d="M1 13h10v10H1z"/>
      <path fill="#7FBA00" d="M13 1h10v10H13z"/>
      <path fill="#FFB900" d="M13 13h10v10H13z"/>
    </svg>
  );
}
