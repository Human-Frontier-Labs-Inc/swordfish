'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';

interface TenantDetail {
  id: string;
  clerkOrgId: string;
  name: string;
  domain: string | null;
  plan: 'starter' | 'pro' | 'enterprise';
  status: 'active' | 'suspended' | 'pending';
  settings: {
    detection: {
      suspiciousThreshold: number;
      quarantineThreshold: number;
      blockThreshold: number;
      enableLlmAnalysis: boolean;
      llmDailyLimit: number;
    };
    notifications: {
      emailEnabled: boolean;
      severityThreshold: string;
    };
    quarantine: {
      autoDeleteAfterDays: number;
      allowUserRelease: boolean;
    };
  };
  userCount: number;
  emailsProcessed: number;
  threatsBlocked: number;
  createdAt: string;
  updatedAt: string;
}

interface TenantUser {
  id: string;
  email: string;
  name: string | null;
  role: string;
  status: string;
  lastLoginAt: string | null;
}

export default function TenantDetailPage() {
  const params = useParams();
  const tenantId = params.id as string;

  const [tenant, setTenant] = useState<TenantDetail | null>(null);
  const [users, setUsers] = useState<TenantUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'users' | 'settings' | 'activity'>('overview');

  useEffect(() => {
    loadTenant();
    loadUsers();
  }, [tenantId]);

  async function loadTenant() {
    try {
      const response = await fetch(`/api/admin/tenants/${tenantId}`);
      if (response.ok) {
        const data = await response.json();
        setTenant(data.tenant);
      }
    } catch (error) {
      console.error('Failed to load tenant:', error);
    } finally {
      setLoading(false);
    }
  }

  async function loadUsers() {
    try {
      const response = await fetch(`/api/admin/tenants/${tenantId}/users`);
      if (response.ok) {
        const data = await response.json();
        setUsers(data.users);
      }
    } catch (error) {
      console.error('Failed to load users:', error);
    }
  }

  async function updateStatus(status: 'active' | 'suspended') {
    if (!confirm(`Are you sure you want to ${status === 'suspended' ? 'suspend' : 'activate'} this tenant?`)) {
      return;
    }

    try {
      const response = await fetch(`/api/admin/tenants/${tenantId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });
      if (response.ok) {
        loadTenant();
      }
    } catch (error) {
      console.error('Failed to update status:', error);
    }
  }

  if (loading) {
    return (
      <div className="animate-pulse space-y-6">
        <div className="h-8 bg-gray-200 rounded w-48" />
        <div className="h-64 bg-gray-200 rounded-lg" />
      </div>
    );
  }

  if (!tenant) {
    return (
      <div className="text-center py-12">
        <h2 className="text-xl font-semibold text-gray-900">Tenant not found</h2>
        <Link href="/admin/tenants" className="text-blue-600 hover:text-blue-800 mt-2 inline-block">
          Back to tenants
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Link href="/admin/tenants" className="text-gray-400 hover:text-gray-600">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <h1 className="text-2xl font-bold text-gray-900">{tenant.name}</h1>
            <StatusBadge status={tenant.status} />
            <PlanBadge plan={tenant.plan} />
          </div>
          {tenant.domain && (
            <p className="text-gray-500 ml-8">{tenant.domain}</p>
          )}
        </div>
        <div className="flex gap-2">
          <Link
            href={`/admin/tenants/${tenantId}/edit`}
            className="px-4 py-2 border rounded-lg hover:bg-gray-50"
          >
            Edit
          </Link>
          {tenant.status === 'active' ? (
            <button
              onClick={() => updateStatus('suspended')}
              className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
            >
              Suspend
            </button>
          ) : (
            <button
              onClick={() => updateStatus('active')}
              className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
            >
              Activate
            </button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b">
        <nav className="flex gap-8">
          {(['overview', 'users', 'settings', 'activity'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`py-3 border-b-2 font-medium text-sm transition-colors ${
                activeTab === tab
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Stats */}
          <div className="lg:col-span-2 grid grid-cols-3 gap-4">
            <StatCard label="Users" value={tenant.userCount} />
            <StatCard label="Emails Processed" value={tenant.emailsProcessed} subtitle="Last 30 days" />
            <StatCard label="Threats Blocked" value={tenant.threatsBlocked} subtitle="Last 30 days" />
          </div>

          {/* Info Card */}
          <div className="bg-white rounded-lg border p-6">
            <h3 className="font-semibold text-gray-900 mb-4">Details</h3>
            <dl className="space-y-3 text-sm">
              <div className="flex justify-between">
                <dt className="text-gray-500">Tenant ID</dt>
                <dd className="font-mono text-gray-900">{tenant.id ? tenant.id.substring(0, 8) + '...' : 'N/A'}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-500">Clerk Org ID</dt>
                <dd className="font-mono text-gray-900">{tenant.clerkOrgId ? tenant.clerkOrgId.substring(0, 12) + '...' : 'N/A'}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-500">Created</dt>
                <dd className="text-gray-900">{new Date(tenant.createdAt).toLocaleDateString()}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-gray-500">Updated</dt>
                <dd className="text-gray-900">{new Date(tenant.updatedAt).toLocaleDateString()}</dd>
              </div>
            </dl>
          </div>
        </div>
      )}

      {activeTab === 'users' && (
        <div className="bg-white rounded-lg border overflow-hidden">
          {users.length === 0 ? (
            <div className="p-8 text-center text-gray-500">No users found</div>
          ) : (
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">User</th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Role</th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Status</th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Last Login</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {users.map((user) => (
                  <tr key={user.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4">
                      <p className="font-medium text-gray-900">{user.name || 'Unnamed'}</p>
                      <p className="text-sm text-gray-500">{user.email}</p>
                    </td>
                    <td className="px-6 py-4 capitalize">{user.role}</td>
                    <td className="px-6 py-4">
                      <StatusBadge status={user.status} />
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500">
                      {user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleDateString() : 'Never'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {activeTab === 'settings' && (
        <div className="bg-white rounded-lg border p-6 space-y-6">
          {tenant.settings?.detection ? (
            <div>
              <h3 className="font-semibold text-gray-900 mb-4">Detection Settings</h3>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="flex justify-between p-3 bg-gray-50 rounded">
                  <span>Suspicious Threshold</span>
                  <span className="font-medium">{tenant.settings.detection.suspiciousThreshold ?? 'N/A'}%</span>
                </div>
                <div className="flex justify-between p-3 bg-gray-50 rounded">
                  <span>Quarantine Threshold</span>
                  <span className="font-medium">{tenant.settings.detection.quarantineThreshold ?? 'N/A'}%</span>
                </div>
                <div className="flex justify-between p-3 bg-gray-50 rounded">
                  <span>Block Threshold</span>
                  <span className="font-medium">{tenant.settings.detection.blockThreshold ?? 'N/A'}%</span>
                </div>
                <div className="flex justify-between p-3 bg-gray-50 rounded">
                  <span>LLM Analysis</span>
                  <span className={`font-medium ${tenant.settings.detection.enableLlmAnalysis ? 'text-green-600' : 'text-gray-400'}`}>
                    {tenant.settings.detection.enableLlmAnalysis ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
              </div>
            </div>
          ) : (
            <div>
              <h3 className="font-semibold text-gray-900 mb-4">Detection Settings</h3>
              <p className="text-gray-500">No detection settings configured</p>
            </div>
          )}

          {tenant.settings?.quarantine ? (
            <div>
              <h3 className="font-semibold text-gray-900 mb-4">Quarantine Settings</h3>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="flex justify-between p-3 bg-gray-50 rounded">
                  <span>Auto-delete After</span>
                  <span className="font-medium">{tenant.settings.quarantine.autoDeleteAfterDays ?? 30} days</span>
                </div>
                <div className="flex justify-between p-3 bg-gray-50 rounded">
                  <span>User Release</span>
                  <span className={`font-medium ${tenant.settings.quarantine.allowUserRelease ? 'text-green-600' : 'text-gray-400'}`}>
                    {tenant.settings.quarantine.allowUserRelease ? 'Allowed' : 'Disabled'}
                  </span>
                </div>
              </div>
            </div>
          ) : (
            <div>
              <h3 className="font-semibold text-gray-900 mb-4">Quarantine Settings</h3>
              <p className="text-gray-500">No quarantine settings configured</p>
            </div>
          )}
        </div>
      )}

      {activeTab === 'activity' && (
        <div className="bg-white rounded-lg border p-6">
          <p className="text-gray-500">Activity log coming soon...</p>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, subtitle }: { label: string; value: number; subtitle?: string }) {
  return (
    <div className="bg-white rounded-lg border p-6">
      <p className="text-sm text-gray-500">{label}</p>
      <p className="text-3xl font-bold text-gray-900 mt-1">{value.toLocaleString()}</p>
      {subtitle && <p className="text-xs text-gray-400 mt-1">{subtitle}</p>}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    active: 'bg-green-100 text-green-700',
    suspended: 'bg-red-100 text-red-700',
    pending: 'bg-yellow-100 text-yellow-700',
    invited: 'bg-yellow-100 text-yellow-700',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded ${colors[status] || colors.pending}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

function PlanBadge({ plan }: { plan: string }) {
  const colors: Record<string, string> = {
    starter: 'bg-gray-100 text-gray-700',
    pro: 'bg-blue-100 text-blue-700',
    enterprise: 'bg-purple-100 text-purple-700',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded ${colors[plan] || colors.starter}`}>
      {plan.charAt(0).toUpperCase() + plan.slice(1)}
    </span>
  );
}
