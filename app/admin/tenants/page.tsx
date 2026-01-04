'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface Tenant {
  id: string;
  clerkOrgId: string;
  name: string;
  domain: string | null;
  plan: 'starter' | 'pro' | 'enterprise';
  status: 'active' | 'suspended' | 'pending';
  userCount: number;
  emailsProcessed: number;
  threatsBlocked: number;
  createdAt: string;
  lastActivityAt: string | null;
}

export default function TenantsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<{ plan?: string; status?: string }>({});

  useEffect(() => {
    loadTenants();
  }, [filter]);

  async function loadTenants() {
    try {
      const params = new URLSearchParams();
      if (filter.plan) params.set('plan', filter.plan);
      if (filter.status) params.set('status', filter.status);

      const response = await fetch(`/api/admin/tenants?${params}`);
      if (response.ok) {
        const data = await response.json();
        setTenants(data.tenants);
      }
    } catch (error) {
      console.error('Failed to load tenants:', error);
    } finally {
      setLoading(false);
    }
  }

  const filteredTenants = tenants.filter(
    (t) =>
      t.name.toLowerCase().includes(search.toLowerCase()) ||
      t.domain?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Tenants</h1>
        <Link
          href="/admin/tenants/new"
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
        >
          Add Tenant
        </Link>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg border p-4">
        <div className="flex flex-wrap gap-4">
          <input
            type="text"
            placeholder="Search tenants..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="border rounded-lg px-4 py-2 w-64"
          />
          <select
            value={filter.plan || ''}
            onChange={(e) => setFilter({ ...filter, plan: e.target.value || undefined })}
            className="border rounded-lg px-4 py-2"
          >
            <option value="">All Plans</option>
            <option value="starter">Starter</option>
            <option value="pro">Pro</option>
            <option value="enterprise">Enterprise</option>
          </select>
          <select
            value={filter.status || ''}
            onChange={(e) => setFilter({ ...filter, status: e.target.value || undefined })}
            className="border rounded-lg px-4 py-2"
          >
            <option value="">All Statuses</option>
            <option value="active">Active</option>
            <option value="suspended">Suspended</option>
            <option value="pending">Pending</option>
          </select>
        </div>
      </div>

      {/* Tenants Table */}
      <div className="bg-white rounded-lg border overflow-hidden">
        {loading ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto" />
          </div>
        ) : filteredTenants.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            No tenants found
          </div>
        ) : (
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-500">
                  Tenant
                </th>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-500">
                  Plan
                </th>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-500">
                  Status
                </th>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-500">
                  Users
                </th>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-500">
                  Emails (30d)
                </th>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-500">
                  Threats
                </th>
                <th className="text-left px-6 py-3 text-sm font-medium text-gray-500">
                  Last Activity
                </th>
                <th className="text-right px-6 py-3 text-sm font-medium text-gray-500">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {filteredTenants.map((tenant) => (
                <tr key={tenant.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <div>
                      <p className="font-medium text-gray-900">{tenant.name}</p>
                      {tenant.domain && (
                        <p className="text-sm text-gray-500">{tenant.domain}</p>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <PlanBadge plan={tenant.plan} />
                  </td>
                  <td className="px-6 py-4">
                    <StatusBadge status={tenant.status} />
                  </td>
                  <td className="px-6 py-4 text-gray-600">{tenant.userCount}</td>
                  <td className="px-6 py-4 text-gray-600">
                    {tenant.emailsProcessed.toLocaleString()}
                  </td>
                  <td className="px-6 py-4 text-gray-600">
                    {tenant.threatsBlocked.toLocaleString()}
                  </td>
                  <td className="px-6 py-4 text-gray-500 text-sm">
                    {tenant.lastActivityAt
                      ? new Date(tenant.lastActivityAt).toLocaleDateString()
                      : 'Never'}
                  </td>
                  <td className="px-6 py-4 text-right">
                    <div className="flex justify-end gap-2">
                      <Link
                        href={`/admin/tenants/${tenant.id}`}
                        className="text-blue-600 hover:text-blue-800 text-sm"
                      >
                        View
                      </Link>
                      <Link
                        href={`/admin/tenants/${tenant.id}/edit`}
                        className="text-gray-600 hover:text-gray-800 text-sm"
                      >
                        Edit
                      </Link>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function PlanBadge({ plan }: { plan: string }) {
  const colors = {
    starter: 'bg-gray-100 text-gray-700',
    pro: 'bg-blue-100 text-blue-700',
    enterprise: 'bg-purple-100 text-purple-700',
  };

  return (
    <span
      className={`px-2 py-1 text-xs font-medium rounded ${
        colors[plan as keyof typeof colors] || colors.starter
      }`}
    >
      {plan.charAt(0).toUpperCase() + plan.slice(1)}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors = {
    active: 'bg-green-100 text-green-700',
    suspended: 'bg-red-100 text-red-700',
    pending: 'bg-yellow-100 text-yellow-700',
  };

  return (
    <span
      className={`px-2 py-1 text-xs font-medium rounded ${
        colors[status as keyof typeof colors] || colors.pending
      }`}
    >
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}
