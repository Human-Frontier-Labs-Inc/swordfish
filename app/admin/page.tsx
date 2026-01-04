'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface MSPStats {
  totalTenants: number;
  activeTenants: number;
  totalUsers: number;
  totalEmailsProcessed: number;
  totalThreatsBlocked: number;
  tenantsByPlan: { plan: string; count: number }[];
  recentActivity: Array<{
    id: string;
    tenantName: string;
    action: string;
    timestamp: string;
  }>;
}

export default function AdminDashboard() {
  const [stats, setStats] = useState<MSPStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadStats();
  }, []);

  async function loadStats() {
    try {
      const response = await fetch('/api/admin/stats');
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (error) {
      console.error('Failed to load admin stats:', error);
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="animate-pulse space-y-6">
        <div className="h-8 bg-gray-200 rounded w-48" />
        <div className="grid grid-cols-4 gap-6">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-32 bg-gray-200 rounded-lg" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">MSP Dashboard</h1>
        <Link
          href="/admin/tenants/new"
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
        >
          Add Tenant
        </Link>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Tenants"
          value={stats?.totalTenants || 0}
          subtitle={`${stats?.activeTenants || 0} active`}
          color="blue"
        />
        <StatCard
          title="Total Users"
          value={stats?.totalUsers || 0}
          color="green"
        />
        <StatCard
          title="Emails Processed"
          value={formatNumber(stats?.totalEmailsProcessed || 0)}
          subtitle="Last 30 days"
          color="purple"
        />
        <StatCard
          title="Threats Blocked"
          value={formatNumber(stats?.totalThreatsBlocked || 0)}
          subtitle="Last 30 days"
          color="red"
        />
      </div>

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Tenants by Plan */}
        <div className="bg-white rounded-lg border p-6">
          <h2 className="font-semibold text-gray-900 mb-4">Tenants by Plan</h2>
          <div className="space-y-3">
            {stats?.tenantsByPlan.map((plan) => (
              <div key={plan.plan} className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className={`w-3 h-3 rounded-full ${getPlanColor(plan.plan)}`} />
                  <span className="capitalize">{plan.plan}</span>
                </div>
                <span className="font-medium">{plan.count}</span>
              </div>
            )) || (
              <>
                <PlanRow plan="Starter" count={0} />
                <PlanRow plan="Pro" count={0} />
                <PlanRow plan="Enterprise" count={0} />
              </>
            )}
          </div>
        </div>

        {/* Recent Activity */}
        <div className="bg-white rounded-lg border p-6">
          <h2 className="font-semibold text-gray-900 mb-4">Recent Activity</h2>
          <div className="space-y-3">
            {stats?.recentActivity.length ? (
              stats.recentActivity.slice(0, 5).map((activity) => (
                <div key={activity.id} className="flex items-center justify-between text-sm">
                  <div>
                    <span className="font-medium">{activity.tenantName}</span>
                    <span className="text-gray-500 ml-2">{activity.action}</span>
                  </div>
                  <span className="text-gray-400 text-xs">
                    {new Date(activity.timestamp).toLocaleString()}
                  </span>
                </div>
              ))
            ) : (
              <p className="text-gray-500 text-sm">No recent activity</p>
            )}
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-white rounded-lg border p-6">
        <h2 className="font-semibold text-gray-900 mb-4">Quick Actions</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <QuickAction
            href="/admin/tenants"
            icon="building"
            label="Manage Tenants"
          />
          <QuickAction
            href="/admin/users"
            icon="users"
            label="Manage Users"
          />
          <QuickAction
            href="/admin/policies"
            icon="shield"
            label="Policy Templates"
          />
          <QuickAction
            href="/admin/audit"
            icon="clipboard"
            label="View Audit Log"
          />
        </div>
      </div>
    </div>
  );
}

function StatCard({
  title,
  value,
  subtitle,
  color,
}: {
  title: string;
  value: number | string;
  subtitle?: string;
  color: 'blue' | 'green' | 'purple' | 'red';
}) {
  const colors = {
    blue: 'bg-blue-50 border-blue-200 text-blue-600',
    green: 'bg-green-50 border-green-200 text-green-600',
    purple: 'bg-purple-50 border-purple-200 text-purple-600',
    red: 'bg-red-50 border-red-200 text-red-600',
  };

  return (
    <div className={`rounded-lg border p-6 ${colors[color]}`}>
      <p className="text-sm font-medium opacity-80">{title}</p>
      <p className="text-3xl font-bold mt-2">{value}</p>
      {subtitle && <p className="text-sm opacity-60 mt-1">{subtitle}</p>}
    </div>
  );
}

function PlanRow({ plan, count }: { plan: string; count: number }) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-3">
        <span className={`w-3 h-3 rounded-full ${getPlanColor(plan.toLowerCase())}`} />
        <span>{plan}</span>
      </div>
      <span className="font-medium">{count}</span>
    </div>
  );
}

function QuickAction({
  href,
  icon,
  label,
}: {
  href: string;
  icon: 'building' | 'users' | 'shield' | 'clipboard';
  label: string;
}) {
  const icons = {
    building: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
      </svg>
    ),
    users: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
      </svg>
    ),
    shield: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
    clipboard: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
      </svg>
    ),
  };

  return (
    <Link
      href={href}
      className="flex flex-col items-center gap-2 p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
    >
      <span className="text-gray-600">{icons[icon]}</span>
      <span className="text-sm font-medium text-gray-700">{label}</span>
    </Link>
  );
}

function getPlanColor(plan: string): string {
  switch (plan.toLowerCase()) {
    case 'starter':
      return 'bg-gray-400';
    case 'pro':
      return 'bg-blue-500';
    case 'enterprise':
      return 'bg-purple-500';
    default:
      return 'bg-gray-400';
  }
}

function formatNumber(num: number): string {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
  return num.toString();
}
