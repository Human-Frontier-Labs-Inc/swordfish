import Link from 'next/link';
import { auth } from '@clerk/nextjs/server';
import { redirect } from 'next/navigation';
import { sql } from '@/lib/db';
import { TenantsTable } from './tenants-table';

interface TenantRow {
  id: string;
  clerk_org_id: string;
  name: string;
  domain: string | null;
  plan: 'starter' | 'pro' | 'enterprise';
  status: 'active' | 'suspended' | 'pending';
  user_count: number;
  emails_processed: number;
  threats_blocked: number;
  created_at: Date;
  last_activity_at: Date | null;
}

async function getInitialTenants() {
  const tenants = await sql`
    SELECT
      t.id,
      t.clerk_org_id,
      t.name,
      t.domain,
      t.plan,
      t.status,
      t.created_at,
      (SELECT COUNT(*)::int FROM users WHERE tenant_id = t.clerk_org_id OR tenant_id = t.id::text) as user_count,
      COALESCE(stats.emails_processed, 0) as emails_processed,
      COALESCE(stats.threats_blocked, 0) as threats_blocked,
      stats.last_activity_at
    FROM tenants t
    LEFT JOIN LATERAL (
      SELECT
        COUNT(*)::int as emails_processed,
        COUNT(*) FILTER (WHERE verdict IN ('quarantine', 'block'))::int as threats_blocked,
        MAX(created_at) as last_activity_at
      FROM email_verdicts
      WHERE tenant_id = t.clerk_org_id OR tenant_id = t.id::text
      AND created_at >= NOW() - INTERVAL '30 days'
    ) stats ON true
    ORDER BY t.created_at DESC
    LIMIT 50
  `;

  return tenants.map((t: Record<string, unknown>) => ({
    id: t.id as string,
    clerkOrgId: t.clerk_org_id as string,
    name: t.name as string,
    domain: t.domain as string | null,
    plan: t.plan as 'starter' | 'pro' | 'enterprise',
    status: t.status as 'active' | 'suspended' | 'pending',
    userCount: (t.user_count as number) || 0,
    emailsProcessed: (t.emails_processed as number) || 0,
    threatsBlocked: (t.threats_blocked as number) || 0,
    createdAt: (t.created_at as Date).toISOString(),
    lastActivityAt: t.last_activity_at ? (t.last_activity_at as Date).toISOString() : null,
  }));
}

export default async function TenantsPage() {
  const { userId } = await auth();

  if (!userId) {
    redirect('/sign-in');
  }

  const tenants = await getInitialTenants();

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

      <TenantsTable initialTenants={tenants} />
    </div>
  );
}
