import { neon, type NeonQueryFunction } from '@neondatabase/serverless';

// Lazy-initialized SQL client to prevent build-time initialization errors
let _sql: NeonQueryFunction<false, false> | null = null;

function getSqlClient(): NeonQueryFunction<false, false> {
  if (!_sql) {
    if (!process.env.DATABASE_URL) {
      throw new Error('DATABASE_URL is not configured');
    }
    _sql = neon(process.env.DATABASE_URL);
  }
  return _sql;
}

// Proxy for backward compatibility - lazily initializes on first use
export const sql = new Proxy((() => {}) as unknown as NeonQueryFunction<false, false>, {
  apply(_target, _thisArg, args: [TemplateStringsArray, ...unknown[]]) {
    return getSqlClient()(args[0], ...args.slice(1));
  },
  get(_, prop) {
    return (getSqlClient() as unknown as Record<string | symbol, unknown>)[prop];
  },
});

// Types for our database entities
export interface Tenant {
  id: string;
  clerk_org_id: string;
  name: string;
  domain: string | null;
  plan: 'starter' | 'pro' | 'enterprise';
  status: 'active' | 'suspended' | 'deleted';
  settings: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
}

export interface User {
  id: string;
  clerk_user_id: string;
  email: string;
  name: string | null;
  role: 'msp_admin' | 'tenant_admin' | 'analyst' | 'viewer';
  tenant_id: string | null;
  is_msp_user: boolean;
  last_login_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

export interface EmailVerdict {
  id: string;
  tenant_id: string;
  message_id: string;
  subject: string | null;
  from_address: string | null;
  from_display_name: string | null;
  to_addresses: string[];
  received_at: Date | null;
  verdict: 'pass' | 'quarantine' | 'block' | 'review';
  confidence: number;
  verdict_reason: string | null;
  signals: Signal[];
  deterministic_score: number | null;
  ml_classification: string | null;
  ml_confidence: number | null;
  llm_recommendation: string | null;
  llm_explanation: string | null;
  processing_time_ms: number | null;
  llm_tokens_used: number | null;
  action_taken: string | null;
  action_taken_at: Date | null;
  action_taken_by: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface Signal {
  type: string;
  severity: 'info' | 'warning' | 'critical';
  detail: string;
}

export interface Quarantine {
  id: string;
  tenant_id: string;
  verdict_id: string;
  status: 'pending' | 'released' | 'deleted';
  released_at: Date | null;
  released_by: string | null;
  deleted_at: Date | null;
  deleted_by: string | null;
  expires_at: Date;
  created_at: Date;
}

export interface Policy {
  id: string;
  tenant_id: string;
  type: 'allowlist' | 'blocklist' | 'rule';
  target: 'domain' | 'email' | 'ip' | 'pattern';
  value: string;
  action: 'allow' | 'block' | 'quarantine';
  priority: number;
  is_active: boolean;
  created_by: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface Integration {
  id: string;
  tenant_id: string;
  type: 'o365' | 'gmail' | 'smtp';
  status: 'pending' | 'connected' | 'error' | 'disconnected';
  config: Record<string, unknown>;
  last_sync_at: Date | null;
  error_message: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface AuditLog {
  id: string;
  tenant_id: string | null;
  actor_id: string | null;
  actor_email: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  before_state: Record<string, unknown> | null;
  after_state: Record<string, unknown> | null;
  ip_address: string | null;
  user_agent: string | null;
  created_at: Date;
}

export interface UsageMetrics {
  id: string;
  tenant_id: string;
  date: Date;
  emails_processed: number;
  emails_blocked: number;
  emails_quarantined: number;
  llm_calls: number;
  llm_tokens_input: number;
  llm_tokens_output: number;
  sandbox_submissions: number;
  created_at: Date;
}

export interface ClickMapping {
  id: string;
  tenant_id: string;
  email_id: string;
  original_url: string;
  click_count: number;
  last_click_at: Date | null;
  expires_at: Date;
  metadata: Record<string, unknown> | null;
  created_at: Date;
}

export interface ActionLog {
  id: string;
  tenant_id: string;
  type: string;
  user_id: string | null;
  email_id: string | null;
  target_url: string | null;
  verdict: string | null;
  risk_score: number | null;
  signals: string | null;
  metadata: string | null;
  ip_address: string | null;
  user_agent: string | null;
  created_at: Date;
}

export interface VIPEntry {
  id: string;
  tenant_id: string;
  email: string;
  display_name: string;
  title: string | null;
  department: string | null;
  role: 'executive' | 'finance' | 'hr' | 'it' | 'legal' | 'board' | 'assistant' | 'custom';
  aliases: string[];
  is_active: boolean;
  created_by: string | null;
  created_at: Date;
  updated_at: Date;
}

// ============================================================================
// QUERY HELPERS WITH TENANT ISOLATION (RLS)
// ============================================================================
//
// IMPORTANT: All queries on tenant-scoped tables MUST use these helpers to
// ensure Row Level Security policies are enforced. Without setting the context,
// queries may fail or (worse) leak data between tenants.
//
// Usage:
//   const threats = await withTenant(tenantId, async () => {
//     return sql`SELECT * FROM threats WHERE status = 'quarantined'`;
//   });
//
// For MSP users who need cross-tenant access:
//   const allThreats = await withMspAccess(tenantId, mspOrgId, async () => {
//     return sql`SELECT * FROM threats WHERE status = 'quarantined'`;
//   });

/**
 * Execute a query with tenant context for RLS policies.
 * This sets app.current_tenant_id for the duration of the query.
 */
export async function withTenant<T>(
  tenantId: string,
  queryFn: () => Promise<T>
): Promise<T> {
  // Set tenant context for RLS policies (LOCAL = transaction-scoped)
  await sql`SELECT set_config('app.current_tenant_id', ${tenantId}, true)`;
  return queryFn();
}

/**
 * Execute a query with both tenant and MSP context for RLS policies.
 * This allows MSP admins to access data across their managed tenants.
 */
export async function withMspAccess<T>(
  tenantId: string,
  mspOrgId: string,
  queryFn: () => Promise<T>
): Promise<T> {
  // Set both contexts for RLS policies
  await sql`SELECT set_config('app.current_tenant_id', ${tenantId}, true)`;
  await sql`SELECT set_config('app.msp_org_id', ${mspOrgId}, true)`;
  return queryFn();
}

/**
 * Execute a query with MSP context only (for cross-tenant queries).
 * Use when you need to query across all tenants managed by an MSP.
 */
export async function withMspContext<T>(
  mspOrgId: string,
  queryFn: () => Promise<T>
): Promise<T> {
  // Set MSP context for cross-tenant access
  await sql`SELECT set_config('app.msp_org_id', ${mspOrgId}, true)`;
  // Clear tenant context to allow cross-tenant queries
  await sql`SELECT set_config('app.current_tenant_id', '', true)`;
  return queryFn();
}

/**
 * Clear all RLS context. Use with caution - only for system operations
 * that need to bypass tenant isolation (e.g., migrations, cron jobs).
 */
export async function withSystemContext<T>(
  queryFn: () => Promise<T>
): Promise<T> {
  await sql`SELECT set_config('app.current_tenant_id', '', true)`;
  await sql`SELECT set_config('app.msp_org_id', '', true)`;
  return queryFn();
}
