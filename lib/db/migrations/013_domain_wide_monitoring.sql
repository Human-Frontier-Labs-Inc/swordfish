-- Domain-Wide Email Monitoring Schema
-- Enables org admins to protect all users without individual OAuth consent

-- Domain-wide configuration for service accounts and app registrations
CREATE TABLE IF NOT EXISTS domain_wide_configs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  -- Provider type
  provider TEXT NOT NULL CHECK (provider IN ('google_workspace', 'microsoft_365')),

  -- Status tracking
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'error', 'disabled')),
  error_message TEXT,

  -- Google Workspace specific (service account with domain-wide delegation)
  google_service_account_email TEXT,
  google_service_account_key BYTEA, -- Encrypted JSON key file
  google_admin_email TEXT, -- Admin email for impersonation
  google_customer_id TEXT, -- Google Workspace customer ID

  -- Microsoft 365 specific (application permissions)
  azure_tenant_id TEXT,
  azure_client_id TEXT,
  azure_client_secret TEXT, -- Encrypted

  -- Sync settings
  sync_enabled BOOLEAN DEFAULT true,
  sync_all_users BOOLEAN DEFAULT true,
  sync_include_groups TEXT[], -- Only sync users in these groups (if not all)
  sync_exclude_groups TEXT[], -- Exclude users in these groups

  -- Monitoring scope
  monitor_incoming BOOLEAN DEFAULT true,
  monitor_outgoing BOOLEAN DEFAULT false,
  monitor_internal BOOLEAN DEFAULT false,

  -- Stats
  total_users_discovered INTEGER DEFAULT 0,
  total_users_active INTEGER DEFAULT 0,
  last_user_sync_at TIMESTAMPTZ,
  last_email_sync_at TIMESTAMPTZ,

  -- Audit
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  created_by TEXT NOT NULL,

  UNIQUE(tenant_id, provider)
);

-- Domain users discovered via directory API
CREATE TABLE IF NOT EXISTS domain_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_config_id UUID NOT NULL REFERENCES domain_wide_configs(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,

  -- User identity
  email TEXT NOT NULL,
  display_name TEXT,
  provider_user_id TEXT, -- Google: user ID, Microsoft: user principal name

  -- Status
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted', 'excluded')),
  excluded_reason TEXT,

  -- Sync tracking
  is_monitored BOOLEAN DEFAULT true,
  last_sync_at TIMESTAMPTZ,
  last_history_id TEXT, -- Gmail history ID or Graph delta token
  webhook_subscription_id TEXT,
  webhook_expires_at TIMESTAMPTZ,

  -- Stats
  emails_scanned INTEGER DEFAULT 0,
  threats_detected INTEGER DEFAULT 0,

  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),

  UNIQUE(domain_config_id, email)
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_domain_wide_configs_tenant ON domain_wide_configs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_domain_wide_configs_status ON domain_wide_configs(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_domain_users_config ON domain_users(domain_config_id);
CREATE INDEX IF NOT EXISTS idx_domain_users_tenant ON domain_users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_domain_users_email ON domain_users(email);
CREATE INDEX IF NOT EXISTS idx_domain_users_monitored ON domain_users(domain_config_id, is_monitored) WHERE is_monitored = true;
CREATE INDEX IF NOT EXISTS idx_domain_users_webhook_expiry ON domain_users(webhook_expires_at) WHERE webhook_expires_at IS NOT NULL;

-- Add domain_config_id to integrations for linking
ALTER TABLE integrations
ADD COLUMN IF NOT EXISTS domain_config_id UUID REFERENCES domain_wide_configs(id) ON DELETE SET NULL;

ALTER TABLE integrations
ADD COLUMN IF NOT EXISTS is_domain_wide BOOLEAN DEFAULT false;

-- Track which domain user an email came from
ALTER TABLE email_verdicts
ADD COLUMN IF NOT EXISTS domain_user_id UUID REFERENCES domain_users(id) ON DELETE SET NULL;
