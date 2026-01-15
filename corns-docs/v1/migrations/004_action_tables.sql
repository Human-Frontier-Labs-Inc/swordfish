-- Migration: Action System Tables
-- Phase 5: Click protection and audit trail

-- Click mappings table for URL rewriting
CREATE TABLE IF NOT EXISTS click_mappings (
  id VARCHAR(32) PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email_id UUID REFERENCES email_verdicts(id) ON DELETE SET NULL,
  original_url TEXT NOT NULL,
  click_count INTEGER DEFAULT 0,
  last_click_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ NOT NULL,
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for click mappings
CREATE INDEX IF NOT EXISTS idx_click_mappings_tenant ON click_mappings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_click_mappings_email ON click_mappings(email_id);
CREATE INDEX IF NOT EXISTS idx_click_mappings_expires ON click_mappings(expires_at);

-- Action logs table for audit trail
CREATE TABLE IF NOT EXISTS action_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  type VARCHAR(50) NOT NULL,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  email_id UUID REFERENCES email_verdicts(id) ON DELETE SET NULL,
  target_url TEXT,
  verdict VARCHAR(20),
  risk_score INTEGER,
  signals JSONB,
  metadata JSONB,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for action logs
CREATE INDEX IF NOT EXISTS idx_action_logs_tenant ON action_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_action_logs_type ON action_logs(type);
CREATE INDEX IF NOT EXISTS idx_action_logs_email ON action_logs(email_id);
CREATE INDEX IF NOT EXISTS idx_action_logs_created ON action_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_action_logs_user ON action_logs(user_id);

-- VIP entries table for executive protection
CREATE TABLE IF NOT EXISTS vip_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email VARCHAR(255) NOT NULL,
  display_name VARCHAR(255) NOT NULL,
  title VARCHAR(255),
  department VARCHAR(255),
  role VARCHAR(20) NOT NULL DEFAULT 'custom',
  aliases TEXT[] DEFAULT '{}',
  is_active BOOLEAN DEFAULT true,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(tenant_id, email)
);

-- Indexes for VIP entries
CREATE INDEX IF NOT EXISTS idx_vip_entries_tenant ON vip_entries(tenant_id);
CREATE INDEX IF NOT EXISTS idx_vip_entries_email ON vip_entries(email);
CREATE INDEX IF NOT EXISTS idx_vip_entries_active ON vip_entries(tenant_id, is_active);

-- Row-level security
ALTER TABLE click_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE vip_entries ENABLE ROW LEVEL SECURITY;

-- RLS policies for click_mappings
CREATE POLICY click_mappings_tenant_isolation ON click_mappings
  FOR ALL USING (tenant_id::text = current_setting('app.current_tenant_id', true));

-- RLS policies for action_logs
CREATE POLICY action_logs_tenant_isolation ON action_logs
  FOR ALL USING (tenant_id::text = current_setting('app.current_tenant_id', true));

-- RLS policies for vip_entries
CREATE POLICY vip_entries_tenant_isolation ON vip_entries
  FOR ALL USING (tenant_id::text = current_setting('app.current_tenant_id', true));

-- Function to clean up expired click mappings
CREATE OR REPLACE FUNCTION cleanup_expired_click_mappings()
RETURNS INTEGER AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM click_mappings
  WHERE expires_at < NOW();
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Comments
COMMENT ON TABLE click_mappings IS 'Stores URL rewrite mappings for click-time protection';
COMMENT ON TABLE action_logs IS 'Audit trail for all security actions taken';
COMMENT ON TABLE vip_entries IS 'VIP/executive list for impersonation protection';
