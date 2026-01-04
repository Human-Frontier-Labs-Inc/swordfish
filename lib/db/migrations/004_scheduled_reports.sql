-- Migration 004: Scheduled Reports
-- Creates table for scheduled report configuration

CREATE TABLE IF NOT EXISTS scheduled_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  frequency TEXT NOT NULL,
  recipients TEXT[] NOT NULL DEFAULT '{}',
  enabled BOOLEAN NOT NULL DEFAULT true,
  last_run_at TIMESTAMPTZ,
  next_run_at TIMESTAMPTZ NOT NULL,
  config JSONB NOT NULL DEFAULT '{}',
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT scheduled_reports_type_check
    CHECK (type IN ('executive_summary', 'threat_report', 'audit_report')),
  CONSTRAINT scheduled_reports_frequency_check
    CHECK (frequency IN ('daily', 'weekly', 'monthly'))
);

CREATE INDEX IF NOT EXISTS idx_scheduled_reports_tenant
  ON scheduled_reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_reports_next_run
  ON scheduled_reports(next_run_at) WHERE enabled = true;

-- Add index for faster analytics queries
CREATE INDEX IF NOT EXISTS idx_email_verdicts_analytics
  ON email_verdicts(tenant_id, created_at DESC, verdict);

CREATE INDEX IF NOT EXISTS idx_threats_analytics
  ON threats(tenant_id, quarantined_at DESC, status);
