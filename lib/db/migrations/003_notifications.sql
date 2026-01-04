-- Migration 003: Notifications System
-- Creates tables for in-app notifications and notification configuration

-- Notifications table
CREATE TABLE IF NOT EXISTS notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  resource_type TEXT,
  resource_id TEXT,
  metadata JSONB,
  read BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT notifications_severity_check
    CHECK (severity IN ('info', 'warning', 'critical'))
);

CREATE INDEX IF NOT EXISTS idx_notifications_tenant
  ON notifications(tenant_id);
CREATE INDEX IF NOT EXISTS idx_notifications_unread
  ON notifications(tenant_id, read) WHERE read = false;
CREATE INDEX IF NOT EXISTS idx_notifications_created
  ON notifications(created_at DESC);

-- Notification configs table
CREATE TABLE IF NOT EXISTS notification_configs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL,
  channel TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  types TEXT[] NOT NULL DEFAULT '{}',
  destination TEXT NOT NULL,
  min_severity TEXT NOT NULL DEFAULT 'warning',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT notification_configs_channel_check
    CHECK (channel IN ('email', 'slack', 'webhook', 'in_app')),
  CONSTRAINT notification_configs_severity_check
    CHECK (min_severity IN ('info', 'warning', 'critical')),
  CONSTRAINT notification_configs_unique
    UNIQUE (tenant_id, channel)
);

CREATE INDEX IF NOT EXISTS idx_notification_configs_tenant
  ON notification_configs(tenant_id);

-- Feedback table for false positive/negative reports
CREATE TABLE IF NOT EXISTS feedback (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL,
  threat_id UUID REFERENCES threats(id),
  verdict_id UUID REFERENCES email_verdicts(id),
  feedback_type TEXT NOT NULL,
  notes TEXT,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT feedback_type_check
    CHECK (feedback_type IN ('false_positive', 'false_negative', 'correct', 'other'))
);

CREATE INDEX IF NOT EXISTS idx_feedback_tenant
  ON feedback(tenant_id);
CREATE INDEX IF NOT EXISTS idx_feedback_threat
  ON feedback(threat_id);

-- Add some useful views

-- Active threats summary view
CREATE OR REPLACE VIEW active_threats_summary AS
SELECT
  tenant_id,
  COUNT(*) FILTER (WHERE status = 'quarantined') as quarantined,
  COUNT(*) FILTER (WHERE status = 'released') as released,
  COUNT(*) FILTER (WHERE status = 'deleted') as deleted,
  COUNT(*) FILTER (WHERE quarantined_at > NOW() - INTERVAL '24 hours') as last_24h,
  AVG(score) FILTER (WHERE status = 'quarantined') as avg_score
FROM threats
GROUP BY tenant_id;

-- Notification summary view
CREATE OR REPLACE VIEW notification_summary AS
SELECT
  tenant_id,
  COUNT(*) FILTER (WHERE read = false) as unread_count,
  COUNT(*) FILTER (WHERE severity = 'critical' AND read = false) as critical_unread,
  MAX(created_at) as latest_notification
FROM notifications
GROUP BY tenant_id;
