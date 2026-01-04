-- Swordfish Database Schema
-- Multi-tenant email security platform

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Tenants (organizations using Swordfish)
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    clerk_org_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    plan VARCHAR(50) DEFAULT 'starter', -- starter, pro, enterprise
    status VARCHAR(50) DEFAULT 'active', -- active, suspended, deleted
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Users (synced from Clerk)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    clerk_user_id VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'viewer', -- msp_admin, admin, analyst, viewer
    status VARCHAR(50) DEFAULT 'active', -- active, invited, suspended
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    is_msp_user BOOLEAN DEFAULT FALSE,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- MSP Organizations (parent orgs managing multiple tenants)
CREATE TABLE msp_organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    clerk_org_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    branding JSONB DEFAULT '{}', -- logo, colors for white-label
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- MSP-Tenant relationships
CREATE TABLE msp_tenant_access (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    msp_org_id UUID REFERENCES msp_organizations(id) ON DELETE CASCADE,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ DEFAULT NOW(),
    granted_by UUID REFERENCES users(id),
    UNIQUE(msp_org_id, tenant_id)
);

-- ============================================================================
-- EMAIL & DETECTION TABLES
-- ============================================================================

-- Email verdicts (analysis results)
CREATE TABLE email_verdicts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id VARCHAR(255) NOT NULL,
    subject TEXT,
    from_address VARCHAR(255),
    from_display_name VARCHAR(255),
    to_addresses JSONB, -- array of recipients
    received_at TIMESTAMPTZ,

    -- Verdict
    verdict VARCHAR(50) NOT NULL, -- pass, quarantine, block, review
    confidence DECIMAL(5,4), -- 0.0000 to 1.0000
    verdict_reason TEXT,

    -- Detection signals
    signals JSONB DEFAULT '[]', -- array of {type, severity, detail}

    -- Layer results
    deterministic_score INTEGER,
    ml_classification VARCHAR(50),
    ml_confidence DECIMAL(5,4),
    llm_recommendation VARCHAR(50),
    llm_explanation TEXT,

    -- Processing metadata
    processing_time_ms INTEGER,
    llm_tokens_used INTEGER,

    -- Remediation
    action_taken VARCHAR(50), -- delivered, quarantined, blocked, deleted
    action_taken_at TIMESTAMPTZ,
    action_taken_by UUID REFERENCES users(id),

    -- User feedback
    user_feedback VARCHAR(50), -- false_positive, false_negative, confirmed_threat, etc

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Quarantined emails
CREATE TABLE quarantine (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    verdict_id UUID NOT NULL REFERENCES email_verdicts(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'pending', -- pending, released, deleted
    released_at TIMESTAMPTZ,
    released_by UUID REFERENCES users(id),
    deleted_at TIMESTAMPTZ,
    deleted_by UUID REFERENCES users(id),
    expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '30 days'),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- URL analysis results
CREATE TABLE url_analyses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    url_hash VARCHAR(64) NOT NULL, -- SHA-256 of original URL
    original_url TEXT NOT NULL,
    final_url TEXT, -- after redirects
    redirect_chain JSONB, -- array of redirect URLs
    verdict VARCHAR(50), -- safe, suspicious, malicious
    reputation_score INTEGER,
    reputation_sources JSONB, -- {virustotal: {...}, urlscan: {...}}
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '24 hours')
);

-- File/attachment analysis results
CREATE TABLE file_analyses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_hash VARCHAR(64) NOT NULL, -- SHA-256
    filename VARCHAR(255),
    file_type VARCHAR(100),
    file_size INTEGER,
    verdict VARCHAR(50), -- clean, suspicious, malicious
    static_analysis JSONB,
    sandbox_result JSONB,
    reputation_sources JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '7 days')
);

-- ============================================================================
-- POLICY TABLES
-- ============================================================================

-- Tenant policies (allow/block lists, rules)
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL, -- allowlist, blocklist, rule
    target VARCHAR(50) NOT NULL, -- domain, email, ip, pattern
    value TEXT NOT NULL, -- the pattern/value to match
    action VARCHAR(50) NOT NULL, -- allow, block, quarantine
    priority INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- MSP policy templates
CREATE TABLE policy_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    msp_org_id UUID REFERENCES msp_organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) DEFAULT 'custom', -- security, compliance, productivity, custom
    settings JSONB DEFAULT '{}', -- detection thresholds, actions, lists
    policies JSONB DEFAULT '[]', -- array of policy definitions (legacy)
    is_default BOOLEAN DEFAULT FALSE,
    created_by VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tenant policy assignments (which templates are applied to which tenants)
CREATE TABLE tenant_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    template_id UUID NOT NULL REFERENCES policy_templates(id) ON DELETE CASCADE,
    applied_at TIMESTAMPTZ DEFAULT NOW(),
    applied_by VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    UNIQUE(tenant_id, template_id)
);

-- User invitations for MSP user management
CREATE TABLE user_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'viewer',
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    invited_by VARCHAR(255) NOT NULL,
    accepted_at TIMESTAMPTZ,
    accepted_by UUID REFERENCES users(id),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(email, tenant_id)
);

-- ============================================================================
-- INTEGRATION TABLES
-- ============================================================================

-- Email provider integrations
CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL, -- o365, gmail, smtp
    status VARCHAR(50) DEFAULT 'pending', -- pending, connected, error, disconnected
    credentials_encrypted BYTEA, -- encrypted OAuth tokens or credentials
    config JSONB DEFAULT '{}',
    last_sync_at TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, type)
);

-- ============================================================================
-- AUDIT & LOGGING
-- ============================================================================

-- Immutable audit log
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_email VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID,
    before_state JSONB,
    after_state JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Make audit_log immutable
CREATE RULE audit_log_no_update AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE RULE audit_log_no_delete AS ON DELETE TO audit_log DO INSTEAD NOTHING;

-- ============================================================================
-- METRICS & USAGE
-- ============================================================================

-- Daily usage metrics per tenant
CREATE TABLE usage_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    emails_processed INTEGER DEFAULT 0,
    emails_blocked INTEGER DEFAULT 0,
    emails_quarantined INTEGER DEFAULT 0,
    llm_calls INTEGER DEFAULT 0,
    llm_tokens_input INTEGER DEFAULT 0,
    llm_tokens_output INTEGER DEFAULT 0,
    sandbox_submissions INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, date)
);

-- ============================================================================
-- THREATS & FEEDBACK TABLES
-- ============================================================================

-- Detected threats (quarantined/blocked emails)
CREATE TABLE IF NOT EXISTS threats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    message_id VARCHAR(512) NOT NULL,
    external_message_id VARCHAR(512), -- Provider's message ID (O365/Gmail)
    integration_type VARCHAR(50), -- o365, gmail
    integration_id UUID,

    -- Email metadata
    subject TEXT,
    sender_email VARCHAR(255),
    sender_name VARCHAR(255),
    recipient_email VARCHAR(255),
    received_at TIMESTAMPTZ,

    -- Threat details
    threat_type VARCHAR(100), -- phishing, malware, spam, bec
    verdict VARCHAR(50) NOT NULL, -- quarantine, block
    score INTEGER DEFAULT 0,
    signals JSONB DEFAULT '[]',
    explanation TEXT,

    -- Status tracking
    status VARCHAR(50) DEFAULT 'quarantined', -- quarantined, released, deleted, dismissed
    original_location VARCHAR(255), -- inbox, sent, etc
    quarantine_folder VARCHAR(255), -- where it was moved

    -- Quarantine timestamps
    quarantined_at TIMESTAMPTZ DEFAULT NOW(),
    quarantined_by VARCHAR(255) DEFAULT 'system',

    -- Release tracking
    released_at TIMESTAMPTZ,
    released_by VARCHAR(255),
    release_reason TEXT,

    -- Delete tracking
    deleted_at TIMESTAMPTZ,
    deleted_by VARCHAR(255),

    -- Dismiss tracking (false positive)
    dismissed_at TIMESTAMPTZ,
    dismissed_by VARCHAR(255),
    dismissal_reason VARCHAR(255),

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- User feedback on verdicts (false positives/negatives)
CREATE TABLE IF NOT EXISTS feedback (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    threat_id UUID REFERENCES threats(id) ON DELETE SET NULL,
    message_id VARCHAR(512),

    -- Who submitted feedback
    user_id VARCHAR(255) NOT NULL,
    user_email VARCHAR(255),

    -- Feedback details
    feedback_type VARCHAR(50) NOT NULL, -- false_positive, false_negative, confirmed_threat, spam, phishing, malware, other
    notes TEXT,

    -- Original verdict info
    original_verdict VARCHAR(50),
    original_score INTEGER,

    -- User's suggested verdict
    corrected_verdict VARCHAR(50),

    -- Processing status
    processed BOOLEAN DEFAULT FALSE,
    processed_at TIMESTAMPTZ,
    processed_by VARCHAR(255),

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Provider connections (simplified integration tracking)
CREATE TABLE IF NOT EXISTS provider_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL, -- o365, gmail
    email VARCHAR(255),
    status VARCHAR(50) DEFAULT 'connected',
    config JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, provider)
);

-- Notifications
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL, -- threat_blocked, threat_quarantined, system_alert
    severity VARCHAR(50) DEFAULT 'info', -- info, warning, critical
    title TEXT NOT NULL,
    message TEXT,
    metadata JSONB DEFAULT '{}',
    read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMPTZ,
    read_by VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- WEBHOOKS & INTEGRATIONS
-- ============================================================================

-- Webhooks for external notifications
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    secret VARCHAR(255) NOT NULL, -- HMAC signing secret
    events JSONB DEFAULT '[]', -- array of event types to send
    is_active BOOLEAN DEFAULT TRUE,
    last_triggered_at TIMESTAMPTZ,
    last_status VARCHAR(50), -- success, failed
    failure_count INTEGER DEFAULT 0,
    created_by VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Sender allow/block lists
CREATE TABLE IF NOT EXISTS sender_lists (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    email_or_domain VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- allow, block
    reason TEXT,
    created_by VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, email_or_domain, type)
);

-- ============================================================================
-- REPORTS & EXPORTS
-- ============================================================================

-- Scheduled reports
CREATE TABLE IF NOT EXISTS scheduled_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- executive_summary, threat_report, compliance, custom
    schedule VARCHAR(50) NOT NULL, -- daily, weekly, monthly
    time_of_day TIME DEFAULT '09:00:00',
    day_of_week INTEGER, -- 0-6 for weekly
    day_of_month INTEGER, -- 1-31 for monthly
    recipients JSONB DEFAULT '[]', -- array of email addresses
    filters JSONB DEFAULT '{}', -- report filters
    format VARCHAR(20) DEFAULT 'pdf', -- pdf, csv, xlsx
    include_charts BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_by VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Report execution history
CREATE TABLE IF NOT EXISTS report_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scheduled_report_id UUID REFERENCES scheduled_reports(id) ON DELETE CASCADE,
    tenant_id VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending', -- pending, processing, completed, failed
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    file_url TEXT,
    file_size INTEGER,
    error_message TEXT,
    recipients_notified INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Export jobs (on-demand exports)
CREATE TABLE IF NOT EXISTS export_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- threats, quarantine, audit, analytics, custom
    format VARCHAR(20) NOT NULL, -- csv, pdf, xlsx, json
    filters JSONB DEFAULT '{}',
    status VARCHAR(50) DEFAULT 'pending', -- pending, processing, completed, failed
    file_url TEXT,
    file_size INTEGER,
    error_message TEXT,
    expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '7 days'),
    requested_by VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_email_verdicts_tenant_created ON email_verdicts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_verdicts_tenant_verdict ON email_verdicts(tenant_id, verdict);
CREATE INDEX IF NOT EXISTS idx_email_verdicts_message_id ON email_verdicts(message_id);

-- Threat indexes
CREATE INDEX IF NOT EXISTS idx_threats_tenant_status ON threats(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_threats_tenant_created ON threats(tenant_id, quarantined_at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_message_id ON threats(message_id);

-- Feedback indexes
CREATE INDEX IF NOT EXISTS idx_feedback_tenant ON feedback(tenant_id);
CREATE INDEX IF NOT EXISTS idx_feedback_type ON feedback(tenant_id, feedback_type);
CREATE INDEX IF NOT EXISTS idx_feedback_threat ON feedback(threat_id);

-- Notification indexes
CREATE INDEX IF NOT EXISTS idx_notifications_tenant ON notifications(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(tenant_id, read) WHERE read = FALSE;
CREATE INDEX IF NOT EXISTS idx_quarantine_tenant_status ON quarantine(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_policies_tenant_active ON policies(tenant_id, is_active);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_created ON audit_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_url_analyses_hash ON url_analyses(url_hash);
CREATE INDEX IF NOT EXISTS idx_file_analyses_hash ON file_analyses(file_hash);
CREATE INDEX IF NOT EXISTS idx_users_clerk_id ON users(clerk_user_id);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_tenant_policies_tenant ON tenant_policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_policies_template ON tenant_policies(template_id);
CREATE INDEX IF NOT EXISTS idx_user_invitations_email ON user_invitations(email);
CREATE INDEX IF NOT EXISTS idx_user_invitations_tenant ON user_invitations(tenant_id);

-- Webhook indexes
CREATE INDEX IF NOT EXISTS idx_webhooks_tenant ON webhooks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_active ON webhooks(tenant_id, is_active) WHERE is_active = TRUE;

-- Sender list indexes
CREATE INDEX IF NOT EXISTS idx_sender_lists_tenant ON sender_lists(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sender_lists_lookup ON sender_lists(tenant_id, type, email_or_domain);

-- Scheduled reports indexes
CREATE INDEX IF NOT EXISTS idx_scheduled_reports_tenant ON scheduled_reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_reports_next_run ON scheduled_reports(next_run_at) WHERE is_active = TRUE;

-- Report jobs indexes
CREATE INDEX IF NOT EXISTS idx_report_jobs_tenant ON report_jobs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_jobs_scheduled ON report_jobs(scheduled_report_id);

-- Export jobs indexes
CREATE INDEX IF NOT EXISTS idx_export_jobs_tenant ON export_jobs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_export_jobs_status ON export_jobs(status) WHERE status IN ('pending', 'processing');

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

ALTER TABLE email_verdicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE quarantine ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_metrics ENABLE ROW LEVEL SECURITY;

-- Tenant isolation policy (applied via application context)
-- These policies require SET app.current_tenant_id before queries
