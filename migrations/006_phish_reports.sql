-- Migration: 006_phish_reports
-- Description: Create phish_reports table for user-reported suspicious emails
-- Date: 2026-01-17
-- Fixed: 2026-02-11 - Changed tenant_id/reviewed_by to UUID to match parent tables

-- Create enum types for report status and verdicts
DO $$ BEGIN
    CREATE TYPE report_source AS ENUM ('outlook_addin', 'gmail_addon', 'manual', 'forwarded');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE analysis_status AS ENUM ('pending', 'analyzing', 'reviewed');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE report_verdict AS ENUM ('confirmed_phish', 'false_positive', 'inconclusive');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create phish_reports table
CREATE TABLE IF NOT EXISTS phish_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Reporter information
    reporter_email VARCHAR(255) NOT NULL,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reporter_comments TEXT,

    -- Original email information
    original_message_id VARCHAR(255),
    subject VARCHAR(500) NOT NULL,
    from_address VARCHAR(255) NOT NULL,
    from_display_name VARCHAR(255),
    to_addresses JSONB NOT NULL DEFAULT '[]',

    -- Report source and client info
    report_source report_source NOT NULL,
    client_info JSONB,

    -- Email content for analysis (stored temporarily)
    email_headers JSONB,
    email_body_text TEXT,
    email_body_html TEXT,

    -- Analysis results
    analysis_status analysis_status NOT NULL DEFAULT 'pending',
    verdict report_verdict,
    verdict_score DECIMAL(5,2),
    signals JSONB NOT NULL DEFAULT '[]',

    -- Admin review
    admin_notes TEXT,
    reviewed_by UUID REFERENCES users(id),
    reviewed_at TIMESTAMPTZ,
    notified_reporter BOOLEAN NOT NULL DEFAULT false,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_phish_reports_tenant_id ON phish_reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_phish_reports_reported_at ON phish_reports(reported_at DESC);
CREATE INDEX IF NOT EXISTS idx_phish_reports_status ON phish_reports(analysis_status);
CREATE INDEX IF NOT EXISTS idx_phish_reports_verdict ON phish_reports(verdict);
CREATE INDEX IF NOT EXISTS idx_phish_reports_source ON phish_reports(report_source);
CREATE INDEX IF NOT EXISTS idx_phish_reports_reporter ON phish_reports(reporter_email);
CREATE INDEX IF NOT EXISTS idx_phish_reports_from ON phish_reports(from_address);
CREATE INDEX IF NOT EXISTS idx_phish_reports_tenant_status ON phish_reports(tenant_id, analysis_status);
CREATE INDEX IF NOT EXISTS idx_phish_reports_tenant_verdict ON phish_reports(tenant_id, verdict);

-- Create composite index for common filtered queries
CREATE INDEX IF NOT EXISTS idx_phish_reports_tenant_date ON phish_reports(tenant_id, reported_at DESC);

-- Create index for full-text search on subject
CREATE INDEX IF NOT EXISTS idx_phish_reports_subject_search ON phish_reports USING gin(to_tsvector('english', subject));

-- Create ml_feedback table for tracking verdicts to improve ML
CREATE TABLE IF NOT EXISTS ml_feedback (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Feedback details
    feedback_type VARCHAR(50) NOT NULL,  -- e.g., 'phish_report_verdict', 'user_feedback', 'analyst_correction'
    source_type VARCHAR(50) NOT NULL,    -- e.g., 'phish_report', 'email_verdict', 'threat'
    source_id UUID NOT NULL,

    -- Label assigned
    label VARCHAR(50) NOT NULL,          -- e.g., 'phish', 'legitimate', 'spam', 'unknown'

    -- Optional additional data
    features JSONB,
    confidence DECIMAL(5,4),

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Prevent duplicate feedback for same source
    UNIQUE(tenant_id, source_type, source_id)
);

CREATE INDEX IF NOT EXISTS idx_ml_feedback_tenant ON ml_feedback(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ml_feedback_type ON ml_feedback(feedback_type);
CREATE INDEX IF NOT EXISTS idx_ml_feedback_label ON ml_feedback(label);
CREATE INDEX IF NOT EXISTS idx_ml_feedback_created ON ml_feedback(created_at DESC);

-- Add trigger for updating updated_at timestamp
CREATE OR REPLACE FUNCTION update_phish_reports_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_phish_reports_updated_at ON phish_reports;
CREATE TRIGGER trigger_phish_reports_updated_at
    BEFORE UPDATE ON phish_reports
    FOR EACH ROW
    EXECUTE FUNCTION update_phish_reports_updated_at();

-- Add RLS policies for tenant isolation
ALTER TABLE phish_reports ENABLE ROW LEVEL SECURITY;

-- Policy for tenant isolation
DROP POLICY IF EXISTS phish_reports_tenant_isolation ON phish_reports;
CREATE POLICY phish_reports_tenant_isolation ON phish_reports
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Policy for ML feedback tenant isolation
ALTER TABLE ml_feedback ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ml_feedback_tenant_isolation ON ml_feedback;
CREATE POLICY ml_feedback_tenant_isolation ON ml_feedback
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Add comments for documentation
COMMENT ON TABLE phish_reports IS 'User-reported suspicious emails from Outlook Add-in, Gmail Add-on, or manual submission';
COMMENT ON COLUMN phish_reports.report_source IS 'Source of the report: outlook_addin, gmail_addon, manual, or forwarded';
COMMENT ON COLUMN phish_reports.analysis_status IS 'Current status: pending (awaiting review), analyzing (being processed), reviewed (verdict provided)';
COMMENT ON COLUMN phish_reports.verdict IS 'Final verdict: confirmed_phish, false_positive, or inconclusive';
COMMENT ON COLUMN phish_reports.signals IS 'Array of detection signals from analysis';
COMMENT ON TABLE ml_feedback IS 'Feedback records for ML model improvement tracking';
