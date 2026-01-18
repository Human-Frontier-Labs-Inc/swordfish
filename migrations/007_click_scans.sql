-- Migration: 007_click_scans
-- Description: Create click_scans table for advanced click-time URL scanning analytics
-- Date: 2026-01-17

-- Create click_scans table for storing detailed scan results
CREATE TABLE IF NOT EXISTS click_scans (
    id BIGSERIAL PRIMARY KEY,
    click_id VARCHAR(64) NOT NULL UNIQUE,

    -- URL information
    original_url TEXT NOT NULL,
    final_url TEXT NOT NULL,
    redirect_chain JSONB NOT NULL DEFAULT '[]',

    -- Scan results
    scan_time_ms INTEGER NOT NULL,
    verdict VARCHAR(20) NOT NULL CHECK (verdict IN ('safe', 'suspicious', 'malicious', 'blocked')),

    -- Threat details
    threats JSONB NOT NULL DEFAULT '[]',

    -- Reputation data
    reputation_score INTEGER NOT NULL DEFAULT 0 CHECK (reputation_score >= 0 AND reputation_score <= 100),
    reputation_sources JSONB NOT NULL DEFAULT '{}',

    -- Decision flags
    should_warn BOOLEAN NOT NULL DEFAULT false,
    should_block BOOLEAN NOT NULL DEFAULT false,

    -- Timestamps
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_click_scans_click_id ON click_scans(click_id);
CREATE INDEX IF NOT EXISTS idx_click_scans_verdict ON click_scans(verdict);
CREATE INDEX IF NOT EXISTS idx_click_scans_scanned_at ON click_scans(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_click_scans_reputation ON click_scans(reputation_score);

-- Create index for domain extraction queries (used in analytics)
CREATE INDEX IF NOT EXISTS idx_click_scans_final_url ON click_scans(final_url);

-- Create index for blocked/warned queries
CREATE INDEX IF NOT EXISTS idx_click_scans_blocked ON click_scans(should_block) WHERE should_block = true;
CREATE INDEX IF NOT EXISTS idx_click_scans_warned ON click_scans(should_warn) WHERE should_warn = true;

-- Create composite index for analytics queries
CREATE INDEX IF NOT EXISTS idx_click_scans_verdict_date ON click_scans(verdict, scanned_at DESC);

-- Add foreign key to click_mappings (if table exists)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'click_mappings') THEN
        ALTER TABLE click_scans
        ADD CONSTRAINT fk_click_scans_mapping
        FOREIGN KEY (click_id) REFERENCES click_mappings(id) ON DELETE CASCADE;
    END IF;
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Add comments for documentation
COMMENT ON TABLE click_scans IS 'Stores detailed results from click-time URL scans including threat analysis and reputation data';
COMMENT ON COLUMN click_scans.click_id IS 'Reference to click_mappings.id for the protected link';
COMMENT ON COLUMN click_scans.redirect_chain IS 'Array of URLs in the redirect chain from original to final';
COMMENT ON COLUMN click_scans.threats IS 'Array of detected threats with type, severity, source, and details';
COMMENT ON COLUMN click_scans.reputation_sources IS 'Object containing results from VirusTotal, URLScan, and internal checks';
COMMENT ON COLUMN click_scans.verdict IS 'Final scan verdict: safe, suspicious, malicious, or blocked';

-- Create function for click analytics aggregation
CREATE OR REPLACE FUNCTION get_click_analytics(
    p_tenant_id VARCHAR(32),
    p_start_date TIMESTAMPTZ,
    p_end_date TIMESTAMPTZ
)
RETURNS TABLE (
    total_clicks BIGINT,
    blocked_clicks BIGINT,
    warned_clicks BIGINT,
    unique_urls BIGINT,
    avg_scan_time_ms NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        COUNT(cs.id)::BIGINT as total_clicks,
        COUNT(cs.id) FILTER (WHERE cs.verdict IN ('blocked', 'malicious'))::BIGINT as blocked_clicks,
        COUNT(cs.id) FILTER (WHERE cs.verdict = 'suspicious')::BIGINT as warned_clicks,
        COUNT(DISTINCT cs.original_url)::BIGINT as unique_urls,
        AVG(cs.scan_time_ms)::NUMERIC as avg_scan_time_ms
    FROM click_scans cs
    JOIN click_mappings cm ON cs.click_id = cm.id
    WHERE cm.tenant_id = p_tenant_id
    AND cs.scanned_at BETWEEN p_start_date AND p_end_date;
END;
$$ LANGUAGE plpgsql;

-- Create function to get top blocked domains
CREATE OR REPLACE FUNCTION get_top_blocked_domains(
    p_tenant_id VARCHAR(32),
    p_start_date TIMESTAMPTZ,
    p_end_date TIMESTAMPTZ,
    p_limit INTEGER DEFAULT 10
)
RETURNS TABLE (
    domain TEXT,
    block_count BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        SUBSTRING(cs.final_url FROM '://([^/]+)') as domain,
        COUNT(*)::BIGINT as block_count
    FROM click_scans cs
    JOIN click_mappings cm ON cs.click_id = cm.id
    WHERE cm.tenant_id = p_tenant_id
    AND cs.verdict IN ('blocked', 'malicious')
    AND cs.scanned_at BETWEEN p_start_date AND p_end_date
    GROUP BY SUBSTRING(cs.final_url FROM '://([^/]+)')
    ORDER BY block_count DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

-- Create function for hourly click distribution
CREATE OR REPLACE FUNCTION get_clicks_by_hour(
    p_tenant_id VARCHAR(32),
    p_start_date TIMESTAMPTZ,
    p_end_date TIMESTAMPTZ
)
RETURNS TABLE (
    hour_of_day INTEGER,
    click_count BIGINT
) AS $$
BEGIN
    RETURN QUERY
    WITH hours AS (
        SELECT generate_series(0, 23) as hour
    )
    SELECT
        h.hour::INTEGER as hour_of_day,
        COALESCE(COUNT(cs.id), 0)::BIGINT as click_count
    FROM hours h
    LEFT JOIN click_scans cs ON EXTRACT(HOUR FROM cs.scanned_at) = h.hour
    LEFT JOIN click_mappings cm ON cs.click_id = cm.id AND cm.tenant_id = p_tenant_id
    WHERE (cs.scanned_at IS NULL OR cs.scanned_at BETWEEN p_start_date AND p_end_date)
    GROUP BY h.hour
    ORDER BY h.hour;
END;
$$ LANGUAGE plpgsql;

-- Grant appropriate permissions
GRANT SELECT, INSERT, UPDATE ON click_scans TO PUBLIC;
GRANT USAGE, SELECT ON SEQUENCE click_scans_id_seq TO PUBLIC;
