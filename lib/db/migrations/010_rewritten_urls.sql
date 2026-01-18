-- Migration: Enhanced URL Rewriting System
-- Creates the rewritten_urls table for comprehensive click-time protection

-- Drop the old click_mappings table if it exists and replace with enhanced version
-- Note: In production, you would want to migrate data first
-- ALTER TABLE click_mappings RENAME TO click_mappings_old;

-- Create the enhanced rewritten_urls table
CREATE TABLE IF NOT EXISTS rewritten_urls (
  -- Primary key: unique click tracking ID
  id VARCHAR(64) PRIMARY KEY,

  -- Tenant isolation
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  -- Email reference (may be null if email was deleted)
  email_id VARCHAR(255) NOT NULL,

  -- URL data
  original_url TEXT NOT NULL,
  expanded_url TEXT, -- For URL shorteners, the expanded destination

  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  clicked_at TIMESTAMPTZ, -- NULL until first click
  expires_at TIMESTAMPTZ NOT NULL,

  -- Click tracking
  click_count INTEGER DEFAULT 0 NOT NULL,

  -- Security verdict from click-time scan
  click_verdict VARCHAR(20), -- 'safe', 'suspicious', 'malicious', 'blocked', 'unknown'

  -- Additional metadata (reason for rewriting, risk indicators, etc.)
  metadata JSONB DEFAULT '{}'::jsonb
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_rewritten_urls_tenant
  ON rewritten_urls(tenant_id);

CREATE INDEX IF NOT EXISTS idx_rewritten_urls_email
  ON rewritten_urls(email_id);

CREATE INDEX IF NOT EXISTS idx_rewritten_urls_expires
  ON rewritten_urls(expires_at)
  WHERE expires_at > NOW(); -- Partial index for active URLs

CREATE INDEX IF NOT EXISTS idx_rewritten_urls_original
  ON rewritten_urls(tenant_id, original_url);

CREATE INDEX IF NOT EXISTS idx_rewritten_urls_clicked
  ON rewritten_urls(tenant_id, clicked_at DESC)
  WHERE clicked_at IS NOT NULL; -- Partial index for clicked URLs

CREATE INDEX IF NOT EXISTS idx_rewritten_urls_verdict
  ON rewritten_urls(tenant_id, click_verdict)
  WHERE click_verdict IS NOT NULL;

-- Full-text search on original URLs for admin search functionality
CREATE INDEX IF NOT EXISTS idx_rewritten_urls_url_search
  ON rewritten_urls USING gin(to_tsvector('english', original_url));

-- Row-level security
ALTER TABLE rewritten_urls ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation
DROP POLICY IF EXISTS rewritten_urls_tenant_isolation ON rewritten_urls;
CREATE POLICY rewritten_urls_tenant_isolation ON rewritten_urls
  FOR ALL USING (tenant_id::text = current_setting('app.current_tenant_id', true));

-- Function to clean up expired URL mappings
CREATE OR REPLACE FUNCTION cleanup_expired_rewritten_urls()
RETURNS TABLE(deleted_count INTEGER, freed_bytes BIGINT) AS $$
DECLARE
  _deleted_count INTEGER;
  _size_before BIGINT;
  _size_after BIGINT;
BEGIN
  -- Get table size before cleanup
  SELECT pg_total_relation_size('rewritten_urls') INTO _size_before;

  -- Delete expired entries
  DELETE FROM rewritten_urls
  WHERE expires_at < NOW();

  GET DIAGNOSTICS _deleted_count = ROW_COUNT;

  -- Get table size after (actual space reclaim requires VACUUM)
  SELECT pg_total_relation_size('rewritten_urls') INTO _size_after;

  RETURN QUERY SELECT _deleted_count, _size_before - _size_after;
END;
$$ LANGUAGE plpgsql;

-- Function to get click statistics for a tenant
CREATE OR REPLACE FUNCTION get_url_click_stats(
  p_tenant_id UUID,
  p_days INTEGER DEFAULT 30
)
RETURNS TABLE(
  total_urls BIGINT,
  total_clicks BIGINT,
  unique_urls_clicked BIGINT,
  malicious_clicks BIGINT,
  suspicious_clicks BIGINT,
  safe_clicks BIGINT,
  avg_clicks_per_url NUMERIC
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    COUNT(*)::BIGINT as total_urls,
    COALESCE(SUM(click_count), 0)::BIGINT as total_clicks,
    COUNT(*) FILTER (WHERE click_count > 0)::BIGINT as unique_urls_clicked,
    COUNT(*) FILTER (WHERE click_verdict = 'malicious')::BIGINT as malicious_clicks,
    COUNT(*) FILTER (WHERE click_verdict = 'suspicious')::BIGINT as suspicious_clicks,
    COUNT(*) FILTER (WHERE click_verdict = 'safe')::BIGINT as safe_clicks,
    COALESCE(AVG(click_count) FILTER (WHERE click_count > 0), 0)::NUMERIC as avg_clicks_per_url
  FROM rewritten_urls
  WHERE tenant_id = p_tenant_id
    AND created_at >= NOW() - (p_days || ' days')::INTERVAL;
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to record a click and update statistics
CREATE OR REPLACE FUNCTION record_url_click(
  p_tracking_id VARCHAR(64),
  p_verdict VARCHAR(20) DEFAULT NULL,
  p_metadata JSONB DEFAULT NULL
)
RETURNS TABLE(
  success BOOLEAN,
  original_url TEXT,
  expanded_url TEXT,
  is_first_click BOOLEAN
) AS $$
DECLARE
  _result RECORD;
BEGIN
  UPDATE rewritten_urls
  SET
    clicked_at = COALESCE(clicked_at, NOW()),
    click_count = click_count + 1,
    click_verdict = COALESCE(p_verdict, click_verdict),
    metadata = CASE
      WHEN p_metadata IS NOT NULL THEN
        COALESCE(metadata, '{}'::jsonb) || p_metadata
      ELSE metadata
    END
  WHERE id = p_tracking_id
    AND expires_at > NOW()
  RETURNING
    TRUE as success,
    rewritten_urls.original_url,
    rewritten_urls.expanded_url,
    (rewritten_urls.click_count = 1) as is_first_click
  INTO _result;

  IF _result IS NULL THEN
    RETURN QUERY SELECT FALSE, NULL::TEXT, NULL::TEXT, FALSE;
  ELSE
    RETURN QUERY SELECT _result.success, _result.original_url, _result.expanded_url, _result.is_first_click;
  END IF;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update email_verdicts when a malicious click is detected
CREATE OR REPLACE FUNCTION update_verdict_on_malicious_click()
RETURNS TRIGGER AS $$
BEGIN
  -- If the click verdict is malicious and this is a new malicious detection
  IF NEW.click_verdict = 'malicious' AND
     (OLD.click_verdict IS NULL OR OLD.click_verdict != 'malicious') THEN

    -- Log the malicious click as an action
    INSERT INTO action_logs (
      tenant_id, type, email_id, target_url, verdict, risk_score, metadata
    )
    SELECT
      NEW.tenant_id,
      'malicious_url_clicked',
      ev.id,
      NEW.original_url,
      'malicious',
      100,
      jsonb_build_object(
        'tracking_id', NEW.id,
        'click_count', NEW.click_count,
        'detected_at', NOW()
      )
    FROM email_verdicts ev
    WHERE ev.message_id = NEW.email_id
      AND ev.tenant_id = NEW.tenant_id
    LIMIT 1;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_malicious_click ON rewritten_urls;
CREATE TRIGGER trigger_malicious_click
  AFTER UPDATE ON rewritten_urls
  FOR EACH ROW
  WHEN (NEW.click_verdict = 'malicious')
  EXECUTE FUNCTION update_verdict_on_malicious_click();

-- =============================================================================
-- Click Events Table - Detailed tracking of individual click events
-- =============================================================================

CREATE TABLE IF NOT EXISTS click_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  url_id VARCHAR(64) NOT NULL,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_email VARCHAR(255),
  clicked_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  user_agent TEXT,
  ip_address VARCHAR(45),
  referrer TEXT,
  decision VARCHAR(20) NOT NULL, -- allow, warn, block
  scan_time_ms INTEGER,
  threat_detected BOOLEAN DEFAULT FALSE,
  bypass_warning BOOLEAN DEFAULT FALSE,
  metadata JSONB DEFAULT '{}'::jsonb
);

-- Performance indexes for click_events
CREATE INDEX IF NOT EXISTS idx_click_events_url_id
  ON click_events(url_id);

CREATE INDEX IF NOT EXISTS idx_click_events_tenant
  ON click_events(tenant_id, clicked_at DESC);

CREATE INDEX IF NOT EXISTS idx_click_events_decision
  ON click_events(tenant_id, decision)
  WHERE decision IN ('block', 'warn');

CREATE INDEX IF NOT EXISTS idx_click_events_user
  ON click_events(tenant_id, user_email)
  WHERE user_email IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_click_events_threats
  ON click_events(tenant_id, threat_detected)
  WHERE threat_detected = TRUE;

-- Row-level security for click_events
ALTER TABLE click_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS click_events_tenant_isolation ON click_events;
CREATE POLICY click_events_tenant_isolation ON click_events
  FOR ALL USING (tenant_id::text = current_setting('app.current_tenant_id', true));

-- =============================================================================
-- Click Scans Table - Detailed scan results for click-time analysis
-- =============================================================================

CREATE TABLE IF NOT EXISTS click_scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  click_id VARCHAR(64) UNIQUE NOT NULL,
  original_url TEXT NOT NULL,
  final_url TEXT,
  redirect_chain JSONB,
  scan_time_ms INTEGER,
  verdict VARCHAR(20) NOT NULL, -- safe, suspicious, malicious, blocked, timeout, error
  threats JSONB DEFAULT '[]'::jsonb,
  reputation_score INTEGER,
  reputation_sources JSONB DEFAULT '{}'::jsonb,
  should_warn BOOLEAN DEFAULT FALSE,
  should_block BOOLEAN DEFAULT FALSE,
  scanned_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Performance indexes for click_scans
CREATE INDEX IF NOT EXISTS idx_click_scans_click_id
  ON click_scans(click_id);

CREATE INDEX IF NOT EXISTS idx_click_scans_original_url
  ON click_scans(original_url);

CREATE INDEX IF NOT EXISTS idx_click_scans_verdict
  ON click_scans(verdict)
  WHERE verdict IN ('malicious', 'blocked');

CREATE INDEX IF NOT EXISTS idx_click_scans_scanned_at
  ON click_scans(scanned_at DESC);

-- =============================================================================
-- URL Scan Submissions Table - Manual scan requests
-- =============================================================================

CREATE TABLE IF NOT EXISTS url_scan_submissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  verdict VARCHAR(20),
  confidence DECIMAL(3,2),
  scan_time_ms INTEGER,
  threats JSONB DEFAULT '[]'::jsonb,
  submitted_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  submitted_by VARCHAR(255)
);

-- Performance indexes for url_scan_submissions
CREATE INDEX IF NOT EXISTS idx_url_scan_submissions_tenant
  ON url_scan_submissions(tenant_id, submitted_at DESC);

-- Row-level security for url_scan_submissions
ALTER TABLE url_scan_submissions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS url_scan_submissions_tenant_isolation ON url_scan_submissions;
CREATE POLICY url_scan_submissions_tenant_isolation ON url_scan_submissions
  FOR ALL USING (tenant_id::text = current_setting('app.current_tenant_id', true));

-- =============================================================================
-- Function to get click event statistics
-- =============================================================================

CREATE OR REPLACE FUNCTION get_click_event_stats(
  p_tenant_id UUID,
  p_days INTEGER DEFAULT 30
)
RETURNS TABLE(
  total_clicks BIGINT,
  blocked_clicks BIGINT,
  warned_clicks BIGINT,
  allowed_clicks BIGINT,
  unique_users BIGINT,
  threat_detections BIGINT,
  warning_bypasses BIGINT,
  avg_scan_time_ms NUMERIC
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    COUNT(*)::BIGINT as total_clicks,
    COUNT(*) FILTER (WHERE decision = 'block')::BIGINT as blocked_clicks,
    COUNT(*) FILTER (WHERE decision = 'warn')::BIGINT as warned_clicks,
    COUNT(*) FILTER (WHERE decision = 'allow')::BIGINT as allowed_clicks,
    COUNT(DISTINCT user_email)::BIGINT as unique_users,
    COUNT(*) FILTER (WHERE threat_detected = TRUE)::BIGINT as threat_detections,
    COUNT(*) FILTER (WHERE bypass_warning = TRUE)::BIGINT as warning_bypasses,
    COALESCE(AVG(scan_time_ms), 0)::NUMERIC as avg_scan_time_ms
  FROM click_events
  WHERE tenant_id = p_tenant_id
    AND clicked_at >= NOW() - (p_days || ' days')::INTERVAL;
END;
$$ LANGUAGE plpgsql STABLE;

-- =============================================================================
-- Function to get top clicked URLs
-- =============================================================================

CREATE OR REPLACE FUNCTION get_top_clicked_urls(
  p_tenant_id UUID,
  p_limit INTEGER DEFAULT 10,
  p_days INTEGER DEFAULT 30
)
RETURNS TABLE(
  url_id VARCHAR,
  original_url TEXT,
  click_count BIGINT,
  last_clicked TIMESTAMPTZ,
  verdict VARCHAR
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    ce.url_id,
    ru.original_url,
    COUNT(*)::BIGINT as click_count,
    MAX(ce.clicked_at) as last_clicked,
    ru.click_verdict
  FROM click_events ce
  LEFT JOIN rewritten_urls ru ON ce.url_id = ru.id
  WHERE ce.tenant_id = p_tenant_id
    AND ce.clicked_at >= NOW() - (p_days || ' days')::INTERVAL
  GROUP BY ce.url_id, ru.original_url, ru.click_verdict
  ORDER BY click_count DESC
  LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE;

-- =============================================================================
-- Function to get blocked clicks
-- =============================================================================

CREATE OR REPLACE FUNCTION get_blocked_clicks(
  p_tenant_id UUID,
  p_limit INTEGER DEFAULT 100,
  p_since TIMESTAMPTZ DEFAULT (NOW() - INTERVAL '30 days')
)
RETURNS TABLE(
  id UUID,
  url_id VARCHAR,
  original_url TEXT,
  user_email VARCHAR,
  clicked_at TIMESTAMPTZ,
  verdict VARCHAR,
  threats JSONB
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    ce.id,
    ce.url_id,
    ru.original_url,
    ce.user_email,
    ce.clicked_at,
    cs.verdict,
    cs.threats
  FROM click_events ce
  LEFT JOIN rewritten_urls ru ON ce.url_id = ru.id
  LEFT JOIN click_scans cs ON ce.url_id = cs.click_id
  WHERE ce.tenant_id = p_tenant_id
    AND ce.decision = 'block'
    AND ce.clicked_at >= p_since
  ORDER BY ce.clicked_at DESC
  LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE;

-- =============================================================================
-- Comments for documentation
-- =============================================================================

COMMENT ON TABLE rewritten_urls IS 'Stores URL rewrite mappings for click-time protection with comprehensive tracking';
COMMENT ON COLUMN rewritten_urls.id IS 'Unique click tracking ID embedded in rewritten URLs';
COMMENT ON COLUMN rewritten_urls.original_url IS 'Original URL from the email before rewriting';
COMMENT ON COLUMN rewritten_urls.expanded_url IS 'Expanded destination for URL shorteners';
COMMENT ON COLUMN rewritten_urls.click_verdict IS 'Security verdict from click-time scan: safe, suspicious, malicious, blocked, unknown';
COMMENT ON COLUMN rewritten_urls.metadata IS 'JSON metadata including rewrite reason, risk indicators, user agent, IP, etc.';

COMMENT ON TABLE click_events IS 'Detailed tracking of individual URL click events for analytics and security monitoring';
COMMENT ON COLUMN click_events.decision IS 'Security decision made: allow, warn, or block';
COMMENT ON COLUMN click_events.threat_detected IS 'Whether any threat indicators were found during scan';
COMMENT ON COLUMN click_events.bypass_warning IS 'Whether user bypassed a security warning to proceed';

COMMENT ON TABLE click_scans IS 'Cached results of URL security scans performed at click time';
COMMENT ON COLUMN click_scans.verdict IS 'Overall security verdict: safe, suspicious, malicious, blocked, timeout, error';
COMMENT ON COLUMN click_scans.threats IS 'JSON array of threat indicators found during scan';

COMMENT ON TABLE url_scan_submissions IS 'Manual URL scan requests submitted by users or administrators';

COMMENT ON FUNCTION cleanup_expired_rewritten_urls() IS 'Removes expired URL mappings and returns cleanup statistics';
COMMENT ON FUNCTION get_url_click_stats(UUID, INTEGER) IS 'Returns click statistics for a tenant over the specified number of days';
COMMENT ON FUNCTION record_url_click(VARCHAR, VARCHAR, JSONB) IS 'Records a click on a rewritten URL and returns the original URL';
COMMENT ON FUNCTION get_click_event_stats(UUID, INTEGER) IS 'Returns detailed click event statistics for a tenant';
COMMENT ON FUNCTION get_top_clicked_urls(UUID, INTEGER, INTEGER) IS 'Returns the most clicked URLs for a tenant';
COMMENT ON FUNCTION get_blocked_clicks(UUID, INTEGER, TIMESTAMPTZ) IS 'Returns blocked click events for a tenant';
