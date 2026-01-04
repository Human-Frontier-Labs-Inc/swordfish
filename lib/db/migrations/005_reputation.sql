-- Reputation cache table
CREATE TABLE IF NOT EXISTS reputation_cache (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity VARCHAR(2048) NOT NULL,
  entity_type VARCHAR(20) NOT NULL, -- domain, ip, url, email
  score INTEGER NOT NULL DEFAULT 50,
  category VARCHAR(20) NOT NULL DEFAULT 'unknown', -- clean, suspicious, malicious, unknown
  sources JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

  UNIQUE(entity, entity_type)
);

-- Threat intelligence table (per-tenant)
CREATE TABLE IF NOT EXISTS threat_intelligence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(255) NOT NULL,
  entity VARCHAR(2048) NOT NULL,
  entity_type VARCHAR(20) NOT NULL, -- domain, ip, url, email
  verdict VARCHAR(20) NOT NULL, -- suspicious, malicious
  source VARCHAR(255) NOT NULL, -- user_report, feed_name, etc.
  details TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE,

  UNIQUE(tenant_id, entity, entity_type)
);

-- ML model predictions log (for training/analysis)
CREATE TABLE IF NOT EXISTS ml_predictions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(255) NOT NULL,
  email_id VARCHAR(255) NOT NULL,
  score DECIMAL(5,2) NOT NULL,
  confidence DECIMAL(5,2) NOT NULL,
  category VARCHAR(50) NOT NULL,
  features JSONB,
  signals JSONB,
  feedback VARCHAR(20), -- correct, incorrect, null if no feedback
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_reputation_cache_lookup
  ON reputation_cache(entity, entity_type);

CREATE INDEX IF NOT EXISTS idx_reputation_cache_cleanup
  ON reputation_cache(created_at);

CREATE INDEX IF NOT EXISTS idx_threat_intel_tenant
  ON threat_intelligence(tenant_id);

CREATE INDEX IF NOT EXISTS idx_threat_intel_lookup
  ON threat_intelligence(entity, entity_type);

CREATE INDEX IF NOT EXISTS idx_ml_predictions_tenant
  ON ml_predictions(tenant_id);

CREATE INDEX IF NOT EXISTS idx_ml_predictions_email
  ON ml_predictions(email_id);

CREATE INDEX IF NOT EXISTS idx_ml_predictions_feedback
  ON ml_predictions(feedback) WHERE feedback IS NOT NULL;
