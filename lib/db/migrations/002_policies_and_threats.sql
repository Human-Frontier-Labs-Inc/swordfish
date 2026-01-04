-- Migration 002: Enhanced Policies and Threats Tables
-- Adds list_entries for allowlists/blocklists and threats table for quarantine management

-- ============================================================================
-- LIST ENTRIES TABLE (Allowlists/Blocklists)
-- ============================================================================

CREATE TABLE IF NOT EXISTS list_entries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    list_type VARCHAR(50) NOT NULL, -- 'allowlist' or 'blocklist'
    entry_type VARCHAR(50) NOT NULL, -- 'email', 'domain', 'ip', 'url'
    value TEXT NOT NULL,
    reason TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by VARCHAR(255) NOT NULL,
    UNIQUE(tenant_id, list_type, entry_type, value)
);

CREATE INDEX IF NOT EXISTS idx_list_entries_tenant_type ON list_entries(tenant_id, list_type);
CREATE INDEX IF NOT EXISTS idx_list_entries_lookup ON list_entries(tenant_id, list_type, entry_type, LOWER(value));

-- ============================================================================
-- THREATS TABLE (Quarantine Management)
-- ============================================================================

CREATE TABLE IF NOT EXISTS threats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id VARCHAR(500) NOT NULL,
    subject TEXT,
    sender_email VARCHAR(255),
    recipient_email VARCHAR(255),
    verdict VARCHAR(50) NOT NULL, -- 'malicious', 'phishing', 'suspicious'
    score INTEGER NOT NULL,
    categories JSONB DEFAULT '[]',
    signals JSONB DEFAULT '[]',
    status VARCHAR(50) DEFAULT 'quarantined', -- 'quarantined', 'released', 'deleted'
    integration_type VARCHAR(50), -- 'o365', 'gmail', 'smtp'
    original_location TEXT, -- Original folder/label
    received_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    released_by VARCHAR(255),
    deleted_at TIMESTAMPTZ,
    deleted_by VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, message_id)
);

CREATE INDEX IF NOT EXISTS idx_threats_tenant_status ON threats(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_threats_tenant_created ON threats(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_tenant_verdict ON threats(tenant_id, verdict);

-- ============================================================================
-- ENHANCED POLICIES TABLE
-- ============================================================================

-- Add new columns to existing policies table if they don't exist
DO $$
BEGIN
    -- Add name column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'policies' AND column_name = 'name') THEN
        ALTER TABLE policies ADD COLUMN name VARCHAR(255);
    END IF;

    -- Add description column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'policies' AND column_name = 'description') THEN
        ALTER TABLE policies ADD COLUMN description TEXT;
    END IF;

    -- Add status column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'policies' AND column_name = 'status') THEN
        ALTER TABLE policies ADD COLUMN status VARCHAR(50) DEFAULT 'active';
    END IF;

    -- Add rules column (JSONB for complex rules)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'policies' AND column_name = 'rules') THEN
        ALTER TABLE policies ADD COLUMN rules JSONB DEFAULT '[]';
    END IF;

    -- Add scope column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'policies' AND column_name = 'scope') THEN
        ALTER TABLE policies ADD COLUMN scope JSONB;
    END IF;

    -- Add updated_by column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'policies' AND column_name = 'updated_by') THEN
        ALTER TABLE policies ADD COLUMN updated_by UUID REFERENCES users(id);
    END IF;
END $$;

-- ============================================================================
-- INTEGRATION STATES TABLE (for OAuth CSRF protection)
-- ============================================================================

CREATE TABLE IF NOT EXISTS integration_states (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL, -- 'o365', 'gmail'
    state VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_integration_states_lookup ON integration_states(tenant_id, provider, state);

-- ============================================================================
-- API KEYS TABLE (for SMTP webhook authentication)
-- ============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of the key
    key_prefix VARCHAR(8) NOT NULL, -- First 8 chars for identification
    scopes JSONB DEFAULT '["*"]', -- Array of allowed scopes
    status VARCHAR(50) DEFAULT 'active', -- 'active', 'revoked'
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by VARCHAR(255) NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id, status);

-- ============================================================================
-- ADD MISSING COLUMNS TO EMAIL_VERDICTS
-- ============================================================================

DO $$
BEGIN
    -- Add score column if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'email_verdicts' AND column_name = 'score') THEN
        ALTER TABLE email_verdicts ADD COLUMN score INTEGER;
    END IF;

    -- Add layer_results column if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'email_verdicts' AND column_name = 'layer_results') THEN
        ALTER TABLE email_verdicts ADD COLUMN layer_results JSONB DEFAULT '{}';
    END IF;

    -- Add explanation column if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'email_verdicts' AND column_name = 'explanation') THEN
        ALTER TABLE email_verdicts ADD COLUMN explanation TEXT;
    END IF;

    -- Add recommendation column if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'email_verdicts' AND column_name = 'recommendation') THEN
        ALTER TABLE email_verdicts ADD COLUMN recommendation TEXT;
    END IF;

    -- Add status column if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'email_verdicts' AND column_name = 'status') THEN
        ALTER TABLE email_verdicts ADD COLUMN status VARCHAR(50);
    END IF;
END $$;

-- Add unique constraint on tenant_id + message_id for email_verdicts
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'email_verdicts_tenant_message_unique'
    ) THEN
        ALTER TABLE email_verdicts
        ADD CONSTRAINT email_verdicts_tenant_message_unique
        UNIQUE (tenant_id, message_id);
    END IF;
EXCEPTION WHEN duplicate_table THEN
    -- Constraint already exists
    NULL;
END $$;

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

ALTER TABLE list_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE threats ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
