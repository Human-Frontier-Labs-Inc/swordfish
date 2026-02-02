-- Migration 022: Direct OAuth (Remove Nango Dependency)
--
-- This migration adds columns for direct OAuth token storage and security constraints
-- to prevent cross-tenant data leakage.
--
-- Key changes:
-- 1. Add encrypted token columns to integrations table
-- 2. Add connected_email column with unique constraint (prevents same email on multiple tenants)
-- 3. Add email verification tracking
-- 4. Create oauth_states table for CSRF protection

-- ============================================================================
-- INTEGRATIONS TABLE UPDATES
-- ============================================================================

-- Add new columns for direct OAuth token storage
ALTER TABLE integrations
ADD COLUMN IF NOT EXISTS connected_email VARCHAR(255),
ADD COLUMN IF NOT EXISTS connected_email_verified_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS oauth_access_token TEXT,
ADD COLUMN IF NOT EXISTS oauth_refresh_token TEXT,
ADD COLUMN IF NOT EXISTS oauth_token_expires_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS oauth_scopes TEXT,
ADD COLUMN IF NOT EXISTS oauth_provider_user_id VARCHAR(255);

-- Create unique index on connected_email per type
-- This PREVENTS cross-tenant data leakage by ensuring each email can only
-- be connected once across all tenants for a given provider type
CREATE UNIQUE INDEX IF NOT EXISTS idx_integrations_connected_email_type
ON integrations (connected_email, type)
WHERE connected_email IS NOT NULL AND status = 'connected';

-- Index for fast email lookup in webhooks
CREATE INDEX IF NOT EXISTS idx_integrations_email_lookup
ON integrations (type, status, connected_email)
WHERE connected_email IS NOT NULL;

-- ============================================================================
-- OAUTH STATE TABLE (CSRF Protection)
-- ============================================================================

CREATE TABLE IF NOT EXISTS oauth_states (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL, -- 'gmail', 'o365'
    state_token VARCHAR(255) NOT NULL UNIQUE,
    code_verifier VARCHAR(255), -- For PKCE
    redirect_uri TEXT NOT NULL,
    expected_email VARCHAR(255), -- The email we expect to be connected
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '10 minutes'),
    used_at TIMESTAMPTZ -- Set when the state is consumed
);

-- Index for state lookup
CREATE INDEX IF NOT EXISTS idx_oauth_states_token ON oauth_states (state_token) WHERE used_at IS NULL;

-- Index for cleanup
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires ON oauth_states (expires_at);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON COLUMN integrations.connected_email IS 'The email address from the OAuth provider. Must be unique per type to prevent cross-tenant data leakage.';
COMMENT ON COLUMN integrations.connected_email_verified_at IS 'When the email ownership was verified (matches user Swordfish email).';
COMMENT ON COLUMN integrations.oauth_access_token IS 'Encrypted OAuth access token (AES-256-GCM).';
COMMENT ON COLUMN integrations.oauth_refresh_token IS 'Encrypted OAuth refresh token (AES-256-GCM).';
COMMENT ON COLUMN integrations.oauth_token_expires_at IS 'When the access token expires.';
COMMENT ON COLUMN integrations.oauth_scopes IS 'OAuth scopes granted by the user.';
COMMENT ON COLUMN integrations.oauth_provider_user_id IS 'User ID from the OAuth provider (for additional validation).';

COMMENT ON TABLE oauth_states IS 'Temporary OAuth state tokens for CSRF protection during OAuth flow.';
COMMENT ON COLUMN oauth_states.expected_email IS 'The email we expect to be connected. If OAuth returns different email, reject.';
COMMENT ON COLUMN oauth_states.code_verifier IS 'PKCE code verifier for enhanced security.';

-- ============================================================================
-- CLEANUP FUNCTION
-- ============================================================================

-- Function to clean up expired OAuth states
CREATE OR REPLACE FUNCTION cleanup_expired_oauth_states()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM oauth_states
    WHERE expires_at < NOW() - INTERVAL '1 hour'
    OR used_at < NOW() - INTERVAL '1 hour';

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
