-- Migration 007: Nango Integration
-- Adds nango_connection_id to track Nango OAuth connections
-- Tokens are now managed by Nango, not stored in our database

-- Add nango_connection_id column to integrations table
ALTER TABLE integrations
ADD COLUMN IF NOT EXISTS nango_connection_id TEXT;

-- Add index for lookups by nango_connection_id
CREATE INDEX IF NOT EXISTS idx_integrations_nango_connection_id
ON integrations(nango_connection_id)
WHERE nango_connection_id IS NOT NULL;

-- Note: We're keeping the config JSONB column because it stores
-- non-token settings like syncEnabled, syncFolders, webhookSubscriptionId, etc.
-- The accessToken, refreshToken, and tokenExpiresAt fields in config
-- will no longer be used for new connections - Nango manages those.

-- For existing connections, they can be migrated by:
-- 1. Re-authenticating through Nango (user clicks "Reconnect")
-- 2. The nango_connection_id gets populated via webhook
-- 3. Old token fields in config become irrelevant

COMMENT ON COLUMN integrations.nango_connection_id IS
'Nango connection ID for OAuth token management. When set, tokens are retrieved from Nango instead of config JSONB.';
