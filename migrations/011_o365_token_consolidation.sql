-- Migration 011: Consolidate Microsoft/Google provider tokens into `integrations`
--
-- CONTEXT (P0-7 split-brain fix):
-- The legacy `app/api/auth/microsoft` route wrote UNENCRYPTED OAuth tokens to
-- `provider_connections`, while the webhook + sync worker read ENCRYPTED tokens
-- from `integrations` (via lib/oauth/token-manager). Connections appeared
-- "successful" in the UI but mail processing could never retrieve a usable token.
--
-- The application now stores tokens ENCRYPTED in `integrations` exclusively.
-- This migration retires `provider_connections`.
--
-- WHY WE DO NOT COPY THE TOKENS:
-- `provider_connections.access_token` / `refresh_token` are PLAINTEXT. The
-- canonical store (`integrations.oauth_*`) is AES-256-GCM encrypted, and that
-- encryption can only be performed in application code (Node crypto), never in
-- SQL. Rather than propagate plaintext secrets into the encrypted column, we
-- migrate only the connection METADATA and force a one-time reconnect, which
-- re-issues fresh tokens that are written encrypted. This is the secure choice:
-- it does not extend the lifetime of plaintext credentials.
--
-- Operator note: after this runs, any tenant that had a Microsoft/Google
-- connection ONLY in provider_connections must reconnect once. Tenants already
-- connected through the encrypted `integrations` path are unaffected.

BEGIN;

-- 1. Ensure an `integrations` row exists for every active provider_connections
--    row, mapping provider name -> integration type.
--      provider_connections.provider 'microsoft' -> integrations.type 'o365'
--      provider_connections.provider 'google'    -> integrations.type 'gmail'
INSERT INTO integrations (tenant_id, type, status, config, connected_email, created_at, updated_at)
SELECT
  pc.tenant_id,
  CASE pc.provider WHEN 'microsoft' THEN 'o365' WHEN 'google' THEN 'gmail' END AS type,
  -- Force reconnect: tokens were plaintext and are intentionally NOT carried over.
  'error' AS status,
  COALESCE(pc.metadata, '{}'::jsonb) AS config,
  LOWER(pc.email) AS connected_email,
  COALESCE(pc.created_at, NOW()),
  NOW()
FROM provider_connections pc
WHERE pc.provider IN ('microsoft', 'google')
  AND pc.status IN ('active', 'pending', 'expired')
ON CONFLICT (tenant_id, type) DO UPDATE SET
  -- Only downgrade/annotate rows that are NOT already connected via the
  -- encrypted path; never clobber a working encrypted connection.
  status = CASE
    WHEN integrations.status = 'connected'
         AND integrations.oauth_access_token IS NOT NULL
    THEN integrations.status
    ELSE 'error'
  END,
  error_message = CASE
    WHEN integrations.status = 'connected'
         AND integrations.oauth_access_token IS NOT NULL
    THEN integrations.error_message
    ELSE 'Reconnect required: migrated from legacy provider_connections (tokens were not encrypted).'
  END,
  connected_email = COALESCE(integrations.connected_email, EXCLUDED.connected_email),
  updated_at = NOW();

-- 2. Annotate rows that need a reconnect with a clear error message so the UI
--    can surface "please reconnect" instead of a silent failure.
UPDATE integrations
SET error_message = 'Reconnect required: migrated from legacy provider_connections (tokens were not encrypted).'
WHERE type IN ('o365', 'gmail')
  AND status = 'error'
  AND oauth_access_token IS NULL
  AND error_message IS NULL;

-- 3. Drop the legacy table and its dependent objects.
DROP TRIGGER IF EXISTS update_provider_connections_updated_at ON provider_connections;
DROP TABLE IF EXISTS provider_connections;

COMMIT;
