-- Migration 009: Consolidate tenant_id columns to VARCHAR(255)
--
-- PROBLEM: The schema has mixed tenant_id types:
-- - Some tables use UUID with FK to tenants table (old pattern)
-- - Some tables use VARCHAR(255) without FK (new pattern)
--
-- SOLUTION: Since we use Clerk for auth with string IDs (personal_xxx, org_xxx),
-- convert all tenant_id columns to VARCHAR(255) without foreign keys.
--
-- This migration safely converts UUID tenant_id columns to VARCHAR(255)
-- and drops foreign key constraints to the tenants table.

-- ============================================================================
-- INTEGRATIONS TABLE
-- ============================================================================

-- Drop FK constraint if exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'integrations_tenant_id_fkey'
        AND table_name = 'integrations'
    ) THEN
        ALTER TABLE integrations DROP CONSTRAINT integrations_tenant_id_fkey;
    END IF;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;

-- Convert tenant_id from UUID to VARCHAR if needed
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'integrations'
        AND column_name = 'tenant_id'
        AND data_type = 'uuid'
    ) THEN
        ALTER TABLE integrations ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::VARCHAR(255);
    END IF;
END $$;

-- ============================================================================
-- EMAIL_VERDICTS TABLE
-- ============================================================================

-- Drop FK constraint if exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'email_verdicts_tenant_id_fkey'
        AND table_name = 'email_verdicts'
    ) THEN
        ALTER TABLE email_verdicts DROP CONSTRAINT email_verdicts_tenant_id_fkey;
    END IF;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;

-- Convert tenant_id from UUID to VARCHAR if needed
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'email_verdicts'
        AND column_name = 'tenant_id'
        AND data_type = 'uuid'
    ) THEN
        ALTER TABLE email_verdicts ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::VARCHAR(255);
    END IF;
END $$;

-- ============================================================================
-- QUARANTINE TABLE
-- ============================================================================

-- Drop FK constraint if exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'quarantine_tenant_id_fkey'
        AND table_name = 'quarantine'
    ) THEN
        ALTER TABLE quarantine DROP CONSTRAINT quarantine_tenant_id_fkey;
    END IF;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;

-- Convert tenant_id from UUID to VARCHAR if needed
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'quarantine'
        AND column_name = 'tenant_id'
        AND data_type = 'uuid'
    ) THEN
        ALTER TABLE quarantine ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::VARCHAR(255);
    END IF;
END $$;

-- ============================================================================
-- POLICIES TABLE
-- ============================================================================

-- Drop FK constraint if exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'policies_tenant_id_fkey'
        AND table_name = 'policies'
    ) THEN
        ALTER TABLE policies DROP CONSTRAINT policies_tenant_id_fkey;
    END IF;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;

-- Convert tenant_id from UUID to VARCHAR if needed
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'policies'
        AND column_name = 'tenant_id'
        AND data_type = 'uuid'
    ) THEN
        ALTER TABLE policies ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::VARCHAR(255);
    END IF;
END $$;

-- ============================================================================
-- TENANT_POLICIES TABLE
-- ============================================================================

-- Drop FK constraint if exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'tenant_policies_tenant_id_fkey'
        AND table_name = 'tenant_policies'
    ) THEN
        ALTER TABLE tenant_policies DROP CONSTRAINT tenant_policies_tenant_id_fkey;
    END IF;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;

-- Convert tenant_id from UUID to VARCHAR if needed
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tenant_policies'
        AND column_name = 'tenant_id'
        AND data_type = 'uuid'
    ) THEN
        ALTER TABLE tenant_policies ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::VARCHAR(255);
    END IF;
END $$;

-- ============================================================================
-- USER_INVITATIONS TABLE
-- ============================================================================

-- Drop FK constraint if exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'user_invitations_tenant_id_fkey'
        AND table_name = 'user_invitations'
    ) THEN
        ALTER TABLE user_invitations DROP CONSTRAINT user_invitations_tenant_id_fkey;
    END IF;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;

-- Convert tenant_id from UUID to VARCHAR if needed
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'user_invitations'
        AND column_name = 'tenant_id'
        AND data_type = 'uuid'
    ) THEN
        ALTER TABLE user_invitations ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::VARCHAR(255);
    END IF;
END $$;

-- ============================================================================
-- AUDIT_LOG TABLE
-- ============================================================================

-- Drop FK constraint if exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'audit_log_tenant_id_fkey'
        AND table_name = 'audit_log'
    ) THEN
        ALTER TABLE audit_log DROP CONSTRAINT audit_log_tenant_id_fkey;
    END IF;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;

-- Convert tenant_id from UUID to VARCHAR if needed
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_log'
        AND column_name = 'tenant_id'
        AND data_type = 'uuid'
    ) THEN
        ALTER TABLE audit_log ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::VARCHAR(255);
    END IF;
END $$;

-- ============================================================================
-- USAGE_METRICS TABLE
-- ============================================================================

-- Drop FK constraint if exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'usage_metrics_tenant_id_fkey'
        AND table_name = 'usage_metrics'
    ) THEN
        ALTER TABLE usage_metrics DROP CONSTRAINT usage_metrics_tenant_id_fkey;
    END IF;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;

-- Convert tenant_id from UUID to VARCHAR if needed
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'usage_metrics'
        AND column_name = 'tenant_id'
        AND data_type = 'uuid'
    ) THEN
        ALTER TABLE usage_metrics ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::VARCHAR(255);
    END IF;
END $$;

-- ============================================================================
-- LIST_ENTRIES TABLE (from migration 002)
-- ============================================================================

-- Drop FK constraint if exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'list_entries_tenant_id_fkey'
        AND table_name = 'list_entries'
    ) THEN
        ALTER TABLE list_entries DROP CONSTRAINT list_entries_tenant_id_fkey;
    END IF;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;

-- Convert tenant_id from UUID to VARCHAR if needed
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'list_entries'
        AND column_name = 'tenant_id'
        AND data_type = 'uuid'
    ) THEN
        ALTER TABLE list_entries ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::VARCHAR(255);
    END IF;
END $$;

-- ============================================================================
-- API_KEYS TABLE (from migration 002)
-- ============================================================================

-- Drop FK constraint if exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'api_keys_tenant_id_fkey'
        AND table_name = 'api_keys'
    ) THEN
        ALTER TABLE api_keys DROP CONSTRAINT api_keys_tenant_id_fkey;
    END IF;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;

-- Convert tenant_id from UUID to VARCHAR if needed
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'api_keys'
        AND column_name = 'tenant_id'
        AND data_type = 'uuid'
    ) THEN
        ALTER TABLE api_keys ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::VARCHAR(255);
    END IF;
END $$;

-- ============================================================================
-- USERS TABLE
-- ============================================================================

-- Drop FK constraint if exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'users_tenant_id_fkey'
        AND table_name = 'users'
    ) THEN
        ALTER TABLE users DROP CONSTRAINT users_tenant_id_fkey;
    END IF;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;

-- Convert tenant_id from UUID to VARCHAR if needed
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users'
        AND column_name = 'tenant_id'
        AND data_type = 'uuid'
    ) THEN
        ALTER TABLE users ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::VARCHAR(255);
    END IF;
END $$;

-- ============================================================================
-- Add NOT NULL constraints where missing (for consistency)
-- ============================================================================

-- These ALTER statements are safe - they only modify if the column exists
-- and doesn't already have the constraint

-- Ensure integrations.tenant_id is NOT NULL
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'integrations'
        AND column_name = 'tenant_id'
        AND is_nullable = 'YES'
    ) THEN
        -- Only add NOT NULL if there are no NULL values
        IF NOT EXISTS (SELECT 1 FROM integrations WHERE tenant_id IS NULL) THEN
            ALTER TABLE integrations ALTER COLUMN tenant_id SET NOT NULL;
        END IF;
    END IF;
EXCEPTION WHEN undefined_table THEN
    NULL;
END $$;

-- ============================================================================
-- CREATE INDEXES for VARCHAR tenant_id columns (if not exists)
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_integrations_tenant ON integrations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_list_entries_tenant ON list_entries(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id ON api_keys(tenant_id);

-- ============================================================================
-- SUMMARY
-- ============================================================================
--
-- Tables converted to VARCHAR(255) tenant_id:
-- - integrations
-- - email_verdicts
-- - quarantine
-- - policies
-- - tenant_policies
-- - user_invitations
-- - audit_log
-- - usage_metrics
-- - list_entries
-- - api_keys
-- - users
--
-- Tables already using VARCHAR (no change needed):
-- - threats (fixed in migration 008)
-- - feedback
-- - provider_connections
-- - notifications
-- - webhooks
-- - sender_lists
-- - scheduled_reports
-- - report_jobs
-- - export_jobs
-- - integration_states
