-- Migration 008: Fix threats table for string tenant_id and add missing columns
-- The original migration used UUID tenant_id, but we use string values like 'personal_xxx'

-- ============================================================================
-- FIX TENANT_ID TYPE
-- ============================================================================

-- First, drop the foreign key constraint if it exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'threats_tenant_id_fkey'
        AND table_name = 'threats'
    ) THEN
        ALTER TABLE threats DROP CONSTRAINT threats_tenant_id_fkey;
    END IF;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;

-- Change tenant_id from UUID to VARCHAR(255) if needed
DO $$
BEGIN
    -- Check if tenant_id is currently UUID type
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'threats'
        AND column_name = 'tenant_id'
        AND data_type = 'uuid'
    ) THEN
        ALTER TABLE threats ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::VARCHAR(255);
    END IF;
END $$;

-- ============================================================================
-- ADD MISSING COLUMNS
-- ============================================================================

DO $$
BEGIN
    -- Add external_message_id if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'threats' AND column_name = 'external_message_id') THEN
        ALTER TABLE threats ADD COLUMN external_message_id VARCHAR(512);
    END IF;

    -- Add integration_id if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'threats' AND column_name = 'integration_id') THEN
        ALTER TABLE threats ADD COLUMN integration_id UUID;
    END IF;

    -- Add quarantined_at if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'threats' AND column_name = 'quarantined_at') THEN
        ALTER TABLE threats ADD COLUMN quarantined_at TIMESTAMPTZ DEFAULT NOW();
    END IF;

    -- Add explanation if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'threats' AND column_name = 'explanation') THEN
        ALTER TABLE threats ADD COLUMN explanation TEXT;
    END IF;

    -- Add remediation tracking columns if not exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'threats' AND column_name = 'remediation_at') THEN
        ALTER TABLE threats ADD COLUMN remediation_at TIMESTAMPTZ;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'threats' AND column_name = 'remediated_by') THEN
        ALTER TABLE threats ADD COLUMN remediated_by VARCHAR(255);
    END IF;
END $$;

-- ============================================================================
-- ENSURE PROPER COLUMN SIZES (fix any VARCHAR(100) issues)
-- ============================================================================

-- Make sure message_id is large enough
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'threats'
        AND column_name = 'message_id'
        AND character_maximum_length < 512
    ) THEN
        ALTER TABLE threats ALTER COLUMN message_id TYPE VARCHAR(512);
    END IF;
END $$;

-- Make sure sender_email is large enough
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'threats'
        AND column_name = 'sender_email'
        AND character_maximum_length < 255
    ) THEN
        ALTER TABLE threats ALTER COLUMN sender_email TYPE VARCHAR(255);
    END IF;
END $$;

-- Make sure recipient_email is large enough
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'threats'
        AND column_name = 'recipient_email'
        AND character_maximum_length < 255
    ) THEN
        ALTER TABLE threats ALTER COLUMN recipient_email TYPE VARCHAR(255);
    END IF;
END $$;

-- Create index on external_message_id
CREATE INDEX IF NOT EXISTS idx_threats_external_message ON threats(external_message_id);

-- Create index on integration_id
CREATE INDEX IF NOT EXISTS idx_threats_integration ON threats(integration_id);
