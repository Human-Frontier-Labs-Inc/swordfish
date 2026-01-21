-- Migration 014: Schema hardening for production readiness
-- - Align notifications schema with app expectations
-- - Widen VARCHAR(100) fields to VARCHAR(255) where appropriate

-- Add missing columns to notifications table
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'notifications'
  ) THEN
    ALTER TABLE notifications
      ADD COLUMN IF NOT EXISTS resource_type VARCHAR(255),
      ADD COLUMN IF NOT EXISTS resource_id TEXT;
  END IF;
END $$;

-- Widen notifications.type from VARCHAR(100) to VARCHAR(255)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'notifications'
      AND column_name = 'type'
      AND data_type = 'character varying'
      AND COALESCE(character_maximum_length, 0) < 255
  ) THEN
    ALTER TABLE notifications ALTER COLUMN type TYPE VARCHAR(255);
  END IF;
END $$;

-- Widen audit_log.action from VARCHAR(100) to VARCHAR(255)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'audit_log'
      AND column_name = 'action'
      AND data_type = 'character varying'
      AND COALESCE(character_maximum_length, 0) < 255
  ) THEN
    ALTER TABLE audit_log ALTER COLUMN action TYPE VARCHAR(255);
  END IF;
END $$;

-- Widen audit_log.resource_type from VARCHAR(100) to VARCHAR(255)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'audit_log'
      AND column_name = 'resource_type'
      AND data_type = 'character varying'
      AND COALESCE(character_maximum_length, 0) < 255
  ) THEN
    ALTER TABLE audit_log ALTER COLUMN resource_type TYPE VARCHAR(255);
  END IF;
END $$;

-- Widen threats.threat_type from VARCHAR(100) to VARCHAR(255)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'threats'
      AND column_name = 'threat_type'
      AND data_type = 'character varying'
      AND COALESCE(character_maximum_length, 0) < 255
  ) THEN
    ALTER TABLE threats ALTER COLUMN threat_type TYPE VARCHAR(255);
  END IF;
END $$;
