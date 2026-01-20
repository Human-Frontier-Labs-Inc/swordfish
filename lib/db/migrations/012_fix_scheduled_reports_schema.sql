-- Fix scheduled_reports schema to match code expectations
-- The code uses 'frequency' but the original schema has 'schedule'

-- Add frequency column if it doesn't exist
ALTER TABLE scheduled_reports
ADD COLUMN IF NOT EXISTS frequency TEXT;

-- Copy data from schedule to frequency if schedule exists
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_name = 'scheduled_reports' AND column_name = 'schedule') THEN
    UPDATE scheduled_reports SET frequency = schedule WHERE frequency IS NULL;
  END IF;
END $$;

-- Add enabled column if it doesn't exist (main schema has is_active)
ALTER TABLE scheduled_reports
ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true;

-- Copy data from is_active to enabled if is_active exists
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_name = 'scheduled_reports' AND column_name = 'is_active') THEN
    UPDATE scheduled_reports SET enabled = is_active WHERE enabled IS NULL;
  END IF;
END $$;

-- Add config column if it doesn't exist
ALTER TABLE scheduled_reports
ADD COLUMN IF NOT EXISTS config JSONB DEFAULT '{}';

-- Add created_by column if it doesn't exist
ALTER TABLE scheduled_reports
ADD COLUMN IF NOT EXISTS created_by TEXT;

-- Set frequency NOT NULL constraint after migration
ALTER TABLE scheduled_reports
ALTER COLUMN frequency SET NOT NULL;

-- Add check constraint
ALTER TABLE scheduled_reports
DROP CONSTRAINT IF EXISTS scheduled_reports_frequency_check;

ALTER TABLE scheduled_reports
ADD CONSTRAINT scheduled_reports_frequency_check
CHECK (frequency IN ('daily', 'weekly', 'monthly'));
