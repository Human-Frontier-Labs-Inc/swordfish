-- Migration 021: Backfill external_message_id for existing threats
-- This fixes data integrity issues where threats have NULL external_message_id
-- which causes remediation operations to fail

-- Backfill external_message_id from email_verdicts where possible
-- The external_message_id in email_verdicts is the actual Gmail/O365 message ID
-- while message_id in threats may be in a different format
UPDATE threats t
SET external_message_id = ev.external_message_id
FROM email_verdicts ev
WHERE t.message_id = ev.message_id
  AND t.tenant_id = ev.tenant_id
  AND t.external_message_id IS NULL
  AND ev.external_message_id IS NOT NULL;

-- Log how many were updated
DO $$
DECLARE
  updated_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO updated_count
  FROM threats
  WHERE external_message_id IS NOT NULL;

  RAISE NOTICE 'Threats with external_message_id: %', updated_count;
END $$;

-- Also ensure integration_id is set where we can infer it
-- Match threats without integration_id to integrations by tenant and type
UPDATE threats t
SET integration_id = i.id
FROM integrations i
WHERE t.integration_id IS NULL
  AND t.integration_type IS NOT NULL
  AND t.tenant_id = i.tenant_id
  AND t.integration_type = i.type;

-- Log final counts
DO $$
DECLARE
  threats_with_integration INTEGER;
  threats_without_external_id INTEGER;
BEGIN
  SELECT COUNT(*) INTO threats_with_integration
  FROM threats
  WHERE integration_id IS NOT NULL;

  SELECT COUNT(*) INTO threats_without_external_id
  FROM threats
  WHERE external_message_id IS NULL;

  RAISE NOTICE 'Threats with integration_id: %', threats_with_integration;
  RAISE NOTICE 'Threats still missing external_message_id: %', threats_without_external_id;
END $$;
