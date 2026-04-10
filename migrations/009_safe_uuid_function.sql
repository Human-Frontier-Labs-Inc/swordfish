-- Migration: 009_safe_uuid_function
-- Create a safe UUID cast function that returns NULL instead of throwing
-- when given a non-UUID string (e.g., Clerk user IDs like 'personal_user_xxx')

CREATE OR REPLACE FUNCTION safe_uuid(text) RETURNS uuid AS $$
BEGIN
  RETURN $1::uuid;
EXCEPTION WHEN invalid_text_representation THEN
  RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
