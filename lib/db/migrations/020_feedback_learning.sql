-- Migration 020: Feedback Learning System
-- Purpose: Store learned patterns and rules from user feedback
-- Phase 5 of 5-phase false positive reduction strategy

-- Create feedback_patterns table for tracking recurring patterns
CREATE TABLE IF NOT EXISTS feedback_patterns (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(255) NOT NULL,

  -- Pattern definition
  pattern_type VARCHAR(50) NOT NULL CHECK (pattern_type IN ('domain', 'url_pattern', 'subject_pattern', 'content_pattern')),
  pattern_value TEXT NOT NULL,
  feedback_type VARCHAR(50) NOT NULL CHECK (feedback_type IN ('false_positive', 'false_negative', 'confirmed_threat')),

  -- Learning metrics
  confidence INTEGER NOT NULL DEFAULT 10 CHECK (confidence >= 0 AND confidence <= 100),
  occurrence_count INTEGER NOT NULL DEFAULT 1,

  -- Timestamps
  first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

  -- Status
  is_active BOOLEAN DEFAULT true,

  -- Additional data
  metadata JSONB DEFAULT '{}'::jsonb,

  -- Unique constraint per tenant
  UNIQUE(tenant_id, pattern_type, pattern_value, feedback_type)
);

-- Create indexes for pattern lookups
CREATE INDEX IF NOT EXISTS idx_feedback_patterns_tenant ON feedback_patterns(tenant_id);
CREATE INDEX IF NOT EXISTS idx_feedback_patterns_type ON feedback_patterns(pattern_type);
CREATE INDEX IF NOT EXISTS idx_feedback_patterns_value ON feedback_patterns(pattern_value);
CREATE INDEX IF NOT EXISTS idx_feedback_patterns_confidence ON feedback_patterns(confidence DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_patterns_active ON feedback_patterns(is_active) WHERE is_active = true;

-- Create learned_rules table for detection adjustments
CREATE TABLE IF NOT EXISTS learned_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(255) NOT NULL,

  -- Rule definition
  rule_type VARCHAR(50) NOT NULL CHECK (rule_type IN ('trust_boost', 'suspicion_boost', 'auto_pass', 'auto_flag')),

  -- Condition
  condition_field VARCHAR(100) NOT NULL,
  condition_operator VARCHAR(50) NOT NULL DEFAULT 'equals' CHECK (condition_operator IN ('equals', 'contains', 'matches', 'starts_with', 'ends_with')),
  condition_value TEXT NOT NULL,

  -- Effect
  score_adjustment INTEGER NOT NULL CHECK (score_adjustment >= -50 AND score_adjustment <= 50),

  -- Confidence and source
  confidence INTEGER NOT NULL DEFAULT 70 CHECK (confidence >= 0 AND confidence <= 100),
  source_feedback_count INTEGER NOT NULL DEFAULT 0,

  -- Status
  is_active BOOLEAN DEFAULT true,

  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE,

  -- Unique constraint
  UNIQUE(tenant_id, condition_field, condition_value)
);

-- Create indexes for rule lookups
CREATE INDEX IF NOT EXISTS idx_learned_rules_tenant ON learned_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_learned_rules_type ON learned_rules(rule_type);
CREATE INDEX IF NOT EXISTS idx_learned_rules_field ON learned_rules(condition_field);
CREATE INDEX IF NOT EXISTS idx_learned_rules_value ON learned_rules(condition_value);
CREATE INDEX IF NOT EXISTS idx_learned_rules_active ON learned_rules(is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_learned_rules_expires ON learned_rules(expires_at) WHERE expires_at IS NOT NULL;

-- Create feedback_learning_log for audit trail
CREATE TABLE IF NOT EXISTS feedback_learning_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(255) NOT NULL,

  -- Event type
  event_type VARCHAR(50) NOT NULL CHECK (event_type IN (
    'pattern_created', 'pattern_updated', 'pattern_deactivated',
    'rule_created', 'rule_expired', 'rule_deactivated',
    'sender_promoted', 'sender_demoted'
  )),

  -- References
  pattern_id UUID REFERENCES feedback_patterns(id),
  rule_id UUID REFERENCES learned_rules(id),
  sender_domain VARCHAR(255),

  -- Details
  details JSONB DEFAULT '{}'::jsonb,

  -- Timestamp
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index for log queries
CREATE INDEX IF NOT EXISTS idx_feedback_learning_log_tenant ON feedback_learning_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_feedback_learning_log_type ON feedback_learning_log(event_type);
CREATE INDEX IF NOT EXISTS idx_feedback_learning_log_created ON feedback_learning_log(created_at DESC);

-- Add tenant_id to existing feedback table if not exists
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'feedback' AND column_name = 'tenant_id'
  ) THEN
    ALTER TABLE feedback ADD COLUMN tenant_id VARCHAR(255);
    CREATE INDEX idx_feedback_tenant ON feedback(tenant_id);
  END IF;
END $$;

-- Create function to automatically expire old rules
CREATE OR REPLACE FUNCTION expire_old_learned_rules()
RETURNS void AS $$
BEGIN
  UPDATE learned_rules
  SET is_active = false
  WHERE is_active = true
    AND expires_at IS NOT NULL
    AND expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Create function to decay confidence over time (run weekly)
CREATE OR REPLACE FUNCTION decay_pattern_confidence()
RETURNS void AS $$
BEGIN
  -- Reduce confidence by 5% for patterns not seen in 30 days
  UPDATE feedback_patterns
  SET confidence = GREATEST(10, confidence - 5)
  WHERE is_active = true
    AND last_seen < NOW() - INTERVAL '30 days';

  -- Deactivate patterns with very low confidence
  UPDATE feedback_patterns
  SET is_active = false
  WHERE confidence < 20
    AND last_seen < NOW() - INTERVAL '60 days';
END;
$$ LANGUAGE plpgsql;

-- Grant permissions (adjust as needed for your setup)
-- GRANT SELECT, INSERT, UPDATE ON feedback_patterns TO app_user;
-- GRANT SELECT, INSERT, UPDATE ON learned_rules TO app_user;
-- GRANT SELECT, INSERT ON feedback_learning_log TO app_user;
