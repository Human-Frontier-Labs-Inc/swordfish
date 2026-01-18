-- Migration: Response Learner Tables
-- Description: Creates tables for ML response learner functionality
-- Version: 011

-- ============================================================================
-- Admin Decisions Table (for backward compatible recordDecision)
-- ============================================================================
CREATE TABLE IF NOT EXISTS admin_decisions (
  id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  verdict_id UUID NOT NULL,
  original_verdict TEXT NOT NULL CHECK (original_verdict IN ('pass', 'quarantine', 'block', 'review')),
  admin_action TEXT NOT NULL CHECK (admin_action IN ('release', 'delete', 'block', 'whitelist', 'confirm')),
  admin_id TEXT NOT NULL,
  reason TEXT,
  timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
  email_features JSONB NOT NULL,
  subsequent_reported_as_phish BOOLEAN DEFAULT FALSE,
  reported_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for admin_decisions
CREATE INDEX IF NOT EXISTS idx_admin_decisions_tenant ON admin_decisions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_admin_decisions_timestamp ON admin_decisions(timestamp);
CREATE INDEX IF NOT EXISTS idx_admin_decisions_action ON admin_decisions(admin_action);
CREATE INDEX IF NOT EXISTS idx_admin_decisions_verdict_id ON admin_decisions(verdict_id);
CREATE INDEX IF NOT EXISTS idx_admin_decisions_admin_id ON admin_decisions(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_decisions_sender_domain ON admin_decisions((email_features->>'senderDomain'));
CREATE INDEX IF NOT EXISTS idx_admin_decisions_original_verdict ON admin_decisions(original_verdict);

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_admin_decisions_tenant_timestamp ON admin_decisions(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_admin_decisions_tenant_action ON admin_decisions(tenant_id, admin_action);

-- ============================================================================
-- Admin Actions Table (for new recordAction interface)
-- ============================================================================
CREATE TABLE IF NOT EXISTS admin_actions (
  action_id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  admin_id TEXT NOT NULL,
  verdict_id TEXT NOT NULL,
  original_verdict TEXT NOT NULL,
  new_verdict TEXT NOT NULL,
  action_type TEXT NOT NULL CHECK (action_type IN ('release', 'quarantine', 'block', 'delete', 'mark_safe', 'mark_threat')),
  reason TEXT,
  timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for admin_actions
CREATE INDEX IF NOT EXISTS idx_admin_actions_tenant ON admin_actions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_admin_actions_timestamp ON admin_actions(timestamp);
CREATE INDEX IF NOT EXISTS idx_admin_actions_admin ON admin_actions(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_actions_verdict ON admin_actions(verdict_id);
CREATE INDEX IF NOT EXISTS idx_admin_actions_action_type ON admin_actions(action_type);

-- Composite indexes
CREATE INDEX IF NOT EXISTS idx_admin_actions_tenant_timestamp ON admin_actions(tenant_id, timestamp DESC);

-- ============================================================================
-- Threshold Adjustments Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS threshold_adjustments (
  id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  threshold_name TEXT NOT NULL,
  current_value DECIMAL NOT NULL,
  suggested_value DECIMAL NOT NULL,
  direction TEXT NOT NULL CHECK (direction IN ('increase', 'decrease')),
  reason TEXT NOT NULL,
  evidence JSONB NOT NULL,
  adjustment_data JSONB,
  previous_settings JSONB NOT NULL,
  applied_at TIMESTAMP WITH TIME ZONE,
  rolled_back_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for threshold_adjustments
CREATE INDEX IF NOT EXISTS idx_threshold_adjustments_tenant ON threshold_adjustments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_threshold_adjustments_applied ON threshold_adjustments(applied_at);
CREATE INDEX IF NOT EXISTS idx_threshold_adjustments_rolled_back ON threshold_adjustments(rolled_back_at);

-- ============================================================================
-- A/B Tests Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS ab_tests (
  id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  suggestion_id UUID NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'cancelled')) DEFAULT 'running',
  control_group JSONB NOT NULL,
  test_group JSONB NOT NULL,
  started_at TIMESTAMP WITH TIME ZONE NOT NULL,
  ended_at TIMESTAMP WITH TIME ZONE,
  results JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for ab_tests
CREATE INDEX IF NOT EXISTS idx_ab_tests_tenant ON ab_tests(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ab_tests_status ON ab_tests(status);
CREATE INDEX IF NOT EXISTS idx_ab_tests_suggestion ON ab_tests(suggestion_id);
CREATE INDEX IF NOT EXISTS idx_ab_tests_started ON ab_tests(started_at);

-- ============================================================================
-- Policy Suggestions Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS policy_suggestions (
  id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('whitelist_domain', 'whitelist_sender', 'adjust_threshold', 'add_rule', 'remove_rule', 'modify_rule')),
  description TEXT NOT NULL,
  confidence DECIMAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  evidence JSONB NOT NULL,
  impact JSONB NOT NULL,
  suggested_value JSONB,
  status TEXT NOT NULL CHECK (status IN ('pending', 'applied', 'rejected', 'testing')) DEFAULT 'pending',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  applied_at TIMESTAMP WITH TIME ZONE,
  rejected_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for policy_suggestions
CREATE INDEX IF NOT EXISTS idx_policy_suggestions_tenant ON policy_suggestions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_policy_suggestions_type ON policy_suggestions(type);
CREATE INDEX IF NOT EXISTS idx_policy_suggestions_status ON policy_suggestions(status);
CREATE INDEX IF NOT EXISTS idx_policy_suggestions_confidence ON policy_suggestions(confidence DESC);
CREATE INDEX IF NOT EXISTS idx_policy_suggestions_created ON policy_suggestions(created_at DESC);

-- ============================================================================
-- User Feedback Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_feedback (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  verdict_id UUID,
  user_id TEXT,
  feedback_type TEXT NOT NULL CHECK (feedback_type IN ('false_positive', 'false_negative', 'missed_threat', 'confirm_threat', 'other')),
  notes TEXT,
  processed BOOLEAN DEFAULT FALSE,
  processed_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for user_feedback
CREATE INDEX IF NOT EXISTS idx_user_feedback_tenant ON user_feedback(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_feedback_verdict ON user_feedback(verdict_id);
CREATE INDEX IF NOT EXISTS idx_user_feedback_type ON user_feedback(feedback_type);
CREATE INDEX IF NOT EXISTS idx_user_feedback_processed ON user_feedback(processed);
CREATE INDEX IF NOT EXISTS idx_user_feedback_created ON user_feedback(created_at DESC);

-- Composite indexes
CREATE INDEX IF NOT EXISTS idx_user_feedback_tenant_created ON user_feedback(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_feedback_tenant_processed ON user_feedback(tenant_id, processed);

-- ============================================================================
-- Learning Patterns Table (for storing identified patterns)
-- ============================================================================
CREATE TABLE IF NOT EXISTS learning_patterns (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT REFERENCES tenants(id) ON DELETE CASCADE, -- NULL for global patterns
  pattern_type TEXT NOT NULL CHECK (pattern_type IN ('domain', 'sender', 'feature', 'time', 'combination')),
  pattern_category TEXT NOT NULL CHECK (pattern_category IN ('false_positive', 'false_negative', 'threat')),
  description TEXT NOT NULL,
  occurrences INTEGER NOT NULL DEFAULT 1,
  confidence DECIMAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  features JSONB NOT NULL,
  example_ids UUID[] DEFAULT ARRAY[]::UUID[],
  first_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for learning_patterns
CREATE INDEX IF NOT EXISTS idx_learning_patterns_tenant ON learning_patterns(tenant_id);
CREATE INDEX IF NOT EXISTS idx_learning_patterns_type ON learning_patterns(pattern_type);
CREATE INDEX IF NOT EXISTS idx_learning_patterns_category ON learning_patterns(pattern_category);
CREATE INDEX IF NOT EXISTS idx_learning_patterns_confidence ON learning_patterns(confidence DESC);
CREATE INDEX IF NOT EXISTS idx_learning_patterns_occurrences ON learning_patterns(occurrences DESC);
CREATE INDEX IF NOT EXISTS idx_learning_patterns_active ON learning_patterns(is_active);

-- Index for JSONB features search
CREATE INDEX IF NOT EXISTS idx_learning_patterns_features ON learning_patterns USING GIN (features);

-- ============================================================================
-- Drift Detection History Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS drift_detection_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  has_drift BOOLEAN NOT NULL,
  drift_score DECIMAL NOT NULL CHECK (drift_score >= 0 AND drift_score <= 1),
  drift_type TEXT CHECK (drift_type IN ('feature', 'label', 'concept', 'none')),
  affected_features TEXT[],
  recommendation TEXT,
  baseline_period_start TIMESTAMP WITH TIME ZONE NOT NULL,
  baseline_period_end TIMESTAMP WITH TIME ZONE NOT NULL,
  comparison_period_start TIMESTAMP WITH TIME ZONE NOT NULL,
  comparison_period_end TIMESTAMP WITH TIME ZONE NOT NULL,
  feature_shifts JSONB,
  override_rate_change DECIMAL,
  detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for drift_detection_history
CREATE INDEX IF NOT EXISTS idx_drift_history_tenant ON drift_detection_history(tenant_id);
CREATE INDEX IF NOT EXISTS idx_drift_history_has_drift ON drift_detection_history(has_drift);
CREATE INDEX IF NOT EXISTS idx_drift_history_detected ON drift_detection_history(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_drift_history_drift_score ON drift_detection_history(drift_score DESC);

-- ============================================================================
-- Training Data Exports Table (for tracking generated training datasets)
-- ============================================================================
CREATE TABLE IF NOT EXISTS training_data_exports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  sample_count INTEGER NOT NULL,
  threat_count INTEGER NOT NULL,
  safe_count INTEGER NOT NULL,
  date_range_start TIMESTAMP WITH TIME ZONE NOT NULL,
  date_range_end TIMESTAMP WITH TIME ZONE NOT NULL,
  options JSONB,
  export_path TEXT,
  generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for training_data_exports
CREATE INDEX IF NOT EXISTS idx_training_exports_tenant ON training_data_exports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_training_exports_generated ON training_data_exports(generated_at DESC);

-- ============================================================================
-- Aggregated Learning Table (for cross-tenant anonymized learning)
-- ============================================================================
CREATE TABLE IF NOT EXISTS aggregated_learning (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_count INTEGER NOT NULL,
  total_samples INTEGER NOT NULL,
  common_patterns JSONB NOT NULL,
  global_threshold_suggestions JSONB,
  emerging_threats JSONB,
  time_window_days INTEGER NOT NULL,
  aggregated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for aggregated_learning
CREATE INDEX IF NOT EXISTS idx_aggregated_learning_aggregated ON aggregated_learning(aggregated_at DESC);

-- ============================================================================
-- Functions and Triggers
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_learning_patterns_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for learning_patterns updated_at
DROP TRIGGER IF EXISTS trigger_learning_patterns_updated_at ON learning_patterns;
CREATE TRIGGER trigger_learning_patterns_updated_at
  BEFORE UPDATE ON learning_patterns
  FOR EACH ROW
  EXECUTE FUNCTION update_learning_patterns_updated_at();

-- ============================================================================
-- Comments
-- ============================================================================
COMMENT ON TABLE admin_decisions IS 'Stores admin decisions on email verdicts for ML learning';
COMMENT ON TABLE admin_actions IS 'Stores admin actions with new/old verdict tracking';
COMMENT ON TABLE threshold_adjustments IS 'Tracks threshold changes with rollback capability';
COMMENT ON TABLE ab_tests IS 'A/B tests for policy suggestion validation';
COMMENT ON TABLE policy_suggestions IS 'AI-generated policy improvement suggestions';
COMMENT ON TABLE user_feedback IS 'User feedback on email verdicts';
COMMENT ON TABLE learning_patterns IS 'Identified patterns from admin decisions';
COMMENT ON TABLE drift_detection_history IS 'History of drift detection runs';
COMMENT ON TABLE training_data_exports IS 'Tracking of generated training datasets';
COMMENT ON TABLE aggregated_learning IS 'Cross-tenant anonymized learning results';
