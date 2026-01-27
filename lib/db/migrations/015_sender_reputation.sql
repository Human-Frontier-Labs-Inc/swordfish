-- Migration 015: Sender Reputation System for False Positive Reduction
-- Purpose: Track sender reputation to reduce marketing email false positives by 60%
-- Phase 1 of 5-phase tuning strategy

-- Create sender_reputation table
CREATE TABLE IF NOT EXISTS sender_reputation (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain VARCHAR(255) NOT NULL UNIQUE,
  display_name VARCHAR(255),
  category VARCHAR(50) NOT NULL CHECK (category IN ('trusted', 'marketing', 'transactional', 'suspicious', 'unknown')),
  trust_score INTEGER NOT NULL CHECK (trust_score >= 0 AND trust_score <= 100),

  -- Tracking patterns
  known_tracking_domains JSONB DEFAULT '[]'::jsonb,
  email_types JSONB DEFAULT '[]'::jsonb,

  -- Usage statistics
  first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  email_count INTEGER DEFAULT 0,

  -- User feedback aggregation
  user_feedback JSONB DEFAULT '{"safe": 0, "threat": 0, "spam": 0}'::jsonb,

  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index for fast domain lookups
CREATE INDEX IF NOT EXISTS idx_sender_reputation_domain ON sender_reputation(domain);
CREATE INDEX IF NOT EXISTS idx_sender_reputation_trust_score ON sender_reputation(trust_score);
CREATE INDEX IF NOT EXISTS idx_sender_reputation_category ON sender_reputation(category);

-- Create trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_sender_reputation_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER sender_reputation_updated_at
  BEFORE UPDATE ON sender_reputation
  FOR EACH ROW
  EXECUTE FUNCTION update_sender_reputation_updated_at();

-- Create email_feedback table for user corrections
CREATE TABLE IF NOT EXISTS email_feedback (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email_id UUID NOT NULL,
  user_id UUID NOT NULL,
  sender_domain VARCHAR(255) NOT NULL,

  -- Original detection results
  original_verdict VARCHAR(50) NOT NULL,
  original_score DECIMAL(5,2) NOT NULL,

  -- User's correction
  corrected_verdict VARCHAR(50) NOT NULL CHECK (corrected_verdict IN ('safe', 'threat', 'spam')),
  reason TEXT,

  -- Metadata
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for feedback queries
CREATE INDEX IF NOT EXISTS idx_email_feedback_sender_domain ON email_feedback(sender_domain);
CREATE INDEX IF NOT EXISTS idx_email_feedback_email_id ON email_feedback(email_id);
CREATE INDEX IF NOT EXISTS idx_email_feedback_user_id ON email_feedback(user_id);
CREATE INDEX IF NOT EXISTS idx_email_feedback_created_at ON email_feedback(created_at);
