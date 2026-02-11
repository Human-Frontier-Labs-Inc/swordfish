-- Migration: 008_rls_policies
-- Description: Add Row Level Security policies for tenant isolation
-- Date: 2025-06-26
-- Author: Neo (HFL)
--
-- CRITICAL SECURITY: This migration implements proper tenant isolation.
-- Without these policies, RLS is enabled but not enforced, meaning
-- any query without a WHERE tenant_id clause could leak data.
--
-- Usage: Before any query, the application must set:
--   SET LOCAL app.current_tenant_id = '<tenant_id>';
--
-- For MSP users with multi-tenant access, also set:
--   SET LOCAL app.msp_org_id = '<msp_org_id>';

-- ============================================================================
-- HELPER FUNCTION: Check if current user has MSP access to a tenant
-- ============================================================================

CREATE OR REPLACE FUNCTION has_msp_access(check_tenant_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
    -- If no MSP org is set, no MSP access
    IF current_setting('app.msp_org_id', true) IS NULL OR current_setting('app.msp_org_id', true) = '' THEN
        RETURN FALSE;
    END IF;
    
    -- Check if the MSP org has access to this tenant
    RETURN EXISTS (
        SELECT 1 FROM msp_tenant_access
        WHERE msp_org_id = current_setting('app.msp_org_id', true)::UUID
        AND tenant_id = check_tenant_id
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- CORE TENANT TABLES - Strict tenant isolation
-- ============================================================================

-- TENANTS: Users can only see their own tenant (or MSP-managed tenants)
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenants_isolation ON tenants;
CREATE POLICY tenants_isolation ON tenants
    FOR ALL
    USING (
        id = current_setting('app.current_tenant_id', true)::UUID
        OR has_msp_access(id)
    );

-- USERS: Users in same tenant, or MSP can see users in managed tenants
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS users_isolation ON users;
CREATE POLICY users_isolation ON users
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        OR has_msp_access(tenant_id)
    );

-- ============================================================================
-- EMAIL & DETECTION TABLES
-- ============================================================================

-- EMAIL_VERDICTS: Tenant isolation
DROP POLICY IF EXISTS email_verdicts_isolation ON email_verdicts;
CREATE POLICY email_verdicts_isolation ON email_verdicts
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        OR has_msp_access(tenant_id)
    );

-- QUARANTINE: Tenant isolation
DROP POLICY IF EXISTS quarantine_isolation ON quarantine;
CREATE POLICY quarantine_isolation ON quarantine
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        OR has_msp_access(tenant_id)
    );

-- THREATS: Tenant isolation (tenant_id is VARCHAR in this table)
ALTER TABLE threats ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS threats_isolation ON threats;
CREATE POLICY threats_isolation ON threats
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)
        OR EXISTS (
            SELECT 1 FROM msp_tenant_access mta
            WHERE mta.msp_org_id = current_setting('app.msp_org_id', true)::UUID
            AND mta.tenant_id::TEXT = threats.tenant_id
        )
    );

-- FEEDBACK: Tenant isolation (tenant_id is VARCHAR)
ALTER TABLE feedback ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS feedback_isolation ON feedback;
CREATE POLICY feedback_isolation ON feedback
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)
        OR EXISTS (
            SELECT 1 FROM msp_tenant_access mta
            WHERE mta.msp_org_id = current_setting('app.msp_org_id', true)::UUID
            AND mta.tenant_id::TEXT = feedback.tenant_id
        )
    );

-- ============================================================================
-- POLICY TABLES
-- ============================================================================

-- POLICIES: Tenant isolation
DROP POLICY IF EXISTS policies_isolation ON policies;
CREATE POLICY policies_isolation ON policies
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        OR has_msp_access(tenant_id)
    );

-- TENANT_POLICIES: Tenant isolation
ALTER TABLE tenant_policies ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_policies_isolation ON tenant_policies;
CREATE POLICY tenant_policies_isolation ON tenant_policies
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        OR has_msp_access(tenant_id)
    );

-- SENDER_LISTS: Tenant isolation (tenant_id is VARCHAR)
ALTER TABLE sender_lists ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS sender_lists_isolation ON sender_lists;
CREATE POLICY sender_lists_isolation ON sender_lists
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)
        OR EXISTS (
            SELECT 1 FROM msp_tenant_access mta
            WHERE mta.msp_org_id = current_setting('app.msp_org_id', true)::UUID
            AND mta.tenant_id::TEXT = sender_lists.tenant_id
        )
    );

-- ============================================================================
-- INTEGRATION TABLES
-- ============================================================================

-- INTEGRATIONS: Tenant isolation
DROP POLICY IF EXISTS integrations_isolation ON integrations;
CREATE POLICY integrations_isolation ON integrations
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        OR has_msp_access(tenant_id)
    );

-- PROVIDER_CONNECTIONS: Tenant isolation (tenant_id is VARCHAR)
ALTER TABLE provider_connections ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS provider_connections_isolation ON provider_connections;
CREATE POLICY provider_connections_isolation ON provider_connections
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)
        OR EXISTS (
            SELECT 1 FROM msp_tenant_access mta
            WHERE mta.msp_org_id = current_setting('app.msp_org_id', true)::UUID
            AND mta.tenant_id::TEXT = provider_connections.tenant_id
        )
    );

-- INTEGRATION_STATES: Tenant isolation (tenant_id is VARCHAR)
ALTER TABLE integration_states ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS integration_states_isolation ON integration_states;
CREATE POLICY integration_states_isolation ON integration_states
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)
    );

-- ============================================================================
-- NOTIFICATION & WEBHOOK TABLES
-- ============================================================================

-- NOTIFICATIONS: Tenant isolation (tenant_id is VARCHAR)
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS notifications_isolation ON notifications;
CREATE POLICY notifications_isolation ON notifications
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)
        OR EXISTS (
            SELECT 1 FROM msp_tenant_access mta
            WHERE mta.msp_org_id = current_setting('app.msp_org_id', true)::UUID
            AND mta.tenant_id::TEXT = notifications.tenant_id
        )
    );

-- WEBHOOKS: Tenant isolation (tenant_id is VARCHAR)
ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS webhooks_isolation ON webhooks;
CREATE POLICY webhooks_isolation ON webhooks
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)
        OR EXISTS (
            SELECT 1 FROM msp_tenant_access mta
            WHERE mta.msp_org_id = current_setting('app.msp_org_id', true)::UUID
            AND mta.tenant_id::TEXT = webhooks.tenant_id
        )
    );

-- ============================================================================
-- AUDIT & METRICS TABLES
-- ============================================================================

-- AUDIT_LOG: Tenant isolation (with NULL tenant_id for system events)
DROP POLICY IF EXISTS audit_log_isolation ON audit_log;
CREATE POLICY audit_log_isolation ON audit_log
    FOR SELECT  -- Audit log is SELECT only (immutable)
    USING (
        tenant_id IS NULL  -- System events visible to all
        OR tenant_id = current_setting('app.current_tenant_id', true)::UUID
        OR has_msp_access(tenant_id)
    );

-- Allow INSERT for all (needed for logging)
DROP POLICY IF EXISTS audit_log_insert ON audit_log;
CREATE POLICY audit_log_insert ON audit_log
    FOR INSERT
    WITH CHECK (TRUE);

-- USAGE_METRICS: Tenant isolation
DROP POLICY IF EXISTS usage_metrics_isolation ON usage_metrics;
CREATE POLICY usage_metrics_isolation ON usage_metrics
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        OR has_msp_access(tenant_id)
    );

-- ============================================================================
-- REPORTS & EXPORTS
-- ============================================================================

-- SCHEDULED_REPORTS: Tenant isolation (tenant_id is VARCHAR)
ALTER TABLE scheduled_reports ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS scheduled_reports_isolation ON scheduled_reports;
CREATE POLICY scheduled_reports_isolation ON scheduled_reports
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)
        OR EXISTS (
            SELECT 1 FROM msp_tenant_access mta
            WHERE mta.msp_org_id = current_setting('app.msp_org_id', true)::UUID
            AND mta.tenant_id::TEXT = scheduled_reports.tenant_id
        )
    );

-- REPORT_JOBS: Tenant isolation (tenant_id is VARCHAR)
ALTER TABLE report_jobs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS report_jobs_isolation ON report_jobs;
CREATE POLICY report_jobs_isolation ON report_jobs
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)
        OR EXISTS (
            SELECT 1 FROM msp_tenant_access mta
            WHERE mta.msp_org_id = current_setting('app.msp_org_id', true)::UUID
            AND mta.tenant_id::TEXT = report_jobs.tenant_id
        )
    );

-- EXPORT_JOBS: Tenant isolation (tenant_id is VARCHAR)
ALTER TABLE export_jobs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS export_jobs_isolation ON export_jobs;
CREATE POLICY export_jobs_isolation ON export_jobs
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)
        OR EXISTS (
            SELECT 1 FROM msp_tenant_access mta
            WHERE mta.msp_org_id = current_setting('app.msp_org_id', true)::UUID
            AND mta.tenant_id::TEXT = export_jobs.tenant_id
        )
    );

-- ============================================================================
-- USER MANAGEMENT
-- ============================================================================

-- USER_INVITATIONS: Tenant isolation
ALTER TABLE user_invitations ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS user_invitations_isolation ON user_invitations;
CREATE POLICY user_invitations_isolation ON user_invitations
    FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        OR has_msp_access(tenant_id)
    );

-- ============================================================================
-- MSP TABLES - Special handling
-- ============================================================================

-- MSP_ORGANIZATIONS: Only visible to members of that MSP
ALTER TABLE msp_organizations ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS msp_organizations_isolation ON msp_organizations;
CREATE POLICY msp_organizations_isolation ON msp_organizations
    FOR ALL
    USING (
        id = current_setting('app.msp_org_id', true)::UUID
    );

-- MSP_TENANT_ACCESS: Visible to MSP org members
ALTER TABLE msp_tenant_access ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS msp_tenant_access_isolation ON msp_tenant_access;
CREATE POLICY msp_tenant_access_isolation ON msp_tenant_access
    FOR ALL
    USING (
        msp_org_id = current_setting('app.msp_org_id', true)::UUID
        OR tenant_id = current_setting('app.current_tenant_id', true)::UUID
    );

-- ============================================================================
-- POLICY TEMPLATES - MSP-owned
-- ============================================================================

-- POLICY_TEMPLATES: MSP can see their templates, or NULL msp_org_id (global)
DROP POLICY IF EXISTS policy_templates_isolation ON policy_templates;
CREATE POLICY policy_templates_isolation ON policy_templates
    FOR ALL
    USING (
        msp_org_id IS NULL  -- Global templates
        OR msp_org_id = current_setting('app.msp_org_id', true)::UUID
    );

-- ============================================================================
-- SHARED/CACHE TABLES - No tenant isolation needed
-- ============================================================================

-- URL_ANALYSES: Shared cache, no tenant data
-- No RLS needed - these are shared lookups

-- FILE_ANALYSES: Shared cache, no tenant data
-- No RLS needed - these are shared lookups

-- ============================================================================
-- DOCUMENTATION
-- ============================================================================

COMMENT ON FUNCTION has_msp_access(UUID) IS 'Check if current MSP org has access to the given tenant. Used by RLS policies.';

-- Add comments explaining RLS usage
COMMENT ON POLICY tenants_isolation ON tenants IS 'Tenant isolation: users see own tenant or MSP-managed tenants';
COMMENT ON POLICY email_verdicts_isolation ON email_verdicts IS 'Tenant isolation: verdict data is tenant-specific';
COMMENT ON POLICY threats_isolation ON threats IS 'Tenant isolation: threat data is tenant-specific';
COMMENT ON POLICY audit_log_isolation ON audit_log IS 'Tenant isolation: audit logs are tenant-specific, system events (NULL tenant) visible to all';
