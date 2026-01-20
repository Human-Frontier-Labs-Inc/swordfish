# Implementation Plan

## Overview

A phased, test-driven development plan for Swordfish. Each phase has clear deliverables and acceptance criteria.

---

## Phase Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                    SWORDFISH IMPLEMENTATION ROADMAP                │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  PHASE 1         PHASE 2         PHASE 3         PHASE 4          │
│  Foundation      Core Engine     Integrations    Production       │
│                                                                    │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│  │ Auth     │    │ Decision │    │ O365     │    │ Sandbox  │     │
│  │ Multi-   │───▶│ Engine   │───▶│ Gmail    │───▶│ Custom   │     │
│  │ Tenant   │    │ ML/LLM   │    │ SMTP GW  │    │ MSP Mode │     │
│  │ Dashboard│    │ URL/File │    │ Remediate│    │ SOC 2    │     │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘     │
│                                                                    │
│  DELIVERABLE:    DELIVERABLE:    DELIVERABLE:    DELIVERABLE:     │
│  Admin can       Detection        Full email      Production-     │
│  onboard and     pipeline         protection      ready            │
│  view tenants    processes        working         deployment       │
│                  test emails                                       │
└────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Foundation & Multi-Tenant Infrastructure

### Objective
Establish core platform with authentication, multi-tenancy, and admin dashboard.

### TDD Approach
Write acceptance tests first, then implement to pass them.

---

### 1.1 Authentication & Authorization

#### Tests to Write First

```typescript
// __tests__/auth/clerk-integration.test.ts
describe('Clerk Authentication', () => {
  it('should redirect unauthenticated users to sign-in', async () => {
    const response = await fetch('/dashboard');
    expect(response.redirected).toBe(true);
    expect(response.url).toContain('/sign-in');
  });

  it('should allow authenticated users to access dashboard', async () => {
    const session = await createTestSession();
    const response = await fetchWithAuth('/dashboard', session);
    expect(response.status).toBe(200);
  });

  it('should enforce organization-based access control', async () => {
    const session = await createTestSession({ orgId: 'org_123' });
    const response = await fetchWithAuth('/api/tenants/tenant_456', session);
    expect(response.status).toBe(403);
  });

  it('should support MSP admin role with multi-tenant access', async () => {
    const session = await createTestSession({
      orgId: 'msp_org',
      role: 'msp_admin'
    });
    const response = await fetchWithAuth('/api/tenants', session);
    const tenants = await response.json();
    expect(tenants.length).toBeGreaterThan(1);
  });

  it('should support tenant admin role with single-tenant access', async () => {
    const session = await createTestSession({
      orgId: 'tenant_org',
      role: 'tenant_admin'
    });
    const response = await fetchWithAuth('/api/tenants', session);
    const tenants = await response.json();
    expect(tenants.length).toBe(1);
  });
});
```

```typescript
// __tests__/auth/rbac.test.ts
describe('Role-Based Access Control', () => {
  it('should allow MSP admin to switch tenants', async () => {
    const session = await createMspSession();
    const response = await fetchWithAuth('/api/context/tenant_123', session, {
      method: 'POST'
    });
    expect(response.status).toBe(200);
  });

  it('should prevent tenant admin from accessing other tenants', async () => {
    const session = await createTenantSession('tenant_123');
    const response = await fetchWithAuth('/api/tenants/tenant_456', session);
    expect(response.status).toBe(403);
  });

  it('should allow tenant admin to manage their own policies', async () => {
    const session = await createTenantSession('tenant_123');
    const response = await fetchWithAuth('/api/tenants/tenant_123/policies', session, {
      method: 'POST',
      body: JSON.stringify({ type: 'allowlist', value: 'trusted@example.com' })
    });
    expect(response.status).toBe(201);
  });

  it('should audit all permission checks', async () => {
    const session = await createTenantSession('tenant_123');
    await fetchWithAuth('/api/tenants/tenant_456', session); // Denied request

    const auditLogs = await getAuditLogs({ action: 'access_denied' });
    expect(auditLogs).toContainEqual(
      expect.objectContaining({
        actor_id: session.userId,
        action: 'access_denied',
        resource_type: 'tenant'
      })
    );
  });
});
```

#### Implementation Deliverables

- [ ] Clerk organization setup with roles (msp_admin, tenant_admin, viewer)
- [ ] Middleware protecting all `/dashboard/*` routes
- [ ] Tenant context provider with switcher
- [ ] Audit logging for all auth events

---

### 1.2 Database Schema & Multi-Tenancy

#### Tests to Write First

```typescript
// __tests__/db/tenant-isolation.test.ts
describe('Tenant Data Isolation', () => {
  it('should never return data from other tenants', async () => {
    // Create verdicts for two tenants
    await createVerdict({ tenantId: 'tenant_a', subject: 'Test A' });
    await createVerdict({ tenantId: 'tenant_b', subject: 'Test B' });

    // Query as tenant_a
    const verdicts = await getVerdicts({ tenantId: 'tenant_a' });

    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].subject).toBe('Test A');
    expect(verdicts.some(v => v.tenantId === 'tenant_b')).toBe(false);
  });

  it('should enforce tenant_id on all queries', async () => {
    // Attempt query without tenant context
    await expect(getVerdicts({})).rejects.toThrow('tenant_id required');
  });

  it('should support MSP querying across tenants with permission', async () => {
    const mspContext = { role: 'msp_admin', tenantIds: ['tenant_a', 'tenant_b'] };
    const verdicts = await getVerdicts({ mspContext });

    expect(verdicts.some(v => v.tenantId === 'tenant_a')).toBe(true);
    expect(verdicts.some(v => v.tenantId === 'tenant_b')).toBe(true);
  });

  it('should cascade delete tenant data on removal', async () => {
    await createTenant({ id: 'tenant_delete_test' });
    await createVerdict({ tenantId: 'tenant_delete_test' });
    await createPolicy({ tenantId: 'tenant_delete_test' });

    await deleteTenant('tenant_delete_test');

    const verdicts = await db.query('SELECT * FROM email_verdicts WHERE tenant_id = $1', ['tenant_delete_test']);
    const policies = await db.query('SELECT * FROM policies WHERE tenant_id = $1', ['tenant_delete_test']);

    expect(verdicts.rows).toHaveLength(0);
    expect(policies.rows).toHaveLength(0);
  });
});
```

```typescript
// __tests__/db/audit-log.test.ts
describe('Audit Logging', () => {
  it('should log all data mutations with actor and timestamp', async () => {
    const before = new Date();
    await createPolicy({
      tenantId: 'tenant_123',
      type: 'allowlist',
      actorId: 'user_456'
    });
    const after = new Date();

    const logs = await getAuditLogs({ tenantId: 'tenant_123' });

    expect(logs[0]).toMatchObject({
      actor_id: 'user_456',
      action: 'create',
      resource_type: 'policy'
    });
    expect(new Date(logs[0].created_at)).toBeGreaterThanOrEqual(before);
    expect(new Date(logs[0].created_at)).toBeLessThanOrEqual(after);
  });

  it('should be immutable (no updates/deletes)', async () => {
    await expect(
      db.query('DELETE FROM audit_log WHERE id = $1', ['some_id'])
    ).rejects.toThrow();

    await expect(
      db.query('UPDATE audit_log SET action = $1 WHERE id = $2', ['modified', 'some_id'])
    ).rejects.toThrow();
  });

  it('should include before/after state for changes', async () => {
    const policy = await createPolicy({
      tenantId: 'tenant_123',
      type: 'allowlist',
      config: { email: 'old@example.com' }
    });

    await updatePolicy(policy.id, {
      config: { email: 'new@example.com' },
      actorId: 'user_456'
    });

    const logs = await getAuditLogs({ resourceId: policy.id, action: 'update' });

    expect(logs[0].before_state.config.email).toBe('old@example.com');
    expect(logs[0].after_state.config.email).toBe('new@example.com');
  });
});
```

#### Implementation Deliverables

- [ ] Neon database setup with connection pooling
- [ ] Database migrations (all tables from schema)
- [ ] Row-level security policies
- [ ] Audit log triggers (immutable)
- [ ] Tenant context middleware

---

### 1.3 Admin Dashboard

#### Tests to Write First

```typescript
// __tests__/dashboard/overview.test.ts
describe('Dashboard Overview', () => {
  it('should display threat count for last 24 hours', async () => {
    await createVerdicts([
      { tenantId: 'tenant_123', verdict: 'block', createdAt: hoursAgo(1) },
      { tenantId: 'tenant_123', verdict: 'block', createdAt: hoursAgo(12) },
      { tenantId: 'tenant_123', verdict: 'block', createdAt: hoursAgo(48) }, // Excluded
    ]);

    render(<DashboardOverview tenantId="tenant_123" />);

    expect(await screen.findByTestId('threat-count-24h')).toHaveTextContent('2');
  });

  it('should display quarantine count awaiting action', async () => {
    await createQuarantineItems([
      { tenantId: 'tenant_123', status: 'pending' },
      { tenantId: 'tenant_123', status: 'pending' },
      { tenantId: 'tenant_123', status: 'released' }, // Excluded
    ]);

    render(<DashboardOverview tenantId="tenant_123" />);

    expect(await screen.findByTestId('quarantine-pending')).toHaveTextContent('2');
  });

  it('should display integration status', async () => {
    await createIntegration({
      tenantId: 'tenant_123',
      type: 'o365',
      status: 'connected'
    });

    render(<DashboardOverview tenantId="tenant_123" />);

    expect(await screen.findByTestId('integration-o365')).toHaveTextContent('Connected');
  });

  it('should load in under 2 seconds', async () => {
    const start = performance.now();
    render(<DashboardOverview tenantId="tenant_123" />);
    await screen.findByTestId('dashboard-loaded');
    const duration = performance.now() - start;

    expect(duration).toBeLessThan(2000);
  });
});
```

```typescript
// __tests__/dashboard/tenant-switcher.test.ts
describe('Tenant Switcher (MSP)', () => {
  it('should display all accessible tenants', async () => {
    const mspSession = await createMspSession({
      tenants: ['Acme Corp', 'Beta LLC', 'Gamma Inc']
    });

    render(<TenantSwitcher />, { session: mspSession });
    await userEvent.click(screen.getByTestId('tenant-switcher-trigger'));

    expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    expect(screen.getByText('Beta LLC')).toBeInTheDocument();
    expect(screen.getByText('Gamma Inc')).toBeInTheDocument();
  });

  it('should switch context in under 200ms', async () => {
    render(<TenantSwitcher />);
    await userEvent.click(screen.getByTestId('tenant-switcher-trigger'));

    const start = performance.now();
    await userEvent.click(screen.getByText('Beta LLC'));
    await waitFor(() => {
      expect(screen.getByTestId('current-tenant')).toHaveTextContent('Beta LLC');
    });
    const duration = performance.now() - start;

    expect(duration).toBeLessThan(200);
  });

  it('should persist last selected tenant', async () => {
    render(<TenantSwitcher />);
    await userEvent.click(screen.getByTestId('tenant-switcher-trigger'));
    await userEvent.click(screen.getByText('Beta LLC'));

    // Simulate page reload
    cleanup();
    render(<TenantSwitcher />);

    expect(screen.getByTestId('current-tenant')).toHaveTextContent('Beta LLC');
  });

  it('should support keyboard navigation (Cmd+K)', async () => {
    render(<TenantSwitcher />);

    await userEvent.keyboard('{Meta>}k{/Meta}');

    expect(screen.getByTestId('global-search')).toBeVisible();
    expect(screen.getByTestId('global-search-input')).toHaveFocus();
  });
});
```

#### Implementation Deliverables

- [ ] Dashboard layout with sidebar navigation
- [ ] Tenant switcher dropdown (MSP mode)
- [ ] Threat summary cards
- [ ] Integration status indicators
- [ ] Empty state for new tenants
- [ ] Global search (Cmd+K) palette

---

### Phase 1 Acceptance Criteria

| Deliverable | Acceptance Criteria | Tests |
|-------------|---------------------|-------|
| User can sign up and create organization | Clerk auth working, org created | 5 |
| MSP can add tenant | Tenant record created, access granted | 3 |
| Dashboard shows tenant overview | Threat counts, integration status visible | 4 |
| Tenant switching works | <200ms switch, context preserved | 3 |
| Audit log captures all actions | Immutable log with actor/timestamp | 4 |

### Definition of Done

- [ ] All tests passing
- [ ] 80%+ code coverage on new code
- [ ] Dashboard accessible at `/dashboard`
- [ ] Tenant switching functional for MSP accounts
- [ ] Database migrations applied and documented
- [ ] E2E test: New user can sign up and see empty dashboard

---

## Phase 2: Detection Engine

### Objective
Build the core email analysis pipeline with deterministic rules, ML, and LLM escalation.

---

### 2.1 Deterministic Detection Layer

#### Tests to Write First

```typescript
// __tests__/detection/deterministic.test.ts
describe('Deterministic Detection', () => {
  describe('SPF/DKIM/DMARC', () => {
    it('should pass email with valid SPF, DKIM, DMARC', async () => {
      const email = createTestEmail({
        headers: {
          'Authentication-Results': 'spf=pass dkim=pass dmarc=pass'
        }
      });

      const result = await runDeterministicAnalysis(email);

      expect(result.signals.filter(s => s.type === 'spf')[0].severity).toBe('info');
      expect(result.score).toBeLessThan(30);
    });

    it('should flag email with SPF fail', async () => {
      const email = createTestEmail({
        headers: {
          'Authentication-Results': 'spf=fail dkim=pass dmarc=pass'
        }
      });

      const result = await runDeterministicAnalysis(email);

      expect(result.signals).toContainEqual(
        expect.objectContaining({ type: 'spf', severity: 'warning' })
      );
      expect(result.score).toBeGreaterThanOrEqual(20);
    });

    it('should flag email with DKIM fail', async () => {
      const email = createTestEmail({
        headers: {
          'Authentication-Results': 'spf=pass dkim=fail dmarc=pass'
        }
      });

      const result = await runDeterministicAnalysis(email);

      expect(result.signals).toContainEqual(
        expect.objectContaining({ type: 'dkim', severity: 'warning' })
      );
    });

    it('should flag email with DMARC fail', async () => {
      const email = createTestEmail({
        headers: {
          'Authentication-Results': 'spf=pass dkim=pass dmarc=fail'
        }
      });

      const result = await runDeterministicAnalysis(email);

      expect(result.signals).toContainEqual(
        expect.objectContaining({ type: 'dmarc', severity: 'critical' })
      );
      expect(result.score).toBeGreaterThanOrEqual(30);
    });
  });

  describe('Domain Analysis', () => {
    it('should flag domains registered < 30 days ago', async () => {
      const email = createTestEmail({
        from: 'offer@brand-new-domain.com'
      });
      mockDomainAge('brand-new-domain.com', 15); // 15 days old

      const result = await runDeterministicAnalysis(email);

      expect(result.signals).toContainEqual(
        expect.objectContaining({
          type: 'domain_age',
          severity: 'warning',
          detail: expect.stringContaining('15 days')
        })
      );
    });

    it('should detect homoglyph domains (paypa1.com)', async () => {
      const email = createTestEmail({
        from: 'support@paypa1.com' // '1' instead of 'l'
      });

      const result = await runDeterministicAnalysis(email);

      expect(result.signals).toContainEqual(
        expect.objectContaining({
          type: 'homoglyph',
          severity: 'critical',
          detail: expect.stringContaining('paypal.com')
        })
      );
    });

    it('should detect cousin domains (paypal-secure.com)', async () => {
      const email = createTestEmail({
        from: 'support@paypal-secure.com'
      });

      const result = await runDeterministicAnalysis(email);

      expect(result.signals).toContainEqual(
        expect.objectContaining({ type: 'cousin_domain', severity: 'warning' })
      );
    });
  });

  describe('Header Anomalies', () => {
    it('should flag From/Reply-To mismatch', async () => {
      const email = createTestEmail({
        from: 'ceo@company.com',
        replyTo: 'attacker@gmail.com'
      });

      const result = await runDeterministicAnalysis(email);

      expect(result.signals).toContainEqual(
        expect.objectContaining({ type: 'header_anomaly', severity: 'warning' })
      );
    });

    it('should flag display name spoofing', async () => {
      const email = createTestEmail({
        from: '"John Smith CEO" <random@gmail.com>'
      });

      const result = await runDeterministicAnalysis(email);

      expect(result.signals).toContainEqual(
        expect.objectContaining({
          type: 'display_name_spoof',
          severity: 'warning'
        })
      );
    });
  });

  describe('URL Analysis', () => {
    it('should extract all URLs from email body', async () => {
      const email = createTestEmail({
        body: `
          Click here: https://example.com/link1
          Or here: https://example.com/link2
          Text without link
          Final link: http://example.com/link3
        `
      });

      const result = await runDeterministicAnalysis(email);

      expect(result.extractedUrls).toHaveLength(3);
    });

    it('should follow redirects up to 5 levels', async () => {
      mockRedirectChain('https://short.url/abc', [
        'https://redirect1.com',
        'https://redirect2.com',
        'https://final-destination.com'
      ]);

      const email = createTestEmail({
        body: 'Click here: https://short.url/abc'
      });

      const result = await runDeterministicAnalysis(email);

      expect(result.signals).toContainEqual(
        expect.objectContaining({
          type: 'url_redirect',
          detail: expect.stringContaining('final-destination.com')
        })
      );
    });

    it('should flag data: and javascript: URLs', async () => {
      const email = createTestEmail({
        body: `
          <a href="javascript:alert('xss')">Click</a>
          <a href="data:text/html,<script>alert('xss')</script>">Click</a>
        `
      });

      const result = await runDeterministicAnalysis(email);

      expect(result.signals).toContainEqual(
        expect.objectContaining({ type: 'dangerous_url', severity: 'critical' })
      );
    });
  });
});
```

#### Implementation Deliverables

- [ ] Email parser (normalize all formats)
- [ ] SPF/DKIM/DMARC checker
- [ ] Domain age lookup integration
- [ ] Homoglyph detection algorithm
- [ ] Header anomaly detector
- [ ] URL extractor and analyzer
- [ ] Scoring engine with configurable weights

---

### 2.2 ML Classification Layer

#### Tests to Write First

```typescript
// __tests__/detection/ml-classifier.test.ts
describe('ML Phishing Classifier', () => {
  it('should classify obvious phishing with >95% confidence', async () => {
    const email = createTestEmail({
      subject: 'URGENT: Your account will be suspended',
      body: `
        Dear Customer,
        Your account has been compromised. Click here immediately
        to verify your identity or your account will be closed.
        http://bank-secure-login.com/verify
      `
    });

    const result = await runMlClassification(email);

    expect(result.classification).toBe('phishing');
    expect(result.confidence).toBeGreaterThan(0.95);
  });

  it('should classify obvious legitimate with >95% confidence', async () => {
    const email = createTestEmail({
      from: 'newsletter@company.com',
      subject: 'Weekly Product Update',
      body: `
        Hi team,
        Here's what's new this week in our product...
        Best regards,
        The Product Team
      `
    });

    const result = await runMlClassification(email);

    expect(result.classification).toBe('legitimate');
    expect(result.confidence).toBeGreaterThan(0.95);
  });

  it('should return low confidence for ambiguous emails', async () => {
    const email = createTestEmail({
      subject: 'Invoice attached',
      body: 'Please review the attached invoice and process payment.'
    });

    const result = await runMlClassification(email);

    expect(result.confidence).toBeLessThan(0.7);
  });

  it('should complete inference in <100ms', async () => {
    const email = createTestEmail({});

    const start = performance.now();
    await runMlClassification(email);
    const duration = performance.now() - start;

    expect(duration).toBeLessThan(100);
  });
});
```

```typescript
// __tests__/detection/ml-gating.test.ts
describe('ML Gating', () => {
  it('should skip ML for emails passing deterministic with high confidence', async () => {
    const email = createTestEmail({
      headers: { 'Authentication-Results': 'spf=pass dkim=pass dmarc=pass' }
    });

    const mlSpy = jest.spyOn(mlClassifier, 'classify');
    await runFullPipeline(email);

    expect(mlSpy).not.toHaveBeenCalled();
  });

  it('should invoke ML for emails with medium deterministic score', async () => {
    const email = createTestEmail({
      headers: { 'Authentication-Results': 'spf=pass dkim=fail dmarc=none' }
    });

    const mlSpy = jest.spyOn(mlClassifier, 'classify');
    await runFullPipeline(email);

    expect(mlSpy).toHaveBeenCalledWith(expect.objectContaining({
      messageId: email.messageId
    }));
  });

  it('should track ML invocation rate per tenant', async () => {
    const tenantId = 'tenant_123';

    // Process 10 emails
    for (let i = 0; i < 10; i++) {
      await runFullPipeline(createTestEmail({ tenantId }));
    }

    const metrics = await getTenantMetrics(tenantId);
    expect(metrics.mlInvocationRate).toBeDefined();
    expect(metrics.mlInvocationRate).toBeLessThanOrEqual(1);
  });
});
```

---

### 2.3 LLM Escalation Layer

#### Tests to Write First

```typescript
// __tests__/detection/llm-escalation.test.ts
describe('LLM Escalation', () => {
  it('should only invoke LLM when ML confidence is 40-70%', async () => {
    const llmSpy = jest.spyOn(llmService, 'analyze');

    // High confidence - no LLM
    await runFullPipeline(createTestEmail({ _mlConfidence: 0.95 }));
    expect(llmSpy).not.toHaveBeenCalled();

    // Low confidence - no LLM (just block)
    await runFullPipeline(createTestEmail({ _mlConfidence: 0.2 }));
    expect(llmSpy).not.toHaveBeenCalled();

    // Medium confidence - LLM invoked
    await runFullPipeline(createTestEmail({ _mlConfidence: 0.55 }));
    expect(llmSpy).toHaveBeenCalled();
  });

  it('should generate human-readable explanation', async () => {
    const result = await llmService.analyze(createTestEmail({
      subject: 'Wire transfer request',
      body: 'Please wire $50,000 to this new account immediately.'
    }));

    expect(result.explanation).toBeDefined();
    expect(result.explanation.length).toBeGreaterThan(50);
    expect(result.explanation).not.toContain('SPF');
    expect(result.explanation).not.toContain('DKIM');
    // Should be plain English
  });

  it('should never make final decision alone', async () => {
    const result = await llmService.analyze(createTestEmail({}));

    expect(result.finalDecision).toBeUndefined();
    expect(result.recommendation).toBeDefined();
    expect(['likely_safe', 'suspicious', 'likely_malicious']).toContain(result.recommendation);
  });

  it('should respect per-tenant LLM budget caps', async () => {
    const tenantId = 'tenant_budget_test';
    await setTenantLlmBudget(tenantId, { dailyLimit: 5 });

    // Use up budget
    for (let i = 0; i < 5; i++) {
      await runFullPipelineWithLlm(createTestEmail({ tenantId }));
    }

    // Next should skip LLM
    const llmSpy = jest.spyOn(llmService, 'analyze');
    await runFullPipelineWithLlm(createTestEmail({ tenantId }));
    expect(llmSpy).not.toHaveBeenCalled();
  });

  it('should complete in <5 seconds', async () => {
    const start = performance.now();
    await llmService.analyze(createTestEmail({}));
    const duration = performance.now() - start;

    expect(duration).toBeLessThan(5000);
  });
});
```

---

### 2.4 URL and Attachment Handling

#### Tests to Write First

```typescript
// __tests__/detection/url-rewrite.test.ts
describe('URL Rewriting', () => {
  it('should rewrite all URLs to edge endpoint', async () => {
    const email = createTestEmail({
      body: '<a href="https://example.com/page">Click here</a>'
    });

    const rewritten = await rewriteUrls(email);

    expect(rewritten.body).toContain('https://click.swordfish.io/');
    expect(rewritten.body).not.toContain('https://example.com/page');
  });

  it('should preserve original URL in signed token', async () => {
    const originalUrl = 'https://example.com/page';
    const email = createTestEmail({
      body: `<a href="${originalUrl}">Click here</a>`
    });

    const rewritten = await rewriteUrls(email);
    const token = extractTokenFromUrl(rewritten.body);
    const decoded = await decodeUrlToken(token);

    expect(decoded.originalUrl).toBe(originalUrl);
    expect(decoded.tenantId).toBe(email.tenantId);
    expect(decoded.signature).toBeDefined();
  });

  it('should respect tenant allowlist', async () => {
    await addToAllowlist('tenant_123', { domain: 'trusted.com' });

    const email = createTestEmail({
      tenantId: 'tenant_123',
      body: '<a href="https://trusted.com/page">Click here</a>'
    });

    const rewritten = await rewriteUrls(email);

    // Should NOT be rewritten
    expect(rewritten.body).toContain('https://trusted.com/page');
  });

  it('should handle malformed URLs gracefully', async () => {
    const email = createTestEmail({
      body: `
        <a href="not-a-url">Bad link</a>
        <a href="https:/example.com">Missing slash</a>
        <a href="">Empty href</a>
      `
    });

    // Should not throw
    const rewritten = await rewriteUrls(email);
    expect(rewritten).toBeDefined();
  });
});
```

```typescript
// __tests__/detection/attachment.test.ts
describe('Attachment Analysis', () => {
  it('should extract file hash and check reputation', async () => {
    const attachment = createTestAttachment({
      filename: 'invoice.pdf',
      content: Buffer.from('test content')
    });

    const reputationSpy = jest.spyOn(reputationService, 'checkHash');
    await analyzeAttachment(attachment);

    expect(reputationSpy).toHaveBeenCalledWith(
      expect.stringMatching(/^[a-f0-9]{64}$/) // SHA-256
    );
  });

  it('should perform static analysis on executables', async () => {
    const attachment = createTestAttachment({
      filename: 'setup.exe',
      content: createMockExecutable()
    });

    const result = await analyzeAttachment(attachment);

    expect(result.staticAnalysis).toBeDefined();
    expect(result.staticAnalysis.fileType).toBe('executable');
  });

  it('should submit unknown files to sandbox', async () => {
    const attachment = createTestAttachment({
      filename: 'document.docm', // Macro-enabled
      content: createMockDocm()
    });
    mockHashReputation('unknown');

    const sandboxSpy = jest.spyOn(sandboxService, 'submit');
    await analyzeAttachment(attachment);

    expect(sandboxSpy).toHaveBeenCalled();
  });

  it('should cache sandbox verdicts by hash', async () => {
    const content = Buffer.from('unique test content ' + Date.now());
    const attachment = createTestAttachment({ content });

    // First analysis - hits sandbox
    const sandboxSpy = jest.spyOn(sandboxService, 'submit');
    await analyzeAttachment(attachment);
    expect(sandboxSpy).toHaveBeenCalledTimes(1);

    // Second analysis with same content - uses cache
    await analyzeAttachment(createTestAttachment({ content }));
    expect(sandboxSpy).toHaveBeenCalledTimes(1); // Still 1
  });

  it('should handle password-protected archives', async () => {
    const attachment = createTestAttachment({
      filename: 'documents.zip',
      content: createPasswordProtectedZip()
    });

    const result = await analyzeAttachment(attachment);

    expect(result.signals).toContainEqual(
      expect.objectContaining({
        type: 'password_protected_archive',
        severity: 'warning'
      })
    );
  });
});
```

---

### Phase 2 Acceptance Criteria

| Deliverable | Acceptance Criteria | Tests |
|-------------|---------------------|-------|
| Deterministic rules engine | SPF/DKIM/DMARC, domain age, homoglyphs | 15 |
| ML classifier integrated | Phishing classification <100ms | 5 |
| LLM escalation working | Gated invocation, explanations | 5 |
| URL rewriting service | Cloudflare Worker deployed | 6 |
| Attachment analysis | Hash check, static, sandbox | 8 |
| Decision API | POST /api/analyze returns verdict | 5 |

### Definition of Done

- [ ] All tests passing with 85%+ coverage
- [ ] API endpoint `/api/analyze` accepts email, returns verdict
- [ ] Latency <1 second for non-sandbox analysis
- [ ] Cost tracking per tenant implemented
- [ ] E2E test: Submit test email, receive correct verdict

---

## Phase 3: Email Integrations

### Objective
Connect to O365, Gmail, and SMTP gateway to process real email.

---

### 3.1 Microsoft 365 Integration

#### Tests to Write First

```typescript
// __tests__/integrations/o365/auth.test.ts
describe('O365 OAuth', () => {
  it('should initiate OAuth flow with correct scopes', async () => {
    const authUrl = await o365Auth.getAuthorizationUrl('tenant_123');
    const url = new URL(authUrl);

    expect(url.searchParams.get('scope')).toContain('Mail.Read');
    expect(url.searchParams.get('scope')).toContain('Mail.ReadWrite');
    expect(url.searchParams.get('response_type')).toBe('code');
  });

  it('should exchange code for tokens', async () => {
    const code = 'test_auth_code';
    mockMicrosoftTokenEndpoint({ access_token: 'access', refresh_token: 'refresh' });

    const tokens = await o365Auth.exchangeCode(code, 'tenant_123');

    expect(tokens.accessToken).toBeDefined();
    expect(tokens.refreshToken).toBeDefined();
    expect(tokens.expiresAt).toBeInstanceOf(Date);
  });

  it('should refresh expired tokens automatically', async () => {
    await storeTokens('tenant_123', {
      accessToken: 'expired',
      refreshToken: 'valid_refresh',
      expiresAt: new Date(Date.now() - 1000) // Expired
    });

    mockMicrosoftTokenEndpoint({ access_token: 'new_access' });

    const token = await o365Auth.getValidToken('tenant_123');

    expect(token).toBe('new_access');
  });

  it('should revoke access on tenant removal', async () => {
    const revokeSpy = jest.spyOn(o365Auth, 'revokeAccess');

    await deleteTenant('tenant_123');

    expect(revokeSpy).toHaveBeenCalledWith('tenant_123');
  });
});
```

```typescript
// __tests__/integrations/o365/graph.test.ts
describe('O365 Graph API', () => {
  it('should subscribe to new mail notifications', async () => {
    mockGraphApi();

    const subscription = await o365Graph.createMailSubscription('tenant_123');

    expect(subscription.resource).toBe('me/mailFolders/Inbox/messages');
    expect(subscription.changeType).toBe('created');
    expect(subscription.expirationDateTime).toBeDefined();
  });

  it('should fetch email content by message ID', async () => {
    mockGraphApi();

    const email = await o365Graph.getMessage('tenant_123', 'message_123');

    expect(email.subject).toBeDefined();
    expect(email.body.content).toBeDefined();
    expect(email.from.emailAddress.address).toBeDefined();
  });

  it('should move email to quarantine folder', async () => {
    const moveSpy = mockGraphApi();

    await o365Graph.quarantineMessage('tenant_123', 'message_123');

    expect(moveSpy).toHaveBeenCalledWith(
      expect.stringContaining('/messages/message_123/move'),
      expect.objectContaining({ destinationId: expect.any(String) })
    );
  });

  it('should delete email with admin consent', async () => {
    const deleteSpy = mockGraphApi();

    await o365Graph.deleteMessage('tenant_123', 'message_123');

    expect(deleteSpy).toHaveBeenCalledWith(
      expect.stringContaining('/messages/message_123'),
      { method: 'DELETE' }
    );
  });
});
```

---

### 3.2 Gmail Integration

#### Tests to Write First

```typescript
// __tests__/integrations/gmail/auth.test.ts
describe('Gmail OAuth', () => {
  it('should initiate OAuth with Gmail API scopes', async () => {
    const authUrl = await gmailAuth.getAuthorizationUrl('tenant_123');
    const url = new URL(authUrl);

    expect(url.searchParams.get('scope')).toContain('gmail.modify');
    expect(url.searchParams.get('scope')).toContain('gmail.readonly');
  });

  it('should handle domain-wide delegation for Workspace', async () => {
    const tokens = await gmailAuth.setupDomainWideDelegation('tenant_123', {
      serviceAccountKey: mockServiceAccountKey,
      adminEmail: 'admin@company.com'
    });

    expect(tokens.type).toBe('service_account');
    expect(tokens.impersonatedUser).toBe('admin@company.com');
  });
});
```

```typescript
// __tests__/integrations/gmail/watch.test.ts
describe('Gmail Watch', () => {
  it('should create Pub/Sub subscription for new mail', async () => {
    mockGmailApi();

    const watch = await gmailWatch.setup('tenant_123');

    expect(watch.historyId).toBeDefined();
    expect(watch.expiration).toBeDefined();
  });

  it('should process Pub/Sub messages within SLA', async () => {
    const message = createPubSubMessage({
      emailAddress: 'user@company.com',
      historyId: '12345'
    });

    const start = performance.now();
    await gmailWatch.handleNotification(message);
    const duration = performance.now() - start;

    expect(duration).toBeLessThan(5000); // 5 second SLA
  });

  it('should renew watch before expiration', async () => {
    const watch = await gmailWatch.setup('tenant_123');
    const renewSpy = jest.spyOn(gmailWatch, 'renew');

    // Fast-forward to near expiration
    jest.advanceTimersByTime(6 * 24 * 60 * 60 * 1000); // 6 days

    expect(renewSpy).toHaveBeenCalled();
  });
});
```

---

### 3.3 SMTP Gateway

#### Tests to Write First

```typescript
// __tests__/integrations/smtp/server.test.ts
describe('SMTP Server', () => {
  it('should accept mail on port 25', async () => {
    const client = await createSmtpClient({ port: 25 });

    const result = await client.send({
      from: 'sender@example.com',
      to: 'recipient@company.com',
      subject: 'Test',
      body: 'Test body'
    });

    expect(result.accepted).toContain('recipient@company.com');
  });

  it('should support STARTTLS', async () => {
    const client = await createSmtpClient({ port: 25 });

    const capabilities = await client.getCapabilities();
    expect(capabilities).toContain('STARTTLS');

    await client.startTls();
    expect(client.isSecure()).toBe(true);
  });

  it('should validate recipient domain', async () => {
    const client = await createSmtpClient({ port: 25 });

    // Unknown domain should be rejected
    const result = await client.send({
      from: 'sender@example.com',
      to: 'recipient@unknown-domain.com',
      subject: 'Test',
      body: 'Test body'
    });

    expect(result.rejected).toContain('recipient@unknown-domain.com');
  });

  it('should queue mail for analysis', async () => {
    const queueSpy = jest.spyOn(analysisQueue, 'add');
    const client = await createSmtpClient({ port: 25 });

    await client.send({
      from: 'sender@example.com',
      to: 'recipient@protected-domain.com',
      subject: 'Test',
      body: 'Test body'
    });

    expect(queueSpy).toHaveBeenCalled();
  });

  it('should forward clean mail to destination', async () => {
    mockAnalysisResult({ verdict: 'pass' });
    const forwardSpy = jest.spyOn(smtpGateway, 'forward');

    await processIncomingMail(createTestEmail({ verdict: 'pass' }));

    expect(forwardSpy).toHaveBeenCalled();
  });

  it('should reject blocked mail with 550 response', async () => {
    mockAnalysisResult({ verdict: 'block' });
    const client = await createSmtpClient({ port: 25 });

    const result = await client.send({
      from: 'attacker@malicious.com',
      to: 'victim@protected-domain.com',
      subject: 'Phishing attempt',
      body: 'Click here to verify your account'
    });

    expect(result.response.code).toBe(550);
  });
});
```

---

### 3.4 Onboarding Flow

#### E2E Test

```typescript
// __tests__/e2e/onboarding.test.ts
describe('Onboarding Flow', () => {
  it('should complete O365 setup in under 10 minutes', async () => {
    const page = await browser.newPage();
    const start = performance.now();

    // Sign up
    await page.goto('/sign-up');
    await page.click('[data-testid="sign-in-microsoft"]');
    await mockMicrosoftLogin(page);

    // Select plan
    await page.click('[data-testid="plan-pro"]');
    await page.click('[data-testid="continue"]');

    // Select integration
    await page.click('[data-testid="integration-o365"]');

    // Authorize
    await page.click('[data-testid="authorize-o365"]');
    await mockMicrosoftConsent(page);

    // Wait for sync
    await page.waitForSelector('[data-testid="sync-complete"]', { timeout: 60000 });

    // Verify protected
    await expect(page.locator('[data-testid="protection-status"]')).toHaveText('Protected');

    const duration = (performance.now() - start) / 1000 / 60; // minutes
    expect(duration).toBeLessThan(10);
  });
});
```

---

### Phase 3 Acceptance Criteria

| Deliverable | Acceptance Criteria | Tests |
|-------------|---------------------|-------|
| O365 OAuth flow | Tenant can authorize via Microsoft | 4 |
| O365 mail processing | New mail triggers analysis | 5 |
| O365 remediation | Quarantine, purge, banner | 4 |
| Gmail OAuth flow | Tenant can authorize via Google | 3 |
| Gmail mail processing | Pub/Sub triggers analysis | 4 |
| Gmail remediation | Labels, trash, delete | 3 |
| SMTP gateway | Accepts and processes mail | 6 |
| Onboarding UI | <10 minute self-service | 1 E2E |

### Definition of Done

- [ ] All tests passing
- [ ] O365 integration fully functional
- [ ] Gmail integration fully functional
- [ ] SMTP gateway processing test traffic
- [ ] Onboarding flow works end-to-end (<10 min)
- [ ] Real email being protected

---

## Phase 4: Production Readiness

### Objective
Harden for production with enhanced sandbox, MSP features, compliance, and AI support.

---

### 4.1 Custom Sandbox (Long-term)

#### Tests to Write First

```typescript
// __tests__/sandbox/detonation.test.ts
describe('Attachment Detonation', () => {
  it('should create ephemeral VM for each analysis', async () => {
    const vmSpy = jest.spyOn(vmManager, 'create');

    await sandbox.analyze(createTestAttachment());

    expect(vmSpy).toHaveBeenCalledWith(
      expect.objectContaining({ ephemeral: true })
    );
  });

  it('should capture network traffic', async () => {
    const result = await sandbox.analyze(createTestAttachment({
      behavior: 'makes_http_request'
    }));

    expect(result.networkCapture).toBeDefined();
    expect(result.networkCapture.requests.length).toBeGreaterThan(0);
  });

  it('should extract IOCs from behavior', async () => {
    const result = await sandbox.analyze(createTestAttachment({
      behavior: 'drops_file'
    }));

    expect(result.iocs).toContainEqual(
      expect.objectContaining({ type: 'file', path: expect.any(String) })
    );
  });

  it('should auto-destroy VM after 30 seconds', async () => {
    const destroySpy = jest.spyOn(vmManager, 'destroy');

    await sandbox.analyze(createTestAttachment());

    expect(destroySpy).toHaveBeenCalled();
  });

  it('should cache verdict by file hash', async () => {
    const content = Buffer.from('test content');

    await sandbox.analyze(createTestAttachment({ content }));
    const vmSpy = jest.spyOn(vmManager, 'create');

    await sandbox.analyze(createTestAttachment({ content }));

    expect(vmSpy).not.toHaveBeenCalled(); // Used cache
  });
});
```

---

### 4.2 MSP Features

#### Tests to Write First

```typescript
// __tests__/msp/policy-templates.test.ts
describe('Policy Templates', () => {
  it('should create policy template at MSP level', async () => {
    const template = await createPolicyTemplate({
      mspOrgId: 'msp_123',
      name: 'Standard Security',
      policies: [
        { type: 'blocklist', config: { domain: 'known-bad.com' } }
      ]
    });

    expect(template.id).toBeDefined();
    expect(template.mspOrgId).toBe('msp_123');
  });

  it('should apply template to multiple tenants', async () => {
    const template = await createPolicyTemplate({ mspOrgId: 'msp_123' });

    await applyTemplate(template.id, ['tenant_a', 'tenant_b', 'tenant_c']);

    const tenantAPolicies = await getPolicies('tenant_a');
    const tenantBPolicies = await getPolicies('tenant_b');

    expect(tenantAPolicies).toEqual(tenantBPolicies);
  });

  it('should allow per-tenant overrides', async () => {
    const template = await createPolicyTemplate({ mspOrgId: 'msp_123' });
    await applyTemplate(template.id, ['tenant_a']);

    await addTenantOverride('tenant_a', {
      type: 'allowlist',
      config: { domain: 'tenant-specific.com' }
    });

    const policies = await getPolicies('tenant_a');
    expect(policies).toContainEqual(
      expect.objectContaining({ config: { domain: 'tenant-specific.com' } })
    );
  });
});
```

```typescript
// __tests__/msp/reporting.test.ts
describe('White-Label Reporting', () => {
  it('should generate PDF report with MSP branding', async () => {
    const report = await generateReport({
      tenantId: 'tenant_123',
      dateRange: { start: '2024-01-01', end: '2024-01-31' },
      branding: {
        logo: 'https://msp.com/logo.png',
        primaryColor: '#123456'
      }
    });

    expect(report.format).toBe('pdf');
    expect(report.content).toContain('msp.com/logo.png'); // Logo embedded
  });

  it('should aggregate threat data across date range', async () => {
    await createVerdicts([
      { tenantId: 'tenant_123', verdict: 'block', createdAt: '2024-01-15' },
      { tenantId: 'tenant_123', verdict: 'block', createdAt: '2024-01-20' },
      { tenantId: 'tenant_123', verdict: 'pass', createdAt: '2024-02-01' } // Outside range
    ]);

    const report = await generateReport({
      tenantId: 'tenant_123',
      dateRange: { start: '2024-01-01', end: '2024-01-31' }
    });

    expect(report.data.threatsBlocked).toBe(2);
  });

  it('should support scheduled report delivery', async () => {
    await scheduleReport({
      tenantId: 'tenant_123',
      schedule: 'weekly',
      recipients: ['admin@company.com']
    });

    // Fast-forward one week
    jest.advanceTimersByTime(7 * 24 * 60 * 60 * 1000);

    const sentEmails = await getSentEmails();
    expect(sentEmails).toContainEqual(
      expect.objectContaining({
        to: 'admin@company.com',
        subject: expect.stringContaining('Weekly Security Report')
      })
    );
  });
});
```

---

### 4.3 Compliance & Security

#### Tests to Write First

```typescript
// __tests__/compliance/data-retention.test.ts
describe('Data Retention', () => {
  it('should purge email body after 7 days', async () => {
    await createVerdict({
      tenantId: 'tenant_123',
      body: 'Sensitive email content',
      createdAt: daysAgo(10)
    });

    await runRetentionJob();

    const verdict = await getVerdict('tenant_123', 'verdict_id');
    expect(verdict.body).toBeNull();
    expect(verdict.subject).toBeDefined(); // Metadata kept
  });

  it('should retain metadata for audit per policy', async () => {
    await setRetentionPolicy('tenant_123', { metadataRetentionDays: 365 });

    await createVerdict({
      tenantId: 'tenant_123',
      createdAt: daysAgo(100)
    });

    await runRetentionJob();

    const verdict = await getVerdict('tenant_123', 'verdict_id');
    expect(verdict).toBeDefined();
    expect(verdict.from_address).toBeDefined();
  });
});
```

```typescript
// __tests__/compliance/encryption.test.ts
describe('Encryption', () => {
  it('should encrypt sensitive fields at rest', async () => {
    await storeIntegration({
      tenantId: 'tenant_123',
      type: 'o365',
      credentials: { accessToken: 'secret_token' }
    });

    // Read raw from database
    const raw = await db.query(
      'SELECT credentials_encrypted FROM integrations WHERE tenant_id = $1',
      ['tenant_123']
    );

    expect(raw.rows[0].credentials_encrypted).not.toContain('secret_token');
  });

  it('should use tenant-specific keys', async () => {
    const keyA = await getEncryptionKey('tenant_a');
    const keyB = await getEncryptionKey('tenant_b');

    expect(keyA).not.toEqual(keyB);
  });

  it('should support key rotation', async () => {
    await storeSecret('tenant_123', 'test_secret');
    const oldKey = await getEncryptionKey('tenant_123');

    await rotateEncryptionKey('tenant_123');

    const newKey = await getEncryptionKey('tenant_123');
    expect(newKey).not.toEqual(oldKey);

    // Data should still be readable
    const secret = await getSecret('tenant_123');
    expect(secret).toBe('test_secret');
  });
});
```

---

### 4.4 AI-Powered Support

#### Tests to Write First

```typescript
// __tests__/support/ai-agent.test.ts
describe('AI Support Agent', () => {
  it('should answer common questions from knowledge base', async () => {
    const response = await aiSupport.chat({
      message: 'How do I release a quarantined email?',
      context: { tenantId: 'tenant_123' }
    });

    expect(response.answer).toContain('quarantine');
    expect(response.confidence).toBeGreaterThan(0.8);
    expect(response.escalatedToHuman).toBe(false);
  });

  it('should escalate unknown issues', async () => {
    const response = await aiSupport.chat({
      message: 'My quantum flux capacitor is malfunctioning',
      context: { tenantId: 'tenant_123' }
    });

    expect(response.escalatedToHuman).toBe(true);
    expect(response.escalationReason).toBeDefined();
  });

  it('should track resolution rate', async () => {
    // Simulate 10 support conversations
    for (let i = 0; i < 10; i++) {
      await aiSupport.chat({ message: 'How do I add a user?' });
    }

    const metrics = await aiSupport.getMetrics();
    expect(metrics.resolutionRate).toBeDefined();
    expect(metrics.resolutionRate).toBeGreaterThan(0.5);
  });

  it('should learn from resolved tickets', async () => {
    // Initial question - low confidence
    const initial = await aiSupport.chat({
      message: 'What is the maximum attachment size?'
    });

    // Admin provides answer
    await aiSupport.trainFromResolution({
      question: 'What is the maximum attachment size?',
      answer: 'The maximum attachment size is 25MB.'
    });

    // Same question - higher confidence
    const subsequent = await aiSupport.chat({
      message: 'What is the maximum attachment size?'
    });

    expect(subsequent.confidence).toBeGreaterThan(initial.confidence);
  });
});
```

---

### Phase 4 Acceptance Criteria

| Deliverable | Acceptance Criteria | Tests |
|-------------|---------------------|-------|
| Custom sandbox | File detonation with IOC extraction | 5 |
| Policy templates | MSP can create and apply | 4 |
| White-label reports | PDF with branding | 3 |
| Data retention | Automated purge | 3 |
| Encryption at rest | Sensitive fields encrypted | 3 |
| AI support agent | Handles common queries | 4 |
| SOC 2 controls | Evidence collection | Audit checklist |

### Definition of Done

- [ ] All Phase 1-3 tests still passing
- [ ] Custom sandbox processing attachments
- [ ] MSP features fully functional
- [ ] Compliance controls documented and tested
- [ ] AI support handling queries
- [ ] Production deployment checklist completed
- [ ] Security audit passed

---

## Related Documents

- [Architecture](./ARCHITECTURE.md) - System design and infrastructure
- [Technical Recommendations](./TECHNICAL_RECOMMENDATIONS.md) - Detection and tooling decisions
- [Test Strategy](./TEST_STRATEGY.md) - Testing approach and CI/CD
- [User Journeys](./USER_JOURNEYS.md) - UX flows to test against
