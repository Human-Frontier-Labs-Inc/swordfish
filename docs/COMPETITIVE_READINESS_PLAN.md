# Competitive Readiness Plan

## Targets

| Metric | Current | Target | Gap |
|--------|---------|--------|-----|
| Production Readiness | 72 | 100 | +28 |
| vs Barracuda (50=parity) | 42 | 60+ | +18 |
| Innovation (50=innovative) | 38 | 60+ | +22 |

## Methodology

- **TDD**: Red → Green → Refactor for every feature
- **Vertical Slices**: Complete end-to-end functionality per slice
- **Test First**: Write failing tests, then implement to pass

---

## Phase 1: Production Hardening (72 → 88)

### Slice 1.1: Load Testing Infrastructure
**Goal**: Prove system handles 10K emails/minute

```
Tests:
- [ ] Concurrent email processing (100, 500, 1000 parallel)
- [ ] Database connection pool under load
- [ ] Memory usage stays bounded
- [ ] Response times under p95 < 500ms
- [ ] No connection leaks after sustained load
- [ ] Graceful degradation at capacity limits

Implementation:
- lib/testing/load-runner.ts
- lib/testing/metrics-collector.ts
- tests/load/email-throughput.test.ts
- tests/load/api-endpoints.test.ts
- tests/load/database-stress.test.ts
```

### Slice 1.2: Circuit Breakers
**Goal**: Graceful degradation when external services fail

```
Tests:
- [ ] Circuit opens after N consecutive failures
- [ ] Circuit half-opens after timeout
- [ ] Circuit closes after successful probe
- [ ] Fallback responses when circuit open
- [ ] Per-service circuit state tracking
- [ ] Circuit state persistence across restarts
- [ ] Metrics emission for circuit events

Implementation:
- lib/resilience/circuit-breaker.ts
- lib/resilience/fallbacks.ts
- tests/resilience/circuit-breaker.test.ts
```

### Slice 1.3: Error Tracking Integration
**Goal**: Catch and report all production errors

```
Tests:
- [ ] Unhandled exceptions captured
- [ ] Error context includes user/tenant
- [ ] Source maps resolve stack traces
- [ ] Error grouping by fingerprint
- [ ] Rate limiting prevents flood
- [ ] Sensitive data scrubbed
- [ ] Breadcrumbs track user journey

Implementation:
- lib/monitoring/error-tracker.ts
- lib/monitoring/context-provider.ts
- tests/monitoring/error-tracking.test.ts
```

### Slice 1.4: Health Check Depth
**Goal**: Know exactly what's healthy/unhealthy

```
Tests:
- [ ] Database connectivity check
- [ ] Redis/cache connectivity check
- [ ] Nango API health check
- [ ] External threat feeds reachable
- [ ] Disk space adequate
- [ ] Memory usage acceptable
- [ ] Individual component status codes
- [ ] Aggregate health score

Implementation:
- lib/api/health-deep.ts
- tests/api/health-deep.test.ts
```

### Slice 1.5: Feature Flags
**Goal**: Safe rollouts with instant rollback

```
Tests:
- [ ] Flag evaluation by tenant
- [ ] Flag evaluation by user
- [ ] Percentage rollouts
- [ ] Flag override for testing
- [ ] Default values when service down
- [ ] Flag change audit logging
- [ ] Stale flag detection

Implementation:
- lib/features/flags.ts
- lib/features/evaluator.ts
- tests/features/flags.test.ts
```

### Slice 1.6: Disaster Recovery
**Goal**: Documented and tested recovery procedures

```
Tests:
- [ ] Database backup creation
- [ ] Database restore from backup
- [ ] Point-in-time recovery
- [ ] Data integrity after restore
- [ ] Backup encryption verification
- [ ] Backup retention policy enforcement
- [ ] Recovery time measurement

Implementation:
- lib/backup/database.ts
- lib/backup/restore.ts
- scripts/backup-database.ts
- scripts/restore-database.ts
- tests/backup/recovery.test.ts
```

### Slice 1.7: Secrets Management
**Goal**: Secure rotation without downtime

```
Tests:
- [ ] Secret retrieval from vault
- [ ] Secret caching with TTL
- [ ] Automatic rotation detection
- [ ] Zero-downtime rotation
- [ ] Secret version tracking
- [ ] Access audit logging
- [ ] Fallback to env vars

Implementation:
- lib/security/secrets.ts
- lib/security/rotation.ts
- tests/security/secrets.test.ts
```

### Slice 1.8: Security Test Suite (Internal Pen Test)
**Goal**: Automated OWASP Top 10 testing

```
Tests:
- [ ] SQL injection attempts blocked
- [ ] XSS attempts sanitized
- [ ] CSRF protection working
- [ ] Authentication bypass prevented
- [ ] Authorization boundaries enforced
- [ ] Sensitive data exposure prevented
- [ ] Security headers present
- [ ] Rate limiting effective
- [ ] Input validation comprehensive

Implementation:
- tests/security/owasp/injection.test.ts
- tests/security/owasp/xss.test.ts
- tests/security/owasp/auth.test.ts
- tests/security/owasp/access-control.test.ts
- tests/security/owasp/headers.test.ts
```

**Phase 1 Deliverables**: +16 production readiness points (72 → 88)

---

## Phase 2: Account Takeover Detection (Major Feature)

### Slice 2.1: Login Event Tracking
**Goal**: Capture all authentication events

```
Tests:
- [ ] Login success events recorded
- [ ] Login failure events recorded
- [ ] IP address captured
- [ ] User agent captured
- [ ] Geolocation resolved
- [ ] Device fingerprint generated
- [ ] Session correlation tracked

Implementation:
- lib/security/login-events.ts
- lib/security/geolocation.ts
- lib/security/device-fingerprint.ts
- tests/security/login-events.test.ts
```

### Slice 2.2: Impossible Travel Detection
**Goal**: Flag logins from impossible locations

```
Tests:
- [ ] Calculate distance between login locations
- [ ] Calculate time between logins
- [ ] Flag impossible travel (>500mph)
- [ ] Handle VPN/proxy detection
- [ ] Whitelist known travel patterns
- [ ] Alert on impossible travel
- [ ] Risk score adjustment

Implementation:
- lib/ato/impossible-travel.ts
- lib/ato/distance-calculator.ts
- tests/ato/impossible-travel.test.ts
```

### Slice 2.3: New Device Detection
**Goal**: Alert on logins from unknown devices

```
Tests:
- [ ] Device fingerprint comparison
- [ ] Known device registry per user
- [ ] New device alert generation
- [ ] Device trust scoring
- [ ] Device approval workflow
- [ ] Trusted device expiration

Implementation:
- lib/ato/device-registry.ts
- lib/ato/device-trust.ts
- tests/ato/device-detection.test.ts
```

### Slice 2.4: Unusual Activity Patterns
**Goal**: Detect compromised account behavior

```
Tests:
- [ ] Baseline sending frequency per user
- [ ] Detect sending spikes
- [ ] Detect unusual recipients
- [ ] Detect unusual send times
- [ ] Detect mass forwarding rules
- [ ] Detect inbox rule changes
- [ ] Composite anomaly score

Implementation:
- lib/ato/activity-baseline.ts
- lib/ato/anomaly-detector.ts
- tests/ato/activity-patterns.test.ts
```

### Slice 2.5: ATO Response Actions
**Goal**: Automated response to account takeover

```
Tests:
- [ ] Session termination
- [ ] Password reset trigger
- [ ] MFA enforcement
- [ ] Admin notification
- [ ] User notification
- [ ] Temporary account lock
- [ ] Audit trail creation

Implementation:
- lib/ato/response-actions.ts
- lib/ato/notifications.ts
- tests/ato/response-actions.test.ts
```

**Phase 2 Deliverables**: +8 Barracuda parity, +6 innovation

---

## Phase 3: Email Authentication (DMARC/SPF/DKIM)

### Slice 3.1: SPF Validation
**Goal**: Verify sender IP authorization

```
Tests:
- [ ] Parse SPF records from DNS
- [ ] Validate sender IP against SPF
- [ ] Handle SPF pass/fail/softfail/neutral
- [ ] Handle nested includes
- [ ] Handle redirect modifier
- [ ] Lookup limit enforcement (10)
- [ ] Cache SPF records

Implementation:
- lib/email-auth/spf.ts
- lib/email-auth/dns-resolver.ts
- tests/email-auth/spf.test.ts
```

### Slice 3.2: DKIM Validation
**Goal**: Verify email signature integrity

```
Tests:
- [ ] Parse DKIM-Signature header
- [ ] Retrieve public key from DNS
- [ ] Verify signature against body
- [ ] Handle multiple signatures
- [ ] Handle canonicalization (relaxed/simple)
- [ ] Handle partial body signing (l= tag)
- [ ] Signature expiration check

Implementation:
- lib/email-auth/dkim.ts
- lib/email-auth/signature-verifier.ts
- tests/email-auth/dkim.test.ts
```

### Slice 3.3: DMARC Policy Evaluation
**Goal**: Apply domain owner's policy

```
Tests:
- [ ] Parse DMARC record from DNS
- [ ] Evaluate SPF alignment
- [ ] Evaluate DKIM alignment
- [ ] Apply policy (none/quarantine/reject)
- [ ] Handle subdomain policy (sp=)
- [ ] Handle percentage (pct=)
- [ ] Generate DMARC report data

Implementation:
- lib/email-auth/dmarc.ts
- lib/email-auth/alignment.ts
- tests/email-auth/dmarc.test.ts
```

### Slice 3.4: Brand Protection Dashboard
**Goal**: Show domain authentication status

```
Tests:
- [ ] Aggregate DMARC results per domain
- [ ] Show pass/fail trends
- [ ] Identify spoofing attempts
- [ ] List unauthorized senders
- [ ] DMARC adoption recommendations
- [ ] Export compliance report

Implementation:
- lib/email-auth/analytics.ts
- app/api/v1/email-auth/route.ts
- tests/email-auth/analytics.test.ts
```

**Phase 3 Deliverables**: +4 Barracuda parity, +2 production readiness

---

## Phase 4: Communication Graph & Behavioral AI

### Slice 4.1: Contact Graph Building
**Goal**: Map communication relationships

```
Tests:
- [ ] Extract sender/recipient pairs
- [ ] Track communication frequency
- [ ] Track first contact date
- [ ] Track last contact date
- [ ] Bidirectional relationship detection
- [ ] Internal vs external classification
- [ ] Graph persistence and updates

Implementation:
- lib/behavioral/contact-graph.ts
- lib/behavioral/graph-storage.ts
- tests/behavioral/contact-graph.test.ts
```

### Slice 4.2: Communication Baselines
**Goal**: Establish normal patterns per user

```
Tests:
- [ ] Calculate typical send volume
- [ ] Calculate typical send times
- [ ] Calculate typical recipients
- [ ] Calculate typical subject patterns
- [ ] Rolling baseline updates
- [ ] Baseline confidence scoring
- [ ] New user baseline bootstrapping

Implementation:
- lib/behavioral/baselines.ts
- lib/behavioral/statistics.ts
- tests/behavioral/baselines.test.ts
```

### Slice 4.3: Anomaly Detection Engine
**Goal**: Score deviations from baseline

```
Tests:
- [ ] Volume anomaly detection
- [ ] Time anomaly detection
- [ ] Recipient anomaly detection
- [ ] Content anomaly detection
- [ ] Composite anomaly score
- [ ] Anomaly explanation generation
- [ ] False positive feedback loop

Implementation:
- lib/behavioral/anomaly-engine.ts
- lib/behavioral/explainer.ts
- tests/behavioral/anomaly-engine.test.ts
```

### Slice 4.4: First Contact Detection
**Goal**: Flag emails from unknown senders

```
Tests:
- [ ] Detect first-time external sender
- [ ] Detect lookalike of known contact
- [ ] Domain age correlation
- [ ] Risk score for first contact
- [ ] VIP sender extra scrutiny
- [ ] Supplier/vendor detection

Implementation:
- lib/behavioral/first-contact.ts
- lib/behavioral/lookalike-detector.ts
- tests/behavioral/first-contact.test.ts
```

**Phase 4 Deliverables**: +10 innovation, +4 Barracuda parity

---

## Phase 5: Advanced Threat Detection

### Slice 5.1: URL Rewriting & Click Protection
**Goal**: Protect users at click time

```
Tests:
- [ ] Rewrite URLs in email body
- [ ] Preserve original URL for display
- [ ] Click-time URL scanning
- [ ] Redirect to warning page if malicious
- [ ] Track click analytics
- [ ] Handle URL shorteners
- [ ] Bypass for whitelisted domains

Implementation:
- lib/protection/url-rewriter.ts
- lib/protection/click-scanner.ts
- app/api/v1/click/route.ts
- tests/protection/url-rewriting.test.ts
```

### Slice 5.2: Lookalike Domain Detection
**Goal**: Catch sophisticated impersonation

```
Tests:
- [ ] Homoglyph detection (rn→m, 0→o)
- [ ] Levenshtein distance calculation
- [ ] Keyboard proximity typos
- [ ] TLD swapping detection
- [ ] Brand name extraction
- [ ] Protected domain registry
- [ ] Risk scoring by similarity

Implementation:
- lib/detection/lookalike.ts
- lib/detection/homoglyphs.ts
- tests/detection/lookalike.test.ts
```

### Slice 5.3: NLP-Based BEC Detection
**Goal**: Understand email intent

```
Tests:
- [ ] Extract urgency signals
- [ ] Extract financial requests
- [ ] Extract credential requests
- [ ] Extract wire transfer requests
- [ ] Detect authority impersonation
- [ ] Detect pressure tactics
- [ ] Confidence scoring

Implementation:
- lib/detection/nlp-bec.ts
- lib/detection/intent-classifier.ts
- tests/detection/nlp-bec.test.ts
```

### Slice 5.4: Attachment Analysis
**Goal**: Deep file inspection

```
Tests:
- [ ] File type detection (magic bytes)
- [ ] Macro detection in Office docs
- [ ] Embedded URL extraction
- [ ] Password-protected file detection
- [ ] Archive inspection (zip, rar)
- [ ] Executable detection
- [ ] Risk scoring by file characteristics

Implementation:
- lib/detection/attachment-analyzer.ts
- lib/detection/file-inspector.ts
- tests/detection/attachment-analysis.test.ts
```

### Slice 5.5: Threat Intel Expansion
**Goal**: More intelligence sources

```
Tests:
- [ ] VirusTotal URL lookup
- [ ] AlienVault OTX integration
- [ ] abuse.ch feeds integration
- [ ] Threat feed aggregation
- [ ] Deduplication across feeds
- [ ] Freshness tracking
- [ ] Confidence weighting

Implementation:
- lib/threat-intel/virustotal.ts
- lib/threat-intel/alienvault.ts
- lib/threat-intel/abusech.ts
- tests/threat-intel/expanded-feeds.test.ts
```

**Phase 5 Deliverables**: +6 Barracuda parity, +8 innovation

---

## Phase 6: User Experience & Reporting

### Slice 6.1: Phish Report Button
**Goal**: End-user threat reporting

```
Tests:
- [ ] Outlook add-in message handling
- [ ] Gmail add-on message handling
- [ ] Report submission API
- [ ] Reported email analysis
- [ ] Feedback to user
- [ ] SOC queue integration
- [ ] False positive handling

Implementation:
- lib/reporting/phish-button.ts
- app/api/v1/report-phish/route.ts
- tests/reporting/phish-button.test.ts
```

### Slice 6.2: Quarantine Management
**Goal**: Admin control over quarantined emails

```
Tests:
- [ ] List quarantined emails
- [ ] Filter by tenant/date/threat type
- [ ] Release email from quarantine
- [ ] Delete email permanently
- [ ] Bulk operations
- [ ] Release with whitelist
- [ ] Audit logging

Implementation:
- lib/quarantine/manager.ts
- app/api/v1/quarantine/route.ts
- tests/quarantine/manager.test.ts
```

### Slice 6.3: Executive Dashboard
**Goal**: Board-ready security metrics

```
Tests:
- [ ] Threat volume trends
- [ ] Threats blocked vs detected
- [ ] Top threat categories
- [ ] Top targeted users
- [ ] Response time metrics
- [ ] Comparison to industry benchmarks
- [ ] PDF export

Implementation:
- lib/reporting/executive-dashboard.ts
- app/api/v1/reports/executive/route.ts
- tests/reporting/executive-dashboard.test.ts
```

### Slice 6.4: Real-time Alerts
**Goal**: Instant notification of threats

```
Tests:
- [ ] Slack webhook integration
- [ ] Microsoft Teams webhook
- [ ] Email alerts
- [ ] Alert severity levels
- [ ] Alert throttling
- [ ] Alert acknowledgment
- [ ] Alert escalation

Implementation:
- lib/alerts/slack.ts
- lib/alerts/teams.ts
- lib/alerts/dispatcher.ts
- tests/alerts/real-time.test.ts
```

**Phase 6 Deliverables**: +4 Barracuda parity, +2 innovation, +4 production readiness

---

## Phase 7: ML & Predictive Intelligence

### Slice 7.1: Threat Prediction Model
**Goal**: Score threats before full analysis

```
Tests:
- [ ] Feature extraction from email
- [ ] Model inference
- [ ] Confidence calibration
- [ ] Threshold tuning
- [ ] A/B testing framework
- [ ] Model versioning
- [ ] Rollback capability

Implementation:
- lib/ml/predictor.ts
- lib/ml/feature-extractor.ts
- tests/ml/predictor.test.ts
```

### Slice 7.2: Autonomous Response Learning
**Goal**: Learn from admin actions

```
Tests:
- [ ] Track admin decisions
- [ ] Identify patterns in overrides
- [ ] Suggest policy adjustments
- [ ] Auto-tune thresholds
- [ ] Feedback incorporation
- [ ] Drift detection

Implementation:
- lib/ml/response-learner.ts
- lib/ml/policy-suggester.ts
- tests/ml/response-learning.test.ts
```

### Slice 7.3: Explainable AI
**Goal**: "Why was this flagged?"

```
Tests:
- [ ] Feature importance extraction
- [ ] Human-readable explanations
- [ ] Evidence linking
- [ ] Confidence breakdown
- [ ] Similar threat examples
- [ ] Recommendation generation

Implementation:
- lib/ml/explainer.ts
- lib/ml/evidence-linker.ts
- tests/ml/explainability.test.ts
```

**Phase 7 Deliverables**: +8 innovation, +2 production readiness

---

## Summary Timeline

| Phase | Focus | Duration | Prod Ready | vs Barracuda | Innovation |
|-------|-------|----------|------------|--------------|------------|
| 1 | Production Hardening | 2 weeks | 72→88 | 42 | 38 |
| 2 | Account Takeover | 1.5 weeks | 88→90 | 42→50 | 38→44 |
| 3 | Email Authentication | 1 week | 90→92 | 50→54 | 44→46 |
| 4 | Behavioral AI | 1.5 weeks | 92→94 | 54→58 | 46→56 |
| 5 | Advanced Detection | 1.5 weeks | 94→96 | 58→64 | 56→64 |
| 6 | UX & Reporting | 1 week | 96→100 | 64→68 | 64→66 |
| 7 | ML & Predictive | 1 week | 100 | 68→70 | 66→74 |

## Final Projected Scores

| Metric | Current | Target | Projected |
|--------|---------|--------|-----------|
| Production Readiness | 72 | 100 | **100** |
| vs Barracuda | 42 | 60+ | **70** |
| Innovation | 38 | 60+ | **74** |

## Test Count Projection

| Phase | New Tests | Running Total |
|-------|-----------|---------------|
| Current | - | 1,270 |
| Phase 1 | ~180 | 1,450 |
| Phase 2 | ~100 | 1,550 |
| Phase 3 | ~80 | 1,630 |
| Phase 4 | ~100 | 1,730 |
| Phase 5 | ~120 | 1,850 |
| Phase 6 | ~80 | 1,930 |
| Phase 7 | ~70 | 2,000 |

**Final: ~2,000 tests**

---

## How to Execute

Each slice follows the TDD cycle:

1. **RED**: Write failing tests for the slice
2. **GREEN**: Implement minimum code to pass
3. **REFACTOR**: Clean up, optimize, document
4. **VERIFY**: Run full test suite
5. **COMMIT**: Atomic commit per slice

Start command:
```bash
# Begin Phase 1, Slice 1.1
npm test -- tests/load/email-throughput.test.ts
```
