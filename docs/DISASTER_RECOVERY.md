# Disaster Recovery & Operations Runbook

**Version:** 1.0.0
**Last Updated:** January 30, 2026
**System:** Swordfish Email Security Platform

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Backup Procedures](#backup-procedures)
3. [Recovery Procedures](#recovery-procedures)
4. [Incident Response](#incident-response)
5. [Monitoring & Alerting](#monitoring--alerting)
6. [Runbook Procedures](#runbook-procedures)
7. [Contact Information](#contact-information)

---

## System Architecture

### Components

| Component | Technology | Hosting | RPO | RTO |
|-----------|------------|---------|-----|-----|
| Web Application | Next.js | Vercel | N/A | 5 min |
| Database | PostgreSQL | Neon | 1 hour | 15 min |
| Authentication | Clerk | Clerk Cloud | N/A | N/A |
| Email Integration | Google/Microsoft | OAuth | N/A | 15 min |
| File Storage | Vercel Blob | Vercel | 24 hours | 30 min |

**RPO** = Recovery Point Objective (max data loss)
**RTO** = Recovery Time Objective (max downtime)

### Critical Dependencies

1. **Neon PostgreSQL** - Primary data store
2. **Clerk** - Authentication and user management
3. **Google Cloud** - Gmail API integration
4. **Microsoft Azure** - Office 365 integration
5. **OpenAI** - LLM analysis (optional)
6. **Vercel** - Hosting and edge functions

---

## Backup Procedures

### Database Backups

#### Automated Backups (Neon)

Neon provides automatic point-in-time recovery:
- Continuous WAL archiving
- 7-day retention (default)
- 30-day retention (Pro plan)

#### Manual Database Export

```bash
# Export full database
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d_%H%M%S).sql

# Export specific tables
pg_dump $DATABASE_URL -t email_verdicts -t quarantined_emails > threats_backup.sql

# Compressed backup
pg_dump $DATABASE_URL | gzip > backup_$(date +%Y%m%d).sql.gz
```

#### Scheduled Backup Script

```bash
#!/bin/bash
# /scripts/backup-database.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups"
RETENTION_DAYS=30

# Create backup
pg_dump $DATABASE_URL | gzip > $BACKUP_DIR/swordfish_$DATE.sql.gz

# Upload to S3 (optional)
aws s3 cp $BACKUP_DIR/swordfish_$DATE.sql.gz s3://swordfish-backups/

# Clean old backups
find $BACKUP_DIR -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: swordfish_$DATE.sql.gz"
```

### Configuration Backups

```bash
# Export environment variables (redact secrets!)
env | grep -E '^(NEXT_|CLERK_|DATABASE_|NEON_)' > .env.backup

# Git-based config backup
git add .env.example prisma/schema.prisma
git commit -m "Config backup $(date +%Y%m%d)"
```

---

## Recovery Procedures

### Scenario 1: Database Corruption

**Symptoms:** Query errors, data inconsistencies, connection failures

**Recovery Steps:**

1. **Assess Damage**
   ```sql
   -- Check table integrity
   SELECT schemaname, tablename
   FROM pg_tables
   WHERE schemaname = 'public';

   -- Check row counts
   SELECT 'email_verdicts' as table_name, COUNT(*) FROM email_verdicts
   UNION ALL
   SELECT 'quarantined_emails', COUNT(*) FROM quarantined_emails;
   ```

2. **Restore from Neon Point-in-Time**
   - Go to Neon Console → Project → Branches
   - Create branch from specific point in time
   - Update DATABASE_URL to new branch
   - Verify data integrity
   - Promote branch to main (if needed)

3. **Restore from Manual Backup**
   ```bash
   # Decompress backup
   gunzip backup_20260130.sql.gz

   # Create fresh database
   psql $DATABASE_URL -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

   # Restore
   psql $DATABASE_URL < backup_20260130.sql

   # Run migrations
   npx prisma migrate deploy
   ```

### Scenario 2: Application Failure

**Symptoms:** 500 errors, deployment failures, build errors

**Recovery Steps:**

1. **Rollback Vercel Deployment**
   ```bash
   # List deployments
   vercel ls

   # Promote previous deployment
   vercel promote <deployment-url>

   # Or via dashboard
   # Vercel → Deployments → ... → Promote to Production
   ```

2. **Rollback Code Changes**
   ```bash
   # Find last working commit
   git log --oneline -10

   # Revert to previous commit
   git revert HEAD
   git push origin main

   # Or hard reset (careful!)
   git reset --hard <commit-hash>
   git push --force-with-lease
   ```

3. **Clear Build Cache**
   ```bash
   # Vercel CLI
   vercel --prod --force

   # Or via dashboard
   # Settings → General → Build Cache → Clear
   ```

### Scenario 3: Authentication Service Outage

**Symptoms:** Login failures, 401 errors, session issues

**Recovery Steps:**

1. **Check Clerk Status**
   - Visit: https://status.clerk.com/
   - Check API status

2. **Enable Maintenance Mode**
   ```typescript
   // middleware.ts - temporary bypass
   export function middleware(request: NextRequest) {
     // During Clerk outage, allow read-only access
     if (process.env.MAINTENANCE_MODE === 'true') {
       return NextResponse.next();
     }
     // ... normal auth flow
   }
   ```

3. **Notify Users**
   - Update status page
   - Send email notification

### Scenario 4: Email Integration Failure

**Symptoms:** Emails not being scanned, webhook errors

**Recovery Steps:**

1. **Check Provider Status**
   - Google: https://www.google.com/appsstatus
   - Microsoft: https://status.office365.com/

2. **Verify OAuth Tokens**
   ```sql
   -- Check token status
   SELECT provider, status, expires_at, last_sync
   FROM provider_connections
   WHERE tenant_id = 'your-tenant-id';
   ```

3. **Re-register Webhooks**
   ```bash
   # Gmail push notifications
   curl -X POST /api/integrations/gmail/register-push

   # Check webhook health
   curl /api/webhooks/health
   ```

4. **Force Token Refresh**
   ```sql
   -- Mark tokens for refresh
   UPDATE provider_connections
   SET status = 'refresh_required'
   WHERE provider = 'gmail' AND expires_at < NOW();
   ```

### Scenario 5: Complete System Recovery

**For catastrophic failure requiring full rebuild:**

1. **Provision New Infrastructure**
   ```bash
   # Create new Neon project
   # Create new Vercel project
   # Configure Clerk application
   ```

2. **Restore Database**
   ```bash
   # Get latest backup
   aws s3 cp s3://swordfish-backups/latest.sql.gz ./
   gunzip latest.sql.gz

   # Restore to new database
   psql $NEW_DATABASE_URL < latest.sql
   ```

3. **Deploy Application**
   ```bash
   vercel deploy --prod
   ```

4. **Reconfigure Integrations**
   - Re-authenticate Gmail/O365 connections
   - Re-register webhooks
   - Verify Clerk configuration

5. **Validate Recovery**
   ```bash
   # Run health checks
   curl https://new-domain.com/api/health

   # Run smoke tests
   npm run test:e2e -- --grep "smoke"
   ```

---

## Incident Response

### Severity Levels

| Level | Description | Response Time | Examples |
|-------|-------------|---------------|----------|
| SEV-1 | Critical - Service down | 15 minutes | Database failure, Auth outage |
| SEV-2 | Major - Degraded service | 1 hour | Slow queries, Integration failures |
| SEV-3 | Minor - Limited impact | 4 hours | UI bugs, Non-critical feature down |
| SEV-4 | Low - No immediate impact | 24 hours | Cosmetic issues, Performance tweaks |

### Incident Workflow

```
1. DETECT → Alert triggered or user report
2. TRIAGE → Determine severity level
3. COMMUNICATE → Notify stakeholders
4. INVESTIGATE → Identify root cause
5. MITIGATE → Apply temporary fix
6. RESOLVE → Implement permanent fix
7. POSTMORTEM → Document and learn
```

### Incident Template

```markdown
## Incident Report

**Date:** YYYY-MM-DD
**Severity:** SEV-X
**Duration:** HH:MM

### Summary
Brief description of what happened.

### Timeline
- HH:MM - Issue detected
- HH:MM - Investigation started
- HH:MM - Root cause identified
- HH:MM - Fix deployed
- HH:MM - Service restored

### Root Cause
Technical explanation of what caused the incident.

### Resolution
What was done to fix the issue.

### Action Items
- [ ] Preventive measure 1
- [ ] Preventive measure 2

### Lessons Learned
What we learned from this incident.
```

---

## Monitoring & Alerting

### Health Endpoints

```bash
# Application health
GET /api/health

# Database connectivity
GET /api/health (includes DB check)

# Webhook receiver health
GET /api/webhooks/health

# Metrics (Prometheus format)
GET /api/metrics
```

### Key Metrics to Monitor

| Metric | Warning | Critical |
|--------|---------|----------|
| Response Time (p95) | > 500ms | > 2000ms |
| Error Rate | > 1% | > 5% |
| Database Connections | > 80% | > 95% |
| Memory Usage | > 75% | > 90% |
| CPU Usage | > 70% | > 85% |
| Failed Emails | > 10/hour | > 50/hour |

### Alert Configuration

```yaml
# Vercel Monitoring (vercel.json)
{
  "monitoring": {
    "alerts": [
      {
        "name": "High Error Rate",
        "type": "errors",
        "threshold": 5,
        "window": "5m"
      },
      {
        "name": "Slow Response",
        "type": "latency",
        "threshold": 2000,
        "percentile": 95
      }
    ]
  }
}
```

---

## Runbook Procedures

### Daily Operations

- [ ] Check `/api/health` status
- [ ] Review error logs in Vercel
- [ ] Monitor active threats dashboard
- [ ] Verify email processing is working

### Weekly Operations

- [ ] Review security alerts
- [ ] Check database growth
- [ ] Review performance metrics
- [ ] Audit user access

### Monthly Operations

- [ ] Rotate API keys
- [ ] Review and update dependencies
- [ ] Test backup restoration
- [ ] Update documentation

### Quarterly Operations

- [ ] Full disaster recovery drill
- [ ] Security audit
- [ ] Performance baseline review
- [ ] Capacity planning

---

## Common Commands

### Database

```bash
# Connect to database
psql $DATABASE_URL

# Run migrations
npx prisma migrate deploy

# Reset database (DANGER!)
npx prisma migrate reset

# Generate Prisma client
npx prisma generate

# View database in browser
npx prisma studio
```

### Deployment

```bash
# Deploy to production
vercel --prod

# View deployment logs
vercel logs

# List deployments
vercel ls

# Rollback deployment
vercel promote <url>
```

### Debugging

```bash
# View Vercel function logs
vercel logs --follow

# Test API endpoint
curl -H "Authorization: Bearer $TOKEN" https://api.swordfish.app/api/health

# Run local development
npm run dev

# Run tests
npm test
npm run test:e2e
```

---

## Contact Information

### On-Call Rotation

| Role | Primary | Backup |
|------|---------|--------|
| Platform Engineer | [Name] | [Name] |
| Backend Engineer | [Name] | [Name] |
| Security Lead | [Name] | [Name] |

### Escalation Path

1. On-call engineer
2. Engineering Manager
3. CTO
4. CEO (SEV-1 only)

### External Contacts

| Service | Support URL | Phone |
|---------|-------------|-------|
| Vercel | support.vercel.com | - |
| Neon | neon.tech/docs/support | - |
| Clerk | clerk.com/support | - |
| Google Cloud | cloud.google.com/support | - |
| Microsoft Azure | azure.microsoft.com/support | - |

---

## Recovery Checklist

### Pre-Recovery

- [ ] Identify scope of incident
- [ ] Notify stakeholders
- [ ] Enable maintenance mode (if needed)
- [ ] Take current state backup

### During Recovery

- [ ] Follow relevant recovery procedure
- [ ] Document all actions taken
- [ ] Test each step before proceeding
- [ ] Keep stakeholders updated

### Post-Recovery

- [ ] Verify all services operational
- [ ] Run smoke tests
- [ ] Disable maintenance mode
- [ ] Notify stakeholders of resolution
- [ ] Schedule postmortem
- [ ] Update runbook if needed

---

*This document should be reviewed and updated quarterly.*
