# Swordfish v1 Documentation

## Overview

This directory contains comprehensive documentation for building Swordfish from its current state (28/100) to an enterprise-grade email security platform (80/100).

## Documents

### [ARCHITECTURE.md](./ARCHITECTURE.md)
Complete system architecture including:
- System overview and design principles
- Component architecture (6-layer detection pipeline)
- API design with REST endpoints
- Data architecture and database schema
- Security architecture and threat model
- Deployment architecture options
- Scalability considerations

### [USER_PERSONAS.md](./USER_PERSONAS.md)
Detailed user personas including:
- **Sarah Chen** - IT Administrator (SMB) - Primary persona
- **Marcus Thompson** - SOC Analyst (Enterprise)
- **Jennifer Walsh** - MSP Security Manager
- **David Park** - Compliance Officer
- **Alex Rivera** - End User (Knowledge Worker)
- Jobs To Be Done (JTBD) for each persona
- Persona-feature mapping matrix

### [USER_STORIES.md](./USER_STORIES.md)
Comprehensive user stories organized by epic:
- **Epic 1**: Real-Time Email Protection (US-001 to US-010)
- **Epic 2**: Dashboard and Visibility (US-011 to US-016)
- **Epic 3**: Policy Management (US-017 to US-019)
- **Epic 4**: Multi-Tenant / MSP (US-020 to US-022)
- **Epic 5**: Integration and API (US-023 to US-025)
- **Epic 6**: User Experience (US-026 to US-027)
- Each story includes acceptance criteria and TDD requirements

### [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md)
Phase-based implementation plan with TDD methodology:
- **Phase 1**: Foundation (28 → 40) - Fix cron, timeouts, schema
- **Phase 2**: Real-Time (40 → 50) - Webhooks, quarantine
- **Phase 3**: Intelligence (50 → 58) - Threat feeds
- **Phase 4**: Detection (58 → 65) - BEC, ML enhancement
- **Phase 5**: Actions (65 → 70) - Banners, link rewriting
- **Phase 6**: MSP (70 → 75) - Multi-tenant support
- **Phase 7**: Integration (75 → 78) - API, SIEM
- **Phase 8**: Operations (78 → 80) - SOC dashboard, polish

## Quick Reference

### Current State: 28/100

**What Works:**
- OAuth connection to Gmail/O365
- Detection pipeline code (5 layers)
- Basic dashboard UI
- Policy engine structure

**What's Broken:**
- Cron job is stubbed (no actual sync)
- Vercel 30s timeout limits processing
- Priority type mismatch in database
- No real-time webhook monitoring

### Target State: 80/100

**Key Capabilities:**
- Real-time email protection (< 5s latency)
- Multi-layer detection with threat intelligence
- Automatic quarantine and remediation
- MSP/multi-tenant support
- SIEM integration (Splunk)
- SOC-ready dashboard

### Score Breakdown

| Score Range | Description |
|-------------|-------------|
| 0-30 | Prototype/POC |
| 30-50 | Basic functionality, not production ready |
| **50** | **Barracuda parity** - basic email security |
| 50-70 | Enhanced detection, most features |
| 70-80 | Enterprise-grade, full feature set |
| 80-90 | Industry leader capabilities |
| 90-100 | Best-in-class, innovative features |

## Implementation Timeline

```
Week 1-2:   Phase 1 - Foundation      (28 → 40)
Week 3-4:   Phase 2 - Real-Time       (40 → 50) ← Barracuda parity
Week 5-6:   Phase 3 - Intelligence    (50 → 58)
Week 7-8:   Phase 4 - Detection       (58 → 65)
Week 9-10:  Phase 5 - Actions         (65 → 70)
Week 11-12: Phase 6 - MSP             (70 → 75)
Week 13-14: Phase 7 - Integration     (75 → 78)
Week 15-16: Phase 8 - Operations      (78 → 80) ← Target
```

## TDD Approach

Every phase follows Test-Driven Development:

1. **Write failing E2E test** (Playwright)
2. **Write failing unit tests** (Vitest)
3. **Implement minimum code** to pass
4. **Refactor** while keeping tests green
5. **Document** new behavior

### Test Commands

```bash
# Run unit tests
npm run test:unit

# Run E2E tests
npm run test:e2e

# Run all tests
npm run test

# Check coverage
npm run test:coverage
```

## Key Files

### Detection Pipeline
- `lib/detection/pipeline.ts` - Main orchestration
- `lib/detection/layers/*.ts` - Each detection layer
- `lib/detection/types.ts` - Type definitions

### Integrations
- `lib/integrations/gmail.ts` - Gmail API
- `lib/integrations/o365.ts` - Microsoft Graph API
- `lib/workers/email-sync.ts` - Background sync worker

### Policies
- `lib/policies/engine.ts` - Policy evaluation
- `lib/policies/types.ts` - Policy types
- `app/api/policies/route.ts` - Policy API

### Dashboard
- `app/dashboard/page.tsx` - Main dashboard
- `app/dashboard/threats/page.tsx` - Threats view
- `app/dashboard/integrations/page.tsx` - Integrations

## Getting Started

1. **Read the architecture** to understand system design
2. **Review personas** to understand who we're building for
3. **Check user stories** for specific requirements
4. **Follow implementation plan** for phase-by-phase execution

## Contributing

When adding features:

1. Identify which phase/story it belongs to
2. Write tests first (TDD)
3. Update documentation if needed
4. Ensure all tests pass before merging

## Support

For questions about this documentation:
- Check existing docs first
- Review code comments
- Ask in team channel
