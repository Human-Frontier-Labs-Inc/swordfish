# SwordPhish UX Audit

**Date:** 2026-04-10
**Auditor:** Claude (automated via Puppeteer MCP)
**Test Account:** claudetestguy@gmail.com
**Target:** https://swordfish-eight.vercel.app
**Viewports:** Desktop (1280px), Tablet (768px), Mobile (375px)

## Scope

Full UX audit covering:
- Onboarding flow (6 steps)
- Main dashboard
- Threat detection / inbox views
- Settings & billing
- Navigation & global UX
- Responsive behavior across 3 viewports

## Severity Levels

| Level | Meaning |
|-------|---------|
| P0 | Broken — blocks user flow, data loss, or security issue |
| P1 | Glitchy — works but feels rough, confusing, or unreliable |
| P2 | Polish — cosmetic, copy, spacing, consistency issues |

## Summary

| Severity | Count |
|----------|-------|
| P0 | 2 (both fixed) |
| P1 | 3 |
| P2 | 5 |

## Findings Index

### P0 — Broken
- [001 - Onboarding completion not persisting](./001-onboarding-completion-broken.md) **FIXED**
- [010 - Policy creation fails (UUID mismatch)](./010-policy-creation-fails.md) **FIXED**

### P1 — Glitchy
- [002 - Dark mode broken across app](./002-dark-mode-broken.md)
- [003 - Mobile sidebar overlapped by Clerk popover](./003-mobile-sidebar-overlap.md)
- [004 - Dashboard stat cards don't respond to dark mode](./004-dashboard-no-dark-mode.md)

### P2 — Polish
- [005 - Default Next.js 404 page, no branding](./005-generic-404.md)
- [006 - Stat card labels truncated on desktop](./006-stat-card-truncation.md)
- [007 - Onboarding "What's Next" items not clickable](./007-whats-next-not-links.md)
- [008 - No error feedback on API failures](./008-no-error-feedback.md)
- [009 - No billing/subscription page in navigation](./009-missing-billing-page.md)

## What Works Well

- **Onboarding flow** — Clean 6-step wizard, good responsive behavior, proper skip/back navigation
- **Dashboard overview** — Good information hierarchy, demo data helps new users understand the product
- **Empty states** — Every section has appropriate empty state messaging with guidance
- **Responsive layout** — Sidebar collapses properly, cards reflow, content remains accessible
- **Navigation** — Clear sidebar with icons, active states, search bar with Cmd+K shortcut
- **Threat cards** — Good use of color-coded badges (Blocked/Quarantined), signal tags, timestamps
- **Integration page** — Clear cards for each provider with connection actions
- **Reports page** — Good structure with Overview/Scheduled/Export tabs, policy effectiveness metrics
