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

## Findings Index

- [001 - Onboarding completion not persisting](./001-onboarding-completion-broken.md)
