# 015 - Dark Mode Remaining Gaps

**Severity:** P2 (downgraded from P1 — core fix landed, remaining is polish)
**Status:** Open — address during aesthetics pass
**Date Found:** 2026-04-10

## What was fixed

- Root cause: Tailwind v4 `@custom-variant dark` directive was missing, so ALL `dark:` prefixes were ignored
- Settings page: all cards, inputs, labels, headings got explicit `dark:` variants
- Command palette: full dark mode support
- globals.css: dark border override for shadcn/ui components

## What still needs dark: variants

Pages/components with hardcoded light backgrounds that don't respond to dark mode:
- Dashboard stat cards (inner card backgrounds)
- Email list items
- Threat list items / detail view
- Quarantine stat cards and list
- Policies page cards
- Integrations page cards
- Reports page cards and metrics
- Various form inputs across non-settings pages

## Recommended approach

Do a single aesthetic pass across all `app/dashboard/` pages and `components/dashboard/` to add `dark:` variants. Pattern: find every `bg-white` and add `dark:bg-slate-800`, every `text-gray-*` without a `dark:` and add the appropriate slate variant.
