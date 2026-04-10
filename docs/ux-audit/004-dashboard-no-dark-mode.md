# 004 - Dashboard Stat Cards Don't Respond to Dark Mode

**Severity:** P1
**Status:** Open
**Date Found:** 2026-04-10
**Affected Pages:** Dashboard overview

## Symptoms

The main dashboard overview page appears identical in light and dark mode. Stat cards, threat list, integrations panel, and demo mode banner all remain light-themed regardless of the dark mode toggle state.

## Root Cause

Dashboard components likely use hardcoded light colors (e.g., `bg-white`, `text-gray-900`) instead of Tailwind dark variants (`dark:bg-gray-800`, `dark:text-white`).

## Impact

Creates an inconsistent experience — the sidebar switches to dark but the main content doesn't, making the app feel half-finished.
