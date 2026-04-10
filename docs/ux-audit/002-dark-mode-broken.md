# 002 - Dark Mode Broken Across App

**Severity:** P1
**Status:** Open
**Date Found:** 2026-04-10
**Affected Pages:** Settings, Quarantine, Policies, and all pages with card-based layouts

## Symptoms

Toggling dark mode (moon icon in top bar) causes text to become invisible or barely readable on most pages:

- **Settings page:** "Score Thresholds" heading, all slider labels, "AI Analysis" section heading, checkbox label, input label and value — all invisible (dark text on dark background)
- **Quarantine page:** Stat card labels ("Quarantined", "Released", etc.) nearly invisible, "Threats" heading and empty state text barely visible
- **Dashboard overview:** Does NOT switch to dark at all — stat cards, threat list, integrations panel all stay light

## Root Cause

Card/content backgrounds don't switch to dark variants. Text color changes but container backgrounds remain white/light, creating contrast failures. Some pages (dashboard overview) don't respond to the theme toggle at all.

## Impact

Dark mode is unusable — a user who toggles it will immediately encounter unreadable content and likely assume the app is broken.

## Recommendation

Either fix dark mode consistently across all components, or remove the toggle until it's ready. A half-working dark mode is worse than no dark mode.
