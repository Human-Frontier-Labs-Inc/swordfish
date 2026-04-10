# 005 - Default Next.js 404 Page

**Severity:** P2
**Status:** Open
**Date Found:** 2026-04-10

## Symptoms

Navigating to a non-existent route (e.g., `/dashboard/nonexistent-page`) shows the default Next.js "404 | This page could not be found." page — plain black text on white background, no branding, no navigation.

## Recommendation

Create a branded 404 page with:
- SwordPhish logo and branding
- "Back to Dashboard" link
- Sidebar navigation (if within the dashboard layout)
