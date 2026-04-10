# 003 - Mobile Sidebar Overlapped by Clerk Popover

**Severity:** P1
**Status:** Open
**Date Found:** 2026-04-10
**Affected Viewport:** Mobile (375px)

## Symptoms

On mobile, tapping the user avatar opens the Clerk user popover, which overlaps the top portion of the mobile sidebar navigation. The top nav items (Overview, Emails, Threats) are hidden behind the popover. The popover is also sticky — difficult to dismiss.

## Root Cause

Z-index conflict between Clerk's `<UserButton>` popover and the mobile sidebar drawer. Both compete for the same screen space when the sidebar is open.

## Impact

Users on mobile may not be able to access the top navigation items if they accidentally open the user menu first.

## Recommendation

- Increase sidebar drawer z-index above Clerk popover
- Or auto-close the Clerk popover when the hamburger menu is opened
- Or relocate the user avatar to inside the sidebar drawer on mobile
