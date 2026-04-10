# 011 - Search/Command Palette Has No Commands

**Severity:** P1
**Status:** Open
**Date Found:** 2026-04-10
**Affected Pages:** All (global search bar in header)

## Symptoms

The search bar shows "Search... Cmd+K" in the header. Clicking it or pressing Ctrl+K opens a command palette overlay with "Search commands..." placeholder. However:

- No results appear for any query ("threats", "settings", etc.)
- No default commands shown when the input is empty
- The palette is completely non-functional

## Impact

Prominent UI element that does nothing — gives the impression the app is unfinished. Users who try to search will be confused.

## Recommendation

Either:
1. Wire up the command palette with navigation commands (Go to Threats, Go to Settings, etc.) and entity search (search emails, policies)
2. Or remove the search bar and Cmd+K shortcut until it's implemented
