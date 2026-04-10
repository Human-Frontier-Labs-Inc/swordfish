# 014 - Gmail OAuth Scopes Not Granted by Google

**Severity:** P0 (blocks core feature)
**Status:** Open — requires Google Cloud Console configuration
**Date Found:** 2026-04-10

## Symptoms

Gmail OAuth token exchange succeeds, but Google only grants:
- `openid`
- `https://www.googleapis.com/auth/userinfo.email`

The app requests but doesn't receive:
- `https://www.googleapis.com/auth/gmail.readonly`
- `https://www.googleapis.com/auth/gmail.modify`

Without these scopes, `getGmailUserProfile()` fails with "Failed to get Gmail profile" since it can't access the Gmail API.

## Root Cause

The code correctly requests Gmail scopes (lib/integrations/gmail.ts lines 113-117). The issue is in Google Cloud Console:

1. **OAuth consent screen** may not list Gmail scopes as requested permissions
2. **App may be in "testing" mode** — sensitive scopes (gmail.readonly/modify) require Google verification or adding test users
3. **Gmail API** may not be enabled in the Google Cloud project

## Fix Required (Google Cloud Console)

1. Go to https://console.cloud.google.com → APIs & Services → OAuth consent screen
2. Verify Gmail scopes are listed under "Scopes for your app"
3. Add `claudetestguy@gmail.com` as a test user if app is in testing mode
4. Enable the Gmail API under "APIs & Services → Enabled APIs"
