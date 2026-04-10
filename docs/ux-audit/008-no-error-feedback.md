# 008 - No Error Feedback on API Failures

**Severity:** P2
**Status:** Open
**Date Found:** 2026-04-10
**Affected Pages:** Onboarding, potentially others

## Symptoms

When the onboarding completion API fails (500 error), the "Go to Dashboard" button appears to do nothing — no error toast, no error message, no loading state change. The user has no idea something went wrong.

## Recommendation

- Show a toast/notification on API errors
- Add loading state to the button while the request is in flight
- Apply this pattern consistently across all forms and actions
