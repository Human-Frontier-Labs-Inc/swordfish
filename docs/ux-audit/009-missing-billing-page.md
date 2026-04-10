# 009 - No Billing/Subscription Page in Navigation

**Severity:** P2
**Status:** Open
**Date Found:** 2026-04-10

## Symptoms

The sidebar shows "Starter Plan" under the tenant name, but there's no way to view or manage billing/subscription. No "Billing", "Subscription", or "Upgrade" link exists in the sidebar or settings page tabs.

The settings page has Detection, Notifications, Quarantine, Integrations, and Display tabs — but no Billing tab.

## Impact

Users on Starter Plan have no visible path to upgrade. Users who need to manage their subscription have no way to access Stripe billing portal.

## Recommendation

Add a Billing/Subscription section — either as a sidebar item or a tab in Settings — that links to the Stripe customer portal.
