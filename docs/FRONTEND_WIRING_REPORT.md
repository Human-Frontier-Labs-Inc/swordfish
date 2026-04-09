# Swordfish Frontend Wiring Report

**Date**: 2026-01-16
**Status**: FIXED - Data Flow Now Complete

---

## Executive Summary

The issue where Threats/Quarantine pages showed 0 items while the Emails page showed quarantined items has been **FIXED**. The root cause was that the `autoRemediate` function in the detection pipeline was not writing to the `threats` table.

### Key Finding

The system has TWO separate database tables for email data:

| Table | Purpose | Used By |
|-------|---------|---------|
| `email_verdicts` | All scanned emails with analysis results | Emails page, Dashboard stats |
| `threats` | Quarantined/blocked threats for remediation | Threats page, Quarantine page |

**The Fix**: `autoRemediate()` in `lib/workers/remediation.ts` now writes to both:
1. Moves email in mailbox (quarantine folder or delete)
2. Inserts/updates record in `threats` table

---

## Complete Data Flow

### Email Detection Pipeline

```
Email arrives → Sync fetched from provider (Gmail/O365)
     ↓
analyzeEmail() in lib/detection/pipeline.ts
     ↓
storeVerdict() → INSERT into `email_verdicts` table
     ↓
If verdict = 'quarantine' or 'block':
     ↓
autoRemediate() → Move email in mailbox
     ↓
[NEW FIX] → INSERT into `threats` table
```

### Frontend Page → API → Database Mapping

| Page | API Endpoint | Database Table | Status |
|------|-------------|----------------|--------|
| `/dashboard/emails` | `/api/dashboard/emails` | `email_verdicts` | ✅ Working |
| `/dashboard/threats` | `/api/threats` | `threats` | ✅ Fixed |
| `/dashboard/quarantine` | `/api/threats?status=...` | `threats` | ✅ Fixed |
| `/dashboard/threats/[id]` | `/api/threats/[id]` | `threats` + `email_verdicts` | ✅ Working |
| `/dashboard` (main) | `/api/stats` | Both tables | ✅ Working |
| `/dashboard/integrations` | `/api/integrations` | `integrations` | ✅ Working |
| `/dashboard/analytics` | `/api/analytics/overview` | `email_verdicts` | ✅ Working |

---

## Page-by-Page Wiring Details

### 1. Dashboard Main (`/dashboard/page.tsx`)

**Calls**: Uses React components that call `/api/stats`

**Stats API Returns**:
- `summary`: totalEmails, passedEmails, threatsDetected, quarantined, blocked
- `timeline`: Daily email counts
- `topThreats`: Most common threat types
- `quarantine`: threatStats from `threats` table

**Data Sources**:
- `getVerdictStats()` → `email_verdicts` table
- `getThreatStats()` → `threats` table

### 2. Emails Page (`/dashboard/emails/page.tsx`)

**Calls**: `GET /api/dashboard/emails?limit=50&verdict=quarantine`

**API Response**:
```typescript
{
  emails: Array<{
    id, messageId, subject, from, to, receivedAt,
    verdict, score, confidence, signals, signalCount,
    primarySignal, processingTimeMs, scannedAt
  }>,
  total: number,
  limit: number,
  offset: number
}
```

**Database**: `email_verdicts` table

**Status**: ✅ Always worked - shows all scanned emails

### 3. Threats Page (`/dashboard/threats/page.tsx`)

**Calls**: `GET /api/threats?stats=true`

**API Response**:
```typescript
{
  threats: ThreatRecord[],
  stats: { quarantinedCount, releasedCount, ... },
  pagination: { limit, offset, hasMore }
}
```

**Database**: `threats` table via `getQuarantinedThreats()`

**Status**: ✅ Fixed - now populated by `autoRemediate()`

### 4. Quarantine Page (`/dashboard/quarantine/page.tsx`)

**Calls**: `GET /api/threats?status=quarantined&stats=true`

**Actions**:
- Release: `POST /api/quarantine/[id]/release` → `releaseEmail()`
- Delete: `DELETE /api/quarantine/[id]` → `deleteEmail()`

**Database**: `threats` table

**Status**: ✅ Fixed - shares same backend as Threats page

### 5. Threat Detail Page (`/dashboard/threats/[id]/page.tsx`)

**Calls**: `GET /api/threats/[id]`

**API Response**: Joins `threats` with `email_verdicts` for full details

**Actions**:
- Release: `POST /api/quarantine/[id]/release`
- Delete: `DELETE /api/threats/[id]`

**Status**: ✅ Working

### 6. Integrations Page (`/dashboard/integrations/page.tsx`)

**Calls**:
- `POST /api/integrations/sync-nango` - Auto-syncs on page load
- `GET /api/integrations` - Lists integrations
- `GET /api/integrations/[type]` - Gets OAuth URL
- `DELETE /api/integrations/[type]` - Disconnects
- `POST /api/sync` - Triggers email sync

**Database**: `integrations` table

**Status**: ✅ Working with Nango OAuth

---

## API Route → Service Function Mapping

### Threats/Quarantine APIs

| Route | HTTP | Function | File |
|-------|------|----------|------|
| `/api/threats` | GET | `getQuarantinedThreats()` | `lib/quarantine/service.ts` |
| `/api/threats/[id]` | GET | SQL query | Route file |
| `/api/threats/[id]` | DELETE | `deleteEmail()` | `lib/workers/remediation.ts` |
| `/api/threats/[id]/release` | POST | Uses `/api/quarantine/[id]/release` | - |
| `/api/quarantine/[id]/release` | POST | `releaseEmail()` | `lib/workers/remediation.ts` |
| `/api/quarantine/[id]` | DELETE | `deleteEmail()` | `lib/workers/remediation.ts` |

### Detection Pipeline APIs

| Route | HTTP | Function | Description |
|-------|------|----------|-------------|
| `/api/analyze` | POST | `analyzeEmail()` | Single email analysis |
| `/api/sync` | POST | `syncTenant()` | Trigger email sync |
| `/api/cron/sync-emails` | GET | `runFullSync()` | Scheduled sync |
| `/api/webhooks/nango` | POST | Handle connection events | Nango OAuth events |
| `/api/webhooks/o365` | POST | `processMicrosoftWebhook()` | Real-time O365 |
| `/api/webhooks/gmail` | POST | `processGmailWebhook()` | Real-time Gmail |

---

## Column Name Mappings

The `threats` table uses specific column names that differ from the TypeScript interface:

| Interface Field | Database Column | Notes |
|-----------------|-----------------|-------|
| `provider` | `integration_type` | Values: 'o365', 'gmail' |
| `providerMessageId` | `external_message_id` | Provider's message ID |
| `originalFolder` | `original_location` | Where email was before quarantine |

The `getQuarantinedThreats()` function correctly maps these at lines 371-373:
```typescript
provider: (t.integration_type === 'o365' ? 'microsoft' : t.integration_type === 'gmail' ? 'google' : 'smtp'),
providerMessageId: t.external_message_id,
```

---

## What Was Fixed

### Before (Broken)

```
autoRemediate() called:
  1. Move email to quarantine folder ✅
  2. Return success ✅
  3. [MISSING] Write to threats table ❌
```

### After (Fixed)

```typescript
// lib/workers/remediation.ts - autoRemediate()

// 1. Move email in mailbox
if (verdict === 'block') {
  await deleteEmail(nangoConnectionId, externalMessageId);
} else {
  await quarantineEmail(nangoConnectionId, externalMessageId);
}

// 2. Write to threats table [NEW FIX]
const existingThreats = await sql`
  SELECT id FROM threats WHERE tenant_id = ${tenantId} AND message_id = ${messageId}
`;

if (existingThreats.length > 0) {
  await sql`UPDATE threats SET status = ${status}, verdict = ${verdict}, ... `;
} else {
  await sql`
    INSERT INTO threats (
      tenant_id, message_id, subject, sender_email, recipient_email,
      verdict, score, status, integration_type, integration_id, external_message_id,
      signals, explanation, quarantined_at
    ) VALUES (...)
  `;
}
```

---

## Remaining Items

### To Populate Existing Data

Existing quarantined emails in `email_verdicts` need to be migrated to `threats` table. Run a one-time sync or trigger a rescan:

1. Go to `/dashboard/integrations`
2. Click "Sync Now" to re-process recent emails
3. New threats will be written to `threats` table

Alternatively, run this SQL migration:
```sql
INSERT INTO threats (
  tenant_id, message_id, subject, sender_email, recipient_email,
  verdict, score, status, signals, explanation, quarantined_at
)
SELECT
  tenant_id, message_id, subject, from_address, to_addresses->>0,
  verdict, score, 'quarantined', signals, explanation, created_at
FROM email_verdicts
WHERE verdict IN ('quarantine', 'block')
ON CONFLICT (tenant_id, message_id) DO NOTHING;
```

### Operational Setup

| Item | Status | Action Required |
|------|--------|-----------------|
| CRON_SECRET in Vercel | ❌ Not set | Set environment variable for auto-sync |
| Nango webhook URL | ❓ Check | Verify `https://swordfish-eight.vercel.app/api/webhooks/nango` is configured |

---

## Test Verification

To verify the fix is working:

1. **Trigger a new email scan**:
   - Go to Integrations page
   - Click "Sync Now"

2. **Check Emails page**:
   - Should show new emails with quarantine/block verdicts

3. **Check Threats page**:
   - Should now show the same quarantined emails

4. **Check Quarantine page**:
   - Should show emails with "Release" and "Delete" actions

5. **Test Release action**:
   - Click Release on a quarantined email
   - Verify it moves back to inbox in provider

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SWORDFISH DATA FLOW                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐    ┌──────────────────┐                      │
│  │    Gmail API     │    │  Microsoft Graph │                      │
│  └────────┬─────────┘    └────────┬─────────┘                      │
│           │                       │                                 │
│           └───────────┬───────────┘                                 │
│                       ▼                                             │
│           ┌───────────────────────┐                                │
│           │    Email Sync Worker   │                                │
│           │  lib/workers/email-sync│                                │
│           └───────────┬───────────┘                                │
│                       ▼                                             │
│           ┌───────────────────────┐                                │
│           │   Detection Pipeline   │                                │
│           │ lib/detection/pipeline │                                │
│           └───────────┬───────────┘                                │
│                       ▼                                             │
│           ┌───────────────────────┐                                │
│           │     storeVerdict()     │                                │
│           │ lib/detection/storage  │                                │
│           └───────────┬───────────┘                                │
│                       ▼                                             │
│         ┌─────────────────────────┐                                │
│         │   email_verdicts table   │◄────── /api/dashboard/emails  │
│         │  (All scanned emails)    │                                │
│         └─────────────────────────┘                                │
│                       │                                             │
│            if verdict = quarantine/block                            │
│                       ▼                                             │
│           ┌───────────────────────┐                                │
│           │    autoRemediate()     │                                │
│           │lib/workers/remediation │                                │
│           └───────────┬───────────┘                                │
│                       │                                             │
│          ┌────────────┼────────────┐                               │
│          ▼            ▼            ▼                               │
│  ┌──────────────┐ ┌────────┐ ┌───────────────┐                    │
│  │Move email in │ │ [NEW]  │ │threats table  │◄─ /api/threats     │
│  │provider      │ │Insert  │ │(Quarantined   │◄─ /api/quarantine  │
│  │(Gmail/O365)  │ │threat  │ │emails only)   │                    │
│  └──────────────┘ └────────┘ └───────────────┘                    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

FRONTEND PAGES:
  /dashboard/emails     → email_verdicts table (all emails)
  /dashboard/threats    → threats table (quarantined/blocked only)
  /dashboard/quarantine → threats table (quarantined status only)
```

---

## Conclusion

The frontend wiring is now complete. All pages should display correct data after the fix is deployed and emails are re-synced.

**Commit**: `e4acf79 fix: Write to threats table when auto-remediating emails`

**Deployed**: Pushed to main, Vercel auto-deploys
