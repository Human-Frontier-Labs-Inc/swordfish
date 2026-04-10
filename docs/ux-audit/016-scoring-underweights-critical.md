# 016 - Threat Scoring Underweights Critical Signals

**Severity:** P0
**Status:** Fixed
**Date Found:** 2026-04-10

## Symptoms

Emails with multiple critical malware/phishing signals scored below the suspicious threshold:

| Email | Critical Signals | Score | Verdict | Expected |
|-------|-----------------|-------|---------|----------|
| .exe attachment + DMARC fail | 6 critical | 47 | pass | block |
| Credential harvest + lookalike domain | 4 critical | 70 | suspicious | block |

## Root Cause

`calculateFinalScore()` in `lib/detection/pipeline.ts` line 1205:
```typescript
const criticalBoost = Math.min(28, criticalSignals.length * 7);
```

- Critical boost capped at 28 points regardless of signal count
- Per-signal boost of only 7 points
- No distinction between threat types (malware vs auth failure)
- An email with 6 critical malware signals could only reach ~47

## Fix

1. Raised critical boost: 9 points each, capped at 54 (was 7/28)
2. Added threat floor: if 2+ high-severity signals (malware, BEC, phishing, credential theft) fire, minimum score is 75 (quarantine). If 1+ fires, minimum is 55 (suspicious).
3. High-severity types: ml_malware_detected, executable, dangerous_attachment, bec_compound_attack, bec_detected, ml_phishing_detected, credential_request

## Impact

Without this fix, real malware and credential harvesting emails could reach user inboxes undetected despite the detection engine correctly identifying the threats.
