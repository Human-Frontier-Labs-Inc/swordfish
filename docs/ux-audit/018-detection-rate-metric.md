# 018 - Detection Rate Metric Misleading

**Severity:** P1
**Status:** Open
**Date Found:** 2026-04-10

## Symptoms

Dashboard shows "Detection Rate: 62.5%" which looks poor. Actual calculation: 5 blocked / 8 total = 62.5%. But all 5 actual threats WERE detected — the other 3 emails were legitimately safe.

## Problem

The metric calculates `threats_found / total_emails_scanned` — this isn't a detection rate, it's a **threat prevalence rate**. A real detection rate should be:

- **True detection rate** = threats correctly identified / total actual threats = 5/5 = 100%
- **False positive rate** = safe emails incorrectly flagged / total safe emails
- **Accuracy** = correctly classified / total = 7/8 = 87.5% (the "ping" test was borderline)

## Market Context

| Vendor | Detection Rate |
|--------|---------------|
| Proofpoint, Abnormal Security | 95-99%+ |
| Barracuda, Fortinet | 90-95% |
| Native M365/Google | 80-85% |
| **SwordPhish (actual)** | **100% of threats caught** |
| SwordPhish (displayed) | 62.5% (misleading metric) |

## Recommendation

1. **Rename or recalculate** — Show "Threat Rate" (% of emails that are threats) OR true detection accuracy
2. **Add better metrics** — True positive rate, false positive rate, precision, recall
3. **Consider showing**: "5 threats blocked out of 8 emails scanned" as plain text instead of a misleading percentage
4. **Industry comparison**: If pitching to customers, show catch rate (threats caught vs threats missed) not threat prevalence
