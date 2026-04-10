# 017 - Detection Edge Case Test Results

**Date:** 2026-04-10
**Status:** Documented — improvements recommended

## Tests Performed

### Passed (correctly detected)
| Test | Score | Verdict | Notes |
|------|-------|---------|-------|
| Spear phishing (fake subdomain google-drive.acme-corp.com) | 86 | block | Caught lookalike domain |
| Double extension (.pdf.scr) | 93 | block | Caught executable disguise |
| Marketing email (flash sale, urgency) | 32 | pass | Correct — no false positive |

### Failed (missed threats)
| Test | Score | Verdict | Expected | Gap |
|------|-------|---------|----------|-----|
| URL shortener (bit.ly hiding payload) | 18 | pass | suspicious+ | Shortener only triggers warning, not escalated |
| Reply chain hijack (fake Re: Re: FW:) | 19 | pass | suspicious+ | No auth (spf/dkim/dmarc=none) + fabricated reply chain not detected |
| Whaling (fake board meeting, NDA pressure) | 48 | pass | block | 2 criticals (financial_request, secrecy_request) but neither in high-severity floor list |

## Recommended Improvements

1. **URL shorteners**: Escalate to at least suspicious when combined with other signals. Known shortener domains (bit.ly, tinyurl, t.co) + no prior communication = high risk.

2. **Reply chain analysis**: Detect fabricated reply chains — check if quoted "original messages" exist in the user's actual sent mail. Missing auth (spf=none, dkim=none) on a "reply" is a strong indicator.

3. **Whaling/secrecy signals**: Add `bec_secrecy_request` and `ml_financial_request` to the high-severity types list in the scoring floor. An email demanding secrecy + financial action is a hallmark BEC pattern.

4. **Auth-based escalation**: Emails with spf=none, dkim=none, dmarc=none that contain links or attachments should get a higher base score. Complete lack of authentication is itself a red flag.
