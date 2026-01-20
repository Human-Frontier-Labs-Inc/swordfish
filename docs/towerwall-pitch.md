# SwordPhish Introduction for Towerwall

## Subject Line:
"Building email security for SMBs - would love your team's feedback"

---

## The Email

Hi [CEO Name],

We're building an email security platform called **SwordPhish** for the SMB/mid-market space, and I'd really value your team's feedback.

### What we're working on

We're trying to solve a problem we kept seeing: organizations with 25-2,000 seats need email protection, but Barracuda/Proofpoint are expensive and over-engineered for their needs. More importantly, when these tools block email, they give cryptic technical explanations that non-security IT folks can't explain to their users.

So we're building something that:
- Integrates via SMTP gateway + Microsoft 365 + Gmail APIs
- Detects phishing, impersonation, BEC, malicious attachments, and URLs
- Actually explains *why* an email was blocked in plain English
- Can be set up in under 10 minutes without vendor hand-holding

We're also building for MSPs who manage multiple clients - single login, bulk operations, policy templates, etc.

### Why I'm reaching out

We're in active testing right now (whitelist-only access while we work out the kinks), and honestly, **we need reality checks from people who actually know security**.

Your team at Towerwall would be perfect for this because:
1. You understand the space way better than we do
2. You'd spot issues or gaps we've missed
3. Your perspective on what MSPs and SMBs actually need would be invaluable

### The ask

Would you or 2-5 people on your team be willing to test SwordPhish with your real email for a few weeks?

I can whitelist your addresses, and you'd have full access to the platform. No meetings required unless you want them. Just use it, break it, tell us what's wrong or what's missing.

If it turns out there's a partnership opportunity down the line, great. But right now I'm genuinely just looking for feedback from people who know what they're doing.

### What you'd be testing

- Admin dashboard for threat review
- Live email analysis and verdict explanations
- Quarantine management
- Policy configuration (allowlists, blocklists, rules)
- Integration with O365 or Gmail
- Detection accuracy on real-world phishing attempts

Setup takes about 10 minutes. I can send you docs or hop on a quick call if you prefer.

Interested in taking a look?

Thanks for considering,
[Your Name]

P.S. If you want technical details first - we have architecture docs showing the detection pipeline, data flow, etc. Happy to share.

---

## Alternative: LinkedIn DM Version

Hi [CEO Name],

We're building **SwordPhish** - email security for SMBs who find Barracuda too expensive and complicated.

Main idea: detect threats (phishing, BEC, malicious attachments/URLs) but explain blocks in plain English so non-security IT can actually understand them.

We're testing with whitelisted users right now and **need feedback from people who actually know this space**.

Would you or your team be interested in trying it out? Takes ~10 min to set up, just whitelist your emails and use it normally.

Totally fine if not - just thought your perspective would be valuable.

[Your Name]

---

## Technical Deep-Dive Attachment (Optional)

If they want more technical details, you can share:
- `/docs/ARCHITECTURE.md` - Full system design
- `/docs/TECHNICAL_RECOMMENDATIONS.md` - Detection approach
- `/docs/initialthoughts.md` - PRD with competitive analysis

## If They Ask Questions

**"What stage are you at?"**
- Active testing phase with whitelisted users
- Working platform with all core features
- Refining based on real-world feedback before wider launch
- Honest answer: we're ironing out the rough edges

**"Why do you need our feedback specifically?"**
- You understand security better than we do
- You know what MSPs and SMBs actually struggle with
- We need reality checks from practitioners, not just our own assumptions
- Frankly, we'd rather find problems now with your help than after launch

**"What about partnerships?"**
- Open to it if it makes sense for both sides
- But right now, genuinely focused on building something good
- Would love to hear your thoughts if you see fit after trying it

**"How's it different from [competitor]?"**
- Honestly trying to be humble here - we think our explainability approach is better
- Detection pipeline is pretty standard (deterministic → ML → LLM when needed)
- Main thing: we're optimizing for SMB IT admins who aren't security experts
- Built for MSPs from day one (not bolted on later)

## Follow-Up Strategy

**If yes:**
1. Whitelist emails same day
2. Send simple onboarding doc (or offer quick call if preferred)
3. Give them space - check in after 1 week to see if they have questions
4. Ask for honest feedback after 2-3 weeks of use

**If interested but busy:**
1. "Totally understand - want me to check back in a few weeks?"
2. Don't push
3. Maybe send one update if something significant changes

**If no response:**
1. One gentle follow-up after 5-7 days
2. Then drop it - respect their time
3. Keep door open: "Feel free to reach out if you're ever curious"

---

## Tone Guidelines

**Do:**
- Be humble about what you don't know
- Ask for help/feedback genuinely
- Acknowledge their expertise
- Make it easy to say no
- Be specific about what you're building

**Don't:**
- Oversell features
- Make big claims about disrupting markets
- Push partnership agenda too early
- Use excessive exclamation points
- Hide that you're still in testing

**Remember:** You're asking security experts for help building something. That's the relationship. Partnership can come later if it makes sense.
