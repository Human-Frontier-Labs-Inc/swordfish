# Technical Recommendations

## Overview

This document covers key technical decisions for the Swordfish email security platform, including detection strategy, sandbox approach, compute providers, and third-party API selections.

---

## 1. Detection Strategy

### Goal
Minimize false positives (<0.1%) while maintaining high catch rate (>99.5%).

### Approach: Layered Detection with Gating

Each layer processes only what the previous layer couldn't definitively classify. This reduces costs and improves accuracy.

```
┌─────────────────────────────────────────────────────────────────┐
│                    DETECTION PIPELINE                           │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 1: Deterministic (100% of mail) - Zero false positives  │
│  ├── SPF/DKIM/DMARC validation                                  │
│  ├── Header anomaly detection                                   │
│  ├── Domain age/reputation (< 30 days = suspicious)             │
│  ├── Homoglyph detection (paypa1.com vs paypal.com)             │
│  ├── Known bad sender/domain blocklists                         │
│  └── QR code phishing detection                                 │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 2: Reputation APIs (Gated - ~40% of mail)                │
│  ├── IP reputation scoring                                      │
│  ├── URL reputation checking                                    │
│  ├── File hash reputation                                       │
│  └── Sender behavioral history                                  │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 3: ML Classification (Gated - ~20% of mail)              │
│  ├── Phishing/BEC text classifier                               │
│  ├── Sender anomaly detection                                   │
│  ├── Thread context analysis                                    │
│  └── Authorship analysis (writing style deviation)              │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 4: LLM Escalation (Gated - ≤5% of mail)                  │
│  ├── Intent interpretation for ambiguous cases                  │
│  ├── Human-readable explanation generation                      │
│  └── NEVER final decision maker - advisory only                 │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 5: Sandbox Detonation (Gated - attachments only)         │
│  ├── Static analysis first (cheap)                              │
│  ├── Dynamic execution for unknowns                             │
│  └── Verdict caching by hash                                    │
└─────────────────────────────────────────────────────────────────┘
```

### Layer Details

#### Layer 1: Deterministic Rules (100% of mail)
**Cost**: Negligible (CPU only)
**Latency**: <50ms
**False Positive Rate**: 0%

| Check | Description | Action on Fail |
|-------|-------------|----------------|
| SPF | Sender Policy Framework validation | +20 score |
| DKIM | DomainKeys signature validation | +20 score |
| DMARC | Domain alignment check | +30 score |
| Domain Age | Flag domains < 30 days old | +25 score |
| Homoglyphs | Detect lookalike characters (рaypal vs paypal) | +40 score |
| From/Reply-To | Mismatch detection | +15 score |
| Display Name | Executive name spoofing | +35 score |
| Known Bad | Blocklist match | Block immediately |

#### Layer 2: Reputation APIs (Gated)
**Cost**: ~$0.001 per lookup
**Latency**: <200ms
**Trigger**: Deterministic score 30-70

| API | Purpose | Provider |
|-----|---------|----------|
| IP Reputation | Known bad senders | AbuseIPDB |
| URL Reputation | Malicious links | URLScan.io |
| File Hash | Known malware | VirusTotal |
| Domain Reputation | Phishing domains | Whoisology |

#### Layer 3: ML Classification (Gated)
**Cost**: ~$0.01 per inference
**Latency**: <100ms
**Trigger**: Reputation layer inconclusive

| Model | Purpose | Confidence Threshold |
|-------|---------|---------------------|
| Phishing Classifier | Text-based phishing detection | >90% to act |
| BEC Classifier | Business email compromise | >90% to act |
| Sender Anomaly | Unusual sender behavior | >85% to flag |
| Authorship | Writing style deviation | >80% to flag |

#### Layer 4: LLM Escalation (Gated)
**Cost**: ~$0.05 per invocation
**Latency**: <3s
**Trigger**: ML confidence 40-70%, requires explanation

**Rules**:
- LLM NEVER makes final decisions
- Used for intent interpretation and explanation generation
- Hard budget cap per tenant (default: 100/day)
- All invocations logged for audit

#### Layer 5: Sandbox Detonation (Attachments Only)
**Cost**: ~$0.50 per detonation
**Latency**: <3 minutes
**Trigger**: Unknown attachment hash, risky file type

**Process**:
1. Check hash against verdict cache
2. Run static analysis (cheap)
3. If suspicious, submit to sandbox
4. Extract IOCs from behavior
5. Cache verdict by hash

### Target Metrics

| Metric | Target | Industry Benchmark |
|--------|--------|-------------------|
| False Positive Rate | < 0.1% | 0.5-2% |
| False Negative Rate | < 0.5% | 1-3% |
| Mean Time to Detect | < 1 second (non-sandbox) | 2-5 seconds |
| Sandbox Verdict Time | < 3 minutes | 5-10 minutes |

### Feedback Loop

Continuous improvement through:
1. **User Reports**: "This is spam" / "This is not spam"
2. **Release Tracking**: Monitor released quarantine for incidents
3. **Threat Intel**: Correlate with external feeds
4. **Model Retraining**: Weekly batch retraining on new data

---

## 2. Sandbox Strategy

### Recommendation: Hybrid Approach

| Phase | Approach | Rationale |
|-------|----------|-----------|
| **V1 (MVP)** | Joe Sandbox Cloud API | Fastest to market, multi-platform support |
| **V1.5** | Add Hybrid Analysis | Free secondary opinion, reduces vendor lock-in |
| **V2** | Custom Firecracker | Long-term cost reduction, full control |

### V1: Joe Sandbox Cloud API

**Why Joe Sandbox**:
- Multi-platform: Windows, Linux, macOS, Android, iOS
- Enterprise-grade: Used by government agencies
- API-ready: SOAR/SIEM integration
- Detailed IOC extraction

**Pricing**:
- Cloud Basic: Free (limited)
- Cloud Light: $5,000/year
- Cloud Pro: Contact sales (private analysis)

**Integration**:
```typescript
// Pseudocode for sandbox submission
async function submitToSandbox(file: Buffer, filename: string): Promise<SandboxVerdict> {
  // 1. Check hash cache first
  const hash = sha256(file);
  const cached = await verdictCache.get(hash);
  if (cached) return cached;

  // 2. Run static analysis
  const staticResult = await staticAnalysis(file, filename);
  if (staticResult.verdict === 'clean') {
    await verdictCache.set(hash, staticResult);
    return staticResult;
  }

  // 3. Submit to Joe Sandbox
  const submission = await joeSandbox.submit({
    file,
    filename,
    systems: ['windows10', 'windows11'],
    timeout: 120
  });

  // 4. Poll for results
  const result = await joeSandbox.waitForResult(submission.id, { maxWait: 180000 });

  // 5. Extract IOCs and cache
  const verdict = {
    hash,
    verdict: result.malicious ? 'malicious' : 'clean',
    confidence: result.score / 100,
    iocs: extractIOCs(result),
    report_url: result.report_url
  };

  await verdictCache.set(hash, verdict, { ttl: '7d' });
  return verdict;
}
```

### V1.5: Add Hybrid Analysis

**Why Add It**:
- Free (CrowdStrike offering)
- Second opinion reduces false negatives
- Different detection techniques

**Integration**: Run in parallel with Joe Sandbox, combine verdicts

### V2: Custom Firecracker Sandbox

**Why Build Custom**:
- Cost reduction at scale (>10,000 mailboxes)
- Full control over analysis environment
- No third-party data sharing
- Hash caching makes 80%+ of requests free

**Architecture**:
```
┌─────────────────────────────────────────────────────────────────┐
│                    SANDBOX CLUSTER                              │
│                   (Hetzner Dedicated)                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Sandbox    │  │  Firecracker│  │   Network   │             │
│  │  Orchestrator│  │   Pool      │  │   Capture   │             │
│  │             │  │             │  │             │             │
│  │  Job queue  │  │  microVMs   │  │  tcpdump    │             │
│  │  Scheduling │  │  Win/Linux  │  │  DNS logs   │             │
│  │  Results    │  │  Ephemeral  │  │  HTTP logs  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

**Specs**:
- Firecracker microVMs (AWS open-source)
- 30-second max execution time
- Ephemeral disk, destroyed after each run
- Network capture for IOC extraction
- Isolated network segment (no egress to internet)

---

## 3. Compute Provider Selection

### Recommendation: Multi-Provider Strategy

| Component | Provider | Rationale |
|-----------|----------|-----------|
| **Edge** | Cloudflare | Best-in-class Workers, R2, WAF |
| **Core Compute** | Hetzner | Best price/performance in EU |
| **US Presence** | Vultr | 32 regions, low latency for US customers |
| **Database** | Neon | Serverless Postgres, SOC 2 |
| **Cache** | Upstash | Serverless Redis, global edge |
| **Queue** | Upstash | Serverless Kafka |
| **Sandbox** | Hetzner Dedicated | Bare metal for Firecracker |

### Why Hetzner for Core Compute

| Factor | Hetzner | DigitalOcean | Vultr |
|--------|---------|--------------|-------|
| Price (4 vCPU, 8GB) | ~$15/mo | ~$48/mo | ~$40/mo |
| Network | 20TB included | 4TB included | 3TB included |
| EU Presence | Excellent | Good | Good |
| US Presence | Limited | Good | Excellent |
| Bare Metal | Yes | No | Yes |

**Decision**: Hetzner for EU/core + Vultr for US edge if needed

### Why Neon for Database

| Factor | Neon | PlanetScale | Supabase |
|--------|------|-------------|----------|
| Serverless | Yes | Yes | Partial |
| SOC 2 | Yes | Yes | Yes |
| Postgres | Yes | No (MySQL) | Yes |
| Branching | Yes | Yes | No |
| Price (10GB) | ~$69/mo | ~$39/mo | ~$25/mo |

**Decision**: Neon for true serverless Postgres with branching for dev/staging

### Cost Estimate

**For 1,000 mailboxes**:

| Service | Monthly Cost |
|---------|-------------|
| Hetzner k3s (3x CX32) | $45 |
| Cloudflare Pro + Workers | $25 |
| Neon Postgres (Scale) | $69 |
| Upstash Redis (Pro) | $20 |
| Upstash Kafka (Standard) | $40 |
| Joe Sandbox API | $400 |
| Reputation APIs | $100 |
| **Total** | ~$700/mo |
| **Per Mailbox** | $0.70 |

**At 10,000 mailboxes**:
- Cost drops to ~$0.40/mailbox with custom sandbox
- Compute scales more efficiently

---

## 4. Third-Party API Selection

### Reputation & Threat Intel

| Category | Primary | Backup | Cost |
|----------|---------|--------|------|
| **Domain Reputation** | Whoisology | DomainTools | $99/mo |
| **IP Reputation** | AbuseIPDB | Spamhaus | Free tier + $50/mo |
| **URL Scanning** | URLScan.io | VirusTotal | Free tier + $100/mo |
| **File Hash** | VirusTotal | MalwareBazaar | Free tier |
| **Threat Intel** | Abuse.ch | PhishTank | Free |

### Why These Choices

**AbuseIPDB** (IP Reputation):
- Free tier: 1,000 checks/day
- Community-driven abuse reports
- Fast API response

**URLScan.io** (URL Scanning):
- Free tier: 50 scans/day
- Full page screenshots
- JavaScript analysis
- Redirect following

**Whoisology** (Domain Reputation):
- Domain age lookup
- Registration patterns
- Registrant history

**VirusTotal** (File Hash):
- 70+ AV engines
- Massive hash database
- Free tier for lookups

### Integration Pattern

```typescript
interface ReputationResult {
  source: string;
  score: number;  // 0-100
  malicious: boolean;
  details: string;
  cached: boolean;
}

async function checkReputation(
  type: 'ip' | 'url' | 'domain' | 'hash',
  value: string
): Promise<ReputationResult[]> {
  // Check cache first
  const cacheKey = `${type}:${value}`;
  const cached = await cache.get(cacheKey);
  if (cached) return cached;

  // Query multiple sources in parallel
  const results = await Promise.allSettled([
    queryPrimary(type, value),
    queryBackup(type, value)
  ]);

  // Combine and cache results
  const combined = combineResults(results);
  await cache.set(cacheKey, combined, { ttl: '1h' });

  return combined;
}
```

---

## 5. ML Model Strategy

### Starting Point

Use pre-trained models, fine-tune on customer data:

| Model | Source | Purpose |
|-------|--------|---------|
| Phishing Classifier | Hugging Face | Text-based phishing detection |
| Spam Classifier | SpamAssassin rules + custom | Spam vs. ham |
| BEC Classifier | Custom trained | Business email compromise |

### Training Data Sources

1. **Public Datasets**:
   - Nazario phishing corpus
   - APWG phishing feeds
   - Enron email dataset (legitimate baseline)

2. **Customer Feedback**:
   - False positive reports
   - False negative reports
   - Quarantine release patterns

3. **Threat Intel**:
   - Abuse.ch feeds
   - PhishTank submissions
   - Internal honeypots

### Deployment

**V1**: Cloudflare Workers AI
- Edge inference for low latency
- Simple deployment
- Pay-per-inference

**V2**: Self-hosted on Hetzner GPU
- Lower cost at scale
- Full model control
- Custom fine-tuning

---

## 6. LLM Integration

### Provider: Claude API (Anthropic)

**Why Claude**:
- Strong instruction following
- Good at structured output
- Competitive pricing
- Lower hallucination rate

### Use Cases

1. **Explanation Generation**: Convert technical signals to human-readable text
2. **Intent Analysis**: Determine email purpose when ML is uncertain
3. **False Positive Analysis**: Review user-reported false positives

### Constraints

- Never final decision maker
- Budget cap per tenant (default: 100/day, $5/day)
- All invocations logged
- Structured output required

### Prompt Template

```
You are an email security analyst. Analyze this email and provide:
1. A threat assessment (safe/suspicious/malicious)
2. A confidence score (0-100)
3. A 2-sentence explanation suitable for a non-technical IT admin

Email details:
- From: {from}
- Subject: {subject}
- Body preview: {body_preview}
- Technical signals: {signals}

Respond in JSON format:
{
  "assessment": "safe|suspicious|malicious",
  "confidence": 0-100,
  "explanation": "string"
}
```

---

## Sources

- [Check Point - AI Phishing Detection Tools 2025](https://www.checkpoint.com/cyber-hub/tools-vendors/top-5-aipowered-phishing-detection-tools-for-2025/)
- [CSA - Email Security Metrics](https://cloudsecurityalliance.org/blog/2025/07/15/7-email-security-metrics-that-matter-how-to-measure-and-improve-your-protection)
- [Joe Sandbox](https://www.joesecurity.org/)
- [SOCRadar - Malware Analysis Tools](https://socradar.io/top-10-malware-analysis-platforms-and-tools/)
- [Hetzner vs Alternatives](https://dev.to/alakkadshaw/hetzner-alternatives-for-2025-digitalocean-linode-vultr-ovhcloud-5936)
- [ServerAvatar - Cloud Comparison](https://serveravatar.com/vultr-vs-digitalocean-vs-linode-vs-hetzner/)
