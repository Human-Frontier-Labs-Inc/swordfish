#!/usr/bin/env tsx
/**
 * Seed a starter labeled corpus for the detection eval.
 *
 * Writes RFC822 .eml files + .eml.label.json sidecars under <out>/ (default
 * tests/fixtures/corpus/) — the on-disk schema load-corpus.ts reads.
 *
 * This first seed is a small, balanced, fully-synthetic set so the eval
 * harness has real files to run end-to-end on without waiting on the external
 * SpamAssassin/Nazario fetch (task: corpus acquisition). The bulk volume
 * (public corpora + a larger hand-curated BEC pack, ~500 samples) lands later;
 * this is the starter.
 *
 * All content is SYNTHETIC — modeled on public BEC/phishing patterns (FBI IC3,
 * anti-phishing.org). No real PII, no copy from real correspondence. Domains
 * use reserved/example TLDs or obviously-fake names where possible.
 *
 * Usage: npx tsx scripts/corpus/seed-corpus.ts [--out tests/fixtures/corpus]
 */

import { mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';

type Label = 'safe' | 'spam' | 'phishing' | 'bec';

interface Seed {
  label: Label;
  category: string;
  fromName: string;
  fromEmail: string;
  replyTo?: string;
  to: string;
  subject: string;
  body: string;
  notes: string[];
}

const SEEDS: Seed[] = [
  // ───────── BEC: CEO impersonation ─────────
  {
    label: 'bec', category: 'ceo-impersonation',
    fromName: 'Robert Kane', fromEmail: 'rkane@kane-holdings-co.com',
    replyTo: 'rkane.urgent@outlook.com', to: 'finance@victmco.com',
    subject: 'Re: Q3 wire — need this handled before I land',
    body: "I'm tied up in back-to-backs all day and flying out shortly. I need you to process a wire for $48,500 to the details below before 2pm — I'll brief you on the why when I'm back. Keep this between us for now.\n\nBank: First Continental / Acct: 8841290 / Routing: 021000021\n\nDon't reply here, I'm off email — text me once it's queued.\n— Bob",
    notes: ['display_name_spoof', 'reply_to_mismatch', 'urgency', 'financial_request', 'vip_spoof', 'secrecy'],
  },
  {
    label: 'bec', category: 'ceo-impersonation',
    fromName: 'Diane Whitfield (CEO)', fromEmail: 'dwhitfield@wh1tfieldcorp.com',
    to: 'assistant@victmco.com',
    subject: 'Are you available? Need a quick favor',
    body: "I just stepped into a meeting and can't talk. Can you pick up $500 in Apple gift cards on the company card? I'll reimburse — it's for a client gift, time-sensitive. Send the codes once you have them. Thanks.",
    notes: ['display_name_spoof', 'lookalike_domain', 'urgency', 'gift_card', 'vip_spoof'],
  },

  // ───────── BEC: wire fraud ─────────
  {
    label: 'bec', category: 'wire-fraud',
    fromName: 'Acme Vendor AP', fromEmail: 'ap@acme-suppllers.com',
    to: 'accounts.payable@victmco.com',
    subject: 'URGENT: Updated banking details for upcoming wire',
    body: "Please note our bank details have changed effective immediately. For the invoice due this Friday, kindly remit to:\n\nBeneficiary: Acme Global / IBAN: GB29 NWBK 6016 1331 9268 19\n\nPlease confirm once the transfer is initiated. Do not use our previous account.\n\nRegards,\nAcme Accounts",
    notes: ['lookalike_domain', 'urgency', 'financial_request', 'bank_detail_change', 'reply_to_mismatch'],
  },
  {
    label: 'bec', category: 'wire-fraud',
    fromName: 'Legal - Coastal Title', fromEmail: 'closings@coasta1title.com',
    to: 'cfo@victmco.com',
    subject: 'Closing instructions changed — wire to new account today',
    body: "Our escrow account has been updated. For today's closing on the Riverside property, wire $312,000 to the new account below instead of the prior instructions.\n\nBank: Harbor Trust / Acct: 9920114 / Routing: 026013576\n\nTime-sensitive — closing is at 3pm.",
    notes: ['lookalike_domain', 'urgency', 'financial_request', 'bank_detail_change'],
  },

  // ───────── BEC: payroll diversion ─────────
  {
    label: 'bec', category: 'payroll-diversion',
    fromName: 'Karen Mendoza', fromEmail: 'kmendoza@victmco.com',
    replyTo: 'karen.mendoza.hr@protonmail.com', to: 'payroll@victmco.com',
    subject: 'Direct deposit update',
    body: "Hi, I'd like to update my direct deposit to a new account effective this pay period. Please route my full paycheck to:\n\nBank: Chase / Acct: 40991182 / Routing: 071000013\n\nThanks,\nKaren",
    notes: ['reply_to_mismatch', 'financial_request', 'payroll_diversion', 'display_name_spoof'],
  },
  {
    label: 'bec', category: 'payroll-diversion',
    fromName: 'James Liu', fromEmail: 'jliu@victmco.com',
    replyTo: 'james.liu.personal@gmx.com', to: 'hr@victmco.com',
    subject: 'Payroll change request',
    body: "Please update my banking info for payroll. New account:\n\nChase, Acct 7765402, Routing 021202337\n\nCan this take effect before payday Friday? Appreciate it.",
    notes: ['reply_to_mismatch', 'financial_request', 'payroll_diversion', 'urgency'],
  },

  // ───────── BEC: vendor change ─────────
  {
    label: 'bec', category: 'vendor-change',
    fromName: 'Pinnacle Logistics', fromEmail: 'billing@pinnac1e-logistics.net',
    to: 'ap@victmco.com',
    subject: 'Action required: new remittance address',
    body: "Due to a system migration, our remittance address has changed. Please update your records and send all future payments, including the open invoice #4419, to the address below.\n\nPay To: Pinnacle Freight LLC / Bank: Truist / Acct: 2200193\n\nConfirm receipt of this update.",
    notes: ['lookalike_domain', 'financial_request', 'bank_detail_change', 'urgency'],
  },

  // ───────── BEC: gift card ─────────
  {
    label: 'bec', category: 'gift-card',
    fromName: 'Susan Park (CFO)', fromEmail: 'spark@victmco.com',
    replyTo: 'susancfo@yandex.com', to: 'reception@victmco.com',
    subject: 'Quick task',
    body: "I need you to get $1,000 in Google Play gift cards for staff rewards — I'm in a board meeting and can't be reached by phone. Buy them and reply with the codes scratched off. Will expense. Go ahead now please.",
    notes: ['reply_to_mismatch', 'display_name_spoof', 'urgency', 'gift_card', 'vip_spoof', 'secrecy'],
  },
  {
    label: 'bec', category: 'gift-card',
    fromName: 'Mark Delgado', fromEmail: 'mdelgado@victmco.xyz',
    to: 'it@victmco.com',
    subject: 'Conference giveaway — need cards today',
    body: "I need 5x $100 Amazon gift cards for the booth giveaway today, can't leave the floor. Grab them and send codes — I'll sign off on the expense tonight. Thanks.",
    notes: ['lookalike_domain', 'urgency', 'gift_card'],
  },

  // ───────── phishing: credential / account ─────────
  {
    label: 'phishing', category: 'credential-phish',
    fromName: 'IT Helpdesk', fromEmail: 'no-reply@victmco-support.com',
    to: 'user@victmco.com',
    subject: 'Your password expires today — verify to avoid lockout',
    body: "Your mailbox password will expire in 24 hours. Verify your credentials to keep access: https://victmco-support.com/verify?id=8f2a\n\nFailure to verify results in account suspension.",
    notes: ['lookalike_domain', 'urgency', 'credential_harvest', 'suspicious_url'],
  },
  {
    label: 'phishing', category: 'credential-phish',
    fromName: 'Microsoft Team', fromEmail: 'alert@outlook-security.net',
    to: 'user@victmco.com',
    subject: 'Unusual sign-in activity',
    body: "We detected a sign-in to your account from a new device. If this wasn't you, secure your account: http://login-msft-verify.tk/auth\n\nMicrosoft Account Team",
    notes: ['suspicious_url', 'credential_harvest', 'lookalike_domain'],
  },

  // ───────── phishing: package / delivery ─────────
  {
    label: 'phishing', category: 'delivery-phish',
    fromName: 'FedEx', fromEmail: 'notification@fedex-shipment-update.com',
    to: 'user@victmco.com',
    subject: 'Your package is on hold — action required',
    body: "We attempted delivery and couldn't reach you. Confirm your address to reschedule: https://fedex-shipment-update.com/track?id=Z9K2\nA fee may apply.",
    notes: ['lookalike_domain', 'suspicious_url', 'urgency'],
  },

  // ───────── phishing: invoice / luring ─────────
  {
    label: 'phishing', category: 'invoice-phish',
    fromName: 'QuickBooks', fromEmail: 'invoices@quickb00ks.online',
    to: 'user@victmco.com',
    subject: 'Invoice #8821 overdue — view document',
    body: "Please review the attached invoice. Amount due: $4,290.00. Open document: https://quickbooks-docs.online/view?ref=8821\n\nAccounts Receivable",
    notes: ['lookalike_domain', 'suspicious_url'],
  },

  // ───────── spam: marketing-ish (unwanted but not malicious) ─────────
  {
    label: 'spam', category: 'marketing-spam',
    fromName: 'Mega Deals Daily', fromEmail: 'deals@megadealsdaily.biz',
    to: 'user@victmco.com',
    subject: '🔥 80% OFF everything — today only!',
    body: "Don't miss our biggest sale! Click now for 80% off storewide. Limited stock. Unsubscribe at the bottom (maybe).",
    notes: ['bulk_marketing', 'excessive_punctuation', 'unsubscribe_present'],
  },
  {
    label: 'spam', category: 'marketing-spam',
    fromName: 'Lotto Winners Club', fromEmail: 'win@lottoclub-promo.win',
    to: 'user@victmco.com',
    subject: 'CONGRATULATIONS!! You\'ve been selected to win $1,000,000',
    body: "You have been chosen as our monthly winner! Reply with your details to claim your $1,000,000 prize today. ACT NOW before it expires!!",
    notes: ['too_good_to_be_true', 'excessive_punctuation', 'urgency'],
  },

  // ───────── safe: legitimate corporate ham ─────────
  {
    label: 'safe', category: 'meeting',
    fromName: 'Priya Natarajan', fromEmail: 'priya.natarajan@victmco.com',
    to: 'team@victmco.com',
    subject: 'Agenda for Thursday\'s product review',
    body: "Hi team — sending the agenda for Thursday's product review ahead of time. We'll cover Q3 roadmap, the detection-engine metrics, and onboarding numbers. Let me know if anything else should be on there.\n\nThanks,\nPriya",
    notes: ['legitimate_internal', 'known_sender'],
  },
  {
    label: 'safe', category: 'receipt',
    fromName: 'Stripe', fromEmail: 'receipts@stripe.com',
    to: 'billing@victmco.com',
    subject: 'Your receipt from Swordfish — $290.00',
    body: "Thanks for your payment. Receipt for $290.00 (Swordfish, 10 mailboxes). View or download at https://dashboard.stripe.com/receipts. No action needed.",
    notes: ['legitimate_transactional', 'known_sender'],
  },
  {
    label: 'safe', category: 'newsletter',
    fromName: 'The Cloud Security Brief', fromEmail: 'brief@cloudsecurityweekly.com',
    to: 'user@victmco.com',
    subject: 'This week: zero-trust myths + a SOC2 roundup',
    body: "In this week's issue: three zero-trust myths that won't die, a SOC 2 Type II roundup, and reader Q&A. Read online or in your inbox.\n\nYou're receiving this because you subscribed. Unsubscribe anytime.",
    notes: ['legitimate_newsletter', 'unsubscribe_present', 'known_sender'],
  },
  {
    label: 'safe', category: 'colleague-reply',
    fromName: 'Tom Alvarez', fromEmail: 'tom.alvarez@victmco.com',
    to: 'user@victmco.com',
    subject: 'Re: lunch Wednesday?',
    body: "Wednesday works for me — noon at the usual place? I'll book.\n\nTom",
    notes: ['legitimate_internal', 'known_sender'],
  },
];

function eml(s: Seed, index: number): string {
  const date = `Tue, 0${1 + (index % 7)} Jun 2026 09:${10 + index}:0${index % 6} +0000`;
  const messageId = `<seed-${index}-${Date.now()}@swordfish-eval.local>`;
  const headers = [
    `From: "${s.fromName}" <${s.fromEmail}>`,
    `To: <${s.to}>`,
    s.replyTo ? `Reply-To: <${s.replyTo}>` : null,
    `Subject: ${s.subject}`,
    `Date: ${date}`,
    `Message-ID: ${messageId}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset=utf-8`,
  ].filter(Boolean);
  return `${headers.join('\n')}\n\n${s.body}\n`;
}

function labelJson(s: Seed): string {
  return JSON.stringify(
    { label: s.label, source: s.category, notes: s.notes },
    null,
    2
  );
}

async function main(): Promise<void> {
  const outArg = process.argv.indexOf('--out');
  const out = outArg >= 0 && process.argv[outArg + 1] ? process.argv[outArg + 1] : 'tests/fixtures/corpus';

  // Start clean so re-seeding is deterministic.
  await rm(out, { recursive: true, force: true });
  await mkdir(out, { recursive: true });

  const counts: Record<Label, number> = { safe: 0, spam: 0, phishing: 0, bec: 0 };
  for (let i = 0; i < SEEDS.length; i++) {
    const s = SEEDS[i];
    const dir = join(out, s.label, s.category);
    await mkdir(dir, { recursive: true });
    const id = `${s.label}-${s.category}-${String(i).padStart(3, '0')}`;
    await writeFile(join(dir, `${id}.eml`), eml(s, i), 'utf8');
    await writeFile(join(dir, `${id}.eml.label.json`), labelJson(s), 'utf8');
    counts[s.label]++;
  }

  process.stdout.write(`Seeded ${SEEDS.length} samples to ${out}\n`);
  process.stdout.write(JSON.stringify(counts, null, 2) + '\n');
}

main().catch((err) => {
  console.error('seed failed:', err);
  process.exit(1);
});
