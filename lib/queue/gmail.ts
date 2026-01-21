/**
 * Gmail ingestion queue backed by Upstash Redis REST.
 * Uses a simple list-based queue to avoid extra dependencies.
 */

import { nanoid } from 'nanoid';

const UPSTASH_REDIS_REST_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_REDIS_REST_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const UPSTASH_QUEUE_NAME = process.env.UPSTASH_QUEUE_NAME || 'gmail-ingest';
const DEAD_LETTER_SUFFIX = 'dead';

export interface GmailQueueJob {
  id: string;
  tenantId: string;
  integrationId: string;
  emailAddress: string;
  historyId: string;
  attempts: number;
  enqueuedAt: string;
  lastError?: string;
}

function requireUpstashConfig(): { url: string; token: string } {
  if (!UPSTASH_REDIS_REST_URL || !UPSTASH_REDIS_REST_TOKEN) {
    throw new Error('Upstash Redis REST is not configured');
  }
  return {
    url: UPSTASH_REDIS_REST_URL.replace(/\/$/, ''),
    token: UPSTASH_REDIS_REST_TOKEN,
  };
}

export function isGmailQueueConfigured(): boolean {
  return !!(UPSTASH_REDIS_REST_URL && UPSTASH_REDIS_REST_TOKEN);
}

function buildUpstashUrl(command: string, ...args: string[]): string {
  const { url } = requireUpstashConfig();
  const encodedArgs = args.map(arg => encodeURIComponent(arg)).join('/');
  return `${url}/${command}/${encodedArgs}`;
}

async function upstashCommand<T>(command: string, ...args: string[]): Promise<T> {
  const { token } = requireUpstashConfig();
  const response = await fetch(buildUpstashUrl(command, ...args), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  const data = await response.json() as { result: T; error?: string };

  if (!response.ok || data.error) {
    throw new Error(data.error || `Upstash command failed: ${command}`);
  }

  return data.result;
}

function queueKey(): string {
  return UPSTASH_QUEUE_NAME;
}

function deadLetterKey(): string {
  return `${UPSTASH_QUEUE_NAME}:${DEAD_LETTER_SUFFIX}`;
}

export async function enqueueGmailJob(params: {
  tenantId: string;
  integrationId: string;
  emailAddress: string;
  historyId: string;
}): Promise<GmailQueueJob> {
  const job: GmailQueueJob = {
    id: nanoid(),
    tenantId: params.tenantId,
    integrationId: params.integrationId,
    emailAddress: params.emailAddress,
    historyId: params.historyId,
    attempts: 0,
    enqueuedAt: new Date().toISOString(),
  };

  await upstashCommand<number>('rpush', queueKey(), JSON.stringify(job));
  return job;
}

export async function requeueGmailJob(job: GmailQueueJob): Promise<void> {
  await upstashCommand<number>('rpush', queueKey(), JSON.stringify(job));
}

export async function moveToDeadLetter(job: GmailQueueJob, reason: string): Promise<void> {
  const payload = {
    ...job,
    lastError: reason,
  };
  await upstashCommand<number>('rpush', deadLetterKey(), JSON.stringify(payload));
}

export async function dequeueGmailJobs(limit: number): Promise<GmailQueueJob[]> {
  if (limit <= 0) return [];

  const raw = await upstashCommand<string | string[] | null>(
    'lpop',
    queueKey(),
    limit.toString()
  );

  if (!raw) return [];

  const entries = Array.isArray(raw) ? raw : [raw];
  const jobs: GmailQueueJob[] = [];

  for (const entry of entries) {
    try {
      const parsed = JSON.parse(entry) as GmailQueueJob;
      if (parsed?.id && parsed.tenantId && parsed.integrationId) {
        jobs.push(parsed);
      }
    } catch (error) {
      console.warn('[Gmail Queue] Failed to parse job payload:', error);
    }
  }

  return jobs;
}
