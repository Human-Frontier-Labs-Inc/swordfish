# Swordfish

Email security SaaS platform for threat detection, monitoring, and security operations.

## Tech Stack

- **Runtime**: Next.js 16 (App Router), React 19, TypeScript
- **Styling**: Tailwind CSS 4, Radix UI, CVA
- **Database**: PostgreSQL via Neon serverless, Drizzle ORM
- **Cache/Queue**: Upstash Redis, Upstash Kafka
- **Auth**: Clerk
- **Payments**: Stripe
- **Webhooks**: Svix
- **Analytics**: PostHog
- **AI**: Anthropic Claude SDK
- **Email**: Google Workspace (Gmail API), Microsoft 365
- **Security**: Joe Sandbox, AbuseIPDB, URLScan.io, VirusTotal
- **Storage**: Cloudflare R2
- **Deployment**: Vercel

## Prerequisites

- Node.js 20+
- npm 10+
- Accounts: Clerk, Neon, Upstash (required for core functionality)
- Optional: Stripe, Google Cloud, Anthropic, Cloudflare

## Getting Started

1. Clone the repository:

```bash
git clone <repo-url>
cd swordfish
```

2. Install dependencies:

```bash
npm install
```

3. Set up environment variables:

```bash
cp .env.example .env.local
```

Edit `.env.local` and fill in your credentials. At minimum you need:

- `CLERK_SECRET_KEY` and `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` (authentication)
- `DATABASE_URL` (Neon PostgreSQL connection string)
- `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` (caching/queues)

See `.env.example` for the full list of available configuration options.

4. Run database migrations:

```bash
npm run migrate:009
npm run migrate:014
```

5. Start the development server:

```bash
npm run dev
```

The app will be available at `http://localhost:3000`.

## Available Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start dev server with Turbopack |
| `npm run build` | Production build |
| `npm run start` | Start production server |
| `npm run lint` | Run ESLint |
| `npm run typecheck` | TypeScript type checking |
| `npm run test` | Run unit/integration tests (Vitest) |
| `npm run test:watch` | Run tests in watch mode |
| `npm run test:coverage` | Run tests with coverage report |
| `npm run test:e2e` | Run E2E tests (Playwright) |
| `npm run test:e2e:ui` | Run E2E tests with UI |
| `npm run test:e2e:headed` | Run E2E tests in headed browser |
| `npm run setup` | Full environment setup |
| `npm run setup:quick` | Quick environment setup |

## Project Structure

```
app/          Next.js App Router (pages, API routes, layouts)
components/   Shared UI components (dashboards, SOC, MSP modules)
lib/          Business logic, server actions, integrations, utilities
tests/        Unit, integration, and E2E test files
migrations/   Database migration files (Drizzle ORM)
scripts/      Setup and utility scripts
docs/         Project documentation
public/       Static assets
```

## Architecture Notes

- React Server Components by default; `'use client'` only when needed.
- No direct database access in routes. All DB operations go through `/lib` action functions.
- Zod validation at system boundaries.
- Strict TypeScript with no `any` types.

## Deployment

Swordfish deploys to Vercel. Push to `main` triggers a production deployment.

Required environment variables must be configured in the Vercel dashboard. See `.env.example` for the full list.

## License

Proprietary. All rights reserved.
