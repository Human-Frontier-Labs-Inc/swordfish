# Swordfish - Claude Code Configuration

## Product

Swordfish is an email security SaaS platform for threat detection, monitoring, and security operations. The project is in the **stabilizing phase** — most features exist, focus is on bugs, polish, and reliability.

## Tech Stack

- **Framework**: Next.js 16 (App Router) with React 19, TypeScript
- **Styling**: Tailwind CSS 4, Radix UI, CVA
- **Database**: PostgreSQL via Neon serverless, Drizzle ORM
- **Cache/Queue**: Upstash Redis
- **Auth**: Clerk
- **Payments**: Stripe
- **Webhooks**: Svix
- **Analytics**: PostHog
- **External APIs**: Google Auth (Gmail integration)
- **AI**: Anthropic SDK
- **Deployment**: Vercel

## Commands

```bash
npm run dev          # Dev server (Turbopack)
npm run build        # Production build
npm run lint         # ESLint (max-warnings=100)
npm run typecheck    # TypeScript type check
npm run test         # Vitest unit/integration tests
npm run test:watch   # Vitest in watch mode
npm run test:coverage # Vitest with coverage
npm run test:e2e     # Playwright E2E tests
```

## Project Structure

```
/app          - Next.js App Router (pages, API routes, route-level components)
/components   - Shared UI components (dashboards, layouts, SOC, MSP modules)
/lib          - Business logic, actions, integrations, utilities
/tests        - Test files (unit, integration, E2E)
/migrations   - Database migration files
/scripts      - Setup and utility scripts
/docs         - Documentation
/public       - Static assets
```

## Code Rules

### TypeScript
- Strict TypeScript everywhere. No `any` types.
- Full type safety with explicit return types on exported functions.
- Use Zod or equivalent for runtime validation at system boundaries.

### Architecture
- **React Server Components by default.** Only add `'use client'` when the component genuinely needs client-side interactivity.
- **No direct database access in routes or pages.** Always go through `/lib` action functions. Routes call lib functions, lib functions call the database.
- Keep files under 500 lines. Split when approaching that limit.
- Never hardcode secrets or API keys. Use environment variables.

### Testing (TDD Required)
- Write tests BEFORE implementation code.
- New features require tests. Bug fixes require a regression test.
- Unit/integration tests go in `/tests`, not the root folder.
- Use Vitest for unit/integration, Playwright for E2E.

### Database
- All schema changes MUST have a corresponding migration file in `/migrations`.
- Never modify the database schema without creating a migration.
- Use Drizzle ORM for all database operations.

### Git Workflow
- Work on feature branches, create PRs for review before merging to main.
- Write clear, descriptive commit messages.

### File Organization
- NEVER save working files, tests, or documentation to the root folder.
- Source code in `/app` or `/lib`, tests in `/tests`, docs in `/docs`, scripts in `/scripts`.

## Priority Order

When making implementation decisions, balance all four concerns — they are all critical for a security product:

1. **Security** — This is a security product. Security best practices are non-negotiable.
2. **Reliability** — Stability, proper error handling, uptime.
3. **User Experience** — Smooth, fast, intuitive interactions.
4. **Ship Speed** — Move efficiently without sacrificing the above.

## Integrations

The current integration set (Clerk, Stripe, Google/Gmail, PostHog, Svix, Neon, Upstash) is the complete picture. Do not introduce new external services without discussion.

## Key Conventions

- Prefer editing existing files over creating new ones.
- Do what was asked — nothing more, nothing less.
- Never proactively create documentation files unless explicitly requested.
- Batch parallel operations in single messages when possible.
