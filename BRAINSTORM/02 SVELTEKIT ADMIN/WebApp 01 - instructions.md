# **SvelteKit + Drizzle + Zod + Superforms** 

# Notes & conventions

## 1) Environment & config

* Read env via $lib/config/env.ts (Zod-verified).
* Put **only non-secret defaults** in `.env.example`. Real secrets in `.env` (ignored by VCS).
* Use ENV (server) and PUBLIC_ENV (client). Do not import server env in client-side code.
* Parse env with Zod (`src/lib/config/env.ts`) and **fail fast** on boot if missing.
* Key vars: `DATABASE_URL`, `ORIGIN`, `TIMEZONE=Asia/Kolkata`.

* 

## 2) Database (Drizzle + Postgres)

* Single source of truth is `schema.ts`.
* Migrations:

  * `npm run db:generate` → generates SQL in `drizzle/migrations`.
  * `npm run db:migrate` → applies them.
* Use **UUID PKs with `defaultRandom()`**, UTC timestamps with timezone.
* Don’t duplicate `stateId` on `device` (derive via `teamId`).

## 3) RBAC

* Roles: `NATIONAL_ADMIN | STATE_ADMIN | SUPERVISOR | TEAM_MEMBER`.
* Store scoped assignments in `user_role (stateId?, teamId?)`.
* Provide helpers:

  * `requireRole(user, 'STATE_ADMIN', { stateId })`
  * `canManageTeam(user, teamId)`
* **Every** mutation calls RBAC before DB writes.

## 4) Validation & Superforms

* For each page with a form:

  * `+page.server.ts`: `superValidate(schema)` in both `load` and `actions`.
  * On invalid: `return fail(400, { form })`.
  * On success: redirect or re-render with success message.
* Keep Zod schemas small, compose when needed (e.g., `teamUpsertSchema` + `id`).

## 5) PIN service (server-only)

* Create/rotate in a **transaction**:

  1. Generate Argon2id **PHC** (`verifierPhc`).
  2. Optionally AEAD-wrap plaintext for admin reveal (`aeadCiphertext`, `aeadNonce`, `aeadKid`).
  3. Set previous `isCurrent=false`, insert new `pin` with `isCurrent=true`.
* Verify path never returns plaintext; compares against `verifierPhc`.

## 6) Devices & enrollment

* **Upsert by `androidId`** on first contact. Attach `teamId` when known.
* `enrollment_token` (short-lived JWT) powers QR flow; record `usedAt/revokedAt`.
* `event` table receives telemetry (type + data JSON). Index `(deviceId, at)`.

## 7) API routes (device-facing)

* Use **JSON POST** under `/api/*`.
* Always validate with Zod (body + signature if applicable).
* Return minimal payloads (policy ids, session expiry, next steps).
* Throttle sensitive endpoints (e.g., PIN verify).

## 8) Logging & audits

* `logger.ts` should add a **request-id** and capture:

  * userId (if any), teamId scope, route, action, success/fail, latency.
* Avoid logging secrets/PINs/plaintext tokens. Log **hashes/ids** instead.

## 9) Testing

* Unit: services (pin/device/enrollment) with **fake PG** or a test DB (Docker).
* E2E (optional): Playwright hitting admin forms and `/api` routes.
* Seeds create a **minimal happy path**: 1 state, 1 team, 1 admin, 1 supervisor.

## 10) CI & deploy

* CI: `typecheck`, `lint`, `db:generate` (no diff), `db:migrate` against a temp DB.
* Deploy: SvelteKit **adapter-node** behind Nginx/HAProxy.
* Run `health/+server.ts` for load balancer checks.
* Keep DB creds in service secrets (not in images).

## 11) Security

* HTTPS everywhere; set `ORIGIN` correctly to enable CSRF protections from Superforms.
* Rate-limit `/api/pin/verify` & `/api/device/heartbeat`.
* Rotate `aeadKid` & `JWT_SECRET` periodically (quarterly).
* Use **strict CORS** for `/api/*` if devices are not same origin (usually same).

## 12) Performance

* Index hot paths already included:

  * pins: `(teamId, kind, isCurrent)`, unique `(teamId, kind, version)`
  * devices: `status`, `teamId`, `lastSeenAt`
  * events: `(deviceId, at)`, `(teamId, at)`, `(type, at)`
* Prefer **paginated** admin lists (devices/events).

## 13) Path aliases & style

* Path alias: use SvelteKit’s default `$lib` (no extra config required).
* Code style: Prettier + ESLint, no `any`, narrow types on services.

## 14) Seed data (scripts/seed.ts)

* Create roles, a national admin, one state+team, and a supervisor user.
* Optionally mint a demo enrollment token and one current team PIN.


## 15) Instructions

1. **Routes:** server actions for mutations; GET load for reads.
2. **Validation:** Zod → `superValidate` both in `load` and `actions`.
3. **DB:** All writes go through a tiny service layer (`src/lib/server/services/*`) for RBAC.
4. **RBAC:** helpers like `canManageTeam(user, teamId)` must be called in every action touching team-scoped tables.
5. **Errors:** Always return `{ form }` with `fail(400, { form })` on validation failure.
6. **Transactions:** Use `db.transaction` for multi-table writes (e.g., creating team + initial PIN).
7. **Timestamps:** store UTC; present in `Asia/Kolkata`.
8. **IDs:** use UUIDs; never trust client-provided scope beyond validation + RBAC.
9. **Migrations:** generated only from schema; never hand-edit SQL unless adding indexes.
10. **Logging:** wrap actions with request-id and audit essentials (userId, teamId, route, success/fail).

## Coding Conventions


## Development Workflow

1. Create feature branch from main
2. Make atomic changes following conventions
3. Add tests for new functionality
4. Run tests and linting
5. Create pull request
6. Merge after approval

## Quality Standards

- All code must pass Black formatting
- All code must pass Flake8 linting
- All functions must have type hints
- All public functions must have docstrings
- Test coverage should be >80%
- All database changes must use Alembic migrations
- No hard deletes - use soft deletes with audit trails

## Security Guidelines

- Never commit secrets or API keys
- Use environment variables for sensitive data
- Hash passwords with Werkzeug
- Validate all user inputs
- Use HTTPS in production
- Implement proper role-based access control
- Log all authentication events
- Use JWT tokens with expiration
- Implement device fingerprinting

## Development Approach

The system will be developed incrementally focusing on:
- Foundation setup and database models
- User management and role-based access control
- Device authentication and session tracking
- PIN recovery system implementation
- Testing and documentation

---


If you want, I can drop:

* `src/lib/server/services/pin.service.ts` (hashing + transaction),
* `src/lib/config/env.ts` (zod-verified env),
* a small `scripts/seed.ts` you can run with `npm run seed`.
