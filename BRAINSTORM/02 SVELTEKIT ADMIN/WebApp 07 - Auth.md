

awesome — here’s a clean BetterAuth setup for your SvelteKit stack with Drizzle, request-id logging, RFC-style audit hooks, and RBAC glue. Drop these in as-is.

# `src/lib/server/auth/betterAuth.ts`

```ts
// Central BetterAuth instance + helpers (server-only)

import { ENV } from "$lib/config/env";
import { db } from "$lib/db";
import { users } from "$lib/server/db/schema";
import { and, eq } from "drizzle-orm";
import argon2 from "argon2";

// --- BetterAuth core (import from the lib you’ve installed) ---
import { betterAuth } from "better-auth/sveltekit";        // server instance
import { drizzleAdapter } from "better-auth/drizzle";       // Drizzle adapter
import type { Handle } from "@sveltejs/kit";

// --- Logger/Audit glue ---
import { audit, childFor } from "$lib/server/utils/logger";

// --- Map your DB user to a session-safe shape ---
export type SessionUser = {
  id: string;
  email: string;
  name: string | null;
  // add anything else you expose to the UI (roles get loaded separately)
};

// Minimal mapper (adjust to your actual columns)
function toSessionUser(row: typeof users.$inferSelect): SessionUser {
  return {
    id: row.id,
    email: row.email,
    name: row.name ?? null,
  };
}

// Create BetterAuth server (password login + JWT sessions)
export const auth = betterAuth({
  secret: ENV.JWT_SECRET,
  adapter: drizzleAdapter(db),
  session: {
    strategy: "jwt",
    jwt: { expiresIn: "7d" },
  },
  // Basic email+password provider using your Users table
  providers: {
    credentials: {
      authorize: async (creds: { email: string; password: string }) => {
        const row = await db.query.users.findFirst({
          where: and(eq(users.email, creds.email), eq(users.disabled, false)),
          columns: { id: true, email: true, name: true, passwordPhc: true },
        });
        if (!row) return null;
        const ok = await argon2.verify(row.passwordPhc, creds.password);
        return ok ? toSessionUser(row as any) : null;
      },
    },
  },
});

// SvelteKit middleware from BetterAuth to attach session on each request
export const handleBetterAuth: Handle = auth.handle();

// Convenience helpers you can import in routes/services
export async function getSessionUser(event: Parameters<Handle>[0]["event"]): Promise<SessionUser | null> {
  const session = await auth.getSession(event);
  return (session?.user ?? null) as SessionUser | null;
}

// Mirror important auth events to RFC 5424 audit (optional examples)
auth.on("signIn:success", async (ctx) => {
  const { event, user } = ctx;
  await audit(event as any, {
    action: "auth.login",
    status: "ok",
    userId: user?.id ?? null,
  });
});

auth.on("signIn:failure", async (ctx) => {
  const { event, error } = ctx;
  await audit(event as any, {
    action: "auth.login",
    status: "fail",
    extra: { reason: error?.message?.slice(0, 64) || "invalid_credentials" },
  });
});

auth.on("signOut", async (ctx) => {
  const { event, session } = ctx;
  const log = childFor(event as any, { mod: "auth" });
  log.info({ at: "auth.logout" });
  await audit(event as any, { action: "auth.logout", status: "ok", userId: (session?.user as any)?.id ?? null });
});
```

---

# `src/hooks.server.ts`

```ts
// Compose request logging ↔ BetterAuth middleware
import type { Handle } from "@sveltejs/kit";
import { withRequestLogging } from "$lib/server/utils/logger";
import { handleBetterAuth } from "$lib/server/auth/betterAuth";

// Order: add request-id first, then auth (so audit logs get req_id)
export const handle: Handle = withRequestLogging(async ({ event, resolve }) => {
  return handleBetterAuth({ event, resolve });
});
```

---

# `src/lib/server/services/rbac.ts` 

Here’s an updated, BetterAuth-friendly rbac.ts that keeps your existing API/signatures (so your services like pin.service.ts continue to call requirePermission(user, perm, { teamId }) exactly the same), but tightens the DB checks and caching logic.




```ts
import { error } from "@sveltejs/kit";
import { and, eq } from "drizzle-orm";
import { db } from "$lib/db";
import { userRole, role, team } from "$lib/server/db/schema";

// ---- DB enum values ----
export type RoleName = "NATIONAL_ADMIN" | "STATE_ADMIN" | "SUPERVISOR" | "TEAM_MEMBER";

export type Permission =
  | "device:provision"
  | "device:manage"
  | "policy:read"
  | "policy:ack"
  | "pin:generate"
  | "pin:reveal"
  | "pin:revoke"
  | "telemetry:write"
  | "enrollment:mint"
  | "enrollment:revoke";

/**
 * SessionUser as seen by your services. Keep this shape stable.
 * When using BetterAuth, construct it from your session user object.
 */
export type SessionUser = {
  id: string;
  email: string;
  // Optional, opportunistic caches (can be absent; DB checks still run)
  global?: RoleName[];                       // roles without scope (e.g., NATIONAL_ADMIN)
  stateScoped?: Record<string, RoleName[]>;  // stateId -> roles
  teamScoped?: Record<string, RoleName[]>;   // teamId -> roles
};

export type Scope = { teamId?: string; stateId?: string };

/** Minimal policy table: which roles grant which permission. */
const POLICY: Record<Permission, RoleName[]> = {
  "device:provision": ["NATIONAL_ADMIN", "STATE_ADMIN", "TEAM_MEMBER", "SUPERVISOR"],
  "device:manage":    ["NATIONAL_ADMIN", "STATE_ADMIN"],
  "policy:read":      ["NATIONAL_ADMIN", "STATE_ADMIN", "TEAM_MEMBER", "SUPERVISOR"],
  "policy:ack":       ["TEAM_MEMBER", "SUPERVISOR"],
  "pin:generate":     ["NATIONAL_ADMIN", "STATE_ADMIN"],
  "pin:reveal":       ["NATIONAL_ADMIN", "STATE_ADMIN"],
  "pin:revoke":       ["NATIONAL_ADMIN", "STATE_ADMIN"],
  "telemetry:write":  ["TEAM_MEMBER", "SUPERVISOR"],
  "enrollment:mint":  ["NATIONAL_ADMIN", "STATE_ADMIN"],
  "enrollment:revoke":["NATIONAL_ADMIN", "STATE_ADMIN"],
};

// ---------- Fast path: use cached claims when present ----------
function hasGlobal(user: SessionUser, allowed: RoleName[]) {
  return user.global?.some((r) => allowed.includes(r)) ?? false;
}
function hasTeam(user: SessionUser, teamId: string, allowed: RoleName[]) {
  return user.teamScoped?.[teamId]?.some((r) => allowed.includes(r)) ?? false;
}
function hasState(user: SessionUser, stateId: string, allowed: RoleName[]) {
  return user.stateScoped?.[stateId]?.some((r) => allowed.includes(r)) ?? false;
}

// ---------- DB helpers ----------
async function rolesForTeam(userId: string, teamId: string): Promise<RoleName[]> {
  const rows = await db
    .select({ name: role.name })
    .from(userRole)
    .leftJoin(role, eq(userRole.roleId, role.id))
    .where(and(eq(userRole.userId, userId), eq(userRole.teamId, teamId)));
  return rows.map((r) => r.name as RoleName);
}

async function rolesForState(userId: string, stateId: string): Promise<RoleName[]> {
  const rows = await db
    .select({ name: role.name })
    .from(userRole)
    .leftJoin(role, eq(userRole.roleId, role.id))
    .where(and(eq(userRole.userId, userId), eq(userRole.stateId, stateId)));
  return rows.map((r) => r.name as RoleName);
}

async function isNationalAdmin(userId: string): Promise<boolean> {
  const rows = await db
    .select({ name: role.name })
    .from(userRole)
    .leftJoin(role, eq(userRole.roleId, role.id))
    .where(eq(userRole.userId, userId));
  return rows.some((r) => r.name === "NATIONAL_ADMIN");
}

async function teamStateId(teamId: string): Promise<string | null> {
  const t = await db.query.team.findFirst({
    where: eq(team.id, teamId),
    columns: { stateId: true }
  });
  return t?.stateId ?? null;
}

// ---------- Core checks ----------
export async function canUser(user: SessionUser, perm: Permission, scope?: Scope): Promise<boolean> {
  if (!user) return false;

  const allowed = POLICY[perm];
  if (!allowed) return false;

  // 1) Global role?
  if (hasGlobal(user, allowed)) return true;
  if (await isNationalAdmin(user.id)) return true;

  // 2) Team-scoped?
  if (scope?.teamId) {
    const { teamId } = scope;
    if (hasTeam(user, teamId, allowed)) return true;

    const teamRoles = await rolesForTeam(user.id, teamId);
    if (teamRoles.some((r) => allowed.includes(r))) return true;

    // If user is STATE_ADMIN of the team's state, allow
    const stId = await teamStateId(teamId);
    if (stId) {
      if (hasState(user, stId, allowed)) return true;
      const sr = await rolesForState(user.id, stId);
      if (sr.includes("STATE_ADMIN")) return true;
    }
    return false;
  }

  // 3) State-scoped?
  if (scope?.stateId) {
    const { stateId } = scope;
    if (hasState(user, stateId, allowed)) return true;

    const sr = await rolesForState(user.id, stateId);
    if (sr.some((r) => allowed.includes(r))) return true;

    return false;
  }

  // 4) No explicit scope: only global/NATIONAL_ADMIN apply
  return false;
}

export async function requirePermission(user: SessionUser, perm: Permission, scope?: Scope) {
  const ok = await canUser(user, perm, scope);
  if (!ok) throw error(403, `Forbidden (${perm})`);
}

export async function requireGlobal(user: SessionUser, allowed: RoleName[]) {
  if (!hasGlobal(user, allowed)) {
    // Final DB check
    const isNA = await isNationalAdmin(user.id);
    if (!(isNA && allowed.includes("NATIONAL_ADMIN"))) {
      throw error(403, "Forbidden (role)");
    }
  }
}

```

---

# `src/routes/api/auth/login/+server.ts`

```ts
import type { RequestHandler } from "@sveltejs/kit";
import { auth } from "$lib/server/auth/betterAuth";
import { audit, childFor, timeit } from "$lib/server/utils/logger";

export const POST: RequestHandler = async (event) => {
  const log = childFor(event, { mod: "api.auth" });
  const done = timeit();

  try {
    const { email, password } = await event.request.json();
    // BetterAuth credentials sign-in
    const res = await auth.signIn(event, "credentials", { email, password });
    const ms = done();

    await audit(event, { action: "auth.login", status: res?.ok ? "ok" : "fail", latencyMs: ms });
    if (!res?.ok) return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401 });

    log.info({ at: "auth.login", email, latency_ms: ms });
    return new Response(null, { status: 204 });
  } catch (e: any) {
    const ms = done();
    await audit(event, { action: "auth.login", status: "fail", latencyMs: ms, extra: { reason: "exception" } });
    return new Response(JSON.stringify({ error: "Login failed" }), { status: 400 });
  }
};
```

---

# `src/routes/api/auth/logout/+server.ts`

```ts
import type { RequestHandler } from "@sveltejs/kit";
import { auth } from "$lib/server/auth/betterAuth";
import { audit, childFor, timeit } from "$lib/server/utils/logger";

export const POST: RequestHandler = async (event) => {
  const log = childFor(event, { mod: "api.auth" });
  const done = timeit();

  try {
    await auth.signOut(event);
    const ms = done();
    await audit(event, { action: "auth.logout", status: "ok", latencyMs: ms });
    log.info({ at: "auth.logout", latency_ms: ms });
    return new Response(null, { status: 204 });
  } catch {
    const ms = done();
    await audit(event, { action: "auth.logout", status: "fail", latencyMs: ms });
    return new Response(JSON.stringify({ error: "Logout failed" }), { status: 400 });
  }
};
```
What’s improved (but fully compatible)
 - Keeps your public API (canUser, requirePermission, requireGlobal, type SessionUser), so existing service code (e.g., pin.service.ts) won’t change.
 - Adds explicit DB helpers for readability and reuse.
 - Still does the team → state fallback so a STATE_ADMIN gets team-scoped permissions inside that state.
 - Works cleanly with BetterAuth sessions: construct a SessionUser from the session user and optionally attach cached role claims if you have them; otherwise the DB helpers kick in.


---

# `src/routes/api/auth/me/+server.ts`

```ts
import type { RequestHandler } from "@sveltejs/kit";
import { auth } from "$lib/server/auth/betterAuth";

export const GET: RequestHandler = async (event) => {
  const session = await auth.getSession(event);
  if (!session) return new Response(JSON.stringify({ user: null }), { status: 200 });
  return new Response(JSON.stringify({ user: session.user }), { status: 200 });
};
```

---

# `src/routes/(protected)/+layout.server.ts` (example protection)

```ts
import type { LayoutServerLoad } from "./$types";
import { auth } from "$lib/server/auth/betterAuth";

export const load: LayoutServerLoad = async (event) => {
  const session = await auth.getSession(event);
  if (!session) {
    return { user: null }; // or throw redirect(302, '/login')
  }
  return { user: session.user };
};
```

---

## Notes & choices

* **BetterAuth**: credentials provider hooks into your `users` table with Argon2 PHC verification. Swap in OAuth providers later without changing middleware.
* **Middleware order**: request-id/latency logs first, then auth; your `audit()` will include `req_id` and user id when available.
* **RBAC**: `requirePermission(event, "pin:generate")` in endpoints/services pulls roles from DB and enforces policy.
* **Audit**: auth events get mirrored to both app JSON logs and your RFC-5424 audit sink.
* **Env**: uses your existing `JWT_SECRET`, `LOG_*`, and audit envs you added.

If you want a simple login page (`+page.svelte` + `+page.server.ts`) that posts to `/api/auth/login`, say the word and I’ll add it.



## Quick, repeatable way to add policies for any new API route (or server function) using your current RBAC.

### 1) Pick a permission name

Use `noun:verb` (lowercase noun, verb), e.g.

* `enrollment:rotate`
* `policy:publish`
* `device:retire`

Keep it consistent with what the route actually does.

### 2) Declare it in `rbac.ts`

Add the permission to the union and map it to allowed roles in `POLICY`.

```ts
// src/lib/server/services/rbac.ts

export type Permission =
  | "device:provision"
  | "device:manage"
  // ...
  | "enrollment:revoke"
  | "enrollment:rotate";        // <-- NEW

const POLICY: Record<Permission, RoleName[]> = {
  // existing…
  "enrollment:rotate": ["NATIONAL_ADMIN", "STATE_ADMIN"], // <-- map to roles
};
```

### 3) Enforce it in the route (team- or state-scoped)

Call `requirePermission` where the action happens. Pass scope so RBAC can evaluate team/state grants (and allow STATE_ADMINs of that team’s state).

```ts
// src/routes/api/enrollment/rotate/+server.ts
import type { RequestHandler } from "@sveltejs/kit";
import { requirePermission } from "$lib/server/services/rbac";
import { audit, childFor, timeit } from "$lib/server/utils/logger";

export const POST: RequestHandler = async (event) => {
  const log = childFor(event, { mod: "api.enrollment" });
  const done = timeit();

  const { teamId } = await event.request.json();

  // Enforce the new policy
  await requirePermission(event.locals.user, "enrollment:rotate", { teamId });

  // …perform the rotate…
  const ms = done();
  await audit(event, { action: "enrollment.rotate", status: "ok", teamId, latencyMs: ms });
  log.info({ at: "enrollment.rotate", teamId, latency_ms: ms });

  return new Response(null, { status: 204 });
};
```

**Which scope to pass?**

* Action affects a **team** → `{ teamId }`
* Action is **state-wide** → `{ stateId }`
* Action is **truly global** (rare) → pass no scope and restrict to `NATIONAL_ADMIN` via `requireGlobal`.

# 4) (Optional) Gate server functions directly

If you call services outside routes, enforce there too:

```ts
export async function rotateEnrollment(user: SessionUser, teamId: string) {
  await requirePermission(user, "enrollment:rotate", { teamId });
  // …do work…
}
```

### 5) (Optional) Add a new role

If you invent a new role (e.g., `ENROLLMENT_MANAGER`):

1. Add it to the `role_name` enum in your DB + Drizzle schema.
2. Extend `RoleName` union in `rbac.ts`.
3. Grant that role in `POLICY` wherever appropriate.
4. Ensure your admin UI/seed gives that role to users.

### 6) UI guards (server load)

Block navigation early and show a friendly message:

```ts
// +page.server.ts
import { canUser } from "$lib/server/services/rbac";

export const load = async (event) => {
  const ok = await canUser(event.locals.user, "enrollment:rotate", { teamId: "t_001" });
  return { canRotate: ok };
};
```

### 7) Quick tests (recommended)

* **Happy path**: `STATE_ADMIN` with a team in their state → allowed.
* **Denied**: `TEAM_MEMBER` → forbidden.
* **Global**: `NATIONAL_ADMIN` → allowed without scope (or with any scope).

---

#### Naming & conventions (keep it clean)

* **Permissions**: `resource:action` (e.g., `pin:reveal`, `device:enroll`, `policy:publish`).
* **Audit `action`** strings: mirror permission but dot-style (e.g., `enrollment.rotate`) for human readability.
* **Scope**: always pass `{ teamId }` or `{ stateId }` when the action is scoped; the RBAC already promotes `STATE_ADMIN` for the team’s state.

That’s all — add to the `POLICY`, enforce with `requirePermission()` at the route or service, and your new endpoint is secured.
