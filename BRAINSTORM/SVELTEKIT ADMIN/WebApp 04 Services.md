# **SvelteKit + Drizzle + Zod + Superforms** 


* Table names are **singular** (`pin`, `device`, `event`, `policyAck`, `enrollmentToken`) and some column names differ (e.g., `verifierPhc`, `isCurrent`, `revoked`, `aeadCiphertext/Nonce/Kid`). 
* Enrollment tokens are stored as **plain JWT** in `enrollment_token.token`  
* Team membership is represented via `user_role` with optional `state_id` / `team_id` scopes — so RBAC team checks query `user_role`

Below are the full, **updated service files** matching your schema and Zod layout.

---

### `src/lib/server/services/rbac.ts`

```ts
import { error } from "@sveltejs/kit";
import { and, eq } from "drizzle-orm";
import { db } from "$lib/db";
import { userRole, role, team, state } from "$lib/server/db/schema"; // <- your paths

// DB enum values
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

export type SessionUser = {
  id: string;
  email: string;
  // Cached role claims (optional); we still hit DB for scoped checks if absent
  global?: RoleName[];                       // roles without scope (e.g., NATIONAL_ADMIN)
  stateScoped?: Record<string, RoleName[]>;  // stateId -> roles
  teamScoped?: Record<string, RoleName[]>;   // teamId -> roles
};

export type Scope = { teamId?: string; stateId?: string };

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

function hasGlobal(user: SessionUser, allowed: RoleName[]) {
  return user.global?.some((r) => allowed.includes(r)) ?? false;
}

function hasTeam(user: SessionUser, teamId: string, allowed: RoleName[]) {
  return user.teamScoped?.[teamId]?.some((r) => allowed.includes(r)) ?? false;
}

function hasState(user: SessionUser, stateId: string, allowed: RoleName[]) {
  return user.stateScoped?.[stateId]?.some((r) => allowed.includes(r)) ?? false;
}

export async function canUser(user: SessionUser, perm: Permission, scope?: Scope): Promise<boolean> {
  const allowed = POLICY[perm];
  if (!allowed) return false;

  if (hasGlobal(user, allowed)) return true;

  if (scope?.teamId) {
    if (hasTeam(user, scope.teamId, allowed)) return true;
    // Fallback to DB check if not cached
    const rows = await db
      .select({ r: role.name })
      .from(userRole)
      .leftJoin(role, eq(userRole.roleId, role.id))
      .where(and(eq(userRole.userId, user.id), eq(userRole.teamId, scope.teamId)));
    if (rows.some((x) => allowed.includes(x.r as RoleName))) return true;

    // If team → infer its state and allow STATE_ADMIN
    const t = await db.query.team.findFirst({ where: eq(team.id, scope.teamId), columns: { stateId: true } });
    if (t?.stateId) {
      const rs = await db
        .select({ r: role.name })
        .from(userRole)
        .leftJoin(role, eq(userRole.roleId, role.id))
        .where(and(eq(userRole.userId, user.id), eq(userRole.stateId, t.stateId)));
      if (rs.some((x) => x.r === "STATE_ADMIN")) return true;
    }
    return false;
  }

  if (scope?.stateId) {
    if (hasState(user, scope.stateId, allowed)) return true;
    const rows = await db
      .select({ r: role.name })
      .from(userRole)
      .leftJoin(role, eq(userRole.roleId, role.id))
      .where(and(eq(userRole.userId, user.id), eq(userRole.stateId, scope.stateId)));
    if (rows.some((x) => allowed.includes(x.r as RoleName))) return true;
  }

  return false;
}

export async function requirePermission(user: SessionUser, perm: Permission, scope?: Scope) {
  if (!(await canUser(user, perm, scope))) throw error(403, `Forbidden (${perm})`);
}

export async function requireGlobal(user: SessionUser, allowed: RoleName[]) {
  if (!hasGlobal(user, allowed)) {
    // final check from DB
    const rows = await db
      .select({ r: role.name })
      .from(userRole)
      .leftJoin(role, eq(userRole.roleId, role.id))
      .where(and(eq(userRole.userId, user.id)));
    const globals = rows.filter((x) => x.r === "NATIONAL_ADMIN").length > 0;
    if (!globals || !allowed.includes("NATIONAL_ADMIN")) throw error(403, "Forbidden (role)");
  }
}
```

---

### `src/lib/server/services/pin.service.ts`

```ts
import { and, desc, eq } from "drizzle-orm";
import { db } from "$lib/db";
import { pin as Pin } from "$lib/server/db/schema";
import type { SessionUser } from "./rbac";
import { requirePermission } from "./rbac";
import {
  hashArgon2id,
  verifyArgon2id,
  randomNumericPin,
  aeadSealXChaCha_db,
  aeadOpenXChaCha_db,
  getAeadKid
} from "$lib/server/utils/crypto";

// DB enum: 'TEAM' | 'SUPERVISOR'
export type PinKind = "TEAM" | "SUPERVISOR";

type CreateOpts = {
  length?: number;      // default 6
  keepReveal?: boolean; // if true, store AEAD bundle for admin reveal
};

function clampPinLength(n?: number) {
  const x = n ?? 6;
  return Math.max(4, Math.min(10, x)); // sane guardrails
}

export async function createOrRotatePin(
  user: SessionUser,
  teamId: string,
  kind: PinKind,
  opts?: CreateOpts
) {
  await requirePermission(user, "pin:generate", { teamId });

  const pinLen = clampPinLength(opts?.length);
  const plaintext = randomNumericPin(pinLen);
  const phc = await hashArgon2id(plaintext);

  // transactional rotate: bump version, clear previous current, insert new
  const result = await db.transaction(async (tx) => {
    const latest = await tx.query.pin.findFirst({
      where: and(eq(Pin.teamId, teamId), eq(Pin.kind, kind)),
      orderBy: [desc(Pin.version)],
      columns: { version: true }
    });
    const nextVersion = (latest?.version ?? 0) + 1;

    // mark prior as not current
    await tx
      .update(Pin)
      .set({ isCurrent: false })
      .where(and(eq(Pin.teamId, teamId), eq(Pin.kind, kind)));

    // Optional AEAD seal for reveal; if AEAD disabled, skip silently
    let aeadCiphertext: Buffer | null = null;
    let aeadNonce: Buffer | null = null;
    let aeadKid: string | null = null;

    if (opts?.keepReveal) {
      try {
        const aad = JSON.stringify({ teamId, kind, version: nextVersion });
        const sealed = await aeadSealXChaCha_db(plaintext, aad);
        aeadCiphertext = sealed.ciphertext;
        aeadNonce = sealed.nonce;
        aeadKid = sealed.kid ?? getAeadKid();
      } catch {
        // AEAD disabled or key invalid → proceed without reveal bundle
        aeadCiphertext = null;
        aeadNonce = null;
        aeadKid = null;
      }
    }

    await tx.insert(Pin).values({
      teamId,
      kind,
      version: nextVersion,
      isCurrent: true,
      revoked: false,
      verifierPhc: phc,
      params: { kdf: "argon2id", t: 3, m: 65536, p: 1 },
      aeadCiphertext,
      aeadNonce,
      aeadKid,
      createdBy: user.id
    });

    return { nextVersion, reveal: !!aeadCiphertext };
  });

  return {
    teamId,
    kind,
    version: result.nextVersion,
    reveal_available: result.reveal
  };
}

export async function revokeCurrentPin(
  user: SessionUser,
  teamId: string,
  kind: PinKind
) {
  await requirePermission(user, "pin:revoke", { teamId });
  await db
    .update(Pin)
    .set({ revoked: true, isCurrent: false })
    .where(and(eq(Pin.teamId, teamId), eq(Pin.kind, kind), eq(Pin.isCurrent, true), eq(Pin.revoked, false)));
}

export async function revealPin(
  user: SessionUser,
  teamId: string,
  kind: PinKind,
  version?: number
) {
  await requirePermission(user, "pin:reveal", { teamId });

  const row = await db.query.pin.findFirst({
    where: and(
      eq(Pin.teamId, teamId),
      eq(Pin.kind, kind),
      eq(Pin.revoked, false),
      ...(version ? [eq(Pin.version, version)] : [])
    ),
    orderBy: [desc(Pin.version)],
    columns: {
      version: true,
      aeadCiphertext: true,
      aeadNonce: true,
      aeadKid: true
    }
  });

  if (!row) throw new Error("PIN not found");
  if (!row.aeadCiphertext || !row.aeadNonce) throw new Error("Reveal disabled (no AEAD seal)");
  if (row.aeadKid && row.aeadKid !== getAeadKid()) throw new Error("Reveal key mismatch");

  // Bind reveal to context via AAD to detect wrong-context opens
  const aad = JSON.stringify({ teamId, kind, version: row.version });
  const pin = await aeadOpenXChaCha_db(row.aeadNonce as Buffer, row.aeadCiphertext as Buffer, aad);

  return { teamId, kind, version: row.version, pin };
}

export async function verifyPin(teamId: string, kind: PinKind, candidate: string) {
  const row = await db.query.pin.findFirst({
    where: and(eq(Pin.teamId, teamId), eq(Pin.kind, kind), eq(Pin.isCurrent, true), eq(Pin.revoked, false)),
    orderBy: [desc(Pin.version)],
    columns: { verifierPhc: true }
  });
  if (!row) return { ok: false };
  const ok = await verifyArgon2id(row.verifierPhc, candidate);
  return { ok };
}


```

---

### `src/lib/server/services/device.service.ts`

```ts
import { and, eq } from "drizzle-orm";
import { db } from "$lib/db";
import { device as Device, event as Event, policyAck as PolicyAck } from "$lib/server/db/schema";
import type { SessionUser } from "./rbac";
import { requirePermission } from "./rbac";

export type UpsertDeviceInput = {
  androidId: string;
  teamId?: string; // may attach on first enrollment
  manufacturer?: string | null;
  model?: string | null;
  osRelease?: string | null;
  osIncremental?: string | null;
  securityPatch?: string | null;
  isDeviceOwner?: boolean;
  appVersion?: string | null;
  counters?: Record<string, unknown> | null;
  firstBootIso?: string | null;
};

export async function upsertByAndroidId(actor: SessionUser | "system", payload: UpsertDeviceInput) {
  if (actor !== "system" && payload.teamId) {
    await requirePermission(actor, "device:manage", { teamId: payload.teamId });
  }

  const existing = await db.query.device.findFirst({
    where: eq(Device.androidId, payload.androidId),
  });

  if (existing) {
    await db
      .update(Device)
      .set({
        teamId: payload.teamId ?? existing.teamId,
        manufacturer: payload.manufacturer ?? existing.manufacturer,
        model: payload.model ?? existing.model,
        osRelease: payload.osRelease ?? existing.osRelease,
        osIncremental: payload.osIncremental ?? existing.osIncremental,
        securityPatch: payload.securityPatch ?? existing.securityPatch,
        isDeviceOwner: payload.isDeviceOwner ?? existing.isDeviceOwner,
        appVersion: payload.appVersion ?? existing.appVersion,
        counters: payload.counters ?? existing.counters,
        lastSeenAt: new Date(),
      })
      .where(eq(Device.id, existing.id));

    return { deviceId: existing.id, created: false, teamId: payload.teamId ?? existing.teamId ?? null };
  }

  const [row] = await db
    .insert(Device)
    .values({
      androidId: payload.androidId,
      teamId: payload.teamId ?? null,
      manufacturer: payload.manufacturer ?? null,
      model: payload.model ?? null,
      osRelease: payload.osRelease ?? null,
      osIncremental: payload.osIncremental ?? null,
      securityPatch: payload.securityPatch ?? null,
      isDeviceOwner: payload.isDeviceOwner ?? false,
      appVersion: payload.appVersion ?? null,
      counters: payload.counters ?? null,
      lastSeenAt: new Date(),
      status: "ACTIVE",
    })
    .returning({ id: Device.id, teamId: Device.teamId });

  return { deviceId: row.id, created: true, teamId: row.teamId ?? null };
}

export type TelemetryEvent = {
  ts?: string; // ISO, optional (server will default)
  type: typeof Event.type._.enumValues[number];
  data?: Record<string, unknown>;
};

export async function ingestTelemetry(androidId: string, items: TelemetryEvent[]) {
  if (!items?.length) return { accepted: 0 };

  const dev = await db.query.device.findFirst({
    where: eq(Device.androidId, androidId),
    columns: { id: true, teamId: true },
  });
  if (!dev) return { accepted: 0 };

  const rows = items.map((e) => ({
    deviceId: dev.id,
    teamId: dev.teamId ?? null,
    type: e.type,
    at: e.ts ? new Date(e.ts) : new Date(),
    data: e.data ?? {},
  }));

  await db.insert(Event).values(rows);
  return { accepted: rows.length };
}

export async function heartbeat(androidId: string, appVersion?: string | null, ip?: string | null) {
  const d = await db.query.device.findFirst({
    where: eq(Device.androidId, androidId),
    columns: { id: true },
  });
  if (!d) return;

  await db
    .update(Device)
    .set({ lastSeenAt: new Date(), appVersion: appVersion ?? null, lastSeenIp: ip ?? null })
    .where(eq(Device.id, d.id));
}

export async function ackPolicy(androidId: string, policyId: string) {
  const d = await db.query.device.findFirst({
    where: eq(Device.androidId, androidId),
    columns: { id: true },
  });
  if (!d) throw new Error("Device not found");

  // record durable ack; ignore duplicates (unique on deviceId+policyId)
  await db.insert(PolicyAck).values({ deviceId: d.id, policyId }).onConflictDoNothing();
  // for quick UI, also mirror onto device row
  await db.update(Device).set({ lastPolicyId: policyId }).where(eq(Device.id, d.id));
}
```

---

### `src/lib/server/services/enrollment.service.ts`

```ts
import crypto from "node:crypto";
import { SignJWT, jwtVerify, type JWTPayload } from "jose";
import { and, eq, isNull } from "drizzle-orm";
import { db } from "$lib/db";
import { enrollmentToken as Enroll } from "$lib/server/db/schema";
import type { SessionUser } from "./rbac";
import { requirePermission } from "./rbac";

const ALG = "HS256";
const ENC_KEY = new TextEncoder().encode(process.env.ENROLL_TOKEN_SECRET!); // validated in env.ts
const DEFAULT_TTL_SEC = 10 * 60;

type EnrollClaims = JWTPayload & {
  sub: "enroll";
  team_id: string;
  jti: string;
};

export async function mintEnrollmentToken(
  user: SessionUser,
  teamId: string,
  ttlSec = DEFAULT_TTL_SEC,
  meta?: Record<string, unknown>
) {
  await requirePermission(user, "enrollment:mint", { teamId });
  const jti = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttlSec;

  const token = await new SignJWT({ sub: "enroll", team_id: teamId, jti } satisfies EnrollClaims)
    .setProtectedHeader({ alg: ALG })
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(ENC_KEY);

  // Your schema stores the token itself (plaintext JWT) — align to that
  await db.insert(Enroll).values({
    teamId,
    jti,
    token,
    expiresAt: new Date(exp * 1000),
    meta: meta ?? {},
  });

  return { token, jti, teamId, expires_at: exp };
}

export async function revokeEnrollmentToken(user: SessionUser, jti: string) {
  // fetch to derive team scope
  const row = await db.query.enrollmentToken.findFirst({ where: eq(Enroll.jti, jti) });
  if (!row) return { ok: false };
  await requirePermission(user, "enrollment:revoke", { teamId: row.teamId });
  if (row.usedAt || row.revokedAt) return { ok: true };

  await db.update(Enroll).set({ revokedAt: new Date() }).where(eq(Enroll.jti, jti));
  return { ok: true };
}

export async function consumeEnrollmentToken(rawToken: string) {
  // verify cryptographically
  const { payload } = await jwtVerify(rawToken, ENC_KEY, { algorithms: [ALG] });
  const claims = payload as EnrollClaims;
  if (claims.sub !== "enroll" || !claims.team_id || !claims.jti) throw new Error("Invalid enrollment token");

  // find the stored row by JTI and TOKEN match, not used/revoked/expired
  const row = await db.query.enrollmentToken.findFirst({
    where: and(eq(Enroll.jti, claims.jti), isNull(Enroll.revokedAt)),
  });
  if (!row) throw new Error("Enrollment token not found/revoked");
  if (row.usedAt) throw new Error("Enrollment token already used");
  if (row.expiresAt && row.expiresAt.getTime() < Date.now()) throw new Error("Enrollment token expired");
  if (row.token !== rawToken) throw new Error("Enrollment token mismatch");

  // mark used
  await db.update(Enroll).set({ usedAt: new Date() }).where(eq(Enroll.jti, claims.jti));

  return { teamId: claims.team_id, jti: claims.jti };
}
```

---

## Why these changes

* **PINs** now toggle `isCurrent` and `revoked` flags and use your column names (`verifierPhc`, `aead*`). Also saves AEAD as `bytea` Buffers to match your schema. 
* **Devices** upsert strictly by `android_id` (unique), optionally attach `teamId`, and write to `event`, `policy_ack`, and `device.last_seen_*` fields you defined. 
* **Enrollment** reads/writes `enrollment_token.token` (plain JWT) and enforces single-use + expiry. 
* **RBAC** checks **scoped roles** from `user_role` (team/state) instead of a separate membership table. 


- #1 AEAD engine swap
From Node’s AES-256-GCM with ad-hoc tag handling → To libsodium XChaCha20-Poly1305 helpers in crypto.ts (more robust nonces, consistent API).
- #2 BYTEA-friendly helpers
Added aeadSealXChaCha_db / aeadOpenXChaCha_db returning/consuming Buffers so you can insert/read Postgres BYTEA columns directly (no base64 juggling).
- #3 Centralized crypto utils
Argon2id hashing/verify and PIN/random helpers moved into utils/crypto.ts. The service now imports hashArgon2id, verifyArgon2id, etc., instead of inlining.
- #4 Context-bound reveals
AEAD now uses AAD (teamId, kind, version). Decrypts fail if the bundle is opened in the wrong context; also checks kid via getAeadKid().
- #5 Safer rotate flow
createOrRotatePin now runs inside a DB transaction, clears previous isCurrent, bumps version, and inserts the new row atomically.
- #6 Config normalization
Switched to PIN_XCHACHA20_KEY_HEX / PIN_AEAD_KID names; the service no longer reads AES envs. One source of truth in crypto.ts.
- #7 Guardrails & ergonomics
Clamp PIN length to 4–10 digits, structured return (reveal_available), and graceful fallback when AEAD isn’t configured (generate works; reveal disabled).
- #8 Cleaner verify path
verifyPin uses the shared verifyArgon2id() and only reads the current, non-revoked PHC.
- Net effect: stronger crypto defaults, schema-clean BYTEA handling, transactional correctness, and simpler service code that leans on reusable utils
