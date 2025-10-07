# **SvelteKit + Drizzle + Zod + Superforms** 

## **`.env`** 

It just stores raw strings; 

Keep **only non-secrets or placeholders**:

```ini
# --- Server ---
# Runtime mode
NODE_ENV=development            # development | production | test

PORT=5173
ORIGIN=http://localhost:5173
TIMEZONE=Asia/Kolkata


# --- Database ---
DATABASE_URL=postgres://user:pass@localhost:5432/surveylauncher

# --- Secrets (set in real .env, never commit) ---
JWT_SECRET=change_me_long_random
POLICY_ED25519_PRIVATE_KEY_BASE64=
POLICY_ED25519_PUBLIC_JWKS_URL=

# --- Public (safe for browser) ---
PUBLIC_APP_NAME=SurveyLauncher
PUBLIC_SUPPORT_EMAIL=support@example.org
PUBLIC_ORIGIN=http://localhost:5173


# Logging
LOG_LEVEL=info                  # trace | debug | info | warn | error | fatal | silent
LOG_PRETTY=true                 # true => pino-pretty (dev); false => NDJSON (prod)
SERVICE_NAME=surveylauncher     # shows up as 'name' in log records


# Split security-grade audit events into a separate RFC 5424 syslog-style stream (auth, PIN generate/reveal/revoke/reset, policy acks, device enroll, etc.), while keeping your existing JSON app logs unchanged.

# Audit sink: "syslog" (UDP) or "file"
AUDIT_DEST=syslog
AUDIT_SYSLOG_HOST=127.0.0.1
AUDIT_SYSLOG_PORT=514
AUDIT_SYSLOG_FACILITY=10          # authpriv (RFC5424 facility code)
AUDIT_FILE=/var/log/surveylauncher/audit.log
AUDIT_APPNAME=surveylauncher-audit
AUDIT_HOSTNAME=localhost          # override if needed


```


## **`src/lib/config/env.ts`** 

It validates & types them with Zod so your app fails fast (and you get autocompletion). Here’s a drop-in, SvelteKit-friendly **`env.ts`** that:

* validates **private** server vars (never shipped to the client),
* validates **public** vars (only those prefixed `PUBLIC_`),
* exposes nice booleans like `DEV/PROD`,
* gives typed access everywhere on the server.

```ts
// src/lib/config/env.ts
import { z } from 'zod';
// SvelteKit runtime env (tree-shakeable & SSR-safe)
import { env as _priv } from '$env/dynamic/private';
import { env as _pub } from '$env/dynamic/public';

// ---------- Helpers ----------
const Boolish = z.union([z.boolean(), z.string()]).transform((v) => {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') return v.trim().toLowerCase() === 'true';
  return false;
});

// ---------- Schemas ----------
const PrivateSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),

  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),

  // server-only secrets/knobs
  JWT_SECRET: z.string().min(16, 'JWT_SECRET must be at least 16 chars'),
  POLICY_ED25519_PRIVATE_KEY_BASE64: z.string().optional(),
  POLICY_ED25519_PUBLIC_JWKS_URL: z.string().url().optional(),

  TIMEZONE: z.string().default('Asia/Kolkata'),
  PORT: z.coerce.number().int().positive().default(5173),
  ORIGIN: z.string().url().default('http://localhost:5173'),

  // ---- Logging (central logger) ----
  LOG_LEVEL: z.enum(['trace','debug','info','warn','error','fatal','silent']).default('info'),
  LOG_PRETTY: Boolish.optional(),                   // pretty in dev by default (resolved below)
  SERVICE_NAME: z.string().default('surveylauncher'),

  // ---- PIN AEAD (libsodium XChaCha20) ----
  PIN_XCHACHA20_KEY_HEX: z.string()
    .regex(/^[0-9a-fA-F]{64}$/, 'Must be 64 hex chars (32 bytes)')
    .optional(),
  PIN_AEAD_KID: z.string().default('pin-xchacha20-v1'),


  // ---- Audit sink ----
  AUDIT_DEST: z.enum(['syslog','file']).default('syslog'),
  AUDIT_SYSLOG_HOST: z.string().default('127.0.0.1'),
  AUDIT_SYSLOG_PORT: z.coerce.number().int().positive().default(514),
  AUDIT_SYSLOG_FACILITY: z.coerce.number().int().min(0).max(23).default(10), // authpriv
  AUDIT_FILE: z.string().default('/var/log/surveylauncher/audit.log'),
  AUDIT_APPNAME: z.string().default('surveylauncher-audit'),
  AUDIT_HOSTNAME: z.string().default('localhost'),


});

const PublicSchema = z.object({
  // Only expose things safe for the browser; must be prefixed PUBLIC_
  PUBLIC_APP_NAME: z.string().default('SurveyLauncher'),
  PUBLIC_SUPPORT_EMAIL: z.string().email().optional(),
  PUBLIC_ORIGIN: z.string().url().optional(),
});

// ---------- Parse & freeze ----------
const _privateParsed = PrivateSchema.safeParse(_priv);
if (!_privateParsed.success) {
  console.error('❌ Invalid private env:', _privateParsed.error.flatten().fieldErrors);
  throw new Error('Fix required private environment variables.');
}

const _publicParsed = PublicSchema.safeParse(_pub);
if (!_publicParsed.success) {
  console.error('❌ Invalid public env:', _publicParsed.error.flatten().fieldErrors);
  throw new Error('Fix required public environment variables.');
}

// Resolve derived/conditional values
const __NODE_ENV = _privateParsed.data.NODE_ENV;
const __LOG_PRETTY = _privateParsed.data.LOG_PRETTY ?? (__NODE_ENV !== 'production');

export const ENV = Object.freeze({
  ..._privateParsed.data,
  LOG_PRETTY: __LOG_PRETTY, // override with resolved boolean
  DEV: __NODE_ENV === 'development',
  PROD: __NODE_ENV === 'production',
  TEST: __NODE_ENV === 'test',
});

export const PUBLIC_ENV = Object.freeze(_publicParsed.data);

// ---------- Types ----------
export type Env = typeof ENV;
export type PublicEnv = typeof PUBLIC_ENV;

```

 - LOG_PRETTY defaults to true in dev and false in prod/test unless explicitly set.
 - SERVICE_NAME is used by the logger as the process name.
 - PIN_XCHACHA20_KEY_HEX/PIN_AEAD_KID are read by your crypto.ts AEAD helpers; if the key is absent, reveal stays disabled but PIN generation/verify continue to work.


## src/lib/server/utils/audit.ts

```ts
import { createSocket } from "node:dgram";
import { appendFile } from "node:fs/promises";
import { ENV } from "$lib/config/env";

/**
 * RFC 5424 syslog message:
 * <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
 * We emit VERSION=1, PROCID='-', MSGID='AUDIT', and SD block [audit@32473 ...]
 */

type AuditFields = {
  action: string;              // e.g., pin.generate, auth.login
  result: "success" | "failure";
  userId?: string | null;
  teamId?: string | null;
  deviceId?: string | null;
  stateId?: string | null;
  clientIp?: string | null;
  requestId?: string | null;
  reason?: string | null;      // short failure reason (no secrets)
  extra?: Record<string, string | number | boolean | null | undefined>;
};

const ENTERPRISE_ID = 32473; // arbitrary enterprise ID for SD-ID namespace

function rfc3339(ts = new Date()) {
  // RFC 5424 allows RFC3339 timestamp with timezone
  return ts.toISOString(); // includes 'Z'; acceptable for 5424
}

function pri(facility: number, severity: number) {
  return `<${facility * 8 + severity}>`; // severity 5=Notice, 6=Info, 4=Warn
}

function sdKV(k: string, v: unknown) {
  if (v === null || v === undefined) return "";
  // escape: " -> \"  \ -> \\  ] -> \]
  const s = String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/]/g, "\\]");
  return ` ${k}="${s}"`;
}

function buildStructuredData(f: AuditFields) {
  const id = `audit@${ENTERPRISE_ID}`;
  let sd = `[${id}`;
  sd += sdKV("action", f.action);
  sd += sdKV("result", f.result);
  sd += sdKV("userId", f.userId);
  sd += sdKV("teamId", f.teamId);
  sd += sdKV("deviceId", f.deviceId);
  sd += sdKV("stateId", f.stateId);
  sd += sdKV("clientIp", f.clientIp);
  sd += sdKV("requestId", f.requestId);
  sd += sdKV("reason", f.reason);
  if (f.extra) {
    for (const [k, v] of Object.entries(f.extra)) sd += sdKV(k, v);
  }
  sd += `]`;
  return sd;
}

async function writeSyslog(line: string) {
  const sock = createSocket("udp4");
  await new Promise<void>((res, rej) => {
    sock.send(Buffer.from(line), ENV.AUDIT_SYSLOG_PORT, ENV.AUDIT_SYSLOG_HOST, (err) => {
      sock.close();
      if (err) rej(err); else res();
    });
  });
}

async function writeFile(line: string) {
  await appendFile(ENV.AUDIT_FILE, line + "\n", { encoding: "utf8" });
}

/** Emit a single RFC5424 audit record to the configured sink. */
export async function emitAuditRFC5424(f: AuditFields) {
  // Facility from env; severity: 5=notice for success, 4=warning for failure
  const severity = f.result === "success" ? 5 : 4;
  const header =
    pri(ENV.AUDIT_SYSLOG_FACILITY, severity) +
    `1 ${rfc3339()} ${ENV.AUDIT_HOSTNAME} ${ENV.AUDIT_APPNAME} - AUDIT `;

  const sd = buildStructuredData(f);
  const msg = ""; // keep free-form MSG empty; all fields live in SD

  const line = `${header}${sd} ${msg}`.trimEnd();

  if (ENV.AUDIT_DEST === "syslog") return writeSyslog(line);
  return writeFile(line);
}

export type { AuditFields };


```


### How this works (env.ts vs .env)

* **`.env`**: where you set values (e.g., `DATABASE_URL=postgres://…`). It’s not code and doesn’t validate anything.
* **`env.ts`**: code that reads from SvelteKit’s `$env/*` modules and **validates** every variable with Zod. If anything is missing/invalid, the server throws immediately with a clear message.

### Usage examples

**Server code (never import this in client code):**

```ts
// src/lib/server/db/client.ts
import { ENV } from '$lib/config/env';
import pg from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';

const pool = new pg.Pool({ connectionString: ENV.DATABASE_URL });
export const db = drizzle({ client: pool });

// elsewhere
if (ENV.PROD) {
  // enable stricter logging, etc.
}
```

**Svelte components / browser (safe public only):**

```svelte
<script lang="ts">
  import { PUBLIC_ENV } from '$lib/config/env';
  const title = PUBLIC_ENV.PUBLIC_APP_NAME; // safe, client-visible
</script>

<h1>{title}</h1>
```


### Gotchas & tips

* Don’t import `ENV` in `+page.svelte` or any client-side module; it contains secrets. Use `PUBLIC_ENV` there.
* Prefer `$env/dynamic/*` (as shown) when you need runtime-set env in serverless/containers; prefer `$env/static/*` for compile-time constants.
* Keep the **same schema** in `drizzle.config.ts` checks (you already have that) for CLI-time validation.
