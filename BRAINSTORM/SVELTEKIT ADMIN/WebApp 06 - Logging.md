# LOGGING

awesome—let’s stand up a tidy, one-stop logging system you can drop in today. 
* one central config (dev vs prod, redaction, pretty printing, sampling)
* middleware for request/response logs with request-id
* tiny, composable helpers for audit events + function/route-level logs


---
## ENVIROIONMENT 
```
AUDIT_DEST=syslog            # or "file"
AUDIT_SYSLOG_HOST=127.0.0.1  # for syslog
AUDIT_SYSLOG_PORT=514
AUDIT_SYSLOG_FACILITY=10     # authpriv
AUDIT_APPNAME=surveylauncher-audit
AUDIT_HOSTNAME=localhost
AUDIT_FILE=/var/log/surveylauncher/audit.log  # used if AUDIT_DEST=file
```

## FILES
Seee below fore code

* `src/lib/server/utils/logger.ts` (central app logger + `audit(event, …)` wrapper)
* `src/lib/server/utils/audit.ts` (RFC-5424 emitter)

## Middleware 

```ts
// src/hooks.server.ts
import type { Handle } from "@sveltejs/kit";
import { withRequestLogging } from "$lib/server/utils/logger";

export const handle: Handle = withRequestLogging(async ({ event, resolve }) => {
  // attach user to event.locals if you have sessions
  return resolve(event);
});
```

## DESTINATION for Syslog/file sink (ops)**

* If `AUDIT_DEST=syslog`: ensure rsyslog/systemd-journald is receiving UDP:514 (or use your SIEM forwarder).
* If `AUDIT_DEST=file`: create the path and set write perms for your app user.




## `src/lib/server/utils/logger.ts` (central logging)

```ts
// src/lib/server/utils/logger.ts
/**
 * Central logger (Pino) + request-id middleware + audit bridge.
 * - Dev: pretty console; Prod: NDJSON to stdout
 * - Request-scoped child loggers: bind req_id/route
 * - audit(): writes both app JSON log AND RFC-5424 audit record
 *
 * Env (validated in $lib/config/env.ts):
 *   NODE_ENV, LOG_LEVEL, LOG_PRETTY, SERVICE_NAME
 *   AUDIT_* (sink + syslog/file options)
 */

import pino, { stdTimeFunctions, type Logger } from "pino";
import { randomUUID } from "node:crypto";
import type { Handle, RequestEvent } from "@sveltejs/kit";
import { ENV } from "$lib/config/env";
import { emitAuditRFC5424 } from "$lib/server/utils/audit";

// ----------------------- Types -----------------------
type AuditInput = {
  action: string;                  // e.g., 'pin.generate', 'auth.login'
  status: "ok" | "fail";
  userId?: string | null;
  teamId?: string | null;
  stateId?: string | null;
  deviceId?: string | null;
  latencyMs?: number | null;
  extra?: Record<string, unknown>; // never put secrets/pins/tokens here
};

// -------------------- Root Logger --------------------
const baseOptions = {
  name: ENV.SERVICE_NAME,
  level: ENV.LOG_LEVEL,
  timestamp: stdTimeFunctions.isoTime, // ISO8601 -> easier ingestion
  redact: {
    // last-line defense; don't rely on this to hide mistakes
    paths: [
      "req.headers.authorization",
      "req.headers.cookie",
      "extra.pin",
      "extra.token",
      "extra.secret",
    ],
    remove: true,
  },
} as const;

const transport = ENV.LOG_PRETTY
  ? {
      target: "pino-pretty",
      options: {
        colorize: true,
        translateTime: "SYS:standard",
        singleLine: true,
        ignore: "pid,hostname",
      },
    }
  : undefined;

const root: Logger = pino({ ...baseOptions, transport });

// Prefer request-scoped children in handlers; root is for process-level logs.
export function getLogger(): Logger {
  return root;
}

// -------------------- Helpers --------------------
function reqIdFromHeaders(h: Headers): string | undefined {
  return h.get("x-request-id") || h.get("x-correlation-id") || undefined;
}

/** Build a request-scoped child logger with req_id/route bound. */
export function childFor(event: RequestEvent, bindings: Record<string, any> = {}) {
  const req_id = (event.locals as any).requestId ?? "n/a";
  const route = event.route.id ?? event.url.pathname;
  return root.child({ req_id, route, ...bindings });
}

/** Small convenience for timing blocks: const done = timeit(); ...; const ms = done(); */
export function timeit() {
  const t0 = Date.now();
  return () => Date.now() - t0;
}

// -------------------- Middleware --------------------
/**
 * SvelteKit handle wrapper that:
 *  - assigns event.locals.requestId
 *  - logs request start/finish with latency
 *  - adds X-Request-Id header to response
 */
export function withRequestLogging(next: Handle): Handle {
  return async ({ event, resolve }) => {
    const started = Date.now();
    const requestId = reqIdFromHeaders(event.request.headers) || randomUUID();
    (event.locals as any).requestId = requestId;

    const log = childFor(event, {
      ip: event.getClientAddress?.(),
      method: event.request.method,
      path: event.url.pathname,
    });

    log.info({ at: "request:start" });

    let response: Response;
    try {
      response = await next({ event, resolve });
    } catch (err: any) {
      log.error({ at: "request:error", err: err?.message, latency_ms: Date.now() - started });
      throw err;
    }

    const latency_ms = Date.now() - started;
    const headers = new Headers(response.headers);
    headers.set("x-request-id", requestId);

    log.info({ at: "request:finish", status: response.status, latency_ms });
    return new Response(response.body, { status: response.status, headers });
  };
}

// -------------------- Audit Bridge --------------------
/**
 * Emit a single audit record:
 *  1) App JSON log (searchable in app logs)
 *  2) RFC-5424 security audit stream (syslog/file), via emitAuditRFC5424()
 *
 * Call AFTER an action completes (success or failure).
 */
export async function audit(event: RequestEvent, a: AuditInput) {
  const requestId = (event.locals as any)?.requestId ?? null;
  const userId = (event.locals as any)?.user?.id ?? a.userId ?? null;
  const clientIp = event.getClientAddress?.() ?? null;

  // 1) Mirror to app log (JSON) for convenience
  childFor(event).info({
    at: "audit",
    action: a.action,
    status: a.status,
    user_id: userId,
    team_id: a.teamId ?? null,
    state_id: a.stateId ?? null,
    device_id: a.deviceId ?? null,
    latency_ms: a.latencyMs ?? null,
    extra: a.extra ?? {},
  });

  // 2) RFC 5424 security-grade audit log
  await emitAuditRFC5424({
    action: a.action,
    result: a.status === "ok" ? "success" : "failure",
    userId,
    teamId: a.teamId ?? null,
    deviceId: a.deviceId ?? null,
    stateId: a.stateId ?? null,
    clientIp,
    requestId,
    // Keep extra short & secret-free; include latency as a convenience.
    extra: a.latencyMs != null ? { latency_ms: a.latencyMs } : undefined,
  });
}

/**
 * Guidance:
 * - Use getLogger() only for startup/process logs.
 * - In routes/endpoints, always use childFor(event) for request-scoped logs.
 * - Use audit() for security-relevant actions (auth, PIN, policy, device ops).
 * - Never log secrets/PINs/tokens; redaction is only a safety net.
 */
```




## src/lib/server/utils/audit.ts (RFC 5424)

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


## Service example (critical function)

```ts
// inside src/lib/server/services/pin.service.ts
import { getLogger } from "$lib/server/utils/logger";
const log = getLogger(); // process-level (avoid per-request data here)

// … when you rotate:
// log.info({ at: "pin.rotate", teamId, kind, version: nextVersion });
```

> Tip: keep request-scoped logs in routes (they have `req_id`), and keep long-lived background/service logs at process scope (no `req_id`). When a service must emit request-scoped logs, pass a logger down (or the RequestEvent) and call `childFor(event)` in the route, then hand the child to the service.

---

# Ops guidance (dev vs prod)

* **Dev (default)**: pretty console logs (human-readable), `LOG_PRETTY=true`, `LOG_LEVEL=debug` recommended.
* **Prod**: set `LOG_PRETTY=false` (or omit; it defaults false in prod). Ship logs as newline-delimited JSON to stdout. Let your runtime (systemd, Docker, k8s) collect → Loki/ELK/Datadog.
* **Levels**:

  * `info`: lifecycle + audits + successful requests
  * `warn`: client errors, soft failures, retries
  * `error`: unhandled server errors
  * `debug`: development details and rare, sampled verbose events

Example `.env`:

```
NODE_ENV=production
LOG_LEVEL=info
LOG_PRETTY=false
SERVICE_NAME=surveylauncher-api
```

---

# What you can log where (quick rules)

* **Middleware** (already handled):

  * `request:start` → method, path
  * `request:finish` → status, latency
  * `request:error` → error + latency
* **Audit** (use `audit(event, {...})`):

  * Action names should be stable verbs: `pin.generate`, `pin.reveal`, `device.enroll`, `policy.ack`
  * Include `teamId`, `userId`, and **never** raw secrets/PINs
* **Endpoints**:

  * `debug` for parameters and branch decisions (without sensitive data)
  * pair every `throw` with a `warn` or `error` log
* **Services/jobs**:

  * `info` on important state changes (rotate, revoke)
  * `error` on crashes; add minimal context keys (ids, counts)

---


## AUDIOT LOGs


* **Syslog path:** With `AUDIT_DEST=syslog`, messages land in your system’s syslog (RFC 5424). On Ubuntu, configure rsyslog to route `authpriv` facility to a dedicated file:

```ini
  # /etc/rsyslog.d/50-surveylauncher-audit.conf
  if ($msg contains "surveylauncher-audit") then /var/log/surveylauncher/audit.log
  & stop
```

Then `sudo systemctl restart rsyslog`.

* **File path:** With `AUDIT_DEST=file`, ensure the directory exists and the app user can write:

```bash
  sudo install -d -m 0750 -o appuser -g adm /var/log/surveylauncher
  sudo touch /var/log/surveylauncher/audit.log && sudo chown appuser:adm /var/log/surveylauncher/audit.log
```

* **Rotation:** use `logrotate` (file sink) or your syslog’s rotation (syslog sink). Sample logrotate stanza:

```bash
  /var/log/surveylauncher/audit.log {
    weekly
    rotate 26
    compress
    missingok
    notifempty
    create 0640 appuser adm
    postrotate
      systemctl reload rsyslog >/dev/null 2>&1 || true
    endscript
  }
```

# 5) What you get

* **Separate, RFC 5424-formatted audit log** for compliance review and SIEM ingestion.
* **App logs unchanged** (pretty in dev, NDJSON in prod).
* **Zero duplication of business logic**—your routes keep calling `audit(event, …)`.







---
# USING LOGGER

## 1) In an API route — call `audit()` after the action

### PIN generate (success + failure)

```ts
// src/routes/api/pin/+server.ts
import { json, error, type RequestHandler } from "@sveltejs/kit";
import { audit, childFor, timeit } from "$lib/server/utils/logger";
import { createOrRotatePin } from "$lib/server/services/pin.service";

export const POST: RequestHandler = async (event) => {
  const log = childFor(event, { mod: "api.pin" });
  const done = timeit();

  try {
    const { teamId, kind, keepReveal } = await event.request.json();
    const out = await createOrRotatePin(event.locals.user!, teamId, kind, { keepReveal });

    const ms = done();
    // RFC 5424 + app JSON log
    await audit(event, {
      action: "pin.generate",
      status: "ok",
      userId: event.locals.user?.id,
      teamId,
      latencyMs: ms,
      extra: { kind }
    });

    log.info({ at: "pin.generate", teamId, kind, latency_ms: ms });
    return json(out, { status: 201 });
  } catch (e: any) {
    const ms = done();
    await audit(event, {
      action: "pin.generate",
      status: "fail",
      latencyMs: ms,
      // keep reason short & secret-free
      extra: { reason: "validation_error" }
    });
    throw error(400, "Unable to generate PIN");
  }
};
```

### PIN reveal (only if allowed)

```ts
import { revealPin } from "$lib/server/services/pin.service";
import { audit, childFor, timeit } from "$lib/server/utils/logger";

export const GET: RequestHandler = async (event) => {
  const log = childFor(event, { mod: "api.pin" });
  const msDone = timeit();

  try {
    const teamId = event.url.searchParams.get("teamId")!;
    const kind   = event.url.searchParams.get("kind") as "TEAM" | "SUPERVISOR";
    const out = await revealPin(event.locals.user!, teamId, kind);

    const ms = msDone();
    await audit(event, {
      action: "pin.reveal",
      status: "ok",
      userId: event.locals.user?.id,
      teamId,
      latencyMs: ms,
      extra: { kind, version: out.version }
    });

    return new Response(JSON.stringify(out), { status: 200 });
  } catch (e: any) {
    const ms = msDone();
    await audit(event, {
      action: "pin.reveal",
      status: "fail",
      latencyMs: ms,
      extra: { reason: "not_allowed" }
    });
    throw e;
  }
};
```

---

# 2) Auth endpoints — same pattern

```ts
// src/routes/api/auth/login/+server.ts
import { audit, childFor, timeit } from "$lib/server/utils/logger";
export const POST: RequestHandler = async (event) => {
  const log = childFor(event, { mod: "api.auth" });
  const done = timeit();

  try {
    const { email, password } = await event.request.json();
    // …perform login…
    const userId = "u_123"; // from DB
    const ms = done();
    await audit(event, { action: "auth.login", status: "ok", userId, latencyMs: ms });
    log.info({ at: "auth.login", userId, latency_ms: ms });
    return new Response(null, { status: 204 });
  } catch (e: any) {
    const ms = done();
    await audit(event, { action: "auth.login", status: "fail", latencyMs: ms, extra: { reason: "bad_credentials" } });
    throw e;
  }
};
```

---

# 3) Services/jobs — pass a logger or just call `emitAuditRFC5424` (optional)

If you’re **not** in a request context (cron job, backfill), you can emit RFC directly:

```ts
// src/jobs/policy-backfill.ts
import { emitAuditRFC5424 } from "$lib/server/utils/audit";
import { getLogger } from "$lib/server/utils/logger";

const log = getLogger().child({ mod: "jobs.policy-backfill" });

export async function backfillPolicyAcks() {
  // …do work…
  log.info({ at: "start" });
  await emitAuditRFC5424({
    action: "policy.ack.backfill",
    result: "success",
    userId: null, teamId: "t_001", stateId: "s_DL",
    extra: { count: 142 }
  });
  log.info({ at: "done", count: 142 });
}
```

---

# 4) What lands where

* **App logs (JSON/pretty)**: still printed by `logger.ts` (request start/finish, your `log.info`, and the JSON “audit mirror”).
* **Audit logs (RFC-5424)**: separate stream via `emitAuditRFC5424` (called inside `audit()`), delivered to:

  * **syslog** (UDP 514) with facility `authpriv` (10), or
  * **file** at `AUDIT_FILE` if you chose `AUDIT_DEST=file`.

Example RFC-5424 line (syslog/file):

```
<85>1 2025-10-07T09:12:34.567Z localhost surveylauncher-audit - AUDIT [audit@32473 action="pin.generate" result="success" userId="u_123" teamId="t_001" clientIp="203.0.113.5" requestId="5d2c..." latency_ms="42"] 
```

* `<85>` is PRI (facility 10 * 8 + severity 5 = Notice).
* All data is in the `[audit@32473 ...]` structured-data block.

The Org ID defined in .env

---

# 5) Ops quick checks

* **Syslog sink**: `sudo journalctl -u rsyslog | tail` and check your file route (if you configured one):

  ```
  sudo tail -f /var/log/surveylauncher/audit.log
  ```
* **File sink**: just tail:

  ```
  sudo tail -f /var/log/surveylauncher/audit.log
  ```

---

# 6) What to put into `audit()` (cheat-sheet)

* `action` — stable verbs: `auth.login`, `pin.generate`, `pin.reveal`, `pin.revoke`, `device.enroll`, `policy.ack`
* `status` — `"ok"` / `"fail"`
* `userId`, `teamId`, `deviceId` — IDs only (no emails/PII)
* `latencyMs` — optional but nice
* `extra.reason` — short code for failure; **no secrets**; no raw request bodies

---

# 7) Common pitfalls (avoid)

* Don’t log raw PINs/tokens anywhere (app logs or audit).
* Don’t put secrets into `extra.*`.
* Keep `extra` small (key=value style). Use the app log for verbose context.

That’s all you need. Copy the route snippets, call `audit(event, …)` after each critical action, and your RFC-grade audit trail will be populated alongside your normal app logs.
