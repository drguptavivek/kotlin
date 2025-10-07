# **SvelteKit + Drizzle + Zod + Superforms** 


# 1) Install & init

```bash
# SvelteKit + tooling
npm i -D typescript vite @sveltejs/kit @sveltejs/adapter-node

# Drizzle (Postgres) + helpers
npm i drizzle-orm drizzle-kit pg
npm i -D @types/pg

# Forms + validation
npm i zod sveltekit-superforms

# Optional: dotenv for local dev
npm i -D dotenv
```

# Project layout

```
surveylauncher/
├─ .env.example
├─ drizzle.config.ts
├─ package.json
├─ tsconfig.json
├─ vite.config.ts
├─ svelte.config.js
├─ src/
│  ├─ app.d.ts
│  ├─ hooks.server.ts
│  ├─ lib/
│  │  ├─ config/
│  │  │  └─ env.ts                 # safe env parsing (zod)
│  │  ├─ server/
│  │  │  ├─ db/
│  │  │  │  ├─ client.ts           # drizzle client (pg Pool)
│  │  │  │  └─ schema.ts           # <-- your final schema
│  │  │  ├─ services/
│  │  │  │  ├─ rbac.ts             # canUser(…)/requireRole(…)
│  │  │  │  ├─ pin.service.ts      # create/rotate/verify PIN (argon2id + AEAD)
│  │  │  │  ├─ device.service.ts   # upsert by androidId, telemetry, policy ack
│  │  │  │  └─ enrollment.service.ts# QR token mint/revoke/use
│  │  │  ├─ auth/
|  |  |  |  ├─ betterAuth/
|  |  |  |  │    └─auth.ts 
│  │  │  │  └─ session.ts          # (if needed) server session helpers
│  │  │  ├
│  │  │  └─ utils/
│  │  │     ├─ crypto.ts           # sodium/argon2 wrappers (PHC helpers)
│  │  │     └─ logger.ts           # request-id, audit logs
│  │  ├─ validation/               #v SEE Zofd schema.md
│  │  │  └─ zod.config.ts                 
|  |  |  ├─ enums.ts                     # shared enums mirroring DB enums
|  |  |  └─ models/
|  |  |   ├─ state.ts
|  |  |   ├─ team.ts
|  |  |   ├─ role.ts
|  |  |   ├─ user.ts
|  |  |   ├─ userRole.ts
|  |  |   ├─ supervisor.ts
|  |  |   ├─ device.ts
|  |  |   ├─ enrollmentToken.ts
|  |  |   ├─ event.ts
|  |  |   ├─ policyAck.ts
|  |  |   ├─ pin.ts
|  |  |   └─ index.ts  
│  │  └─ ui/
│  │     ├─ forms/
│  │     │  └─ fields.ts           # small helpers for superforms
│  │     └─ components/
│  │        └─ Card.svelte
│  └─ routes/
│     ├─ +layout.svelte
│     ├─ +layout.server.ts         # load user/session/roles
│     ├─ (admin)/
│     │  ├─ teams/
│     │  │  ├─ +page.server.ts     # list/create teams via superforms
│     │  │  └─ +page.svelte
│     │  ├─ pins/
│     │  │  ├─ +page.server.ts     # rotate team/supervisor PIN, mark isCurrent
│     │  │  └─ +page.svelte
│     │  ├─ devices/
│     │  │  ├─ +page.server.ts     # block/unblock, assign team, telemetry view
│     │  │  └─ +page.svelte
│     │  └─ enrollments/
│     │     ├─ +page.server.ts     # mint/revoke QR tokens
│     │     └─ +page.svelte
│     ├─ api/
│     │  ├─ device/
│     │  │  └─ heartbeat/+server.ts # POST device heartbeat/telemetry (JSON)
│     │  ├─ policy/
│     │  │  └─ ack/+server.ts       # POST device policy ACK
│     │  └─ pin/
│     │     └─ verify/+server.ts    # POST pin verify (device login)
│     └─ health/+server.ts          # GET healthz for LB
├─ drizzle/
│  └─ migrations/                   # generated SQL
└─ scripts/
   ├─ seed.ts                       # seed roles, admin, demo state/team
   └─ demo-data.ts                  # optional demo fillers
```



---

# 2) ENVIRONMENT
WebApp 00.1- environment.md


---

# 3) `drizzle.config.ts`

```ts
// drizzle.config.ts
import 'dotenv/config';
import { defineConfig } from 'drizzle-kit';
import { z } from 'zod';

const Env = z.object({
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required')
}).safeParse(process.env);

if (!Env.success) {
  console.error('❌ Invalid environment variables for Drizzle:', Env.error.flatten().fieldErrors);
  throw new Error('Fix .env before running Drizzle.');
}

export default defineConfig({
  schema: './src/lib/server/db/schema.ts',   // keep in sync if you move the file
  out: './drizzle/migrations',               // generated SQL migrations
  dialect: 'postgresql',
  dbCredentials: { url: Env.data.DATABASE_URL },
  strict: true,                              // fail on unknown data types
  verbose: true                              // more logging from drizzle-kit
});

```

---

# 4) DB schema (`src/lib/server/db/schema.ts`) and drizzle 

see "WebApp 02 - Schema.md"

Notes
- Scopes: device derives state through team (no duplicate stateId on device).
- PINs: use verifierPhc (Argon2id PHC) + optional AEAD bundle and isCurrent flag. Unique (teamId, kind, version) guarantees versioning; index (teamId, kind, isCurrent) makes “active PIN” lookups cheap.
- Enrollment: enrollment_token formalizes the QR flow (short-lived JWT w/ jti, revoke/use audit).
- Telemetry & Policy: event covers device activity; policy_ack dedupes by (deviceId, policyId).
- Consistency: singular table names, defaultRandom() UUIDs, UTC timestamps with TZ, compact indexes for common queries.

#### DB client (Drizzle)

`src/lib/server/db/client.ts`

```ts
import { drizzle } from 'drizzle-orm/node-postgres';
import pg from 'pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL! });
export const db = drizzle({ client: pool });
```

---

# Zod Valdiation

see "WebApp 03 - Zod valdiation.md"


# Services

See "WebApp 04 Services.md"


---

# Superforms pattern (create Team)

`src/routes/(admin)/teams/+page.server.ts`

```ts
import { superValidate } from 'sveltekit-superforms/server';
import { teamUpsertSchema } from '$lib/validation/team';
import { db } from '$lib/server/db/client';
import { teams } from '$lib/server/db/schema';
import { fail, redirect } from '@sveltejs/kit';

export const load = async () => ({
  form: await superValidate(teamUpsertSchema)
});

export const actions = {
  create: async ({ request }) => {
    const form = await superValidate(request, teamUpsertSchema);
    if (!form.valid) return fail(400, { form });

    await db.insert(teams).values({
      name: form.data.name,
      stateId: form.data.stateId,
      timezone: form.data.timezone
    });

    throw redirect(303, '/teams');
  }
};
```

`src/routes/(admin)/teams/+page.svelte`

```svelte
<script lang="ts">
  import { enhance } from 'sveltekit-superforms/client';
  export let data; // { form }
</script>

<form method="POST" use:enhance>
  <input name="name" value={data.form.data.name} />
  <input name="stateId" value={data.form.data.stateId} />
  <input name="timezone" value={data.form.data.timezone} />
  <button name="?/create" value="1">Create</button>
  {#if data.form.errors.name}<p>{data.form.errors.name}</p>{/if}
</form>
```

---

# 7)

---

# 8) Scripts

`package.json` (snippets)

```json
{
  "scripts": {
    "dev": "svelte-kit dev",
    "build": "svelte-kit build",
    "preview": "svelte-kit preview",
    "start": "node build",                   

    "typecheck": "tsc -p tsconfig.json --noEmit",
    "lint": "eslint .",
    "format": "prettier --write .",

    "db:generate": "drizzle-kit generate",
    "db:migrate": "drizzle-kit migrate",
    "db:studio": "drizzle-kit studio",

    "seed": "tsx src/lib/server/db/seed.ts"
  }
}

Notes:
start assumes adapter-node output (run after build).
seed uses tsx; install with npm i -D tsx (or swap for ts-node if you prefer)

```

---

# 9) LLM-friendly conventions (SvelteKit)


---

# 10) What’s next (quick picks)

* Want me to add **seed scripts** (roles, an admin user, a demo state/team) and a **PIN service** (server-generated Argon2id verifier + AEAD ciphertext) wired to a Superform?
* Or sketch the **policy JSON signer** service and a `/api/policy` route stub?

> P.S. All of this tracks with your earlier flows/spec (team-scoped PINs, device JIT provisioning, QR phases, admin reveal model). If you want the SvelteKit versions of those endpoints next, say the word and I’ll drop the `/v1/*` route stubs with Zod + Superforms-backed admin screens.   
