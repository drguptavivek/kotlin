# **SvelteKit + Drizzle + Zod + Superforms** 

nice—here’s a compact, production-ready **Zod config** you can drop in to standardize validation across pages, APIs, and Superforms.


absolutely — the cleanest way is to keep **one Zod module per DB model**, plus a tiny shared enums file. Here’s a ready-to-drop structure and code.

# Layout

```
src/lib/validation/
├─ zod.config.ts                # (you already have this)
├─ enums.ts                     # shared enums mirroring DB enums
└─ models/
   ├─ state.ts
   ├─ team.ts
   ├─ role.ts
   ├─ user.ts
   ├─ userRole.ts
   ├─ supervisor.ts
   ├─ device.ts
   ├─ enrollmentToken.ts
   ├─ event.ts
   ├─ policyAck.ts
   ├─ pin.ts
   └─ index.ts                  # barrel exports
```

# `src/lib/validation/zod.config.ts`
here you go — a complete `src/lib/validation/zod.config.ts` tailored for the **model-wise split** (only globals, primitives, shared shapes + error map). Import this once in `hooks.server.ts` (and optionally `hooks.client.ts`) to register the error map.

```ts
// src/lib/validation/zod.config.ts
import { z, ZodErrorMap, ZodIssueCode } from 'zod';

/* =========================================================
   Global Zod error map (short, friendly messages)
   ========================================================= */
const errorMap: ZodErrorMap = (issue, ctx) => {
  const d = (m: string) => ({ message: m });

  if (issue.code === ZodIssueCode.invalid_type && issue.received === 'undefined') return d('Required');

  if (issue.code === ZodIssueCode.too_small) {
    if (issue.type === 'string') return d(`Min ${issue.minimum} chars`);
    if (issue.type === 'number') return d(`Min ${issue.minimum}`);
    if (issue.type === 'array')  return d(`Pick at least ${issue.minimum}`);
  }

  if (issue.code === ZodIssueCode.too_big) {
    if (issue.type === 'string') return d(`Max ${issue.maximum} chars`);
    if (issue.type === 'number') return d(`Max ${issue.maximum}`);
    if (issue.type === 'array')  return d(`Pick at most ${issue.maximum}`);
  }

  if (issue.code === ZodIssueCode.invalid_string) {
    if (issue.validation === 'email') return d('Invalid email');
    if (issue.validation === 'uuid')  return d('Invalid id');
    if (issue.validation === 'url')   return d('Invalid URL');
  }

  // Optional i18n hook via issue.params.i18n
  if (issue.code === ZodIssueCode.custom && typeof issue.params?.i18n === 'string') {
    return d(issue.params.i18n);
  }

  return { message: ctx.defaultError };
};
z.setErrorMap(errorMap);

/* =========================================================
   Primitive helpers (trimmed, coercions, ids)
   Keep this file free of model-specific schemas.
   ========================================================= */

// Basic trimmed string
export const zStr = (min = 1, max = 255) => z.string().trim().min(min).max(max);

// Optional trimmed string → undefined if empty
export const zStrOpt = (max = 255) =>
  z.string().trim().max(max).transform((s) => (s === '' ? undefined : s)).optional();

// UUID
export const zUUID = () => z.string().uuid();

// Email
export const zEmail = () => z.string().email().toLowerCase();

// India-centric phone (flexible, 10–15 digits with optional +)
export const zPhone = () => z.string().trim().regex(/^\+?\d{10,15}$/, 'Invalid phone number');

// Short codes (TEAM/STATE)
export const zTeamCode  = () => z.string().trim().min(2).max(32).regex(/^[A-Z0-9_\-]+$/, 'Use A–Z, 0–9, _ or -');
export const zStateCode = () => z.string().trim().min(2).max(16).regex(/^[A-Z0-9_\-]+$/, 'Use A–Z, 0–9, _ or -');

// Android ID (typical 16 hex; allow OEM variants up to 64 & dashes)
export const zAndroidId = () => z.string().trim().regex(/^[a-fA-F0-9-]{8,64}$/, 'Invalid androidId');

// Numeric PIN (4–8 digits)
export const zPin = (min = 4, max = 8) =>
  z.string().trim().regex(new RegExp(`^\\d{${min},${max}}$`), `PIN must be ${min}–${max} digits`);

// JWT (coarse)
export const zJwt = () =>
  z.string().trim().regex(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/, 'Invalid token');

// Coercions
export const zInt  = (min?: number, max?: number) => {
  let s = z.coerce.number().int();
  if (min !== undefined) s = s.min(min);
  if (max !== undefined) s = s.max(max);
  return s;
};
export const zBool = () => z.coerce.boolean();
export const zDate = () => z.coerce.date(); // store UTC on server

/* =========================================================
   Shared shapes (reused across model modules)
   ========================================================= */

// Pagination for admin lists
export const zPagination = z.object({
  page: zInt(1).default(1),
  pageSize: zInt(1, 200).default(25)
});

// Optional audit reason (attach to admin mutations)
export const zAuditMeta = z.object({
  reason: zStr(3, 160)
}).partial();

/* =========================================================
   Utilities
   ========================================================= */

// Strict parse helper with compact error details (good for services/APIs)
export function parseOrThrow<T extends z.ZodTypeAny>(schema: T, data: unknown): z.infer<T> {
  const r = schema.safeParse(data);
  if (!r.success) {
    const details = r.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message }));
    const e = new Error('ValidationError');
    (e as any).details = details;
    throw e;
  }
  return r.data;
}

// Re-export Zod for convenience (so model files can `import { z } from '$lib/validation/zod.config'`)
export { z };
```

**Wire-up tip:**
Add `import '$lib/validation/zod.config';` so the error map is registered app-wide. in 
 - `src/hooks.server.ts` 
 - Optionally `src/hooks.client.ts`




---

# `src/lib/validation/enums.ts`

```ts
import { z } from 'zod';

// Keep these arrays as **single source of truth** for UI selects & validation.
// They mirror your DB pgEnum definitions.
export const ROLE_NAME = ['NATIONAL_ADMIN','STATE_ADMIN','SUPERVISOR','TEAM_MEMBER'] as const;
export const PIN_KIND  = ['TEAM','SUPERVISOR'] as const;
export const DEVICE_STATUS = ['ACTIVE','BLOCKED','RETIRED'] as const;
export const EVENT_TYPE = [
  'login_success','login_denied','app_launch','app_launch_denied',
  'pin_success','pin_failure','supervisor_session_started','supervisor_session_expired',
  'policy_applied','time_violation','heartbeat'
] as const;

export const zRoleName = z.enum(ROLE_NAME);
export const zPinKind = z.enum(PIN_KIND);
export const zDeviceStatus = z.enum(DEVICE_STATUS);
export const zEventType = z.enum(EVENT_TYPE);

export type RoleName = z.infer<typeof zRoleName>;
export type PinKind  = z.infer<typeof zPinKind>;
export type DeviceStatus = z.infer<typeof zDeviceStatus>;
export type EventType = z.infer<typeof zEventType>;
```

---

Below, each model file imports primitives from `zod.config.ts`:

```ts
// import helpers
import { z, type ZodType } from 'zod';
import {
  zUUID, zStr, zStrOpt, zEmail, zPhone, zTeamCode, zStateCode,
  zAndroidId, zPin, zInt, zDate, zPagination
} from '$lib/validation/zod.config';
```

I’ll show compact, production-ready schemas for all models.

---

## `src/lib/validation/models/state.ts`

```ts
import { z } from 'zod';
import { zUUID, zStr, zStateCode, zPagination } from '$lib/validation/zod.config';

export const zStateId = z.object({ id: zUUID() });

export const zStateCreate = z.object({
  code: zStateCode(),
  name: zStr(2, 128)
});

export const zStateUpdate = zStateCreate.partial().extend({
  id: zUUID()
});

export const zStateFilter = z.object({
  q: zStr(0, 64).optional(),
  ...zPagination.shape
});

export type StateId = z.infer<typeof zStateId>;
export type StateCreate = z.infer<typeof zStateCreate>;
export type StateUpdate = z.infer<typeof zStateUpdate>;
export type StateFilter = z.infer<typeof zStateFilter>;
```

---

## `src/lib/validation/models/team.ts`

```ts
import { z } from 'zod';
import { zUUID, zStr, zTeamCode, zPagination } from '$lib/validation/zod.config';

export const zTeamId = z.object({ id: zUUID() });

export const zTeamCreate = z.object({
  stateId: zUUID(),
  code: zTeamCode(),
  name: zStr(2, 128),
  timezone: zStr(2, 64).default('Asia/Kolkata')
});

export const zTeamUpdate = zTeamCreate.partial().extend({ id: zUUID() });

export const zTeamFilter = z.object({
  stateId: zUUID().optional(),
  q: zStr(0, 64).optional(),
  ...zPagination.shape
});

export type TeamCreate = z.infer<typeof zTeamCreate>;
export type TeamUpdate = z.infer<typeof zTeamUpdate>;
export type TeamFilter = z.infer<typeof zTeamFilter>;
```

---

## `src/lib/validation/models/role.ts`

```ts
import { z } from 'zod';
import { zRoleName } from '$lib/validation/enums';

export const zRoleCreate = z.object({
  name: zRoleName,
  description: z.string().max(512).optional()
});

export const zRoleUpdate = zRoleCreate.partial().extend({
  id: z.string().uuid()
});

export type RoleCreate = z.infer<typeof zRoleCreate>;
export type RoleUpdate = z.infer<typeof zRoleUpdate>;
```

---

## `src/lib/validation/models/user.ts`

```ts
import { z } from 'zod';
import { zUUID, zEmail, zStrOpt } from '$lib/validation/zod.config';

export const zUserId = z.object({ id: zUUID() });

export const zUserCreate = z.object({
  email: zEmail(),
  fullName: zStrOpt(255),
  isActive: z.boolean().default(true),
  homeStateId: zUUID().optional()
});

export const zUserUpdate = zUserCreate.partial().extend({ id: zUUID() });

export type UserCreate = z.infer<typeof zUserCreate>;
export type UserUpdate = z.infer<typeof zUserUpdate>;
```

---

## `src/lib/validation/models/userRole.ts`

```ts
import { z } from 'zod';
import { zUUID } from '$lib/validation/zod.config';
import { zRoleName } from '$lib/validation/enums';

export const zUserRoleCreate = z.object({
  userId: zUUID(),
  roleName: zRoleName,          // map to role by name server-side
  stateId: zUUID().optional(),  // scope (optional)
  teamId: zUUID().optional()
}).refine(
  (v) => !(v.roleName === 'STATE_ADMIN' && !v.stateId),
  { message: 'stateId required for STATE_ADMIN', path: ['stateId'] }
).refine(
  (v) => !(v.roleName === 'SUPERVISOR' && !v.teamId),
  { message: 'teamId required for SUPERVISOR', path: ['teamId'] }
);

export const zUserRoleDelete = z.object({ id: zUUID() }); // if you track by id

export type UserRoleCreate = z.infer<typeof zUserRoleCreate>;
```

---

## `src/lib/validation/models/supervisor.ts`

```ts
import { z } from 'zod';
import { zUUID, zPhone, zStrOpt } from '$lib/validation/zod.config';

export const zSupervisorCreate = z.object({
  userId: zUUID(),
  teamId: zUUID(),
  phone: zPhone().optional(),
  notes: zStrOpt(512),
  isActive: z.boolean().default(true)
});

export const zSupervisorUpdate = zSupervisorCreate.partial().extend({
  id: zUUID()
});

export type SupervisorCreate = z.infer<typeof zSupervisorCreate>;
export type SupervisorUpdate = z.infer<typeof zSupervisorUpdate>;
```

---

## `src/lib/validation/models/device.ts`

```ts
import { z } from 'zod';
import { zUUID, zStrOpt, zAndroidId, zStr } from '$lib/validation/zod.config';
import { zDeviceStatus } from '$lib/validation/enums';

export const zDeviceUpsert = z.object({
  androidId: zAndroidId(),
  teamId: zUUID().optional(),     // may be attached later
  manufacturer: zStrOpt(64),
  model: zStrOpt(64),
  osRelease: zStrOpt(32),
  osIncremental: zStrOpt(64),
  securityPatch: zStrOpt(16),
  isDeviceOwner: z.boolean().default(false),
  appVersion: zStrOpt(32),
  counters: z.any().optional()
});

export const zDeviceAssignTeam = z.object({
  androidId: zAndroidId(),
  teamId: zUUID()
});

export const zDeviceSetStatus = z.object({
  androidId: zAndroidId(),
  status: zDeviceStatus
});

export type DeviceUpsert = z.infer<typeof zDeviceUpsert>;
export type DeviceAssignTeam = z.infer<typeof zDeviceAssignTeam>;
export type DeviceSetStatus = z.infer<typeof zDeviceSetStatus>;
```

---

## `src/lib/validation/models/enrollmentToken.ts`

```ts
import { z } from 'zod';
import { zUUID, zInt } from '$lib/validation/zod.config';

export const zEnrollmentMint = z.object({
  teamId: zUUID(),
  ttlMinutes: zInt(5, 24 * 60).default(60)
});

export const zEnrollmentRevoke = z.object({
  id: zUUID() // or jti if you expose it
});

export type EnrollmentMint = z.infer<typeof zEnrollmentMint>;
```

---

## `src/lib/validation/models/event.ts`

```ts
import { z } from 'zod';
import { zUUID, zAndroidId, zStrOpt } from '$lib/validation/zod.config';
import { zEventType } from '$lib/validation/enums';

// Device-facing telemetry ingest
export const zEventIngest = z.object({
  androidId: zAndroidId(),
  teamId: zUUID().optional(),   // optional (server can derive via device)
  type: zEventType,
  data: z.any().optional()
});

// Admin filters
export const zEventFilter = z.object({
  teamId: zUUID().optional(),
  type: zEventType.optional()
});

export type EventIngest = z.infer<typeof zEventIngest>;
export type EventFilter = z.infer<typeof zEventFilter>;
```

---

## `src/lib/validation/models/policyAck.ts`

```ts
import { z } from 'zod';
import { zAndroidId, zStr } from '$lib/validation/zod.config';

export const zPolicyAckPost = z.object({
  androidId: zAndroidId(),
  policyId: zStr(1, 64)
});

export type PolicyAckPost = z.infer<typeof zPolicyAckPost>;
```

---

## `src/lib/validation/models/pin.ts`

```ts
import { z } from 'zod';
import { zUUID, zTeamCode, zPin, zStr } from '$lib/validation/zod.config';
import { zPinKind } from '$lib/validation/enums';

// Admin-side rotate/generate
export const zPinRotate = z.object({
  teamId: zUUID(),
  kind: zPinKind,                  // TEAM | SUPERVISOR
  reason: zStr(3, 160)
});

// Device-side verify
export const zPinVerify = z.object({
  androidId: z.string().min(1),    // you might prefer zAndroidId()
  teamCode: zTeamCode(),
  pin: zPin()
});

export type PinRotate = z.infer<typeof zPinRotate>;
export type PinVerify = z.infer<typeof zPinVerify>;
```

---

## `src/lib/validation/models/index.ts` (barrel)

```ts
export * as State from './state';
export * as Team from './team';
export * as Role from './role';
export * as User from './user';
export * as UserRole from './userRole';
export * as Supervisor from './supervisor';
export * as Device from './device';
export * as EnrollmentToken from './enrollmentToken';
export * as Event from './event';
export * as PolicyAck from './policyAck';
export * as Pin from './pin';
```

---

# How to use (patterns)

* **Superforms page**: import the specific `...Create` / `...Update` schema for that page.
* **Admin JSON APIs**: use `...Filter`, `...SetStatus`, etc. in your `+server.ts`.
* **Device APIs**: only the device-facing schemas (`PinVerify`, `EventIngest`, `PolicyAckPost`) should be imported in `/api/*`.
* **Enums**: import from `enums.ts` once; reuse values for UI dropdowns and schema validation to avoid drift with DB.

This keeps validation **cohesive, discoverable, and model-centric**, so your LLM (and you) always know where to look and what to reuse.


**Superforms page:**

```ts
// +page.server.ts
import { superValidate } from 'sveltekit-superforms/server';
import { zTeamUpsert } from '$lib/validation/zod.config';
import { fail, redirect } from '@sveltejs/kit';
import { db } from '$lib/server/db/client';
import { team } from '$lib/server/db/schema';

export const load = async () => ({ form: await superValidate(zTeamUpsert) });

export const actions = {
  create: async ({ request }) => {
    const form = await superValidate(request, zTeamUpsert);
    if (!form.valid) return fail(400, { form });

    await db.insert(team).values(form.data);
    throw redirect(303, '.');
  }
};
```

**API endpoint:**

```ts
// src/routes/api/pin/verify/+server.ts
import { json, error } from '@sveltejs/kit';
import { zPinVerify, parseOrThrow } from '$lib/validation/zod.config';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async ({ request }) => {
  const data = parseOrThrow(zPinVerify, await request.json());
  // … call service.verify(data)
  return json({ ok: true });
};
```

**Client form schema reuse (Superforms client):**

```ts
// +page.svelte
<script lang="ts">
  import { enhance } from 'sveltekit-superforms/client';
  export let data; // contains { form }
</script>

<form method="POST" use:enhance>
  <!-- bind fields; errors come from data.form.errors.* -->
</form>
```

---

### Tips

* Keep all schemas here so your LLM has a single source for validation.
* Extend with enums derived from your DB where helpful (e.g., `pin_kind`, `device_status`) if you surface them in forms.
* For stricter Android ID formats per your fleet, tighten `zAndroidId()` later.
* If you want localized messages, swap the errorMap strings or wire an i18n layer.
