# **SvelteKit + Drizzle + Zod + Superforms** 

# Schema.ts
```ts
// src/lib/server/db/schema.ts
import {
  pgTable, uuid, varchar, boolean, timestamp, integer, text, jsonb, pgEnum,
  uniqueIndex, index, bytea
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// ============ Enums ============
export const roleNameEnum   = pgEnum('role_name', ['NATIONAL_ADMIN','STATE_ADMIN','SUPERVISOR','TEAM_MEMBER']);
export const pinKindEnum    = pgEnum('pin_kind', ['TEAM','SUPERVISOR']);
export const deviceStatEnum = pgEnum('device_status', ['ACTIVE','BLOCKED','RETIRED']);
export const eventTypeEnum  = pgEnum('event_type', [
  // compact telemetry vocabulary (extend as needed)
  'login_success','login_denied','app_launch','app_launch_denied',
  'pin_success','pin_failure','supervisor_session_started','supervisor_session_expired',
  'policy_applied','time_violation','heartbeat'
]);

// ============ State ============
export const state = pgTable('state', {
  id: uuid('id').primaryKey().defaultRandom(),
  code: varchar('code', { length: 16 }).notNull().unique(),
  name: varchar('name', { length: 128 }).notNull().unique(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

export const stateRelations = relations(state, ({ many }) => ({
  teams: many(team),
}));

// ============ Team ============
export const team = pgTable('team', {
  id: uuid('id').primaryKey().defaultRandom(),
  stateId: uuid('state_id').references(() => state.id, { onDelete: 'restrict' }).notNull(),
  code: varchar('code', { length: 32 }).notNull().unique(),
  name: varchar('name', { length: 128 }).notNull(),
  timezone: varchar('timezone', { length: 64 }).notNull().default('Asia/Kolkata'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, t => ({
  stateIdx: index('ix_team_state').on(t.stateId),
}));

export const teamRelations = relations(team, ({ one, many }) => ({
  state: one(state, { fields: [team.stateId], references: [state.id] }),
  devices: many(device),
  pins: many(pin),
}));

// ============ Identity: User / Role / UserRole ============
export const user = pgTable('user', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  fullName: varchar('full_name', { length: 255 }),
  isActive: boolean('is_active').notNull().default(true),
  homeStateId: uuid('home_state_id').references(() => state.id, { onDelete: 'set null' }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

export const role = pgTable('role', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: roleNameEnum('name').notNull().unique(),
  description: text('description'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export const userRole = pgTable('user_role', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').references(() => user.id, { onDelete: 'cascade' }).notNull(),
  roleId: uuid('role_id').references(() => role.id, { onDelete: 'restrict' }).notNull(),
  // scoped access (optional depending on role)
  stateId: uuid('state_id').references(() => state.id, { onDelete: 'cascade' }),
  teamId: uuid('team_id').references(() => team.id, { onDelete: 'cascade' }),
  assignedAt: timestamp('assigned_at', { withTimezone: true }).defaultNow().notNull(),
}, t => ({
  uqUserRoleScope: uniqueIndex('uq_user_role_user_role_scope').on(t.userId, t.roleId, t.stateId, t.teamId),
  userIdx: index('ix_user_role_user').on(t.userId),
  roleIdx: index('ix_user_role_role').on(t.roleId),
  scopeIdx: index('ix_user_role_role_scopes').on(t.roleId, t.stateId, t.teamId),
}));

export const userRelations = relations(user, ({ many, one }) => ({
  roles: many(userRole),
  supervisorProfile: one(supervisor, { fields: [user.id], references: [supervisor.userId] }),
  homeState: one(state, { fields: [user.homeStateId], references: [state.id] }),
}));

export const roleRelations = relations(role, ({ many }) => ({
  users: many(userRole),
}));

export const userRoleRelations = relations(userRole, ({ one }) => ({
  user: one(user, { fields: [userRole.userId], references: [user.id] }),
  role: one(role, { fields: [userRole.roleId], references: [role.id] }),
  state: one(state, { fields: [userRole.stateId], references: [state.id] }),
  team: one(team, { fields: [userRole.teamId], references: [team.id] }),
}));

// ============ Supervisor profile (1:1 user, bound to team) ============
export const supervisor = pgTable('supervisor', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').references(() => user.id, { onDelete: 'cascade' }).notNull().unique(),
  teamId: uuid('team_id').references(() => team.id, { onDelete: 'cascade' }).notNull(),
  phone: varchar('phone', { length: 32 }),
  notes: varchar('notes', { length: 512 }),
  // optional coarse session bookkeeping (per-user; device-bound sessions can be a future table)
  lastSessionStartedAt: timestamp('last_session_started_at', { withTimezone: true }),
  lastSessionExpiresAt: timestamp('last_session_expires_at', { withTimezone: true }),
  isActive: boolean('is_active').notNull().default(true),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, t => ({
  teamIdx: index('ix_supervisor_team').on(t.teamId),
}));

export const supervisorRelations = relations(supervisor, ({ one }) => ({
  user: one(user, { fields: [supervisor.userId], references: [user.id] }),
  team: one(team, { fields: [supervisor.teamId], references: [team.id] }),
}));

// ============ Devices (no pre-enrollment; upsert by androidId) ============
export const device = pgTable('device', {
  id: uuid('id').primaryKey().defaultRandom(),
  androidId: varchar('android_id', { length: 64 }).notNull().unique(),
  teamId: uuid('team_id').references(() => team.id, { onDelete: 'set null' }), // may attach on first provisioning
  manufacturer: varchar('manufacturer', { length: 64 }),
  model: varchar('model', { length: 64 }),
  osRelease: varchar('os_release', { length: 32 }),
  osIncremental: varchar('os_incremental', { length: 64 }),
  securityPatch: varchar('security_patch', { length: 16 }),
  isDeviceOwner: boolean('is_device_owner').notNull().default(false),

  appVersion: varchar('app_version', { length: 32 }),
  lastSeenAt: timestamp('last_seen_at', { withTimezone: true }),
  lastSeenIp: varchar('last_seen_ip', { length: 45 }),

  status: deviceStatEnum('status').notNull().default('ACTIVE'),

  // Optional policy tracking for UI (authoritative ack lives in policy_ack)
  lastPolicyId: varchar('last_policy_id', { length: 64 }),

  // Loose counters/notes for ops (battery, sync counts, etc.)
  counters: jsonb('counters'),

  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, t => ({
  teamIdx: index('ix_device_team').on(t.teamId),
  statusIdx: index('ix_device_status').on(t.status),
  seenIdx: index('ix_device_last_seen').on(t.lastSeenAt),
}));

export const deviceRelations = relations(device, ({ one, many }) => ({
  team: one(team, { fields: [device.teamId], references: [team.id] }),
  events: many(event),
  policyAcks: many(policyAck),
}));

// ============ Enrollment Tokens (QR Phase-B) ============
export const enrollmentToken = pgTable('enrollment_token', {
  id: uuid('id').primaryKey().defaultRandom(),
  teamId: uuid('team_id').references(() => team.id, { onDelete: 'cascade' }).notNull(),
  jti: varchar('jti', { length: 64 }).notNull().unique(),          // JWT ID
  token: text('token').notNull(),                                   // JWT (short-lived)
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  usedAt: timestamp('used_at', { withTimezone: true }),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
  meta: jsonb('meta'),                                              // ip, ua, notes
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, t => ({
  teamIdx: index('ix_enrollment_token_team').on(t.teamId),
  liveIdx: index('ix_enrollment_token_live').on(t.teamId, t.expiresAt),
}));

export const enrollmentTokenRelations = relations(enrollmentToken, ({ one }) => ({
  team: one(team, { fields: [enrollmentToken.teamId], references: [team.id] }),
}));

// ============ Device Telemetry Events ============
export const event = pgTable('event', {
  id: uuid('id').primaryKey().defaultRandom(),
  deviceId: uuid('device_id').references(() => device.id, { onDelete: 'cascade' }).notNull(),
  teamId: uuid('team_id').references(() => team.id, { onDelete: 'set null' }),
  type: eventTypeEnum('type').notNull(),
  at: timestamp('at', { withTimezone: true }).notNull().defaultNow(),
  // compact, schemaless details (app package, reason codes, versions, etc.)
  data: jsonb('data'),
}, t => ({
  deviceIdx: index('ix_event_device_at').on(t.deviceId, t.at),
  teamIdx: index('ix_event_team_at').on(t.teamId, t.at),
  typeIdx: index('ix_event_type_at').on(t.type, t.at),
}));

export const eventRelations = relations(event, ({ one }) => ({
  device: one(device, { fields: [event.deviceId], references: [device.id] }),
  team: one(team, { fields: [event.teamId], references: [team.id] }),
}));

// ============ Policy Acknowledgements ============
export const policyAck = pgTable('policy_ack', {
  id: uuid('id').primaryKey().defaultRandom(),
  deviceId: uuid('device_id').references(() => device.id, { onDelete: 'cascade' }).notNull(),
  policyId: varchar('policy_id', { length: 64 }).notNull(), // e.g., content hash or KID/version
  ackedAt: timestamp('acked_at', { withTimezone: true }).defaultNow().notNull(),
}, t => ({
  uqDevicePolicy: uniqueIndex('uq_policy_ack_device_policy').on(t.deviceId, t.policyId),
  deviceIdx: index('ix_policy_ack_device').on(t.deviceId),
}));

export const policyAckRelations = relations(policyAck, ({ one }) => ({
  device: one(device, { fields: [policyAck.deviceId], references: [device.id] }),
}));

// ============ PINs (team-scoped, versioned, PHC verifier + AEAD bundle) ============
export const pin = pgTable('pin', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  teamId: uuid('team_id').references(() => team.id, { onDelete: 'cascade' }).notNull(),
  kind: pinKindEnum('kind').notNull(),                     // TEAM | SUPERVISOR
  version: integer('version').notNull(),                   // monotonically increasing per (team, kind)
  isCurrent: boolean('is_current').notNull().default(false),
  revoked: boolean('revoked').notNull().default(false),

  // Argon2id PHC string (e.g., $argon2id$v=19$m=...,t=...,p=...$salt$hash)
  verifierPhc: text('verifier_phc').notNull(),

  // Optional KDF/AEAD params (future-proof)
  params: jsonb('params'),                                  // { kdf: 'argon2id', ... }

  // AEAD-wrapped plaintext PIN material for admin reveal (if policy permits)
  aeadCiphertext: bytea('aead_ciphertext'),
  aeadNonce: bytea('aead_nonce'),
  aeadKid: varchar('aead_kid', { length: 64 }),

  createdBy: uuid('created_by').references(() => user.id, { onDelete: 'set null' }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, t => ({
  uqTeamKindVersion: uniqueIndex('uq_pin_team_kind_version').on(t.teamId, t.kind, t.version),
  ixTeamKindCurrent: index('ix_pin_team_kind_current').on(t.teamId, t.kind, t.isCurrent),
}));

export const pinRelations = relations(pin, ({ one }) => ({
  team: one(team, { fields: [pin.teamId], references: [team.id] }),
}));

// ============ Relations (already declared inline above) ============
```

