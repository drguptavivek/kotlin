# SurveyLauncher Specification (Agent-Focused)

- [1. BMAD](#1-bmad)
- [2. Architecture Guidance](#2-architecture-guidance)
- [3. Conventions & Standards](#3-conventions--standards)
- [4. Entities & Policies](#4-entities--policies)
- [5. TDD Strategy](#5-tdd-strategy)
- [6. Backend Dashboard Specification](#6-backend-dashboard-specification)
- [7. Logging & Observability](#7-logging--observability)
- [8. Roadmap & Milestones](#8-roadmap--milestones)
- [9. Deliverables & Acceptance](#9-deliverables--acceptance)
- [10. Security & Privacy](#10-security--privacy)
- [11. Risks & Mitigations](#11-risks--mitigations)
- [Appendix A — Android Policies/APIs](#appendix-a--android-policiesapis-reference)
- [Appendix B — Server Endpoints (v1)](#appendix-b--server-endpoints-v1)

---

**Project:** aiims.app.surveylauncher (Android launcher) + SVELTEKIT
**Version:** 1.1 • **Date:** 2025-10-04

## 1. BMAD

### Brief
Build a custom Android launcher (**SurveyLauncher**, package: `aiims.app.surveylauncher`) and a Flask backend for ~1200 field teams & 50 supervisors.  
Launcher runs as **Device Owner**, enforces kiosk behavior, **daily server login**, **local PIN** unlocks, **team-based time windows**, **trusted server time**, **radios/background data controls**, and **audit logging**. No paid MDM or Google account required.

### Mission
- **Android:** Replace HOME, enforce policy (apps/windows/grace/PIN), maintain trusted time, support Forgot PIN & Server-Managed PIN, disable radios, minimize background data, log events, operate offline within grace.
- **Server:** Authenticate users, generate **signed team policies**, return server time, store/query events, manage supervisors/overrides, dashboards, retention & observability.

### Activities (Milestones → Epics → Atomic Tasks)
See [8. Roadmap & Milestones](#8-roadmap--milestones).

### Deliverables
See [9. Deliverables & Acceptance](#9-deliverables--acceptance).

---

## 2. Architecture Guidance

### Client (Android)
**Principles**
- Single-responsibility modules; deterministic offline behavior via state machines.
- All decisions use **trusted clock** (server-anchored), never wall time directly.
- DPM calls are idempotent and re-applied on boot/login/heartbeat.

**Layers**
- `ui`: Jetpack Compose screens (Login, Pin, Home, Locked, ForgotPin, SetPin)
- `domain`: use-cases (Auth, Pin, PolicyApply, AppLaunchGuard, TrustedClock, RadiosEnforcer, Telemetry)
- `data`:
  - Repos: AuthRepo, PolicyRepo, PinVault, EventsRepo, DeviceOwnerRepo, AppsRepo
  - Sources: ApiClient (Retrofit/Ktor), LocalStore (EncryptedSharedPreferences/DataStore), PackageManager, DPM

**DI & Concurrency**
- Hilt for DI (Singleton, ActivityRetained, ViewModel)
- Coroutines + Flows; UiState via StateFlow

**Persistence**
- EncryptedSharedPreferences (tokens, PIN materials)
- Proto DataStore (policy cache, trusted time), atomic apply

**Networking**
- Retrofit/Ktor + OkHttp (TLS only; optional cert pinning)
- Timeouts: 10s connect / 30s read; exponential backoff + jitter
- Offline queue for `/api/events`

**Policy Application**
- Validate **Ed25519 signature** before apply
- Two-phase: write temp → verify → promote active → emit `policy_applied`

**Trusted Time**
- Store `{last_server_epoch_ms, last_monotonic_ms}`; compute `trusted_now()` via `elapsedRealtime()`
- On reboot+offline: gate by grace; require sync to re-anchor

**Kiosk Enforcement**
- Persistent HOME, lock task, status bar disable (API-gated), restrictions, hide/suspend apps
- Admin-only escape hatch (long-press + admin PIN)

**Radios Control**
- Enforce DISALLOW_* restrictions; periodic re-enforcement worker
- Data Saver ON; background allowlist only for SurveyLauncher + ODK
- Location ON; grant `ACCESS_FINE_LOCATION` to ODK only

**Logging & Testing**
- Structured events; batch upload; include policy_id, reason, trusted_time, skew
- Unit/robolectric/instrumented tests; soak tests for power & reboot/offline

### Server (Flask)
**Principles**
- Separation: API (Blueprints) / Services / Repos / Models
- Stateless auth; idempotent device endpoints; transactional services

**Structure**
```
app/
  api/ (auth, policy, events, pin, teams, overrides, reports)
  services/ (auth_service, policy_service, pin_service, events_service, geo_service)
  repos/ (user_repo, team_repo, device_repo, event_repo, policy_repo)
  models/ (SQLAlchemy)
  schemas/ (Pydantic/Marshmallow)
  core/ (jwt, crypto, signing, config, rate_limits)
  tasks/ (retention, compaction, alerts)
migrations/ (Alembic)
```
**Infra**
- Postgres (partitions for events), Redis (cache/OTPs), gunicorn behind nginx (TLS)
- Policy cache + ETag; read replicas optional

**Security/Validation**
- Pydantic validation; JWT ≤24h (claims: sub, dev, scope); policy **Ed25519** signed
- Rate limits: login, pin reset, events

**Time Authority**
- `server_epoch_ms` from NTP-synced hosts, included in `/auth/login` & `/ping`

**Observability**
- Structured logs (JSON), request_id propagation; metrics & alerts

### Cross-Cutting
- API versioning `/api/v1`
- JSON schemas committed; examples in `/docs`
- Separate signing keys for policy vs JWT; quarterly rotation
- Error envelope: `{ ok:false, code, message, details? }`
- Policies specify `timezone=Asia/Kolkata`; server stores UTC

---

## 3. Conventions & Standards

**Android/Kotlin**
- Compose-first, ViewModels → StateFlow; MockK + Turbine
- ktlint + detekt (warnings as errors)
- Domain errors via sealed classes; no throwing across UI

**Python/Flask**
- Python 3.11+, type hints everywhere; mypy strict
- Black + isort + flake8
- SQLAlchemy 2.0; Alembic migrations (with downgrade paths)
- Pydantic (preferred) for request/response validation

**Git/Release**
- Branches: main (protected), develop, feature/*
- Conventional commits; CI must pass + review
- SemVer; schema_version tracked separately

**Secrets**
- No secrets in code; env vars + `.env.example`
- Rotate JWT/policy keys quarterly

**Policy Signing**
- Ed25519; include `kid`; device validates via JWKS TTL cache
- On signature failure: keep last-good, emit alert

**Telemetry**
- Event fields standardized; IP truncated in dashboards; GPS precision reduced for non-admins

**Performance Targets**
- Client: cold start < 2s; unlock-to-home < 400ms; gate decision < 10ms
- Server: P95 login < 500ms; policy < 200ms; events batch < 250ms

**Documentation**
- ADRs for DPM strategy, trusted time model, policy signing, PIN recovery
- Provisioning playbook, supervisor guide, incident runbooks

---

## 4. Entities & Policies

**Entities**
- User(id, username, pw_hash, role, team_id, is_active)
- Supervisor(id, user_id)
- Team(id, name, supervisor_id, windows, whitelist, grace, timezone)
- Device(id, android_id, manufacturer, model, tablet_name, team_id, last_seen_at)
- Policy(id, team_id, payload_json, signature, valid_from, valid_to)
- Event(id, ts_utc, user_id, device_id, team_id, type, reason, gps, ip, policy_id, trusted_time, wall_time, skew_ms)
- PinPolicy(mode, min_length, max_retries, lockout_seconds, rotate_days, serverPin(hash|sealed)?, recovery_config)
- PinResetRequest(id, user_id, device_id, status, channel, created_at, resolved_at)
- Override(id, code, scope_user_id, scope_device_id, team_id, expires_at, used_at, reason)

**Team Policy JSON (Signed)**

```json
{
  "policy_id": "v2025-10-05T00:00Z",
  "team_id": 1234,
  "timezone": "Asia/Kolkata",
  "authIntervalHours": 24,
  "offlineGraceHours": 24,
  "apps": {"whitelist": ["org.odk.collect.android","aiims.app.browser","aiims.app.custom"]},
  "windows": {
    "login": {"mon-sat":[["08:00","18:00"]], "sun":[]},
    "launch": {"org.odk.collect.android":[["08:00","18:00"]]}
  },
  "minVersions": {"aiims.app.surveylauncher": 3},
  "pinPolicy": {
    "mode": "local|server-managed|server-temp",
    "minLength": 6,
    "maxRetries": 5,
    "lockoutSeconds": 300,
    "rotateDays": 90,
    "serverPin": {"type":"hash","kdf":"scrypt","params":{"N":16384,"r":8,"p":1},"salt_b64":"...","hash_b64":"...","expires_at":"2025-11-01T00:00:00Z","oneTime":true},
    "recovery": {"enabled": true, "supervisorOverride": true, "offlineCode": true, "otpChannels": ["email"]}
  },
  "valid_from": "2025-10-05T00:00:00Z",
  "valid_to": "2026-10-05T00:00:00Z",
  "signature": "...",
  "kid": "policy-key-2025Q4"
}
```

**Reason Codes (examples)**
- `outside_login_window`, `outside_app_window`, `token_expired`, `pin_locked_out`, `time_skew_violation`, `policy_signature_invalid`, `override_used`

---

## 5. TDD Strategy

**Principles**
- Tests first for critical paths; bug → failing test → fix.
- Isolate Android DPM & I/O behind interfaces.

**Pyramid**
- Android: Unit (JUnit5, Turbine), Robolectric (policy gating, PIN flows), Instrumented (kiosk, tiles, reboot/offline)
- Server: Unit (pytest, freezegun), API contract (schemathesis/pydantic), Integration (Postgres/Redis), Load (k6/locust)

**Coverage Gates**
- Android ≥80% overall; ≥90% core domain
- Server ≥85% services; ≥90% auth/policy/pin

**Fixtures/Mocks**
- Android: FakeDpm, FakePolicyRepo, FakeTimeSource, FakeLocationProvider, FakeEventsSink
- Server: In-memory repos, stub JWT signer, testcontainers Postgres

**BDD Examples**
- Login within window → token, unlock with PIN, event=login_success  
- App launch outside window → blocked, grey tile, event=app_denied  
- Backdate attempt → warn >±2m, block >±10m, event=time_skew_violation  
- Forgot PIN with supervisor override → one-time unlock → force SetPin

**Performance Budgets**
- Client: cold_start_ms=2000; unlock_to_home_ms=400; decision_ms=10  
- Server: p95_login_ms=500; p95_policy_ms=200; p95_events_ms=250

---

## 6. Backend Dashboard Specification

**Stack**
- Flask Blueprints (admin, supervisor, reports), Jinja2/HTMX or React SPA
- Role-based authz (admin, supervisor), CSRF, secure cookies

**Navigation**
- Overview, Teams & Windows, Live Status, Overrides & PIN Resets, Events & Reports, Settings (admin)

**Key Pages & Features**
- **Overview:** KPIs (active_devices_now, logins_today, denied_today, skew_alerts), map cluster, trends  
- **Teams & Windows:** CRUD, weekly window editor, app launch windows, whitelist, bulk apply/clone, PIN policy editor  
- **Live Status:** device/user last_seen, policy_id, skew_badge; filters; actions (refresh policy, mark lost)  
- **Overrides & PIN Resets:** queue, issue override (single-use, scoped), issue offline token, full audit trail  
- **Events & Reports:** filter/search, CSV export, reports: window adherence, denials by reason, device health

**Performance & Security**
- FMP < 1.5s; server pagination; lazy map  
- Least privilege; audit admin mutations; CSP/HSTS/CSRF

---

## 7. Logging & Observability

**Client (Android)**
- JSON line events, POST `/api/events` in batches (≤100 or 128KB)  
- Levels: INFO (login_success, app_launch, policy_applied), WARN (login_denied, app_denied, time_skew_warning), ERROR (policy_signature_invalid, events_upload_failed)  
- Privacy: no PIN/password; coarse GPS for non-admin views  
- Retry with backoff; summarize dropped batches as ERROR

**Server**
- JSON logs (request_id, route, status, latency_ms, ids if present)  
- Metrics: auth success, events ingested/rejected, overrides issued, pin resets, devices online, policy age  
- Alerts: high login failure %, events backlog, signature errors, skew %, DB/migration errors  
- Retention: app logs 30d hot / 12m cold; events 12–18m (monthly partition purge)

**Ops Dashboards**
- Grafana/Metabase panels; runbooks linked to alerts  
- Health endpoints: `/healthz`, `/readyz`

---

## 8. Roadmap & Milestones

**M0 Foundations**  
- Repos, CI, scripts, coverage gates, TESTING.md, LOGGING.md

**M1 Device Owner & Kiosk**  
- AdminReceiver, HOME, lock task, restrictions, hide/suspend

**M2 Auth & PIN**  
- Login → token → PIN; offline grace; server returns server_epoch_ms + policy

**M3 Policy & Time Windows**  
- Signed policy; cache; enforce login/launch windows; grey tiles

**M4 Trusted Time**  
- `trusted_now()`, skew detection, require auto time; enforce via trusted clock

**M5 Radios & Background Data**  
- Disable Bluetooth/NFC/tethering/USB; Data Saver; GPS only for ODK

**M6 Event Logging & Location**  
- Client emits events; server stores, partitions, indexes; alerts

**M7 PIN Recovery & Server PIN**  
- Forgot PIN flows (supervisor/OTP/offline); server-managed PIN; temp PIN forces reset

**M8 Supervisor & Admin Dashboards**  
- Windows editor, overrides, live status, reports, CSV export, map

**M9 TDD Hardening & Performance**  
- Coverage goals, load tests, CI gates, flaky test quarantine

Each milestone contains epics & atomic tasks as defined earlier.

---

## 9. Deliverables & Acceptance

**Deliverables**
- Android APK (kiosk-ready)  
- Flask backend (auth, policy, events, PIN)  
- Policy JSON schema & signing keys  
- Dashboards (admin/supervisor)  
- Provisioning scripts (ADB/QR) + SOPs  
- Structured logs, retention jobs, reports

**Acceptance**
- ≥95% devices operational daily without manual intervention  
- ≥90% logins within windows  
- Time skew violations <2% after week 2  
- Background data reduced ≥60%  
- Policy changes propagate ≤10 min TTL  
- Forgot PIN completes ≤5 min online; server-managed PIN applied next login

---

## 10. Security & Privacy

- HTTPS; JWTs ≤24h; device-bound claims  
- PIN hashed (scrypt/argon2), never plaintext  
- Policy signature verification mandatory  
- Location snapshots only on login/heartbeat; precision reduced in dashboards  
- Offline recovery tokens short-lived, signed, scoped (device+team)

---

## 11. Risks & Mitigations

- **OEM DPM variance** → feature detection, fallbacks, model matrix docs  
- **Offline w/o recovery** → block; pre-issue offline tokens for remote teams  
- **Morning surge** → policy caching, client jitter, stateless auth, autoscale  
- **Policy desync** → device ACK endpoint; alert if not applied within TTL

---

### Appendix A — Android Policies/APIs Reference
- `DevicePolicyManager.addPersistentPreferredActivity`  
- `DevicePolicyManager.setLockTaskPackages`  
- `Activity.startLockTask()`  
- `DevicePolicyManager.setStatusBarDisabled(admin, true)` (API 28+)  
- `DevicePolicyManager.addUserRestriction(admin, DISALLOW_*)`  
- `DevicePolicyManager.setApplicationHidden(...)`  
- `DevicePolicyManager.setPackagesSuspended(...)`  
- `DevicePolicyManager.setPermissionGrantState(...)` for `ACCESS_FINE_LOCATION`

### Appendix B — Server Endpoints (v1)
- `POST /api/auth/login` → `{ ok, token, server_epoch_ms, policy }`  
- `POST /api/ping` → `{ ok, server_epoch_ms }`  
- `GET  /api/policy?team_id=...` (or inline on login)  
- `POST /api/events` (batch)  
- `POST /api/pin/request-reset`  
- `POST /api/pin/verify`  
- `POST /api/pin/apply`  
- `POST /api/pin/issue-offline-token`  
- Admin CRUD: `/api/teams`, `/api/overrides`, `/api/reports`
