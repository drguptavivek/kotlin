Here you go — drop these into `src/lib/server/utils/` in your SvelteKit repo. They match the spec (Argon2id PHC + XChaCha20-Poly1305 AEAD, request-id propagation, structured audit logs) and the project layout you set earlier.   

---

### `src/lib/server/utils/crypto.ts`

```ts
/**
 * crypto.ts — sodium/argon2 wrappers (PHC helpers)
 *
 * - Argon2id hashing (PHC strings) via `argon2` npm (battle-tested, cross-platform)
 * - AEAD (XChaCha20-Poly1305, libsodium) for optional admin PIN reveal bundle
 * - Small helpers for random numeric PINs and constant-time equality
 *
 * Env (validated in $lib/config/env.ts if you want):
 *   PIN_AEAD_KID           = pin-xchacha20-v1
 *   PIN_XCHACHA20_KEY_HEX  = <64 hex chars>  // 32-byte key (required to enable AEAD)
 */
/**
 * crypto.ts — sodium/argon2 wrappers (PHC helpers)
 *
 * - Argon2id hashing (PHC strings) via `argon2`
 * - AEAD (XChaCha20-Poly1305, libsodium) for optional admin PIN reveal bundle
 * - Helpers for random numeric PINs and constant-time equality
 *
 * Env (validate in $lib/config/env.ts if desired):
 *   PIN_AEAD_KID           = pin-xchacha20-v1
 *   PIN_XCHACHA20_KEY_HEX  = <64 hex chars>  // 32-byte key (required to enable AEAD)
 */

import * as sodium from "libsodium-wrappers-sumo";
import argon2 from "argon2";
import crypto from "node:crypto";

export type Argon2Opts = {
  timeCost?: number;     // default 3
  memoryCost?: number;   // KiB, default 65536 (64 MiB)
  parallelism?: number;  // default 1
  hashLength?: number;   // default 32
};

export const ARGON_DEFAULTS: Required<Argon2Opts> = {
  timeCost: 3,
  memoryCost: 64 * 1024,
  parallelism: 1,
  hashLength: 32
};

// --- libsodium init (once) ---
let _ready: Promise<void> | null = null;
export function initSodium() {
  if (!_ready) _ready = sodium.ready;
  return _ready;
}

// --- Argon2id (PHC) ---
export async function hashArgon2id(plaintext: string, opts: Argon2Opts = {}) {
  const o = { ...ARGON_DEFAULTS, ...opts, type: argon2.argon2id };
  return argon2.hash(plaintext, o); // `$argon2id$v=19$...`
}

export async function verifyArgon2id(phc: string, plaintext: string) {
  return argon2.verify(phc, plaintext);
}

// --- XChaCha20-Poly1305 AEAD (libsodium) ---
function getAeadKey(): Uint8Array | undefined {
  const hex = process.env.PIN_XCHACHA20_KEY_HEX?.trim();
  if (!hex) return undefined;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error("PIN_XCHACHA20_KEY_HEX must be 64 hex chars (32 bytes)");
  }
  return sodium.from_hex(hex);
}

export function getAeadKid(): string {
  return process.env.PIN_AEAD_KID?.trim() || "pin-xchacha20-v1";
}

/**
 * Seal plaintext using XChaCha20-Poly1305 (nonce is 24 bytes).
 * Returns base64 nonce and ciphertext (ciphertext includes auth tag).
 */
export async function aeadSealXChaCha(
  plaintextUtf8: string,
  aadUtf8?: string
): Promise<{ nonce_b64: string; ciphertext_b64: string; kid: string }> {
  await initSodium();
  const key = getAeadKey();
  if (!key) {
    throw new Error("AEAD disabled (PIN_XCHACHA20_KEY_HEX not set)");
  }
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const m = sodium.from_string(plaintextUtf8);
  const ad = aadUtf8 ? sodium.from_string(aadUtf8) : null;

  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(m, ad, null, nonce, key);
  return {
    nonce_b64: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
    ciphertext_b64: sodium.to_base64(ct, sodium.base64_variants.ORIGINAL),
    kid: getAeadKid()
  };
}

/** Open XChaCha20-Poly1305 bundle produced by aeadSealXChaCha */
export async function aeadOpenXChaCha(
  nonce_b64: string,
  ciphertext_b64: string,
  aadUtf8?: string
): Promise<string> {
  await initSodium();
  const key = getAeadKey();
  if (!key) {
    throw new Error("AEAD disabled (PIN_XCHACHA20_KEY_HEX not set)");
  }
  const nonce = sodium.from_base64(nonce_b64, sodium.base64_variants.ORIGINAL);
  const ct = sodium.from_base64(ciphertext_b64, sodium.base64_variants.ORIGINAL);
  const ad = aadUtf8 ? sodium.from_string(aadUtf8) : null;

  const msg = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, ad, nonce, key);
  return sodium.to_string(msg);
}

/** Seal → Buffers for direct BYTEA insert */
export async function aeadSealXChaCha_db(
  plaintextUtf8: string,
  aadUtf8?: string
): Promise<{ nonce: Buffer; ciphertext: Buffer; kid: string }> {
  await initSodium();
  const key = getAeadKey();
  if (!key) throw new Error("AEAD disabled (PIN_XCHACHA20_KEY_HEX not set)");
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const m = sodium.from_string(plaintextUtf8);
  const ad = aadUtf8 ? sodium.from_string(aadUtf8) : null;
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(m, ad, null, nonce, key);
  return { nonce: Buffer.from(nonce), ciphertext: Buffer.from(ct), kid: getAeadKid() };
}

/** Open from BYTEA (Buffers) read from DB */
export async function aeadOpenXChaCha_db(
  nonce: Uint8Array | Buffer,
  ciphertext: Uint8Array | Buffer,
  aadUtf8?: string
): Promise<string> {
  await initSodium();
  const key = getAeadKey();
  if (!key) throw new Error("AEAD disabled (PIN_XCHACHA20_KEY_HEX not set)");
  const ad = aadUtf8 ? sodium.from_string(aadUtf8) : null;
  const msg = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    new Uint8Array(ciphertext),
    ad,
    new Uint8Array(nonce),
    key
  );
  return sodium.to_string(msg);
}

// --- Helpers ---
/** Cryptographically random numeric PIN (len digits). */
export function randomNumericPin(len = 6): string {
  const bytes = crypto.randomBytes(len);
  let s = "";
  for (let i = 0; i < len; i++) s += (bytes[i] % 10).toString();
  return s;
}

/** Constant-time equality for small strings/buffers. */
export function secureEqual(a: string | Buffer, b: string | Buffer): boolean {
  const A = typeof a === "string" ? Buffer.from(a) : Buffer.from(a);
  const B = typeof b === "string" ? Buffer.from(b) : Buffer.from(b);
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}

// Convenience base64 helpers (original alphabet)
export const b64e = (buf: Uint8Array | Buffer) => Buffer.from(buf).toString("base64");
export const b64d = (b64: string) => Buffer.from(b64, "base64");


```

---

### `src/lib/server/utils/logger.ts`

SEE LOGGING

---

#### Notes

* `crypto.ts` gives you PHC strings for DB (`pin.verifierPhc`) and optional AEAD seal/open to populate the `aeadCiphertext/aeadNonce/aeadKid` columns — exactly how your PIN storage model is designed. 
* AEAD uses **XChaCha20-Poly1305** (libsodium) as called for in your admin PIN API notes; devices never receive plaintext; reveal only decrypts server-side. 
* `logger.ts` follows your logging guidance: **request-id propagation**, structured JSON logs, concise audit events, and avoiding secrets in logs. Wire it up in `hooks.server.ts` as shown. 
 

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
