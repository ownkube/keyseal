# keyseal bundle format, version 1

This document is the contract every keyseal implementation follows. The
TypeScript implementation is written against it, as will be any other
language, and the fixtures in `testvectors/` are the conformance suite: an
implementation is
correct when it opens every `valid` vector to the expected values and rejects
every `invalid` vector with the expected error code.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Overview

A bundle is one JSON file holding the secrets for one environment
(`secrets.production.ks.json`). It is meant to be committed to git.

- Secret **names** are plaintext, so diffs and code review stay readable.
- Secret **values** are encrypted, one ciphertext per value.
- Every bundle has a random 256-bit **data key**. The data key never appears
  in the file; only a copy wrapped (encrypted) by a key provider, AWS KMS or
  a local key, is stored.
- A bundle-wide **MAC** covers every field, so adding, removing, reordering,
  downgrading or swapping anything is detected before any value is decrypted.
- A bundle **version** increases on every write, so a running process can
  refuse to go back to an older bundle.

## 2. Encoding conventions

- `b64u(x)`: base64url (RFC 4648 section 5), **no padding**. Decoders MUST
  reject padding and characters outside the base64url alphabet.
- Timestamps: RFC 3339 in UTC with a literal `Z` and whole seconds,
  `YYYY-MM-DDTHH:MM:SSZ`. Implementations MUST write this exact form and
  MUST treat the string as opaque bytes for the MAC.
- Integers: JSON numbers, non-negative, at most 2^53 - 1. In the MAC
  transcript they are written as base-10 ASCII with no sign and no leading
  zeros (`0` is `0`).
- All strings are UTF-8.

## 3. File layout

```json
{
  "keyseal": 1,
  "id": "Xq3m0yJw6Zr1k2v9Qp7tLg",
  "env": "production",
  "version": 7,
  "updatedAt": "2026-10-22T10:00:00Z",
  "key": {
    "provider": "aws-kms",
    "keyId": "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
    "epoch": 2,
    "wrapped": "AQIDAHh..."
  },
  "secrets": {
    "OPENAI_API_KEY": {
      "v": 3,
      "rotatedAt": "2026-10-22T09:58:12Z",
      "value": "8Jq...",
      "previous": {
        "v": 2,
        "expiresAt": "2026-10-23T09:58:12Z",
        "value": "kV0..."
      }
    }
  },
  "mac": "q4b..."
}
```

| Field | Rule |
|---|---|
| `keyseal` | MUST be the number `1`. Any other value is `unsupported_format`. |
| `id` | `b64u` of 16 random bytes (22 characters). Set once at creation, never changed. |
| `env` | Matches `^[a-z0-9][a-z0-9-]{0,62}$`. |
| `version` | Integer >= 1. MUST increase by at least 1 on every write. |
| `updatedAt` | Timestamp of the last write. |
| `key.provider` | Key provider name, matches `^[a-z0-9][a-z0-9-]{0,31}$`. Defined: `aws-kms`. Reserved: `test` (section 9). |
| `key.keyId` | Provider-specific key reference. For `aws-kms` the full key ARN. Printable ASCII, 1 to 2048 bytes. |
| `key.epoch` | Integer >= 1. The data key's generation: `1` at creation, plus 1 on every `rekey` (section 8). |
| `key.wrapped` | `b64u` of the provider's wrapped data key. |
| `secrets` | Object keyed by secret name. MAY be empty. |
| secret name | Matches `^[A-Za-z_][A-Za-z0-9_]{0,254}$` (a portable environment variable name). |
| `v` | Integer >= 1. Per-secret version, incremented every time that secret's value changes. |
| `rotatedAt` | Timestamp the current value was set. |
| `value` | Encrypted value, section 5. |
| `previous` | Optional. The value replaced by the last rotation, kept for a grace window. `previous.v` MUST be less than `v`. |
| `previous.expiresAt` | After this instant readers MUST NOT return the previous value. Writers SHOULD drop expired `previous` entries on the next write. |
| `mac` | `b64u` of the bundle MAC, section 6. |

Readers MUST reject (`invalid_format`) a bundle with unknown top-level,
`key`, secret or `previous` fields, missing required fields, or fields that
break the rules above. Strictness is deliberate: an unknown field could be
an attempt to smuggle in data the MAC doesn't cover.

## 4. Keys

### 4.1 Data key

On creation (and on `rekey`) the writer asks the key provider for a new
32-byte data key `DK`. The provider returns `DK` in plaintext plus a wrapped
copy, stored as `key.wrapped`. Readers get `DK` back by asking the provider
to unwrap `key.wrapped`.

The provider MUST bind the wrapped key to this **key context**:

| Context key | Value |
|---|---|
| `keyseal:bundle` | the bundle `id` |
| `keyseal:env` | the bundle `env` |
| `keyseal:epoch` | decimal(`key.epoch`) |

For `aws-kms` the key context is the KMS `EncryptionContext` passed to
`GenerateDataKey` and `Decrypt`, so a wrapped key copied into a bundle with a
different id, environment or epoch fails to unwrap, and AWS CloudTrail
records all three values on every decrypt. For `local` it is part of the
wrap AAD (section 4.3). The key context is derived from the bundle, never
stored separately.

**Revocation.** Because the epoch is in the key context, the key's owner can
refuse to unwrap any older data key of a bundle. For `aws-kms` this is an IAM
`Deny` on `kms:Decrypt` where `kms:EncryptionContext:keyseal:bundle` equals
the bundle `id` and `kms:EncryptionContext:keyseal:epoch` is any value below
the current epoch. After a rekey and that Deny, every older copy of the
bundle (git history, old object versions, a copy an attacker serves in place
of the current one) fails with `key_unavailable`, even in a process that has
never seen the current bundle. The epoch is covered by the MAC (section 6),
so editing it to dodge the Deny makes the bundle fail `mac_mismatch` (and,
for `aws-kms`, fail to unwrap, since the context no longer matches). The
`local` provider can't revoke epochs (section 4.3).

### 4.2 Derived keys

`DK` is never used directly. Two keys are derived with HKDF-SHA256
(RFC 5869):

```
salt   = UTF-8(id)
encKey = HKDF-SHA256(ikm = DK, salt, info = "keyseal/v1/enc", L = 32)
macKey = HKDF-SHA256(ikm = DK, salt, info = "keyseal/v1/mac", L = 32)
```

Implementations SHOULD hold `encKey` and `macKey` as non-exportable key
handles where the platform allows it, and SHOULD discard `DK` after
derivation.

### 4.3 The `local` provider

The `local` provider wraps `DK` with a 32-byte key `LK` that the user holds
directly, with no key service. `LK` is written as:

```
"keyseal_local_" || b64u(LK)          (57 characters)
```

Two keys are derived from `LK` with HKDF-SHA256, with an empty salt:

```
keyId   = b64u( HKDF-SHA256(ikm = LK, salt = "", info = "keyseal/v1/local-id",   L = 16) )
wrapKey =       HKDF-SHA256(ikm = LK, salt = "", info = "keyseal/v1/local-wrap", L = 32)
```

`key.keyId` is that 22-character `keyId`. It identifies the key without
revealing it, so a reader holding several local keys can pick the right one.

The data key is wrapped with AES-256-GCM under `wrapKey`, a fresh random
96-bit nonce and a 128-bit tag. The key context is bound as the AAD, using
the field encoding of section 6:

```
aad     = field("keyseal/v1/local-wrap") || field(keyId) || field(id)
          || field(env) || field(decimal(key.epoch))
wrapped = nonce(12) || ciphertext(32) || tag(16)          (60 bytes)
key.wrapped = b64u(wrapped)
```

A reader with no local key whose `keyId` matches, a `wrapped` that isn't 60
bytes, or a tag that fails to verify, MUST fail with `key_unavailable`.

The epoch is bound like any other context value, but there is no key
service to refuse older epochs: anyone holding `LK` can open every bundle
ever sealed with it. Moving to a new `LK` (a rekey under a new key) is the
only revocation. `spec/THREAT_MODEL.md` covers what this provider does and
doesn't protect.

### 4.4 The `worker` provider

`key.provider` is `"worker"`. The local key `LK` of section 4.3 lives in a
key service (the reference is a Cloudflare Worker), and readers ask it to
unwrap. `key.keyId` and `key.wrapped` are exactly as in 4.3, so a holder of
`LK` can always open a worker bundle with the `local` algorithm offline.

The service's URL is never stored in the bundle. Readers MUST take it from
their own configuration, so an edited bundle can't send credentials to
another host. Clients MUST use https (plain http only to localhost) and
MUST NOT follow redirects.

Requests are `POST`, JSON, with `Authorization: Bearer <credential>`:

```
POST {base}/v1/generate  {"keyId", "context": {"bundleId", "env", "epoch"}}
                      -> {"keyId", "plaintext", "wrapped"}
POST {base}/v1/decrypt   {"keyId", "wrapped", "context": {...}}
                      -> {"plaintext"}
```

Binary fields are b64u. In `generate`, `keyId` may be `"current"`: the
service wraps under the key it writes with and returns that key's id, which
the writer stores. Errors are `{"error": <status>, "message"}` with status
400 (bad request), 401 (unknown credential), 403 (not allowed: role,
environment, bundle, address or a revoked epoch), 404 (no such key), 422
(unwrap failed) or 500 (service misconfigured). Readers MUST map every
failure to `key_unavailable`.

The service MUST refuse a request whose `context.epoch` is below the lowest
epoch configured for that bundle; that is how a rekey revokes older copies.

## 5. Value encryption

Each value (current and previous) is encrypted separately with AES-256-GCM
under `encKey`, a fresh random 96-bit nonce, and a 128-bit tag.

```
aad   = "keyseal/v1/value" 0x00 id 0x00 env 0x00 name 0x00 decimal(v) 0x00 slot
slot  = "current" | "previous"
value = b64u( nonce(12) || ciphertext || tag(16) )
```

`0x00` is a single zero byte. None of `id`, `env`, `name` or the decimal can
contain a zero byte, so the encoding is unambiguous. `v` is the version of the
value being encrypted (`previous.v` for the previous slot).

The plaintext is the UTF-8 secret value. Values MAY be empty and MUST NOT be
longer than 65536 bytes.

The AAD binds every ciphertext to its bundle, environment, name, version and
slot, so a ciphertext moved to another name or slot fails to decrypt even
before the MAC is considered.

The bundle `version` is intentionally **not** in the AAD. Changing one secret
leaves every other ciphertext byte-for-byte unchanged, which keeps git diffs
to the lines that changed.

## 6. Bundle MAC

```
mac = b64u( HMAC-SHA256(macKey, transcript) )
```

The transcript is a sequence of fields. Each field is written as its byte
length as a 4-byte unsigned big-endian integer, followed by its UTF-8 bytes:

```
field(s) = uint32_be(len(UTF-8(s))) || UTF-8(s)
```

Fields, in this order:

1. `"keyseal/v1/bundle"`
2. `id`
3. `env`
4. decimal(`version`)
5. `updatedAt`
6. `key.provider`
7. `key.keyId`
8. decimal(`key.epoch`)
9. `key.wrapped`
10. decimal(number of secrets)
11. For each secret, in ascending byte order of the UTF-8 name:
    1. name
    2. decimal(`v`)
    3. `rotatedAt`
    4. `value`
    5. `"1"` if `previous` is present, otherwise `"0"`
    6. if present: decimal(`previous.v`), `previous.expiresAt`, `previous.value`

Readers MUST check the MAC in constant time and MUST check it before they
decrypt any value. A mismatch is `mac_mismatch`.

JSON whitespace, key order and formatting are not part of the transcript, so
any JSON serializer works. Writers SHOULD emit 2-space indented JSON with keys
in the order shown in section 3, secrets sorted by name, and a trailing
newline, so files written by different implementations diff cleanly.

## 7. Reading

A reader opening a bundle MUST, in order:

1. Parse the JSON and validate it against section 3 (`invalid_format`,
   `unsupported_format`).
2. If the caller pinned an environment and `env` differs, fail with
   `env_mismatch`.
3. If `key.provider` is not the provider the caller supplied, fail with
   `provider_mismatch`.
4. Unwrap `DK` through the provider with the key context
   (`key_unavailable` on any provider error).
5. Derive `encKey` and `macKey`, then verify the MAC (`mac_mismatch`).
6. Decrypt every current value, and every previous value whose
   `expiresAt` is in the future (`decrypt_failed`).

A reader that already holds a bundle with the same `id` MUST NOT replace it
with one whose `version` is lower (`rollback`). An equal version with a
different MAC is also `rollback`: two different bundles must never share a
version. Readers SHOULD let the caller set a minimum version for the first
load, because a fresh process has no earlier version to compare against.
Revoking older epochs (section 4.1) covers the same gap from the key
provider's side, without any reader configuration.

## 8. Writing

Every write (set, remove, rotate, rekey) MUST:

- set `version` to the previous version plus one;
- set `updatedAt` to the current time;
- recompute the MAC.

Setting a secret's value increments its `v` and sets `rotatedAt`. When the
writer keeps the old value for a grace window, the old ciphertext MUST be
re-encrypted for the `previous` slot (the AAD differs) and `expiresAt` set to
the end of the window. Without a grace window `previous` is removed.

`rekey` sets `key.epoch` to the previous epoch plus one, asks the provider
for a new data key under the new key context (optionally under a different
`keyId`), re-encrypts every value, and keeps `id`, `env` and every `v`. It is
the way to move a bundle to a new KMS key, and the response when a data key
might have been exposed: rekey, roll out the new bundle, then revoke the
older epochs (section 4.1). A new bundle starts at epoch 1.

## 9. The `test` provider

The provider name `test` is reserved for conformance fixtures. Its
`key.wrapped` is the fixed string `dGVzdA` and its data key is supplied
out of band by the test harness. Production readers MUST NOT accept the
`test` provider unless the caller explicitly passes a test provider.

## 10. Error codes

| Code | Meaning |
|---|---|
| `invalid_format` | Not valid JSON, or breaks a rule in section 3. |
| `unsupported_format` | `keyseal` is not `1`. |
| `env_mismatch` | Bundle `env` is not the pinned environment. |
| `provider_mismatch` | Bundle names a provider the caller didn't supply. |
| `key_unavailable` | The provider could not unwrap the data key. |
| `mac_mismatch` | The MAC doesn't verify. The bundle was modified or the data key is wrong. |
| `decrypt_failed` | A value failed to decrypt. Only reachable with a valid MAC, so it means a writer bug or an edit by someone holding the data key. |
| `rollback` | The bundle is older than one already loaded, or than the pinned minimum. |
| `not_found` | A requested secret isn't in the bundle. |

Implementations also use these codes for runtime conditions outside the
file format. They are not covered by the test vectors.

| Code | Meaning |
|---|---|
| `bundle_changed` | A running reader's source started serving a bundle with a different `id`. |
| `source_unavailable` | The bundle could not be fetched. |
| `invalid_argument` | The caller passed something invalid, e.g. a bad secret name or environment. |

## 11. Conformance

`spec/testvectors/v1.json` lists bundles with the expected result of
opening each one. An implementation conforms when every vector produces
exactly the expected secrets or error code. Its `local` array holds
wrapped data keys for the `local` provider (section 4.3), each with the
key, the key context, and the expected key id and data key or error. An
implementation that supports `local` must pass those too. The file is generated
deterministically by the reference implementation (`ts/`, `pnpm vectors`).
