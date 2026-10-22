# keyseal threat model

The usual way to give an app its secrets is a platform's env var store. Two
properties of that design decide how bad a leak of the store is, and keyseal
is built around both:

1. **Who holds the decryption key.** If the platform holds it, encryption at
   rest doesn't matter: whoever gets into the platform gets the key too.
2. **Whether rotation depends on a deploy.** If new values only reach apps
   through the platform's deploy pipeline, a paused pipeline freezes
   rotation, and leaked keys stay live until it resumes.

## What keyseal changes

| Problem | keyseal |
|---|---|
| The platform holds the key | The data key is wrapped by a KMS key **in your cloud account**. The platform stores ciphertext and, at most, one narrow credential that can call `kms:Decrypt` on one key. |
| A breach is invisible | Every unwrap is a KMS `Decrypt` call, logged in CloudTrail with the caller, source IP and the bundle id and environment from the encryption context. You can see whether anyone else decrypted. |
| You have to rotate N secrets right now | You revoke **one** credential and stop all further decryption. Then you rotate the secrets at their providers at your own pace, knowing from CloudTrail whether they were read. |
| Rotation waits for a deploy | Apps can poll the bundle from a source you control (S3, any HTTPS URL). Upload a new bundle and running apps switch to the new values within the poll interval, with no build and no deploy. |
| Old and new keys can't overlap | A rotation can keep the previous value for a grace window, so webhooks and token verification accept both while you roll over. |

The table describes AWS KMS mode. Local mode trades most of the first three
rows for not needing an AWS account; read the next section before using it.

## Local mode: what it protects and what it doesn't

> **Local mode does not protect you from an env store leak.** The
> app gets its local key from the `KEYSEAL_KEY` env var, so the key sits in
> the same platform env store that leaked. Anyone who reads that store and
> the repo can read every value in every bundle sealed with that key.

With `keyseal init --local`, the data key is wrapped by a 32-byte key you
generate and hold yourself, instead of by KMS. Nothing calls out to a cloud
service, so there is no audit trail and no server that can refuse a
request.

| Threat | AWS KMS | Local key |
|---|---|---|
| Repo leaks (1) | Protected | Protected |
| Bundle edited (2) | Protected | Protected |
| Env store leaks (3) | Nothing usable with workload identity; otherwise one narrow credential | **Not protected**: the store holds the key |
| Knowing whether anyone decrypted | CloudTrail logs every unwrap | **No record at all** |
| Cutting off a leaked key | Deactivate one IAM credential; no deploy | Rekey with a new local key, change `KEYSEAL_KEY` on the platform, then rotate every value |
| Old bundles in git history | IAM Deny on older epochs | Readable by anyone with the old key, forever |
| Deploy freeze (4) | Rotation by polling still works | Rotation by polling still works, but you can't swap a leaked key if changing env vars needs a deploy |

What local mode still gives you over plain env vars:

- The platform stores one secret instead of all of them, and a leaked repo
  or bundle alone reveals nothing.
- Bundles are tamper evident and versioned in git.
- Rotation without a deploy still works by polling a source you control.

Use it to get started, for development and staging, and on projects where an
env store breach is an acceptable risk. For production secrets that matter,
move the bundle to KMS with `keyseal rekey <file> --kms-key <key>`; nothing
else changes.

The key also lives on every machine that edits a bundle, in
`~/.config/keyseal/keys`. That file reads every value: treat it like a
password manager export, and back it up, because a bundle whose key is lost
can't be opened by anyone.

## Cloudflare Worker mode

With `keyseal init --worker <url>`, the local key lives as a secret in a
Worker on **your** Cloudflare account, and apps ask the Worker to unwrap.
It brings back most of what local mode gives up, without an AWS account:

| Threat | Worker, OIDC client | Worker, token client |
|---|---|---|
| Env store leaks (3) | Protected: the platform stores no secret, only a URL | One token, usable only for this app's bundle and environment, and only from pinned addresses if you set `ips` |
| Knowing whether anyone decrypted | Workers Logs line per request: client, address, bundle, environment, epoch | Same |
| Cutting off a leaked credential | Remove the client from `KEYSEAL_ACCESS` and deploy the Worker | Same; no app deploy |
| Old bundles in git history | `minEpoch` refuses older epochs | Same |

What it doesn't cover:

- **Your Cloudflare account is the root.** Anyone who can deploy to the
  Worker can change `KEYSEAL_ACCESS` or ship code that returns the key. Use
  hardware 2FA and few admins, as you would for the AWS account in KMS mode.
- **Logs are short.** The free plan keeps Workers Logs for 3 days. Export
  them (Logpush, or `wrangler tail` into storage) if you need a longer
  trail.
- **The key is exportable by you.** You generated it, so whoever holds your
  offline copy can open every bundle without the Worker. Store that copy
  like a root credential.

## Assets

- Secret values.
- The data key of each bundle.
- The KMS key and the IAM permissions to use it, or the local key.
- Bundle integrity: which secrets exist, their values and their versions.

## Adversaries and what happens

### 1. Someone reads the repo (leaked repo, malicious contributor, public fork)

They see secret names, versions and rotation times. They can't read values
without `kms:Decrypt` on the bundle's key with the bundle's encryption
context, or the local key. **Protected.**

Names are deliberately visible. If a name is itself sensitive, it doesn't
belong in a bundle.

### 2. Someone edits a bundle (repo write access, compromised CI, writable bucket)

Any change to any field breaks the MAC, and readers reject the bundle before
decrypting anything. Ciphertexts can't be moved between names, slots,
environments or bundles. **Integrity protected.**

The MAC key comes from the data key, so anyone who can unwrap a bundle can
also seal a valid edited copy, without asking KMS or the Worker for
anything new. That includes every app. Write access to the repo, bucket or
URL is what stops it: keep it for people and your publishing CI job.

They can serve an **older, validly sealed bundle** (a rollback), for example
to bring back a secret you rotated. A running process refuses any version
lower than the one it holds. A freshly started process has nothing to compare
with, so pin `minVersion` in deploy config, and make the poll source (S3
bucket, URL) writable only by you. **Partially protected.**

After a `rekey` and the IAM Deny that `keyseal policy` prints, every bundle
sealed under an older epoch fails to unwrap in KMS, in any process, with no
reader configuration. Editing the epoch breaks the MAC and the encryption
context. **Protected for every bundle older than the last rekey.** Rollbacks
between two rekeys still rely on `minVersion`. A local key can't deny old
epochs: only a new key (`rekey --local`) cuts old bundles off.

Rotating a value in keyseal does not revoke it at its provider. If a value
leaked, revoke it there. Old bundles in git history still decrypt until you
rekey and deny the older epochs.

### 3. The platform's env store leaks

What's in the store depends on how the app authenticates to KMS:

- **Workload identity** (EKS, ECS, Lambda, EC2 roles, or OIDC federation from
  platforms that issue workload tokens): no AWS secret is stored on the
  platform. The attacker gets nothing usable. **Protected.**
- **A static access key** (platforms without workload identity): the attacker
  gets one IAM credential. With the bundle as well, they can decrypt. This is
  still much better than the plaintext store:
  - the credential can do exactly one thing: `kms:Decrypt` on one key, for
    one environment and bundle (encryption context conditions in its IAM
    policy);
  - its IAM policy can pin `aws:SourceIp` to the platform's egress addresses,
    which makes the credential useless from anywhere else;
  - every use is in CloudTrail, so you can tell whether it was used;
  - deactivating the key in IAM cuts off all further decryption at once,
    without a deploy.

  **Reduced to one narrow, audited, revocable credential.**
- **A local key** (`KEYSEAL_KEY`): the attacker gets the key. With the
  bundle, they read every value, and nothing records that they did.
  **Not protected.**

### 4. The deploy pipeline is frozen

With a polling source, running apps pick up rotated values without a deploy.
With `keyseal run --watch`, apps that read env vars are restarted with the new
values. This depends on the source being outside the frozen platform (your S3
bucket, your URL). A bundle baked into the image only changes on a deploy.
**Protected when you poll a source you control.**

### 5. The host running your app is compromised

An attacker with code execution on the host, or with access to the process's
memory, can read decrypted values and can use the process's KMS access while
they have it. No secrets tool prevents that. keyseal limits the damage:
values stay out of `process.env` unless you ask for them, `redact()` scrubs
them from log lines, and decryption shows up in CloudTrail. **Not
protected.**

### 6. Your AWS account is compromised

An attacker who can use your KMS key can decrypt every bundle sealed with it.
A key per environment limits that to one environment, at $1 a month per key.
Restrict key administration and alert on `Decrypt` calls from unexpected
principals. **Not protected.**

### 7. A dependency is compromised (supply chain)

The core has no runtime dependencies and uses only the platform's WebCrypto.
The AWS SDK packages are pinned to exact versions. Releases are published
with npm provenance. **Reduced.**

## Deliberate non-goals

- **Hiding secret names.** Readable diffs matter more for review and incident
  response.
- **Protecting values in memory.** A process that uses a secret has the
  secret.
- **Revoking leaked values.** That happens at the secret's provider, never in
  a file.
- **Access control per secret.** Anyone who can decrypt a bundle can read all
  of it. Use one bundle per environment, or per service when they need
  different access.

## Recommended KMS setup

- One KMS key per environment, or one shared key. A shared key is safe for
  apps, because the policy from `keyseal policy` limits each one to its own
  environment and bundle. Separate keys add a second barrier, so a mistake
  in one IAM policy can't expose another environment.
- People who write bundles: `kms:GenerateDataKey` and `kms:Decrypt`.
  Editing a bundle means opening it, so anyone who can edit can read every
  value.
- CI jobs that publish bundles to S3: `s3:PutObject` only, no KMS access.
- Apps: `kms:Decrypt` only, with conditions on
  `kms:EncryptionContext:keyseal:env` and `keyseal:bundle`, plus a Deny for
  every older epoch. `keyseal policy <bundle>` prints exactly this.
- Static credentials only when workload identity isn't available, and then
  restricted with `aws:SourceIp`.
- A CloudTrail alert on `Decrypt` calls for the key from any principal or
  address you don't expect.

## Status

keyseal has not had an external security review yet. The
format and this document are open for review, and reports go to
security@ownkube.io.
