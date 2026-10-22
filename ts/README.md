<p align="center">
  <img src="https://raw.githubusercontent.com/ownkube/keyseal/main/.github/assets/logo-512.png" width="96" height="96" alt="keyseal">
</p>

# @ownkube/keyseal

[![CI](https://github.com/ownkube/keyseal/actions/workflows/ci.yml/badge.svg)](https://github.com/ownkube/keyseal/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@ownkube/keyseal?color=f59e0b&label=npm)](https://www.npmjs.com/package/@ownkube/keyseal)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ownkube/keyseal/badge)](https://scorecard.dev/viewer/?uri=github.com/ownkube/keyseal)
[![MIT license](https://img.shields.io/badge/license-MIT-52525b)](https://github.com/ownkube/keyseal/blob/main/LICENSE)

Secrets your app unlocks at runtime, through a key service you own.
Nothing that opens them is stored on your hosting platform.

**The problem.** Platforms keep your secrets in an env var store and hold
the key themselves, so a leak of the store is a leak of every value, and
new values only arrive with a deploy. Encrypting a file in your repo
doesn't help if the key that opens it sits in that same store.

**How keyseal unlocks.** Secrets stay encrypted in a bundle you commit or
publish to S3 or any URL. At startup the app proves who it is (OIDC, an
IAM role or one scoped token) to a key service you own, which checks the
app, bundle and environment, logs the request, and unwraps the data key.
Running apps poll for new bundles, so rotation doesn't wait for a deploy.

```sh
npm install --save-exact @ownkube/keyseal
```

## Key providers

| Provider | Where the key lives | `init` flag | In code |
| --- | --- | --- | --- |
| [AWS KMS](https://github.com/ownkube/keyseal/blob/main/docs/aws.md) | KMS, in your AWS account | `--kms-key <key>` | `awsKms()` from `@ownkube/keyseal/aws` |
| [Cloudflare Worker](https://github.com/ownkube/keyseal/blob/main/docs/cloudflare.md) | A Worker on your Cloudflare account (free plan) | `--worker <url>` | `worker()` |
| [Local key](https://github.com/ownkube/keyseal/blob/main/docs/local.md) | Your machine and the app's env | `--local` | `localKey()` |

KMS and the Worker keep your secrets sealed if the platform's env store
leaks. A local key does not; use it to get started or for low-stakes apps.
`keyseal rekey` moves a bundle between providers.

## Use it

```sh
npx keyseal init secrets/production.ks.json --env production --worker https://keyseal.acme.workers.dev
npx keyseal import secrets/production.ks.json .env.production   # prints names only
npx keyseal set secrets/production.ks.json STRIPE_SECRET_KEY    # hidden prompt
npx keyseal policy secrets/production.ks.json                   # what the app needs to unlock
```

Run your app with the secrets as environment variables:

```sh
keyseal run secrets/production.ks.json --env production -- node server.js
keyseal run s3://acme-keyseal/production.ks.json --env production --watch -- node server.js
```

Or load them in code:

```ts
import { createKeyseal, worker } from "@ownkube/keyseal";

const secrets = await createKeyseal({
  source: "secrets/production.ks.json", // or s3(...) or url(...)
  keys: worker(), // or awsKms(), or localKey()
  env: "production",
});

secrets.get("STRIPE_SECRET_KEY");
secrets.on("rotated", (e) => console.log("rotated", e.changed));
```

Test without any cloud account:

```ts
import { createKeyseal } from "@ownkube/keyseal";
import { sealTestBundle, testKeys, testSource } from "@ownkube/keyseal/testing";

const keys = testKeys();
const secrets = await createKeyseal({
  source: testSource(
    await sealTestBundle({ STRIPE_SECRET_KEY: "sk_test_1" }, { keys })
  ),
  keys,
  env: "test",
  poll: false,
});
```

A process unlocks once, at startup. Rotations reuse the data key and make
no key service calls.

## Docs

- [Getting started](https://github.com/ownkube/keyseal/blob/main/docs/getting-started.md)
- [Rotation without a deploy](https://github.com/ownkube/keyseal/blob/main/docs/rotation.md)
- [Testing](https://github.com/ownkube/keyseal/blob/main/docs/testing.md)
- [AWS KMS](https://github.com/ownkube/keyseal/blob/main/docs/aws.md)
- [Cloudflare Worker](https://github.com/ownkube/keyseal/blob/main/docs/cloudflare.md)
- [Local keys](https://github.com/ownkube/keyseal/blob/main/docs/local.md)
- [CLI and API reference](https://github.com/ownkube/keyseal/blob/main/docs/reference.md)
- [Runbook for AI coding agents](https://github.com/ownkube/keyseal/blob/main/docs/agent-setup.md)
- [Threat model](https://github.com/ownkube/keyseal/blob/main/spec/THREAT_MODEL.md)

Requires Node 22.12 or later. MIT licensed.
