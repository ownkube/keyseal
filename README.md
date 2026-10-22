# keyseal

Encrypted secrets in your repo, unlocked by your own KMS key, rotated
without a redeploy.

Most hosting platforms keep your secrets in an env var store and hold the
key to it themselves. If that store leaks, encryption at rest doesn't help,
because the key leaks with it. And when new values only reach your app
through a deploy, you can't rotate while deploys are paused.

keyseal is built on two rules:

- **The key stays in your AWS account.** Secrets are encrypted with a data
  key wrapped by your KMS key. Your platform stores ciphertext, and every
  decrypt is a KMS call that shows up in your CloudTrail.
- **Rotation doesn't need a deploy.** Apps can poll the bundle from your S3
  bucket. Publish a new bundle and running apps switch to the new values
  within 30 seconds.

No AWS account? Run the [keyseal Worker](docs/cloudflare.md) on your own
Cloudflare account, free plan included. It holds the key, unwraps only for
the apps you list, and logs every request; with OIDC from Vercel, Fly or
GitHub Actions, the platform stores no secret at all. Or use
`keyseal init --local`, a key you hold yourself, which keeps secrets out of
the repo but not out of a leaked env store ([local keys](docs/local.md)).

```sh
npm install --save-exact @ownkube/keyseal

npx keyseal init secrets/production.ks.json --env production --kms-key alias/keyseal-production --region us-east-1
npx keyseal import secrets/production.ks.json .env.production
git add secrets/production.ks.json
npx keyseal policy secrets/production.ks.json --s3 s3://acme-keyseal/production.ks.json   # attach to the app's AWS role

# start the app with the secrets as env vars, restarting when they rotate
npx keyseal run s3://acme-keyseal/production.ks.json --env production --watch -- node server.js
```

Or from code, with no restart on rotation:

```ts
import { createKeyseal } from "@ownkube/keyseal";
import { awsKms } from "@ownkube/keyseal/aws";
import { s3 } from "@ownkube/keyseal/s3";

const secrets = await createKeyseal({
  source: s3("s3://acme-keyseal/production.ks.json"),
  keys: awsKms(),
  env: "production",
});

secrets.get("STRIPE_SECRET_KEY");
```

## What a bundle looks like

One JSON file per environment. Names, versions and rotation times are
readable, so code review and `git log` show what changed. Values are
AES-256-GCM ciphertext, and a MAC over the whole file catches any edit.

```json
{
  "keyseal": 1,
  "env": "production",
  "version": 7,
  "secrets": {
    "STRIPE_SECRET_KEY": { "v": 3, "rotatedAt": "2026-10-22T09:58:12Z", "value": "8Jq..." }
  }
}
```

(Trimmed. The full format is in [spec/FORMAT.md](spec/FORMAT.md).)

## Does the app need AWS access? Will it hit KMS limits?

The app needs `kms:Decrypt` on one key, scoped to its bundle, plus
`s3:GetObject` on one object if it polls S3. `keyseal policy` prints the
exact IAM policy. On AWS that comes from the
app's role, with no secret stored anywhere. Elsewhere it comes from OIDC
federation or one narrowly scoped access key.

A process calls KMS once, when it starts. Rotations reuse the data key, so
they make no KMS calls. The default KMS quota is thousands of requests per
second, and typical costs are $1 a month per key plus cents of requests.
Details: [docs/aws.md](docs/aws.md).

## Docs

| | |
|---|---|
| [Getting started](docs/getting-started.md) | From a `.env` file to an encrypted bundle, step by step. |
| [Rotation](docs/rotation.md) | Polling S3, publishing from CI, grace windows. |
| [Incidents and hardening](docs/hardening.md) | The breach playbook, revoking old bundles, rollback protection. |
| [Testing](docs/testing.md) | Unit tests without AWS, checking a real setup, a rotation drill. |
| [AWS access, costs and limits](docs/aws.md) | IAM policies, credentials per platform, KMS call counts, quotas, prices. |
| [Cloudflare Worker](docs/cloudflare.md) | A key service on your Cloudflare account: setup, OIDC, revocation, logs. |
| [Local keys](docs/local.md) | Using keyseal with a key you hold, and what you give up. |
| [Reference](docs/reference.md) | Every CLI command and flag, the library API, error codes. |
| [Agent runbook](docs/agent-setup.md) | Setup steps for AI coding agents, with checks and stop points. |
| [Threat model](spec/THREAT_MODEL.md) | What keyseal protects against, and what it doesn't. |
| [Format spec](spec/FORMAT.md) | The bundle format and conformance vectors. |

## Status

Pre-1.0. Node 22.12 or later. Key providers: AWS KMS, local keys, and a
Cloudflare Worker. The format
is specified separately from the code, with conformance vectors in
[spec/testvectors](spec/testvectors), so other languages can follow.

keyseal has not had an external security review yet. Report security
issues to security@ownkube.io.

## Layout

```
spec/   format spec, threat model, conformance vectors
ts/     @ownkube/keyseal: library and CLI
worker/ the Cloudflare Worker template
docs/   user documentation
```

## License

MIT
