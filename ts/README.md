# @ownkube/keyseal

Encrypted secrets in your repo, unlocked by your own KMS key, rotated
without a redeploy.

- Secrets live in a JSON bundle you commit. Names are readable, values are
  encrypted with a data key wrapped by **your** AWS KMS key.
- Your hosting platform stores ciphertext. Every decrypt is a KMS call in
  your CloudTrail.
- Apps can poll the bundle from your S3 bucket, so rotating a secret
  doesn't wait for a deploy.

```sh
npm install --save-exact @ownkube/keyseal
```

## Use it

Create a bundle and add secrets (the CLI uses your normal AWS credentials):

```sh
npx keyseal init secrets/production.ks.json --env production --kms-key alias/keyseal-production --region us-east-1
npx keyseal import secrets/production.ks.json .env.production   # prints names only
npx keyseal set secrets/production.ks.json STRIPE_SECRET_KEY    # hidden prompt
npx keyseal ls secrets/production.ks.json
```

Run your app with the secrets as environment variables:

```sh
keyseal run secrets/production.ks.json --env production -- node server.js
keyseal run s3://acme-keyseal/production.ks.json --env production --watch -- node server.js
```

Or load them in code:

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
secrets.on("rotated", (e) => console.log("rotated", e.changed));
```

Test without AWS:

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

## AWS access and cost

The app needs `kms:Decrypt` on one key (plus `s3:GetObject` if it polls
S3). Each process calls KMS once at startup. Rotations make no KMS calls.
Expect about $1 a month per key.

No AWS account? `keyseal init --worker <url>` uses a
[keyseal Worker](https://github.com/ownkube/keyseal/blob/main/docs/cloudflare.md)
on your own Cloudflare account (`@ownkube/keyseal/cloudflare`, free plan
included): it holds the key, unwraps only for the apps you list, and logs
every request. `keyseal init --local` seals with a key you hold, and the
app reads it from `KEYSEAL_KEY`. That keeps secrets out of the repo but not
out of a leaked env store; read
[local keys](https://github.com/ownkube/keyseal/blob/main/docs/local.md)
before using it in production.

## Docs

- [Getting started](https://github.com/ownkube/keyseal/blob/main/docs/getting-started.md)
- [Rotation without a deploy](https://github.com/ownkube/keyseal/blob/main/docs/rotation.md)
- [Testing](https://github.com/ownkube/keyseal/blob/main/docs/testing.md)
- [AWS access, costs and limits](https://github.com/ownkube/keyseal/blob/main/docs/aws.md)
- [Cloudflare Worker (no AWS)](https://github.com/ownkube/keyseal/blob/main/docs/cloudflare.md)
- [Local keys (no AWS)](https://github.com/ownkube/keyseal/blob/main/docs/local.md)
- [CLI and API reference](https://github.com/ownkube/keyseal/blob/main/docs/reference.md)
- [Runbook for AI coding agents](https://github.com/ownkube/keyseal/blob/main/docs/agent-setup.md)
- [Threat model](https://github.com/ownkube/keyseal/blob/main/spec/THREAT_MODEL.md)

Requires Node 22.12 or later. MIT licensed.
