# Rotating secrets without a deploy

A bundle in your repo is encrypted with your key, but if the app reads it
from its own image, a new value still needs a deploy to reach production.
When your platform has paused deploys, that's exactly when you can't ship.

The fix is to have apps poll the bundle from a place you control, usually
an S3 bucket in your AWS account. You publish a new bundle and every
running process picks it up within the poll interval (30 seconds by
default), with no build and no deploy.

The repo stays the source of truth. A CI job, or you, copies the committed
bundle to S3.

```
edit bundle → commit → publish to S3 → apps poll → new values in memory
```

## 1. Create the bucket

```sh
BUCKET=acme-keyseal
REGION=us-east-1

aws s3api create-bucket --bucket "$BUCKET" --region "$REGION"
# Outside us-east-1, add: --create-bucket-configuration LocationConstraint=$REGION

aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws s3api put-bucket-versioning --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled
```

Versioning keeps every published bundle, so you can see what was live when.
Leave default encryption as SSE-S3: the bundle is already encrypted, and
SSE-KMS would add a KMS call to every poll.

The bucket holds ciphertext, but who can **write** to it matters: someone
who can write could publish an older bundle. Running apps refuse older
versions (see [Rollback protection](hardening.md#rollback-protection)), but
keep write access to you and your publishing CI job.

## 2. Publish

By hand:

```sh
npx keyseal ls secrets/production.ks.json
aws s3 cp secrets/production.ks.json s3://acme-keyseal/production.ks.json \
  --content-type application/json
```

`keyseal ls` checks that the file is a well-formed bundle without needing
AWS access. The app verifies the MAC when it loads the bundle.

### From GitHub Actions

This workflow publishes every bundle when it changes on `main`. It signs in
to AWS with OIDC, so no AWS key is stored in GitHub, and its role can only
upload. It has no KMS access and can't read values.

`.github/workflows/publish-secrets.yml`:

```yaml
name: Publish secrets

on:
  push:
    branches: [main]
    paths: ["secrets/*.ks.json"]

permissions:
  id-token: write
  contents: read

concurrency: publish-secrets

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.1
      - uses: actions/setup-node@v7.1.0
        with:
          node-version: 24
      - uses: aws-actions/configure-aws-credentials@v6.3.0
        with:
          role-to-assume: arn:aws:iam::111122223333:role/keyseal-publish
          aws-region: us-east-1
      - name: Publish bundles
        run: |
          for f in secrets/*.ks.json; do
            npx --yes @ownkube/keyseal@0.1.0 ls "$f" > /dev/null
            aws s3 cp "$f" "s3://acme-keyseal/$(basename "$f")" \
              --content-type application/json
          done
```

The `keyseal-publish` role needs this trust policy (replace the account and
`acme/api` with your org and repo):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:acme/api:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

It also needs an `s3:PutObject` permission policy on
`arn:aws:s3:::acme-keyseal/*.ks.json`. If your account doesn't have the
GitHub OIDC provider yet:

```sh
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com
```

## 3. Point the app at S3

The app also needs `s3:GetObject` on the object. Re-print its policy with
the object added, and replace the one you attached:

```sh
npx keyseal policy secrets/production.ks.json --s3 s3://acme-keyseal/production.ks.json
```

### With `keyseal run --watch`

```sh
keyseal run s3://acme-keyseal/production.ks.json --env production --watch -- node server.js
```

keyseal polls every 30 seconds (`--poll 10s` to change it). When values
change, it sends the app `SIGTERM`, waits up to 10 seconds
(`--stop-timeout`) before `SIGKILL`, and starts it again with the new
values. Rotation reaches any language this way, at the cost of a restart.
Set `AWS_REGION` (or `--region`) to the bucket's region.

### With the library

```ts
import { createKeyseal } from "@ownkube/keyseal";
import { awsKms } from "@ownkube/keyseal/aws";
import { s3 } from "@ownkube/keyseal/s3";

export const secrets = await createKeyseal({
  source: s3("s3://acme-keyseal/production.ks.json"),
  keys: awsKms(),
  env: "production",
  minVersion: Number(process.env.KEYSEAL_MIN_VERSION ?? 1),
});

secrets.on("rotated", (e) => {
  logger.info({ version: e.version, changed: e.changed }, "secrets rotated");
});
secrets.on("error", (err) => {
  // A failed poll keeps the current values; this is for your logs.
  logger.warn({ err }, "could not refresh secrets");
});
```

No restart is needed. Two habits make rotation take effect everywhere:

- **Read values when you use them.** `secrets.get("API_KEY")` at call time
  always returns the current value. A value copied into a variable at
  startup never changes.
- **Rebuild clients that hold a value**, such as an SDK client constructed
  with an API key:

  ```ts
  let stripe = new Stripe(secrets.get("STRIPE_SECRET_KEY"));
  secrets.on("rotated", (e) => {
    if (e.changed.includes("STRIPE_SECRET_KEY")) {
      stripe = new Stripe(secrets.get("STRIPE_SECRET_KEY"));
    }
  });
  ```

Polling never calls KMS unless the bundle was rekeyed. Rotated values use
the same data key, which the process already holds. A poll that finds no
change is one S3 request. See [aws.md](aws.md) for costs.

In Lambda, timers don't run while an environment is frozen. Set
`poll: false` and refresh at the start of an invocation instead:

```ts
let checked = Date.now();
export async function handler(event) {
  if (Date.now() - checked > 30_000) {
    checked = Date.now();
    await secrets.refresh().catch(() => {}); // keep current values on failure
  }
  // ...
}
```

## Rotating a value

```sh
npx keyseal rotate secrets/production.ks.json STRIPE_SECRET_KEY --grace 1h
git commit -am "Rotate Stripe key" && git push   # CI publishes
```

`rotate` keeps the old value readable for the grace window (24 hours by
default; `set` keeps none). The library exposes it as
`secrets.previous("STRIPE_SECRET_KEY")`, which matters for values checked
on the way in, like webhook signing secrets:

```ts
function verify(payload: string, signature: string): boolean {
  if (check(payload, signature, secrets.get("WEBHOOK_SECRET"))) return true;
  const old = secrets.previous("WEBHOOK_SECRET");
  return old !== undefined && check(payload, signature, old);
}
```

The usual order for an API key:

1. Create the new key at the provider. Leave the old one active.
2. `keyseal rotate`, commit and publish.
3. Wait for apps to pick it up (watch for the `rotated` log line).
4. Revoke the old key at the provider.

Rotating a value in keyseal never revokes the old one at its provider.
Revoking happens there. Old bundles in git history also still decrypt to it
until you [revoke the old bundles](hardening.md#revoking-old-bundles).

If your platform's env store has leaked, follow the [incident
playbook](hardening.md#incident-playbook).
