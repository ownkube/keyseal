# Getting started

This guide moves a Node app from secrets in a platform's env store to an
encrypted bundle in its repo. If an AI coding agent is doing the setup,
point it at [agent-setup.md](agent-setup.md) instead, which covers the same
steps with checks and stop points.

The short version:

```sh
npx keyseal init secrets/production.ks.json --env production --kms-key alias/keyseal-production --region us-east-1
npx keyseal import secrets/production.ks.json .env.production
git add secrets/production.ks.json && git commit -m "Add encrypted secrets"
npx keyseal policy secrets/production.ks.json    # attach to the app's AWS role
npx keyseal run secrets/production.ks.json --env production -- node server.js
```

You need:

- Node 22.12 or later.
- An AWS account, and the AWS CLI signed in with permission to create KMS
  keys and IAM policies.
- The app's current secret values, for example in a `.env` file.

No AWS account? Follow [local keys](local.md) instead. It's quicker to set
up but doesn't protect you if the platform's env store leaks.

## 1. Install

```sh
npm install --save-exact @ownkube/keyseal
```

This gives you the library and the `keyseal` command. It signs in to AWS
the same way the AWS CLI does: `AWS_PROFILE`, SSO, environment variables or
a role.

## 2. Create a KMS key per environment

```sh
KEY_ARN=$(aws kms create-key --region us-east-1 \
  --description "keyseal production" --query KeyMetadata.Arn --output text)
aws kms create-alias --region us-east-1 \
  --alias-name alias/keyseal-production --target-key-id "$KEY_ARN"
aws kms enable-key-rotation --region us-east-1 --key-id "$KEY_ARN"
```

Repeat for `staging`, `development` and so on, so a credential for one
environment can never open another. Each key costs $1 a month and never
leaves AWS ([costs](aws.md#costs)). To pay for one key, share it across
environments: the app policy in step 6 still limits each app to its own
environment and bundle.

## 3. Create a bundle and add secrets

```sh
npx keyseal init secrets/production.ks.json \
  --env production --kms-key alias/keyseal-production --region us-east-1
npx keyseal import secrets/production.ks.json .env.production
```

`import` prints names, never values, and only changes values that differ.
To add or change one value later, `npx keyseal set secrets/production.ks.json
STRIPE_SECRET_KEY` reads it from a hidden prompt or a pipe. keyseal never
takes a value as a command-line argument.

Check the result:

```sh
npx keyseal ls secrets/production.ks.json       # names and dates, no AWS call
npx keyseal status secrets/production.ks.json   # decrypts and verifies everything
```

## 4. Commit it

```sh
git add secrets/production.ks.json
git commit -m "Add encrypted production secrets"
```

Names are readable, values are not, so diffs show which secrets changed and
when. Keep `.env*` files out of git.

If two people edit a bundle at once, git reports a conflict. Don't merge
bundle JSON by hand, because the result won't verify. Take one side, then
re-run the other person's `keyseal set` on top of it.

## 5. Load secrets in the app

**No code changes:** `keyseal run` starts your command with the secrets as
environment variables. It works with any language.

```json
{
  "scripts": {
    "start": "keyseal run secrets/production.ks.json --env production -- node server.js"
  }
}
```

`--env production` refuses a bundle for any other environment, so a staging
bundle can never end up in production by mistake.

**From code:** values stay out of `process.env`, so a dependency that dumps
the environment can't leak them.

```ts
import { createKeyseal } from "@ownkube/keyseal";
import { awsKms } from "@ownkube/keyseal/aws";

export const secrets = await createKeyseal({
  source: "secrets/production.ks.json",
  keys: awsKms(),
  env: "production",
});

const stripe = new Stripe(secrets.get("STRIPE_SECRET_KEY"));
```

See the [reference](reference.md#library) for `inject` and `redact`.

## 6. Give the app access

Print the app's IAM policy. It allows exactly one thing: decrypting this
bundle's data key.

```sh
npx keyseal policy secrets/production.ks.json
```

Attach it to the app's role: the ECS task role, the EKS service account's
role, the Lambda execution role, or the EC2 instance profile. On another
platform, use a role it can assume with OIDC if it supports that, otherwise
an IAM user with only this policy ([trade-offs](aws.md#off-aws-without-oidc-a-scoped-static-key)).

If you have a CLI profile for the app's role, check before you deploy:

```sh
AWS_PROFILE=app-production npx keyseal status secrets/production.ks.json --env production
```

## 7. Deploy, then clean up

Deploy, check that the app works, then delete the plaintext values from the
platform's env store and your local `.env.production`. That last step is
what makes a breach of the platform's store harmless.

## Local development

Use a separate key and bundle, so a developer laptop never needs production
access:

```sh
npx keyseal init secrets/development.ks.json \
  --env development --kms-key alias/keyseal-development --region us-east-1
npx keyseal run secrets/development.ks.json --env development -- npm run dev
```

## Next steps

- [Rotate secrets without a deploy](rotation.md) by polling S3.
- [Test code that uses keyseal](testing.md).
- [Incidents and hardening](hardening.md), for when something goes wrong.
- [AWS access, costs and limits](aws.md) and the [reference](reference.md).
