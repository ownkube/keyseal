# AWS access, costs and limits

Short answers:

- **Does the app need AWS access?** Yes, one permission: `kms:Decrypt` on one
  KMS key, limited to one environment. If it polls S3 for rotations, also
  `s3:GetObject` on one object. That access is the point: the key lives in
  your account, so the platform running your app can't read your secrets
  without asking AWS, and AWS logs every time it does.
- **Will you hit KMS limits?** Almost certainly not. A running process calls
  KMS once, when it starts. Rotating secret values makes no KMS calls at
  all. You would need thousands of processes starting in the same second to
  get near the default request quota.

The rest of this page has the details.

## Who needs what

| Who | Needs | Why |
|---|---|---|
| People and CI jobs that **edit** bundles | `kms:GenerateDataKey`, `kms:Decrypt` | `init` and `rekey` ask KMS for a data key. Every other edit opens the bundle first, which is a `Decrypt`. |
| The **app** | `kms:Decrypt` | Unwraps the bundle's data key once at startup. |
| The app, when polling S3 | `s3:GetObject` on the bundle object | Fetches new bundle versions. |
| A CI job that **publishes** bundles to S3 | `s3:PutObject` on the bundle object | Uploads only. No KMS access, so CI can't read values. |
| Anyone running `keyseal ls` | Nothing in KMS | `ls` reads names and dates without decrypting. |

Anyone who can edit a bundle can read every value in it, because editing
means decrypting. Give `kms:GenerateDataKey` only to people who should see
production values.

### Policies

Don't write the app policy by hand. `keyseal policy` prints it from the
bundle, with the real key ARN, bundle id and environment filled in:

```sh
npx keyseal policy secrets/production.ks.json --s3 s3://acme-keyseal/production.ks.json
npx keyseal policy secrets/production.ks.json --role editor
```

It makes no AWS call. Run it on your local copy of the bundle, not on a URL
someone else can write to. The encryption context conditions mean this
access opens the `production` bundle only, even if another bundle uses the
same key. For a bundle at epoch 1 the app policy looks like this:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KeysealDecrypt",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
      "Condition": {
        "StringEquals": {
          "kms:EncryptionContext:keyseal:env": "production",
          "kms:EncryptionContext:keyseal:bundle": "Xq3m0yJw6Zr1k2v9Qp7tLg"
        }
      }
    },
    {
      "Sid": "KeysealBundle",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::acme-keyseal/production.ks.json"
    }
  ]
}
```

Bundle editors (people, or a CI job that edits):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KeysealEdit",
      "Effect": "Allow",
      "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
      "Resource": "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
      "Condition": {
        "StringEquals": { "kms:EncryptionContext:keyseal:env": "production" }
      }
    }
  ]
}
```

Publishing CI job:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KeysealPublish",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::acme-keyseal/production.ks.json"
    }
  ]
}
```

These are IAM policies. They work with the default KMS key policy, which
lets IAM grant access to the key. If your key has a custom key policy, it
must allow the same principals.

After a `rekey`, `keyseal policy` also prints a Deny for the bundle's older
key epochs, which makes every older copy of the bundle unreadable. See
[Revoking old bundles](hardening.md#revoking-old-bundles).

## How the app gets AWS credentials

keyseal uses the AWS SDK's standard credential chain, so whatever already
gives your app AWS credentials works.

| Where the app runs | Credentials | Secret stored on the platform |
|---|---|---|
| ECS / Fargate | Task role | None |
| EKS | IRSA or EKS Pod Identity | None |
| Lambda | Execution role | None |
| EC2 | Instance profile | None |
| A platform that issues OIDC tokens to workloads | An IAM role that trusts the platform's issuer (web identity federation) | None |
| Any other platform | An IAM user's access key, scoped as below | One narrow AWS key |

### Off AWS without OIDC: a scoped static key

Some platforms can't federate, so the app needs an access key. Be clear
about what that buys you. The access key sits in the same env store that
could leak. If an attacker gets that key and the bundle, they can decrypt.
That is still a much better position than a store full of plaintext secrets:

- **It's one credential, not twenty.** It can do exactly one thing:
  `kms:Decrypt` on one key, for one environment, plus reading one S3 object.
- **You can see whether it was used.** Every `Decrypt` is in CloudTrail with
  the caller and source IP (see [Checking who decrypted](#checking-who-decrypted)).
- **You can pin it to your platform.** If the platform has fixed egress IPs,
  add a condition and the key is useless anywhere else:

  ```json
  "Condition": {
    "StringEquals": {
      "kms:EncryptionContext:keyseal:env": "production",
      "kms:EncryptionContext:keyseal:bundle": "Xq3m0yJw6Zr1k2v9Qp7tLg"
    },
    "IpAddress": { "aws:SourceIp": ["203.0.113.10/32", "203.0.113.11/32"] }
  }
  ```

- **You can revoke it in seconds**, in IAM, without a deploy.

What happens after you revoke it: running processes keep serving the values
already in memory, but they can't fetch new bundles, and new instances fail
to start until the platform has a new key. Use the [incident
playbook](hardening.md#incident-playbook) to decide when to revoke.

## How often keyseal calls KMS

| Event | KMS calls |
|---|---|
| App process starts | 1 `Decrypt` |
| A new bundle with rotated, added or removed values is published | **0**. The data key is unchanged, so the app reuses the one in memory. |
| `keyseal rekey` is published | 1 `Decrypt` per running process, on its next poll |
| Polling finds no change | 0 KMS calls (one S3 GET) |
| `keyseal get`, `export`, `status`, `run` | 1 `Decrypt` |
| `keyseal set`, `rotate`, `import`, `rm` | 1 `Decrypt` |
| `keyseal init`, `rekey` | 1 `GenerateDataKey` (plus 1 `Decrypt` for `rekey`) |
| `keyseal ls`, `policy` | 0 |

Calling `secrets.get()` never calls KMS. Values are decrypted once and
served from memory.

The one way to call KMS far too often is to create a new client per request.
Create it once per process (at module scope in Lambda) and share it.

## Quotas

KMS request quotas are per account and per region. Symmetric operations
(`Decrypt`, `GenerateDataKey` and others) share one quota: at least 5,500
requests per second, and higher in some large regions. That quota is shared
with everything else in the account that uses KMS in that region. Check the
current value in the Service Quotas console under AWS Key Management
Service.

To put that in proportion, 5,500 per second means 5,500 processes starting
in the same second. Normal deploys, autoscaling and Lambda cold starts are
far below that.

If you are throttled, the AWS SDK retries with backoff. If a process still
can't unwrap the key, startup fails with `key_unavailable` and your
orchestrator restarts it. Running processes are never affected, because
they don't call KMS.

## Costs

AWS prices change, so check the KMS and S3 pricing pages. At the time of
writing:

| Item | Price | Typical keyseal use |
|---|---|---|
| KMS key | $1 per month per key | One per environment, or one shared |
| KMS automatic key rotation | A small extra monthly charge for the first rotations of each key | Optional, recommended |
| KMS requests | $0.03 per 10,000, with 20,000 free per month | One per process start |
| S3 GET | About $0.0004 per 1,000 | One per poll per process |
| S3 storage | Negligible | One small JSON file per environment |

Examples:

- **10 containers, deployed 5 times a day:** about 1,500 `Decrypt` calls a
  month, inside the free tier. Polling every 30 seconds is about 864,000 S3
  GETs a month, roughly $0.35.
- **A Lambda function with 1 million cold starts a month:** about 1 million
  `Decrypt` calls, roughly $3.
- **Two environments:** $2 a month for the keys.

The S3 cost scales with process count and poll interval. Polling every 30
seconds costs about $0.035 a month per process. Raise the interval if you
run thousands of processes.

Keep the bucket on its default encryption (SSE-S3). The bundle is already
encrypted, and SSE-KMS would add a KMS call to every poll.

## Checking who decrypted

Every `Decrypt` of a bundle key is a CloudTrail event that includes the
caller, the source IP and the encryption context (bundle id and
environment). CloudTrail's event history keeps 90 days of these with no
setup:

```sh
aws cloudtrail lookup-events \
  --region us-east-1 \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab \
  --max-results 50 \
  --query 'Events[].CloudTrailEvent' --output text \
| jq -r '[.eventTime, .eventName, (.userIdentity.arn // .userIdentity.accessKeyId), .sourceIPAddress, (.requestParameters.encryptionContext["keyseal:env"] // "")] | @tsv'
```

Anything from a principal or address you don't recognise is worth an alert.
For alerts, send CloudTrail to CloudWatch Logs or EventBridge and match
`eventSource = kms.amazonaws.com` and `eventName = Decrypt` for the key.
