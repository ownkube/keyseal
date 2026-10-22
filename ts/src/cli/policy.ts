// `keyseal policy`: the IAM policy for a bundle, with every older key epoch
// denied, or for a Worker bundle the matching KEYSEAL_ACCESS entry.
// Generated rather than hand-written because the Deny is what makes a rekey
// revoke old bundles, and a typo in it fails open.

import type { Bundle } from "../format.ts";
import { parseS3Url } from "../s3.ts";

export type PolicyRole = "app" | "editor";

interface Statement {
  Sid: string;
  Effect: "Allow" | "Deny";
  Action: string | string[];
  Resource: string;
  Condition?: Record<string, Record<string, string | string[]>>;
}

export interface IamPolicy {
  Version: "2012-10-17";
  Statement: Statement[];
}

const CTX = "kms:EncryptionContext:keyseal";

export function bundlePolicy(
  b: Bundle,
  opts: { role?: PolicyRole; s3?: string } = {}
): IamPolicy {
  const role = opts.role ?? "app";
  const statements: Statement[] = [
    role === "app"
      ? {
          Sid: "KeysealDecrypt",
          Effect: "Allow",
          Action: "kms:Decrypt",
          Resource: b.key.keyId,
          Condition: {
            StringEquals: {
              [`${CTX}:env`]: b.env,
              [`${CTX}:bundle`]: b.id,
            },
          },
        }
      : {
          // Not pinned to the bundle id: `init` needs a key for a new id.
          Sid: "KeysealEdit",
          Effect: "Allow",
          Action: ["kms:GenerateDataKey", "kms:Decrypt"],
          Resource: b.key.keyId,
          Condition: { StringEquals: { [`${CTX}:env`]: b.env } },
        },
  ];
  if (b.key.epoch > 1) {
    statements.push({
      // Resource "*": older epochs may have used a different KMS key.
      Sid: "KeysealRevokedEpochs",
      Effect: "Deny",
      Action: ["kms:Decrypt", "kms:GenerateDataKey"],
      Resource: "*",
      Condition: {
        StringEquals: {
          [`${CTX}:bundle`]: b.id,
          [`${CTX}:epoch`]: Array.from({ length: b.key.epoch - 1 }, (_, i) =>
            String(i + 1)
          ),
        },
      },
    });
  }
  if (opts.s3) {
    const { bucket, key } = parseS3Url(opts.s3);
    statements.push({
      Sid: "KeysealBundle",
      Effect: "Allow",
      Action:
        role === "app" ? "s3:GetObject" : ["s3:GetObject", "s3:PutObject"],
      Resource: `arn:aws:s3:::${bucket}/${key}`,
    });
  }
  return { Version: "2012-10-17", Statement: statements };
}

export interface WorkerAccessSnippet {
  clients: Record<string, string>[];
  minEpoch?: Record<string, number>;
}

/**
 * The KEYSEAL_ACCESS entry for a Worker bundle, with every older epoch
 * revoked through minEpoch. The token hash is a placeholder the Worker
 * rejects until you paste in the one `keyseal token` printed.
 */
export function workerAccess(
  b: Bundle,
  opts: { role?: PolicyRole } = {}
): WorkerAccessSnippet {
  const role = opts.role ?? "app";
  const client: Record<string, string> =
    role === "app"
      ? { name: `${b.env}-app`, role, env: b.env, bundle: b.id }
      : // Not pinned to the bundle id: `init` needs a key for a new id.
        { name: `${b.env}-editor`, role, env: b.env };
  client.token = "sha256:PASTE_FROM_KEYSEAL_TOKEN";
  return {
    clients: [client],
    ...(b.key.epoch > 1 ? { minEpoch: { [b.id]: b.key.epoch } } : {}),
  };
}
