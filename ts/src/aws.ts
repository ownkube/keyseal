// AWS KMS key provider. The data key is generated and unwrapped by KMS with
// the bundle id and environment as encryption context, so every unwrap shows
// up in CloudTrail tagged with exactly which bundle was opened.

import {
  DecryptCommand,
  GenerateDataKeyCommand,
  KMSClient,
  type KMSClientConfig,
} from "@aws-sdk/client-kms";
import { type Bytes, own } from "./encoding.ts";
import { KeysealError } from "./errors.ts";
import {
  type GeneratedDataKey,
  type KeyContext,
  type KeyProvider,
  keyContextMap,
} from "./keys.ts";

export interface AwsKmsOptions {
  /** Use this client for every call (its region wins). */
  client?: KMSClient;
  /** Region for key ids that aren't ARNs. Defaults to the SDK's chain. */
  region?: string;
  /** Extra config for clients this provider creates. */
  clientConfig?: KMSClientConfig;
}

const ARN_RE = /^arn:aws[a-z-]*:kms:([a-z0-9-]+):\d{12}:(key|alias)\/.+$/;

export function regionFromKeyId(keyId: string): string | undefined {
  return ARN_RE.exec(keyId)?.[1];
}

export function awsKms(opts: AwsKmsOptions = {}): KeyProvider {
  const clients = new Map<string, KMSClient>();

  function clientFor(keyId: string): KMSClient {
    if (opts.client) return opts.client;
    // A key ARN carries its region; follow it so one bundle opens anywhere.
    const region = regionFromKeyId(keyId) ?? opts.region ?? "";
    let c = clients.get(region);
    if (!c) {
      c = new KMSClient({
        ...opts.clientConfig,
        ...(region ? { region } : {}),
      });
      clients.set(region, c);
    }
    return c;
  }

  return {
    name: "aws-kms",

    async generateDataKey(
      keyId: string,
      ctx: KeyContext
    ): Promise<GeneratedDataKey> {
      const res = await clientFor(keyId).send(
        new GenerateDataKeyCommand({
          KeyId: keyId,
          KeySpec: "AES_256",
          EncryptionContext: keyContextMap(ctx),
        })
      );
      if (!res.Plaintext || !res.CiphertextBlob || !res.KeyId) {
        throw new KeysealError(
          "key_unavailable",
          "KMS GenerateDataKey returned an incomplete response"
        );
      }
      const plaintext = own(res.Plaintext);
      res.Plaintext.fill(0);
      // Store the key ARN, not an alias: retargeting an alias must never
      // silently change which key a bundle trusts.
      return { plaintext, wrapped: res.CiphertextBlob, keyId: res.KeyId };
    },

    async decryptDataKey(
      keyId: string,
      wrapped: Uint8Array,
      ctx: KeyContext
    ): Promise<Bytes> {
      const res = await clientFor(keyId).send(
        new DecryptCommand({
          // Pinning KeyId stops a crafted bundle from pointing at a key the
          // attacker controls.
          KeyId: keyId,
          CiphertextBlob: wrapped,
          EncryptionContext: keyContextMap(ctx),
          EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
        })
      );
      if (!res.Plaintext || res.Plaintext.length !== 32) {
        throw new KeysealError(
          "key_unavailable",
          "KMS Decrypt did not return a 32-byte data key"
        );
      }
      const out = own(res.Plaintext);
      res.Plaintext.fill(0);
      return out;
    },
  };
}
