import { describe, expect, it } from "vite-plus/test";
import { BundleEditor } from "../src/bundle.ts";
import { bundlePolicy } from "../src/cli/policy.ts";
import { parseBundle } from "../src/format.ts";
import { provider, sealed } from "./helpers.ts";

async function atEpoch(epoch: number) {
  let text = await sealed({ A: "alpha" });
  for (let e = 1; e < epoch; e++) {
    const ed = await BundleEditor.open(text, provider());
    await ed.rekey();
    text = await ed.seal();
  }
  return parseBundle(text);
}

describe("bundlePolicy", () => {
  it("allows only Decrypt for this bundle and env at epoch 1", async () => {
    const b = await atEpoch(1);
    const p = bundlePolicy(b);
    expect(p.Statement).toEqual([
      {
        Sid: "KeysealDecrypt",
        Effect: "Allow",
        Action: "kms:Decrypt",
        Resource: "test-key",
        Condition: {
          StringEquals: {
            "kms:EncryptionContext:keyseal:env": "production",
            "kms:EncryptionContext:keyseal:bundle": b.id,
          },
        },
      },
    ]);
  });

  it("denies every older epoch after a rekey", async () => {
    const b = await atEpoch(3);
    const deny = bundlePolicy(b).Statement.find((s) => s.Effect === "Deny");
    expect(deny?.Resource).toBe("*");
    expect(deny?.Condition?.StringEquals).toEqual({
      "kms:EncryptionContext:keyseal:bundle": b.id,
      "kms:EncryptionContext:keyseal:epoch": ["1", "2"],
    });
  });

  it("adds S3 access scoped to the object, write only for editors", async () => {
    const b = await atEpoch(1);
    const s3 = "s3://acme-keyseal/production.ks.json";
    const arn = "arn:aws:s3:::acme-keyseal/production.ks.json";
    const app = bundlePolicy(b, { s3 }).Statement.at(-1);
    expect(app).toMatchObject({ Action: "s3:GetObject", Resource: arn });
    const editor = bundlePolicy(b, { role: "editor", s3 }).Statement;
    expect(editor[0]?.Action).toEqual(["kms:GenerateDataKey", "kms:Decrypt"]);
    expect(editor.at(-1)).toMatchObject({
      Action: ["s3:GetObject", "s3:PutObject"],
      Resource: arn,
    });
  });
});
