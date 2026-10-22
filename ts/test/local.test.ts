import { afterEach, describe, expect, it } from "vite-plus/test";
import { BundleEditor, openBundle } from "../src/bundle.ts";
import { isKeysealError } from "../src/errors.ts";
import { parseBundle } from "../src/format.ts";
import { generateLocalKey, localKey, localKeyId } from "../src/local.ts";
import { testKeys } from "../src/testing.ts";

async function sealedWith(key: string): Promise<string> {
  const ed = await BundleEditor.create({
    env: "production",
    keyId: await localKeyId(key),
    provider: localKey({ keys: key }),
  });
  await ed.set("STRIPE_SECRET_KEY", "sk_test_local");
  return ed.seal();
}

async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "ok";
  } catch (e) {
    if (isKeysealError(e)) return e.code;
    throw e;
  }
}

const saved = process.env.KEYSEAL_KEY;
afterEach(() => {
  if (saved === undefined) delete process.env.KEYSEAL_KEY;
  else process.env.KEYSEAL_KEY = saved;
});

describe("local key provider", () => {
  it("makes keys with a recognisable prefix and a stable id", async () => {
    const key = generateLocalKey();
    expect(key).toMatch(/^keyseal_local_[A-Za-z0-9_-]{43}$/);
    const id = await localKeyId(key);
    expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(await localKeyId(key)).toBe(id);
    expect(await localKeyId(generateLocalKey())).not.toBe(id);
  });

  it("seals and opens a bundle, picking the right key out of several", async () => {
    const key = generateLocalKey();
    const text = await sealedWith(key);
    const b = parseBundle(text);
    expect(b.key.provider).toBe("local");
    expect(b.key.keyId).toBe(await localKeyId(key));

    const keys = `${generateLocalKey()}, ${key}\n${generateLocalKey()}`;
    const { secrets } = await openBundle(text, localKey({ keys }));
    expect(secrets.get("STRIPE_SECRET_KEY")?.value).toBe("sk_test_local");
  });

  it("reads KEYSEAL_KEY by default", async () => {
    const key = generateLocalKey();
    const text = await sealedWith(key);
    process.env.KEYSEAL_KEY = key;
    const { secrets } = await openBundle(text, localKey());
    expect(secrets.size).toBe(1);
  });

  it("fails key_unavailable without the right key", async () => {
    const text = await sealedWith(generateLocalKey());
    delete process.env.KEYSEAL_KEY;
    expect(await codeOf(openBundle(text, localKey()))).toBe("key_unavailable");
    expect(
      await codeOf(openBundle(text, localKey({ keys: generateLocalKey() })))
    ).toBe("key_unavailable");
  });

  it("refuses a malformed key up front without echoing it", () => {
    const bad = "keyseal_local_not-a-real-key";
    let err: unknown;
    try {
      localKey({ keys: bad });
    } catch (e) {
      err = e;
    }
    expect(isKeysealError(err, "invalid_argument")).toBe(true);
    expect((err as Error).message).not.toContain("not-a-real-key");
  });

  it("binds the wrapped key to the epoch, before the MAC is even checked", async () => {
    const key = generateLocalKey();
    const o = JSON.parse(await sealedWith(key)) as {
      key: { epoch: number };
    };
    o.key.epoch = 2;
    expect(
      await codeOf(openBundle(JSON.stringify(o), localKey({ keys: key })))
    ).toBe("key_unavailable");
  });

  it("rekeys to a new local key, after which only the new key opens it", async () => {
    const oldKey = generateLocalKey();
    const newKey = generateLocalKey();
    const ed = await BundleEditor.open(
      await sealedWith(oldKey),
      localKey({ keys: oldKey })
    );
    await ed.rekey(await localKeyId(newKey), localKey({ keys: newKey }));
    const text = await ed.seal();
    expect(parseBundle(text).key.epoch).toBe(2);
    expect(await codeOf(openBundle(text, localKey({ keys: newKey })))).toBe(
      "ok"
    );
    expect(await codeOf(openBundle(text, localKey({ keys: oldKey })))).toBe(
      "key_unavailable"
    );
  });

  it("moves a bundle to another provider on rekey", async () => {
    const key = generateLocalKey();
    const ed = await BundleEditor.open(
      await sealedWith(key),
      localKey({ keys: key })
    );
    await ed.rekey("test", testKeys());
    const text = await ed.seal();
    expect(parseBundle(text).key.provider).toBe("test");
    const { secrets } = await openBundle(text, testKeys());
    expect(secrets.get("STRIPE_SECRET_KEY")?.value).toBe("sk_test_local");
  });

  it("needs a key id to change provider", async () => {
    const key = generateLocalKey();
    const ed = await BundleEditor.open(
      await sealedWith(key),
      localKey({ keys: key })
    );
    expect(await codeOf(ed.rekey(undefined, testKeys()))).toBe(
      "invalid_argument"
    );
  });
});
