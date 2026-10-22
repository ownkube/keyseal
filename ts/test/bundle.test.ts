import { describe, expect, it } from "vite-plus/test";
import { BundleEditor, openBundle } from "../src/bundle.ts";
import { isKeysealError } from "../src/errors.ts";
import { parseBundle } from "../src/format.ts";
import {
  type KeyContext,
  type KeyProvider,
  keyContextMap,
} from "../src/keys.ts";
import { testKeys } from "../src/testing.ts";
import { clock, HOUR, provider, sealed, T0 } from "./helpers.ts";

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    if (isKeysealError(e)) return e.code;
    throw e;
  }
  throw new Error("expected a KeysealError");
}

describe("BundleEditor", () => {
  it("round-trips values through seal and open", async () => {
    const text = await sealed({ A_KEY: "alpha", B_KEY: "" });
    const { bundle, secrets } = await openBundle(text, provider());
    expect(bundle.version).toBe(1);
    expect(secrets.get("A_KEY")?.value).toBe("alpha");
    expect(secrets.get("B_KEY")?.value).toBe("");
  });

  it("starts at version 1 and bumps by one per seal", async () => {
    const c = clock();
    const v1 = await sealed({ A: "1" }, { now: c.now });
    const ed = await BundleEditor.open(v1, provider(), { now: c.now });
    expect(ed.version).toBe(1);
    await ed.set("A", "2");
    const v2 = await ed.seal();
    expect(parseBundle(v2).version).toBe(2);
  });

  it("returns false and changes nothing for an unchanged value", async () => {
    const text = await sealed({ A: "same" });
    const ed = await BundleEditor.open(text, provider());
    expect(await ed.set("A", "same")).toBe(false);
    expect(ed.dirty).toBe(false);
  });

  it("keeps the ciphertext of untouched secrets byte for byte", async () => {
    const text = await sealed({ A: "a-value", B: "b-value" });
    const ed = await BundleEditor.open(text, provider());
    await ed.set("B", "b-new");
    const after = parseBundle(await ed.seal());
    expect(after.secrets.get("A")?.value).toBe(
      parseBundle(text).secrets.get("A")?.value
    );
  });

  it("keeps the old value readable for the grace window", async () => {
    const c = clock();
    const text = await sealed({ KEY: "old" }, { now: c.now });
    const ed = await BundleEditor.open(text, provider(), { now: c.now });
    await ed.set("KEY", "new", { grace: 24 * HOUR });
    const rotated = await ed.seal();

    const live = await openBundle(rotated, provider(), { now: T0 + HOUR });
    expect(live.secrets.get("KEY")).toMatchObject({
      value: "new",
      v: 2,
      previous: { value: "old", v: 1 },
    });

    const later = await openBundle(rotated, provider(), {
      now: T0 + 25 * HOUR,
    });
    expect(later.secrets.get("KEY")?.previous).toBeUndefined();
  });

  it("drops expired previous values when sealing", async () => {
    const c = clock();
    const text = await sealed({ KEY: "old" }, { now: c.now });
    const ed = await BundleEditor.open(text, provider(), { now: c.now });
    await ed.set("KEY", "new", { grace: HOUR });
    const rotated = await ed.seal();

    c.advance(2 * HOUR);
    const ed2 = await BundleEditor.open(rotated, provider(), { now: c.now });
    await ed2.set("OTHER", "x");
    const next = parseBundle(await ed2.seal());
    expect(next.secrets.get("KEY")?.previous).toBeUndefined();
  });

  it("removes secrets", async () => {
    const text = await sealed({ A: "1", B: "2" });
    const ed = await BundleEditor.open(text, provider());
    expect(ed.remove("A")).toBe(true);
    expect(ed.remove("A")).toBe(false);
    const { secrets } = await openBundle(await ed.seal(), provider());
    expect([...secrets.keys()]).toEqual(["B"]);
  });

  it("rekeys every value and stays readable", async () => {
    const text = await sealed({ A: "alpha" });
    const ed = await BundleEditor.open(text, provider());
    await ed.rekey("new-key");
    const rekeyed = parseBundle(await ed.seal());
    expect(rekeyed.key.keyId).toBe("new-key");
    expect(rekeyed.secrets.get("A")?.value).not.toBe(
      parseBundle(text).secrets.get("A")?.value
    );
    const { secrets } = await openBundle(rekeyed, provider());
    expect(secrets.get("A")?.value).toBe("alpha");
  });

  it("starts at epoch 1, bumps it on rekey and binds it into the key context", async () => {
    const seen: KeyContext[] = [];
    const inner = provider();
    const spy: KeyProvider = {
      name: inner.name,
      generateDataKey: (keyId, ctx) => {
        seen.push(ctx);
        return inner.generateDataKey(keyId, ctx);
      },
      decryptDataKey: (keyId, wrapped, ctx) => {
        seen.push(ctx);
        return inner.decryptDataKey(keyId, wrapped, ctx);
      },
    };
    const text = await sealed({ A: "alpha" });
    expect(parseBundle(text).key.epoch).toBe(1);
    const ed = await BundleEditor.open(text, spy);
    await ed.rekey();
    expect(ed.epoch).toBe(2);
    const rekeyed = parseBundle(await ed.seal());
    expect(rekeyed.key.epoch).toBe(2);
    expect(seen.map((c) => c.epoch)).toEqual([1, 2]);
    expect(keyContextMap(seen[1] as KeyContext)).toEqual({
      "keyseal:bundle": rekeyed.id,
      "keyseal:env": "production",
      "keyseal:epoch": "2",
    });
  });

  it("fails the MAC under the wrong data key", async () => {
    const text = await sealed({ A: "alpha" });
    const other = testKeys(Uint8Array.from({ length: 32 }, () => 7));
    expect(await code(openBundle(text, other))).toBe("mac_mismatch");
  });

  it("rejects invalid names and environments", async () => {
    const ed = await BundleEditor.open(await sealed({}), provider());
    expect(await code(ed.set("1BAD", "x"))).toBe("invalid_argument");
    expect(await code(ed.set("has-dash", "x"))).toBe("invalid_argument");
    expect(
      await code(
        BundleEditor.create({
          env: "Production",
          keyId: "k",
          provider: provider(),
        })
      )
    ).toBe("invalid_argument");
  });

  it("never puts values in toJSON", async () => {
    const ed = await BundleEditor.open(
      await sealed({ A: "super-secret-value" }),
      provider()
    );
    expect(JSON.stringify(ed)).not.toContain("super-secret-value");
  });
});

describe("openBundle", () => {
  it("enforces the env pin and minimum version", async () => {
    const text = await sealed({ A: "1" });
    expect(await code(openBundle(text, provider(), { env: "staging" }))).toBe(
      "env_mismatch"
    );
    expect(await code(openBundle(text, provider(), { minVersion: 2 }))).toBe(
      "rollback"
    );
  });

  it("reports a provider failure as key_unavailable", async () => {
    const text = await sealed({ A: "1" });
    const failing = {
      ...provider(),
      decryptDataKey: async () => {
        throw new Error("AccessDeniedException");
      },
    };
    expect(await code(openBundle(text, failing))).toBe("key_unavailable");
  });
});
