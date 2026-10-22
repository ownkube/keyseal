import { inspect } from "node:util";
import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import { BundleEditor } from "../src/bundle.ts";
import { createKeyseal, type RotatedEvent } from "../src/client.ts";
import { isKeysealError } from "../src/errors.ts";
import { inline } from "../src/sources.ts";
import { sealTestBundle, testKeys, testSource } from "../src/testing.ts";
import { provider, sealed } from "./helpers.ts";

async function edit(
  text: string,
  fn: (ed: BundleEditor) => Promise<unknown>
): Promise<string> {
  const ed = await BundleEditor.open(text, provider());
  await fn(ed);
  return ed.seal();
}

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    if (isKeysealError(e)) return e.code;
    throw e;
  }
  throw new Error("expected a KeysealError");
}

afterEach(() => {
  vi.useRealTimers();
});

describe("createKeyseal", () => {
  it("serves values from an inline bundle", async () => {
    const ks = await createKeyseal({
      source: inline(await sealed({ API_KEY: "k-123", DB_URL: "pg://x" })),
      keys: provider(),
      env: "production",
    });
    expect(ks.get("API_KEY")).toBe("k-123");
    expect(ks.has("DB_URL")).toBe(true);
    expect(ks.names()).toEqual(["API_KEY", "DB_URL"]);
    expect({ ...ks.toEnv() }).toEqual({ API_KEY: "k-123", DB_URL: "pg://x" });
    expect(() => ks.get("NOPE")).toThrow(/not in the bundle/);
    ks.close();
  });

  it("refuses a bundle for another environment", async () => {
    const src = inline(await sealed({ A: "1" }));
    expect(
      await code(createKeyseal({ source: src, keys: provider(), env: "dev" }))
    ).toBe("env_mismatch");
  });

  it("picks up a rotation and reports what changed", async () => {
    const v1 = await sealed({ KEEP: "same", ROTATE: "old", DROP: "gone" });
    const src = testSource(v1);
    const ks = await createKeyseal({
      source: src,
      keys: provider(),
      poll: false,
    });
    const events: RotatedEvent[] = [];
    ks.on("rotated", (e) => events.push(e));

    expect(await ks.refresh()).toBe(false);

    src.publish(
      await edit(v1, async (ed) => {
        await ed.set("ROTATE", "new", { grace: 3_600_000 });
        await ed.set("ADDED", "fresh");
        ed.remove("DROP");
      })
    );
    expect(await ks.refresh()).toBe(true);
    expect(ks.version).toBe(2);
    expect(ks.get("ROTATE")).toBe("new");
    expect(ks.previous("ROTATE")).toBe("old");
    expect(ks.has("DROP")).toBe(false);
    expect(events).toEqual([
      { version: 2, changed: ["ROTATE"], added: ["ADDED"], removed: ["DROP"] },
    ]);
    ks.close();
  });

  it("refuses an older bundle and keeps serving the current one", async () => {
    const v1 = await sealed({ A: "one" });
    const v2 = await edit(v1, (ed) => ed.set("A", "two"));
    const src = testSource(v2);
    const ks = await createKeyseal({
      source: src,
      keys: provider(),
      poll: false,
    });
    src.publish(v1);
    expect(await code(ks.refresh())).toBe("rollback");
    expect(ks.get("A")).toBe("two");
    ks.close();
  });

  it("refuses a different bundle at the same version", async () => {
    const v1 = await sealed({ A: "one" });
    const ours = await edit(v1, (ed) => ed.set("A", "two"));
    const forked = await edit(v1, (ed) => ed.set("A", "evil"));
    const src = testSource(ours);
    const ks = await createKeyseal({
      source: src,
      keys: provider(),
      poll: false,
    });
    src.publish(forked);
    expect(await code(ks.refresh())).toBe("rollback");
    ks.close();
  });

  it("refuses a swap to a different bundle", async () => {
    const src = testSource(await sealed({ A: "one" }));
    const ks = await createKeyseal({
      source: src,
      keys: provider(),
      poll: false,
    });
    src.publish(await sealed({ A: "other" }));
    expect(await code(ks.refresh())).toBe("bundle_changed");
    ks.close();
  });

  it("enforces minVersion on the first load", async () => {
    expect(
      await code(
        createKeyseal({
          source: inline(await sealed({ A: "1" })),
          keys: provider(),
          minVersion: 2,
        })
      )
    ).toBe("rollback");
  });

  it("polls on an interval and stops on close", async () => {
    vi.useFakeTimers();
    const src = testSource(await sealed({ A: "1" }));
    const ks = await createKeyseal({
      source: src,
      keys: provider(),
      poll: 1_000,
    });
    expect(src.reads).toBe(1);
    await vi.advanceTimersByTimeAsync(3_000);
    expect(src.reads).toBe(4);
    ks.close();
    await vi.advanceTimersByTimeAsync(3_000);
    expect(src.reads).toBe(4);
  });

  it("redacts every value of 8 or more characters", async () => {
    const ks = await createKeyseal({
      source: inline(
        await sealed({
          TOKEN: "tok_abcdefgh",
          SHORT: "abc",
          LONGER: "tok_abcdefgh_ij",
        })
      ),
      keys: provider(),
    });
    expect(ks.redact("a=tok_abcdefgh_ij b=tok_abcdefgh c=abc")).toBe(
      "a=[redacted:LONGER] b=[redacted:TOKEN] c=abc"
    );
    ks.close();
  });

  it("injects into process.env only when asked, and cleans up removals", async () => {
    const v1 = await sealed({ KS_TEST_A: "a", KS_TEST_B: "b" });
    const src = testSource(v1);
    const ks = await createKeyseal({
      source: src,
      keys: provider(),
      poll: false,
      inject: true,
    });
    try {
      expect(process.env.KS_TEST_A).toBe("a");
      src.publish(await edit(v1, async (ed) => ed.remove("KS_TEST_B")));
      await ks.refresh();
      expect(process.env.KS_TEST_B).toBeUndefined();
    } finally {
      ks.close();
      delete process.env.KS_TEST_A;
      delete process.env.KS_TEST_B;
    }

    const plain = await createKeyseal({
      source: inline(await sealed({ KS_TEST_C: "c" })),
      keys: provider(),
    });
    expect(process.env.KS_TEST_C).toBeUndefined();
    plain.close();
  });

  it("never prints values when logged", async () => {
    const ks = await createKeyseal({
      source: inline(await sealed({ A: "super-secret-value" })),
      keys: provider(),
    });
    expect(JSON.stringify(ks)).not.toContain("super-secret-value");
    expect(inspect(ks)).not.toContain("super-secret-value");
    ks.close();
  });

  it("points S3 strings at s3()", async () => {
    expect(
      await code(createKeyseal({ source: "s3://bucket/key", keys: provider() }))
    ).toBe("invalid_argument");
  });
});

// Mirrors the example in docs/testing.md, so the docs stay true.
describe("testing helpers", () => {
  it("run the documented rotation test", async () => {
    const keys = testKeys();
    const source = testSource(
      await sealTestBundle({ STRIPE_KEY: "sk_test_old" }, { keys })
    );
    const secrets = await createKeyseal({
      source,
      keys,
      env: "test",
      poll: false,
    });
    expect(secrets.get("STRIPE_KEY")).toBe("sk_test_old");

    const editor = await BundleEditor.open(source.body, keys);
    await editor.set("STRIPE_KEY", "sk_test_new");
    source.publish(await editor.seal());

    await secrets.refresh();
    expect(secrets.get("STRIPE_KEY")).toBe("sk_test_new");
    secrets.close();
  });
});
