import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vite-plus/test";
import {
  buildVectors,
  canon,
  runLocalVector,
  runVector,
  serializeVectors,
  type VectorFile,
} from "./vectors.ts";

const path = new URL("../../spec/testvectors/v1.json", import.meta.url);
const text = await readFile(path, "utf8").catch(() => {
  throw new Error(
    "spec/testvectors/v1.json is missing; run `pnpm vectors` to generate it"
  );
});
const file = JSON.parse(text) as VectorFile;

describe("spec/testvectors/v1.json", () => {
  it.each(file.vectors.map((v) => [v.name, v] as const))("%s", async (_, v) => {
    expect(canon(await runVector(v))).toBe(canon(v.expect));
  });

  it.each(file.local.map((v) => [v.name, v] as const))("%s", async (_, v) => {
    expect(canon(await runLocalVector(v))).toBe(canon(v.expect));
  });

  it("matches what the generator produces today", async () => {
    expect(serializeVectors(await buildVectors())).toBe(text);
  });

  it("covers every error a reader can raise from a file", () => {
    const errors = new Set(
      file.vectors.flatMap((v) => (v.expect.ok ? [] : [v.expect.error]))
    );
    expect([...errors].sort()).toEqual([
      "decrypt_failed",
      "env_mismatch",
      "invalid_format",
      "mac_mismatch",
      "provider_mismatch",
      "unsupported_format",
    ]);
  });
});
