// Regenerate spec/testvectors/v1.json. The output is deterministic, so a
// changed file means the format (or this implementation) changed.

import { mkdir, writeFile } from "node:fs/promises";
import { buildVectors, serializeVectors } from "../test/vectors.ts";

const out = new URL("../../spec/testvectors/v1.json", import.meta.url);
await mkdir(new URL(".", out), { recursive: true });
const file = await buildVectors();
await writeFile(out, serializeVectors(file));
console.log(
  `wrote ${file.vectors.length} bundle and ${file.local.length} local vectors to ${out.pathname}`
);
