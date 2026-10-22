import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    entry: {
      index: "src/index.ts",
      aws: "src/aws.ts",
      s3: "src/s3.ts",
      testing: "src/testing.ts",
      cli: "src/cli.ts",
      // Runs on Cloudflare Workers: WebCrypto and fetch only, no node: imports.
      cloudflare: "src/cloudflare/index.ts",
    },
    format: "esm",
    platform: "node",
    target: "node22.12",
    // Plain .js/.d.ts names so they match the exports map in package.json.
    fixedExtension: false,
    // isolatedDeclarations is on in tsconfig, so declarations come from oxc and
    // never need the TypeScript compiler API.
    dts: { generator: "oxc" },
    clean: true,
    sourcemap: false,
  },

  test: {
    include: ["test/**/*.test.ts"],
  },

  fmt: {
    printWidth: 80,
    tabWidth: 2,
    useTabs: false,
    semi: true,
    singleQuote: false,
    trailingComma: "es5",
    arrowParens: "always",
    ignorePatterns: ["dist/**"],
  },

  lint: {
    plugins: ["typescript", "unicorn", "oxc"],
    ignorePatterns: ["dist/**"],
    // typeCheck makes `vp check` the type checker too; no separate tsc step.
    options: { typeAware: true, typeCheck: true },
    rules: {
      // Library code must never print: values could be secrets.
      "no-console": "error",
    },
    overrides: [
      {
        files: ["src/cli.ts", "src/cli/**", "scripts/**"],
        rules: { "no-console": "off" },
      },
      {
        files: ["test/**"],
        plugins: ["vitest"],
      },
    ],
  },
});
