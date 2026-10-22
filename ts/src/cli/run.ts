// `keyseal run`: start a command with the bundle's secrets as env vars. With
// --watch, poll the source and restart the command when secrets rotate, so
// apps in any language get rotation without a deploy.

import { type ChildProcess, spawn } from "node:child_process";
import { constants } from "node:os";
import { createKeyseal } from "../client.ts";
import type { KeyProvider } from "../keys.ts";
import type { Source } from "../sources.ts";

export interface RunOptions {
  source: Source;
  keys: KeyProvider;
  command: string[];
  env?: string;
  minVersion?: number;
  watch: boolean;
  pollMs: number;
  /** How long a child gets to exit after SIGTERM before SIGKILL. */
  stopTimeoutMs: number;
}

function log(msg: string): void {
  process.stderr.write(`keyseal: ${msg}\n`);
}

export async function runCommand(opts: RunOptions): Promise<number> {
  const [cmd, ...args] = opts.command;
  if (!cmd) throw new Error("nothing to run");

  const ks = await createKeyseal({
    source: opts.source,
    keys: opts.keys,
    poll: opts.watch ? opts.pollMs : false,
    ...(opts.env !== undefined ? { env: opts.env } : {}),
    ...(opts.minVersion !== undefined ? { minVersion: opts.minVersion } : {}),
  });

  return new Promise<number>((resolve) => {
    let child: ChildProcess;
    let restarting = false;
    let killTimer: ReturnType<typeof setTimeout> | undefined;

    // The child gets the secrets, never the key or token that opens them.
    const inherited = { ...process.env };
    delete inherited.KEYSEAL_KEY;
    delete inherited.KEYSEAL_WORKER_TOKEN;

    const start = (): void => {
      // Bundle values win over anything the platform already set.
      child = spawn(cmd, args, {
        stdio: "inherit",
        env: { ...inherited, ...ks.toEnv() },
      });
      child.on("error", (err) => {
        log(`could not start ${cmd}: ${err.message}`);
        finish(127);
      });
      child.on("exit", (code, signal) => {
        if (killTimer) clearTimeout(killTimer);
        if (restarting) {
          restarting = false;
          start();
          return;
        }
        finish(code ?? 128 + (signal ? (constants.signals[signal] ?? 0) : 0));
      });
    };

    let finished = false;
    const finish = (code: number): void => {
      if (finished) return;
      finished = true;
      ks.close();
      for (const [sig, fn] of handlers) process.off(sig, fn);
      resolve(code);
    };

    // A terminal already delivers Ctrl-C to the whole process group, so only
    // forward SIGINT when it can't have reached the child on its own.
    const forwarded: NodeJS.Signals[] = process.stdin.isTTY
      ? ["SIGTERM", "SIGHUP"]
      : ["SIGTERM", "SIGHUP", "SIGINT"];
    const handlers: [NodeJS.Signals, () => void][] = forwarded.map((sig) => [
      sig,
      () => {
        restarting = false;
        child.kill(sig);
      },
    ]);
    if (process.stdin.isTTY) handlers.push(["SIGINT", () => {}]);
    for (const [sig, fn] of handlers) process.on(sig, fn);

    if (opts.watch) {
      ks.on("rotated", (e) => {
        const names = [...e.changed, ...e.added, ...e.removed];
        // A rekey changes no values, so there's nothing to restart for, and
        // a restart already in flight will pick up the latest values.
        if (names.length === 0 || restarting) return;
        log(
          `bundle version ${e.version} changed ${names.join(", ")}; restarting ${cmd}`
        );
        restarting = true;
        child.kill("SIGTERM");
        killTimer = setTimeout(() => child.kill("SIGKILL"), opts.stopTimeoutMs);
      });
      ks.on("error", (err) => {
        log(
          `could not refresh secrets, keeping the current ones: ${(err as Error).message}`
        );
      });
    }

    start();
  });
}
