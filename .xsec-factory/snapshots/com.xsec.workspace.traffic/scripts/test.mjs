import { build } from "esbuild";
import { readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const output = join(tmpdir(), `xsec-traffic-tests-${process.pid}`);
const tests = (await readdir(resolve("tests")))
  .filter((name) => name.endsWith(".test.ts"))
  .map((name) => resolve("tests", name));

try {
  await build({ entryPoints: tests, outdir: output, bundle: true, platform: "node", format: "esm", target: "node22" });
  const result = spawnSync(process.execPath, ["--test", ...tests.map((file) => join(output, file.split("/").at(-1).replace(/\.ts$/, ".js")))], { stdio: "inherit" });
  process.exitCode = result.status ?? 1;
} finally {
  await rm(output, { recursive: true, force: true });
}
