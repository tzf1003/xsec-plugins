import { readFile } from "node:fs/promises";
import { build } from "esbuild";
import { buildOptions, outputPath } from "./build-options.mjs";

const result = await build({ ...buildOptions, outfile: outputPath, write: false });
const committed = await readFile(outputPath, "utf8");
const generated = result.outputFiles[0]?.text;

if (generated !== committed) {
  throw new Error("committed single-esm frontend is stale; run npm run build");
}
