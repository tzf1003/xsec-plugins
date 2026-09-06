import { build } from "esbuild";
import { buildOptions, outputPath } from "./build-options.mjs";

await build({ ...buildOptions, outfile: outputPath });
