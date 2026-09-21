import { build } from "esbuild";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const pluginRoot = new URL("../", import.meta.url);
const root = fileURLToPath(pluginRoot);
const frontendOutput = fileURLToPath(new URL("com.xsec.desktop/frontend/index.js", pluginRoot));
const MINIFIED_ACTIVATION = "function activate(host){";
const MINIFIED_ACTIVATION_EXPORT = "export{activate};";

function replaceExactlyOnce(source, target, replacement) {
  const parts = source.split(target);
  if (parts.length !== 2) throw new Error(`Expected exactly one generated ${target}`);
  return parts.join(replacement);
}

await build({
  bundle: true,
  charset: "utf8",
  entryPoints: [fileURLToPath(new URL("frontend-src/index.js", pluginRoot))],
  format: "esm",
  legalComments: "none",
  minify: false,
  minifySyntax: true,
  minifyWhitespace: true,
  outfile: frontendOutput,
  target: "es2022",
  absWorkingDir: root,
});

const bundle = await readFile(frontendOutput, "utf8");
const frontend = replaceExactlyOnce(
  replaceExactlyOnce(bundle, MINIFIED_ACTIVATION, `export ${MINIFIED_ACTIVATION}`),
  MINIFIED_ACTIVATION_EXPORT,
  "",
);
await writeFile(frontendOutput, `${frontend.trimEnd()}\n`, "utf8");
