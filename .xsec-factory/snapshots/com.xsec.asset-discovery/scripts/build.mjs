import { build } from "esbuild";
import { readFile, writeFile } from "node:fs/promises";

const pluginRoot = new URL("../", import.meta.url);
const frontendOutput = new URL("com.xsec.desktop/frontend/index.js", pluginRoot);

function addExplicitActivatorExport(source) {
  const functionMarker = "function activate(host){";
  const exportMarker = "export{activate};";
  const parts = source.split(functionMarker);
  if (parts.length !== 2 || !parts[1].endsWith(exportMarker + "\n")) {
    throw new Error("Expected the generated frontend activator export");
  }
  return `${parts[0]}export function activate(host) {${parts[1].slice(0, -exportMarker.length - 1).trimEnd()}\n`;
}

await build({
  entryPoints: [new URL("frontend-src/index.tsx", pluginRoot).pathname],
  outfile: frontendOutput.pathname,
  bundle: true,
  format: "esm",
  target: ["es2022"],
  jsx: "automatic",
  define: { "process.env.NODE_ENV": '"production"' },
  minifyIdentifiers: false,
  minifySyntax: false,
  minifyWhitespace: true,
  legalComments: "none",
});

const bundle = await readFile(frontendOutput, "utf8");
await writeFile(frontendOutput, addExplicitActivatorExport(bundle), "utf8");
