import { readFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("plugin.json", root), "utf8"));
const codexManifest = JSON.parse(readFileSync(new URL(".codex-plugin/plugin.json", root), "utf8"));
const desktop = manifest.extensions?.["com.xsec.desktop"];

if (JSON.stringify(manifest) !== JSON.stringify(codexManifest)) throw new Error("manifest copies differ");
if (manifest.name !== "io.xsec.project-files" || manifest.version !== "1.0.0") throw new Error("plugin identity is invalid");
if (!desktop?.contributes?.workspaceTools?.["project-file-browser"]) throw new Error("workspace tool is missing");
if (!desktop?.permissions?.["filesystem.workspace.read"] || !desktop?.permissions?.["workspace.composer.write"]) {
  throw new Error("required capabilities are missing");
}
if (desktop.entrypoints?.frontend !== "./com.xsec.desktop/frontend/index.js") throw new Error("frontend entrypoint is invalid");
