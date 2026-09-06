import { build } from "esbuild";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const output = resolve("com.xsec.desktop/frontend/index.js");
const activateDocumentation = `/**
 * Activate the Traffic frontend and expose its host lifecycle.
 * @param {object} host Desktop host bridge for the active plugin surface.
 * @returns {object} Explicit mount, update, and dispose lifecycle delegates.
 */`;

// Factory reads this boundary statically, so preserve the named lifecycle source.
const frontendFooter = `${activateDocumentation}
export function activate(host){
  const controller=__xsecTrafficFrontend.activate(host);
  return{
    /**
     * Mount the active Traffic surface into the supplied root and context.
     * @param {Element} root Host-owned element for the active surface.
     * @param {object} context Initial workspace-tool or settings-page context.
     * @returns {void} The delegated mount completes synchronously.
     */
    mount(root,context){return controller.mount(root,context)},
    /**
     * Update the active Traffic surface with the next host context.
     * @param {object} context Current workspace-tool or settings-page context.
     * @returns {void} The delegated update completes synchronously.
     */
    update(context){return controller.update(context)},
    /**
     * Dispose subscriptions, rendered content, and retained surface state.
     * @returns {void} The delegated cleanup completes synchronously.
     */
    dispose(){return controller.dispose()}
  };
}`;
await mkdir(dirname(output), { recursive: true });
await build({
  entryPoints: [resolve("src/entrypoint.tsx")],
  outfile: output,
  bundle: true,
  format: "iife",
  globalName: "__xsecTrafficFrontend",
  platform: "browser",
  target: ["es2022"],
  charset: "utf8",
  jsx: "automatic",
  jsxImportSource: "preact",
  loader: { ".css": "text" },
  footer: { js: frontendFooter },
  legalComments: "none",
  minifyIdentifiers: false,
  minifySyntax: true,
  minifyWhitespace: true,
  sourcemap: false,
});
