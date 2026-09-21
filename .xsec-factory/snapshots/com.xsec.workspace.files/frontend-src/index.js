import { ProjectFilesController } from "./controller.js";

function createProjectFilesController(host) {
  const api = {
    list(directory) {
      return host.request("xsec.files.list", { directory: directory || undefined });
    },
    read(path) {
      return host.request("xsec.files.read", { path });
    },
    addPath(entry) {
      return host.request("xsec.workspace.composer.path.add", entry);
    },
    addLineComment(comment) {
      return host.request("xsec.workspace.composer.line-comment.add", comment);
    },
  };
  return new ProjectFilesController(api);
}

export function activate(host) {
  console.debug("project-files.activate", { apiVersion: host.apiVersion });
  const controller = createProjectFilesController(host);
  return {
    mount(root, context) {
      return controller.mount(root, context);
    },
    update(context) {
      return controller.update(context);
    },
    dispose() {
      return controller.dispose();
    },
  };
}
