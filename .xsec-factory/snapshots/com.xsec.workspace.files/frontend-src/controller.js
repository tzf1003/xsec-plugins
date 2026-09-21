import { commentText, composerWritable, fileContent, fileEntries, workspaceKey } from "./model.js";
import { renderPreview } from "./preview-view.js";
import { styles } from "./styles.js";
import { renderTree } from "./tree-view.js";
import { element } from "./view-utils.js";

function initialState() {
  return {
    actionError: "",
    actionNotice: "",
    addingPaths: new Set(),
    comment: "",
    commentLine: null,
    content: "",
    directoryErrors: new Map(),
    expanded: new Set(),
    fileLoading: false,
    filesByDirectory: new Map(),
    loadingDirectories: new Set(),
    previewError: "",
    selected: null,
    submittingComment: false,
  };
}

function pathRequest(entry) {
  return { path: entry.path, expectedIsDirectory: entry.isDirectory };
}

export class ProjectFilesController {
  constructor(api) {
    this.api = api;
    this.state = initialState();
    this.contextKey = "";
    this.composerWritable = false;
    this.directoryRequests = new Map();
    this.fileRequest = 0;
    this.revision = 0;
    this.root = null;
  }

  async mount(root, context) {
    this.root = root;
    console.info("project-files.mount", { composerWritable: composerWritable(context), workspaceBound: Boolean(workspaceKey(context)) });
    this.applyContext(context, true);
  }

  update(context) {
    this.applyContext(context, false);
  }

  dispose() {
    console.debug("project-files.dispose");
    this.revision += 1;
    this.root = null;
  }

  applyContext(context, initial) {
    const nextKey = workspaceKey(context);
    this.composerWritable = composerWritable(context);
    if (!initial && nextKey === this.contextKey) {
      this.render();
      return;
    }
    this.contextKey = nextKey;
    this.reset();
    void this.loadDirectory("");
  }

  reset() {
    this.revision += 1;
    this.directoryRequests.clear();
    this.fileRequest = 0;
    this.state = initialState();
    this.render();
  }

  refresh() {
    this.reset();
    void this.loadDirectory("");
  }

  render() {
    if (!this.root) return;
    const style = element("style", "", styles);
    const content = this.state.selected ? renderPreview(this) : renderTree(this);
    this.root.replaceChildren(style, content);
  }

  directoryCurrent(directory, request, revision) {
    return this.revision === revision && this.directoryRequests.get(directory) === request;
  }

  fileCurrent(revision, request, selected) {
    return this.revision === revision && this.fileRequest === request && this.state.selected === selected;
  }

  async loadDirectory(directory) {
    const revision = this.revision;
    const request = (this.directoryRequests.get(directory) ?? 0) + 1;
    this.directoryRequests.set(directory, request);
    this.state.loadingDirectories.add(directory);
    this.state.directoryErrors.delete(directory);
    this.render();
    console.info("project-files.directory-list.started", { scope: directory ? "nested" : "root" });
    try {
      const result = await this.api.list(directory);
      if (!this.directoryCurrent(directory, request, revision)) return;
      const entries = fileEntries(result);
      this.state.filesByDirectory.set(directory, entries);
      console.info("project-files.directory-list.completed", { entryCount: entries.length, scope: directory ? "nested" : "root" });
    } catch (error) {
      if (!this.directoryCurrent(directory, request, revision)) return;
      console.error("project-files.directory-list.failed", { errorType: error instanceof Error ? error.name : typeof error, scope: directory ? "nested" : "root" });
      this.state.directoryErrors.set(directory, `列出项目文件失败：${String(error)}`);
    } finally {
      if (this.directoryCurrent(directory, request, revision)) {
        this.state.loadingDirectories.delete(directory);
        this.render();
      }
    }
  }

  async toggleDirectory(entry) {
    if (this.state.expanded.has(entry.path)) {
      this.state.expanded.delete(entry.path);
      this.render();
      return;
    }
    this.state.expanded.add(entry.path);
    this.render();
    if (!this.state.filesByDirectory.has(entry.path)) await this.loadDirectory(entry.path);
  }

  async openFile(entry) {
    const revision = this.revision;
    const request = this.fileRequest + 1;
    this.fileRequest = request;
    this.state.comment = "";
    this.state.commentLine = null;
    this.state.content = "";
    this.state.fileLoading = true;
    this.state.previewError = "";
    this.state.submittingComment = false;
    this.state.selected = entry;
    this.render();
    console.info("project-files.file-read.started", { targetType: "file" });
    try {
      const result = await this.api.read(entry.path);
      if (this.revision !== revision || this.fileRequest !== request) return;
      this.state.content = fileContent(result);
      console.info("project-files.file-read.completed", { characterCount: this.state.content.length });
    } catch (error) {
      if (this.revision !== revision || this.fileRequest !== request) return;
      console.error("project-files.file-read.failed", { errorType: error instanceof Error ? error.name : typeof error });
      this.state.previewError = `读取文件失败：${String(error)}`;
    } finally {
      if (this.revision === revision && this.fileRequest === request) {
        this.state.fileLoading = false;
        this.render();
      }
    }
  }

  closeFile() {
    this.fileRequest += 1;
    this.state.submittingComment = false;
    this.state.comment = "";
    this.state.commentLine = null;
    this.state.selected = null;
    this.render();
  }

  startComment(line) {
    if (!this.composerWritable) return;
    this.state.comment = "";
    this.state.commentLine = line;
    this.render();
  }

  cancelComment() {
    this.state.comment = "";
    this.state.commentLine = null;
    this.render();
  }

  async addPath(entry) {
    if (!this.composerWritable || this.state.addingPaths.has(entry.path)) return;
    const revision = this.revision;
    const addingPaths = this.state.addingPaths;
    addingPaths.add(entry.path);
    this.state.actionError = "";
    this.state.actionNotice = "";
    this.render();
    console.info("project-files.composer-path-add.started", { targetType: entry.isDirectory ? "directory" : "file" });
    try {
      await this.api.addPath(pathRequest(entry));
      if (this.revision !== revision) return;
      console.info("project-files.composer-path-add.completed", { targetType: entry.isDirectory ? "directory" : "file" });
      this.state.actionNotice = `已将“${entry.name}”添加到会话`;
    } catch (error) {
      if (this.revision !== revision) return;
      console.error("project-files.composer-path-add.failed", { errorType: error instanceof Error ? error.name : typeof error, targetType: entry.isDirectory ? "directory" : "file" });
      this.state.actionError = `添加“${entry.name}”失败：${String(error)}`;
    } finally {
      if (this.state.addingPaths === addingPaths) {
        addingPaths.delete(entry.path);
        this.render();
      }
    }
  }

  async submitComment(line, code) {
    if (!this.composerWritable || !this.state.selected || this.state.submittingComment) return;
    const revision = this.revision;
    const request = this.fileRequest;
    const selected = this.state.selected;
    let comment;
    try {
      comment = commentText(this.state.comment);
    } catch (error) {
      this.state.actionError = String(error);
      this.render();
      return;
    }
    try {
      this.state.actionError = "";
      this.state.submittingComment = true;
      this.render();
      console.info("project-files.line-comment-add.started", { line });
      await this.api.addLineComment({
        comment,
        expectedLine: code,
        line,
        path: this.state.selected.path,
      });
      if (!this.fileCurrent(revision, request, selected)) return;
      console.info("project-files.line-comment-add.completed", { line });
      this.cancelComment();
    } catch (error) {
      if (!this.fileCurrent(revision, request, selected)) return;
      console.error("project-files.line-comment-add.failed", { errorType: error instanceof Error ? error.name : typeof error, line });
      this.state.actionError = `添加第 ${line} 行评论失败：${String(error)}`;
    } finally {
      if (this.fileCurrent(revision, request, selected)) {
        this.state.submittingComment = false;
        this.render();
      }
    }
  }
}
