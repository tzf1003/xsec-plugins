export const MAX_COMMENT_CHARACTERS = 32_768;
export const MAX_PREVIEW_LINES = 2_000;
const PREVIEW_OVERFLOW_ALLOWANCE = 1;
const KILOBYTE = 1_024;
const MEGABYTE = KILOBYTE * KILOBYTE;

function text(value, label) {
  if (typeof value !== "string" || !value) throw new Error(`${label}格式无效`);
  return value;
}

function fileEntry(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("项目文件条目格式无效");
  const entry = value;
  if (typeof entry.is_dir !== "boolean" || typeof entry.size !== "number" || !Number.isFinite(entry.size)) {
    throw new Error("项目文件元数据格式无效");
  }
  return { name: text(entry.name, "文件名"), path: text(entry.path, "文件路径"), isDirectory: entry.is_dir, size: entry.size };
}

export function fileEntries(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !Array.isArray(value.files)) {
    throw new Error("项目文件列表结果无效");
  }
  return value.files.map(fileEntry);
}

export function fileContent(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.content !== "string") {
    throw new Error("文件读取结果无有效文本内容");
  }
  return value.content;
}

export function previewLines(content) {
  const lines = content.split(/\r?\n/, MAX_PREVIEW_LINES + PREVIEW_OVERFLOW_ALLOWANCE);
  return { lines: lines.slice(0, MAX_PREVIEW_LINES), truncated: lines.length > MAX_PREVIEW_LINES };
}

export function formatFileSize(size) {
  if (size < KILOBYTE) return `${size} B`;
  if (size < MEGABYTE) return `${(size / KILOBYTE).toFixed(size < KILOBYTE * 10 ? 1 : 0)} KB`;
  return `${(size / MEGABYTE).toFixed(1)} MB`;
}

export function workspaceKey(context) {
  const revision = context?.surface?.bindingRevision;
  return typeof revision === "string" ? revision : "";
}

export function composerWritable(context) {
  return context?.workspace?.canAddComposerReference === true;
}

export function commentText(value) {
  const comment = text(value, "评论").trim();
  if (!comment || comment.length > MAX_COMMENT_CHARACTERS) throw new Error("评论内容无效");
  return comment;
}
