function text(value,label){if(typeof value!="string"||!value)throw new Error(`${label}格式无效`);return value}function fileEntry(value){if(!value||typeof value!="object"||Array.isArray(value))throw new Error("项目文件条目格式无效");let entry=value;if(typeof entry.is_dir!="boolean"||typeof entry.size!="number"||!Number.isFinite(entry.size))throw new Error("项目文件元数据格式无效");return{name:text(entry.name,"文件名"),path:text(entry.path,"文件路径"),isDirectory:entry.is_dir,size:entry.size}}function fileEntries(value){if(!value||typeof value!="object"||Array.isArray(value)||!Array.isArray(value.files))throw new Error("项目文件列表结果无效");return value.files.map(fileEntry)}function fileContent(value){if(!value||typeof value!="object"||Array.isArray(value)||typeof value.content!="string")throw new Error("文件读取结果无有效文本内容");return value.content}function previewLines(content){let lines=content.split(/\r?\n/,2001);return{lines:lines.slice(0,2e3),truncated:lines.length>2e3}}function formatFileSize(size){return size<1024?`${size} B`:size<1048576?`${(size/1024).toFixed(size<1024*10?1:0)} KB`:`${(size/1048576).toFixed(1)} MB`}function workspaceKey(context){let workspace=context?.workspace;return typeof workspace?.projectId=="string"?workspace.projectId:""}function composerWritable(context){return context?.workspace?.canAddComposerReference===!0}function commentText(value){let comment=text(value,"评论").trim();if(!comment||comment.length>32768)throw new Error("评论内容无效");return comment}var SVG_NAMESPACE="http://www.w3.org/2000/svg";var iconPaths={at:["circle:12:12:4","path:M16 8v1a4 4 0 0 1-8 0v-1a4 4 0 0 1 8 0Z","path:M16 8v4a2 2 0 0 0 4 0v-1a8 8 0 1 0-3 6"],chevronDown:["path:M6 9l6 6 6-6"],chevronRight:["path:M9 6l6 6-6 6"],file:["path:M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z","path:M14 2v6h6","path:M8 13h8","path:M8 17h8"],folder:["path:M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z","path:M3 9h18"],message:["path:M21 11.5a8.4 8.4 0 0 1-9 8.4 8.6 8.6 0 0 1-3.7-.9L3 21l1.8-4.6a8.4 8.4 0 0 1-.9-3.9 8.4 8.4 0 0 1 8.4-8.4 8.5 8.5 0 0 1 8.7 7.5Z"]};function svgElement(name){return document.createElementNS(SVG_NAMESPACE,name)}function appendShape(svg,descriptor){let[kind,...values]=descriptor.split(":"),node=svgElement(kind);kind==="circle"&&["cx","cy","r"].forEach((name,index)=>node.setAttribute(name,values[index])),kind==="path"&&node.setAttribute("d",values.join(":")),svg.append(node)}function icon(name){let svg=svgElement("svg");svg.setAttribute("aria-hidden","true"),svg.setAttribute("fill","none"),svg.setAttribute("height","16"),svg.setAttribute("stroke","currentColor"),svg.setAttribute("stroke-linecap","round"),svg.setAttribute("stroke-linejoin","round"),svg.setAttribute("stroke-width","2"),svg.setAttribute("viewBox","0 0 24 24"),svg.setAttribute("width","16");for(let descriptor of iconPaths[name]??[])appendShape(svg,descriptor);return svg}function element(name,className,content){let node=document.createElement(name);return className&&(node.className=className),content!==void 0&&(node.textContent=content),node}function actionButton(className,label,onClick){let button=element("button",className);return button.type="button",button.setAttribute("aria-label",label),button.addEventListener("click",onClick),button}function errorPanel(message,retry){let panel=element("section","project-files-error",message);if(retry){let button=actionButton("project-files-retry","重试",retry);button.textContent="重试",panel.append(button)}return panel}function emptyPanel(message){return element("section","project-files-empty",message)}function noticePanel(message){let notice=element("div","project-files-notice",message);return notice.setAttribute("aria-live","polite"),notice.setAttribute("role","status"),notice}function loadingPanel(rows=8){let panel=element("section","project-files-loading");for(let index=0;index<rows;index+=1)panel.append(element("span","project-files-loading-row"));return panel}function focusLater(selector){queueMicrotask(()=>document.querySelector(selector)?.focus())}function composerButton(controller,file){let button=actionButton("project-file-header-action",`添加 ${file.name} 到会话`,()=>{controller.addPath(file)}),busy=controller.state.addingPaths.has(file.path);return button.disabled=!controller.composerWritable||busy,button.title=controller.composerWritable?"添加到会话":"当前会话不可编辑",busy&&button.setAttribute("aria-busy","true"),button.append(icon("at")),button}function commentEditor(controller,lineNumber,code){let editor=element("form","file-line-comment-editor"),heading=element("div","file-line-comment-heading");heading.append(icon("message"),element("strong","","本地评论"),element("small","",`对第 ${lineNumber} 行发表评论`));let input=document.createElement("textarea");input.dataset.commentInput="",input.placeholder="输入给 Agent 的评论…",input.value=controller.state.comment;let submit;input.addEventListener("input",()=>{controller.state.comment=input.value,submit&&(submit.disabled=!controller.composerWritable||!input.value.trim())}),input.addEventListener("keydown",event=>{(event.metaKey||event.ctrlKey)&&event.key==="Enter"&&(event.preventDefault(),controller.submitComment(lineNumber,code))});let footer=element("footer","file-line-comment-footer"),cancel=actionButton("","取消评论",()=>controller.cancelComment());return cancel.textContent="取消",submit=actionButton("project-files-primary","添加到对话框",()=>{controller.submitComment(lineNumber,code)}),submit.disabled=!controller.composerWritable||controller.state.submittingComment||!input.value.trim(),controller.state.submittingComment&&submit.setAttribute("aria-busy","true"),submit.textContent="添加到对话框",editor.addEventListener("submit",event=>{event.preventDefault(),controller.submitComment(lineNumber,code)}),footer.append(cancel,submit),editor.append(heading,input,footer),focusLater("[data-comment-input]"),editor}function codeRows(controller){let table=element("div","project-file-code");table.setAttribute("aria-label",`${controller.state.selected.name} 文件内容`),table.setAttribute("role","table");let preview=previewLines(controller.state.content);return preview.lines.forEach((code,index)=>{let lineNumber=index+1,line=element("div",`project-file-line${controller.state.commentLine===lineNumber?" is-commenting":""}`);line.setAttribute("role","row");let trigger=actionButton("file-line-comment-trigger",`评论第 ${lineNumber} 行`,()=>controller.startComment(lineNumber));trigger.disabled=!controller.composerWritable,trigger.append(icon("message")),line.append(trigger,element("span","file-line-number",String(lineNumber)),element("code","",code||" ")),controller.state.commentLine===lineNumber&&line.append(commentEditor(controller,lineNumber,code)),table.append(line)}),{table,truncated:preview.truncated}}function renderPreview(controller){let file=controller.state.selected,view=element("section","project-files-view has-preview"),preview=element("section","project-file-preview"),header=element("header",""),back=actionButton("project-file-header-action","返回项目文件树",()=>controller.closeFile());if(back.append(icon("folder")),header.append(back,element("strong","",file.name),element("small","",file.path),composerButton(controller,file)),preview.append(header),controller.state.actionError&&preview.append(errorPanel(controller.state.actionError)),controller.state.actionNotice&&preview.append(noticePanel(controller.state.actionNotice)),controller.state.previewError)preview.append(errorPanel(controller.state.previewError,()=>{controller.openFile(file)}));else if(controller.state.fileLoading)preview.append(loadingPanel());else{let code=codeRows(controller);preview.append(code.table),code.truncated&&preview.append(noticePanel(`文件行数较多，仅显示前 ${2e3.toLocaleString()} 行`))}return view.append(preview),view}var styles=`
:root {
  background: var(--xsec-surface-base);
  color: var(--xsec-text-primary);
  font-family: var(--xsec-font-family, system-ui, sans-serif);
}
* { box-sizing: border-box; }
html, body, [data-xsec-plugin-root] { min-width: 0; min-height: 100%; margin: 0; }
button, textarea { font: inherit; }
button:focus-visible, textarea:focus-visible { outline: 2px solid var(--xsec-accent); outline-offset: 2px; }
.project-files-view { min-height: 100%; background: var(--xsec-surface-base); }
.project-files-toolbar { display: flex; align-items: center; justify-content: space-between; min-height: 42px; padding: 0 12px; border-bottom: 1px solid var(--xsec-border-subtle); }
.project-files-toolbar strong { font-size: 13px; }
.project-files-refresh { padding: 4px 8px; border: 1px solid var(--xsec-border); border-radius: var(--xsec-radius-md); background: var(--xsec-surface-container); color: var(--xsec-text-secondary); cursor: pointer; }
.project-files-refresh:disabled { cursor: not-allowed; opacity: .45; }
.file-tree { display: grid; padding: 8px 0; }
.file-tree-branch { display: contents; }
.file-tree-row {
  display: grid;
  min-width: 0;
  height: 36px;
  grid-template-columns: minmax(0, 1fr) 34px;
  padding-left: calc(var(--file-tree-depth) * 18px);
}
.file-tree-row:hover { background: var(--xsec-surface-hover); }
.file-tree-main-action {
  display: grid;
  min-width: 0;
  grid-template-columns: 14px 18px minmax(0, 1fr) auto;
  align-items: center;
  gap: 6px;
  padding: 0 4px 0 12px;
  border: 0;
  background: transparent;
  color: var(--xsec-text-secondary);
  cursor: pointer;
  text-align: left;
}
.file-tree-main-action:active { background: var(--xsec-accent-soft); }
.file-tree-main-action svg, .file-tree-add-action svg { flex: 0 0 auto; }
.file-tree-add-action {
  display: grid;
  width: 28px;
  height: 28px;
  place-self: center;
  place-items: center;
  padding: 0;
  border: 0;
  border-radius: var(--xsec-radius-md);
  background: transparent;
  color: var(--xsec-text-tertiary);
  cursor: pointer;
  opacity: 0;
}
.file-tree-row:hover .file-tree-add-action,
.file-tree-add-action:focus-visible,
.file-tree-add-action[aria-busy="true"] { opacity: 1; }
.file-tree-add-action:hover:not(:disabled) { background: var(--xsec-accent-soft); color: var(--xsec-accent); }
.file-tree-add-action:disabled { cursor: not-allowed; opacity: .35; }
.file-tree-chevron { color: var(--xsec-text-tertiary); font-size: 10px; }
.file-tree-name { overflow: hidden; color: var(--xsec-text-primary); text-overflow: ellipsis; white-space: nowrap; }
.file-tree-metadata { color: var(--xsec-text-tertiary); font-size: 11px; }
.project-file-preview { min-width: 0; }
.project-file-preview > header {
  display: grid;
  height: 48px;
  grid-template-columns: 30px minmax(0, auto) minmax(0, 1fr) 30px;
  align-items: center;
  gap: 8px;
  padding: 0 12px;
  border-bottom: 1px solid var(--xsec-border-subtle);
}
.project-file-header-action {
  display: grid;
  width: 28px;
  height: 28px;
  place-items: center;
  padding: 0;
  border: 0;
  border-radius: var(--xsec-radius-md);
  background: transparent;
  color: var(--xsec-text-secondary);
  cursor: pointer;
}
.project-file-header-action:hover:not(:disabled) { background: var(--xsec-surface-hover); color: var(--xsec-text-primary); }
.project-file-header-action:disabled { cursor: not-allowed; color: var(--xsec-text-tertiary); }
.project-file-preview > header strong, .project-file-preview > header small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.project-file-preview > header small { color: var(--xsec-text-tertiary); }
.project-file-code { overflow: auto; padding: 6px 0 24px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; line-height: 24px; }
.project-file-line { position: relative; display: grid; min-width: max-content; grid-template-columns: 28px 42px minmax(240px, 1fr); }
.project-file-line:hover, .project-file-line.is-commenting { background: var(--xsec-accent-soft); }
.file-line-comment-trigger {
  opacity: 0;
  pointer-events: none;
  width: 24px;
  height: 24px;
  padding: 0;
  border: 0;
  border-radius: var(--xsec-radius-sm);
  background: var(--xsec-surface-subtle);
  color: var(--xsec-text-primary);
  cursor: pointer;
}
.project-file-line:hover .file-line-comment-trigger:not(:disabled), .file-line-comment-trigger:focus-visible {
  opacity: 1;
  pointer-events: auto;
}
.file-line-comment-trigger:disabled { cursor: not-allowed; opacity: .35; }
.file-line-number { padding-right: 12px; color: var(--xsec-text-tertiary); text-align: right; user-select: none; }
.project-file-line code { padding-right: 16px; color: var(--xsec-text-primary); white-space: pre; }
.file-line-comment-editor {
  grid-column: 2 / 4;
  width: min(460px, calc(100vw - 72px));
  margin: 6px 12px 12px 0;
  padding: 12px;
  border: 1px solid var(--xsec-border);
  border-radius: 12px;
  background: var(--xsec-surface-container);
  box-shadow: 0 10px 26px rgb(0 0 0 / 18%);
  font-family: var(--xsec-font-family, system-ui, sans-serif);
}
.file-line-comment-heading { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.file-line-comment-heading small { margin-left: auto; color: var(--xsec-text-tertiary); }
.file-line-comment-editor textarea {
  width: 100%;
  min-height: 76px;
  resize: vertical;
  padding: 9px 10px;
  border: 1px solid var(--xsec-border);
  border-radius: var(--xsec-radius-lg);
  background: var(--xsec-surface-subtle);
  color: var(--xsec-text-primary);
  line-height: 1.5;
}
.file-line-comment-editor textarea:focus { border-color: var(--xsec-accent); outline: 0; }
.file-line-comment-footer { display: flex; justify-content: flex-end; gap: 8px; margin-top: 10px; }
.file-line-comment-footer button, .project-files-retry {
  padding: 5px 10px;
  border: 1px solid var(--xsec-border);
  border-radius: var(--xsec-radius-md);
  background: var(--xsec-surface-container);
  color: var(--xsec-text-secondary);
  cursor: pointer;
}
.file-line-comment-footer button:disabled { cursor: not-allowed; opacity: .45; }
.project-files-primary { border-color: var(--xsec-accent) !important; background: var(--xsec-accent) !important; color: #fff !important; }
.project-files-notice { margin: 8px 12px; color: var(--xsec-status-success, var(--xsec-accent)); font-size: 13px; }
.project-files-error, .project-files-empty { display: grid; min-height: 160px; place-content: center; gap: 12px; padding: 24px; color: var(--xsec-text-secondary); text-align: center; }
.project-files-error { color: var(--xsec-status-error); }
.project-files-loading { display: grid; gap: 9px; padding: 14px 12px; }
.project-files-loading-row { display: block; height: 18px; border-radius: var(--xsec-radius-sm); background: var(--xsec-surface-subtle); }
@media (max-width: 520px) {
  .file-line-comment-trigger:not(:disabled) { opacity: 1; pointer-events: auto; }
  .project-file-preview > header { grid-template-columns: 30px minmax(0, 1fr) 30px; }
  .project-file-preview > header small { display: none; }
  .file-line-comment-editor { width: calc(100vw - 54px); }
}
`;function entryAction(controller,entry){return entry.isDirectory?()=>{controller.toggleDirectory(entry)}:()=>{controller.openFile(entry)}}function addButton(controller,entry){let label=`添加 ${entry.name} 到会话`,button=actionButton("file-tree-add-action",label,()=>{controller.addPath(entry)}),busy=controller.state.addingPaths.has(entry.path);return button.disabled=!controller.composerWritable||busy,button.title=controller.composerWritable?"添加到会话":"当前会话不可编辑",busy&&button.setAttribute("aria-busy","true"),button.append(icon("at")),button}function row(controller,entry,depth){let branch=element("div","file-tree-branch"),item=element("div","file-tree-row");item.style.setProperty("--file-tree-depth",String(depth));let main=actionButton("file-tree-main-action",entry.isDirectory?`展开 ${entry.name}`:`打开 ${entry.name}`,entryAction(controller,entry));main.setAttribute("role","treeitem");let expanded=controller.state.expanded.has(entry.path);entry.isDirectory&&main.setAttribute("aria-expanded",String(expanded));let chevron=element("span","file-tree-chevron");entry.isDirectory&&chevron.append(icon(expanded?"chevronDown":"chevronRight"));let name=element("span","file-tree-name",entry.name),metadata=element("small","file-tree-metadata",entry.isDirectory&&controller.state.loadingDirectories.has(entry.path)?"加载中…":entry.isDirectory?"":formatFileSize(entry.size));return main.append(chevron,icon(entry.isDirectory?"folder":"file"),name,metadata),item.append(main,addButton(controller,entry)),branch.append(item),entry.isDirectory&&expanded&&appendDirectory(branch,controller,entry.path,depth+1),branch}function appendDirectory(parent,controller,directory,depth){let files=controller.state.filesByDirectory.get(directory),error=controller.state.directoryErrors.get(directory);if(error){parent.append(errorPanel(error,()=>{controller.loadDirectory(directory)}));return}if(!files){parent.append(loadingPanel(3));return}for(let entry of files)parent.append(row(controller,entry,depth))}function toolbar(controller){let header=element("header","project-files-toolbar");header.append(element("strong","","项目文件"));let refresh=actionButton("project-files-refresh","刷新项目文件",()=>controller.refresh());return refresh.disabled=controller.state.loadingDirectories.has(""),refresh.textContent="刷新",header.append(refresh),header}function renderTree(controller){let rootFiles=controller.state.filesByDirectory.get(""),rootError=controller.state.directoryErrors.get(""),view=element("section","project-files-view");if(controller.state.actionError&&view.append(errorPanel(controller.state.actionError)),controller.state.actionNotice&&view.append(noticePanel(controller.state.actionNotice)),view.append(toolbar(controller)),rootError&&!rootFiles)return view.append(errorPanel(rootError,()=>{controller.loadDirectory("")})),view;if(!rootFiles&&controller.state.loadingDirectories.has(""))return view.append(loadingPanel()),view;if(!rootFiles?.length)return view.append(emptyPanel(controller.contextKey?"项目目录为空":"尚未绑定工作区")),view;let tree=element("div","file-tree");tree.setAttribute("aria-label","项目文件"),tree.setAttribute("role","tree");for(let entry of rootFiles)tree.append(row(controller,entry,0));return view.append(tree),view}function initialState(){return{actionError:"",actionNotice:"",addingPaths:new Set,comment:"",commentLine:null,content:"",directoryErrors:new Map,expanded:new Set,fileLoading:!1,filesByDirectory:new Map,loadingDirectories:new Set,previewError:"",selected:null,submittingComment:!1}}function pathRequest(entry){return{path:entry.path,expectedIsDirectory:entry.isDirectory}}var ProjectFilesController=class{constructor(api){this.api=api,this.state=initialState(),this.contextKey="",this.composerWritable=!1,this.directoryRequests=new Map,this.fileRequest=0,this.revision=0,this.root=null}async mount(root,context){this.root=root,console.info("project-files.mount",{composerWritable:composerWritable(context),workspaceBound:!!workspaceKey(context)}),this.applyContext(context,!0)}update(context){this.applyContext(context,!1)}dispose(){console.debug("project-files.dispose"),this.revision+=1,this.root=null}applyContext(context,initial){let nextKey=workspaceKey(context);if(this.composerWritable=composerWritable(context),!initial&&nextKey===this.contextKey){this.render();return}this.contextKey=nextKey,this.reset(),this.loadDirectory("")}reset(){this.revision+=1,this.directoryRequests.clear(),this.fileRequest=0,this.state=initialState(),this.render()}refresh(){this.reset(),this.loadDirectory("")}render(){if(!this.root)return;let style=element("style","",styles),content=this.state.selected?renderPreview(this):renderTree(this);this.root.replaceChildren(style,content)}directoryCurrent(directory,request,revision){return this.revision===revision&&this.directoryRequests.get(directory)===request}fileCurrent(revision,request,selected){return this.revision===revision&&this.fileRequest===request&&this.state.selected===selected}async loadDirectory(directory){let revision=this.revision,request=(this.directoryRequests.get(directory)??0)+1;this.directoryRequests.set(directory,request),this.state.loadingDirectories.add(directory),this.state.directoryErrors.delete(directory),this.render(),console.info("project-files.directory-list.started",{scope:directory?"nested":"root"});try{let result=await this.api.list(directory);if(!this.directoryCurrent(directory,request,revision))return;let entries=fileEntries(result);this.state.filesByDirectory.set(directory,entries),console.info("project-files.directory-list.completed",{entryCount:entries.length,scope:directory?"nested":"root"})}catch(error){if(!this.directoryCurrent(directory,request,revision))return;console.error("project-files.directory-list.failed",{errorType:error instanceof Error?error.name:typeof error,scope:directory?"nested":"root"}),this.state.directoryErrors.set(directory,`列出项目文件失败：${String(error)}`)}finally{this.directoryCurrent(directory,request,revision)&&(this.state.loadingDirectories.delete(directory),this.render())}}async toggleDirectory(entry){if(this.state.expanded.has(entry.path)){this.state.expanded.delete(entry.path),this.render();return}this.state.expanded.add(entry.path),this.render(),this.state.filesByDirectory.has(entry.path)||await this.loadDirectory(entry.path)}async openFile(entry){let revision=this.revision,request=this.fileRequest+1;this.fileRequest=request,this.state.comment="",this.state.commentLine=null,this.state.content="",this.state.fileLoading=!0,this.state.previewError="",this.state.submittingComment=!1,this.state.selected=entry,this.render(),console.info("project-files.file-read.started",{targetType:"file"});try{let result=await this.api.read(entry.path);if(this.revision!==revision||this.fileRequest!==request)return;this.state.content=fileContent(result),console.info("project-files.file-read.completed",{characterCount:this.state.content.length})}catch(error){if(this.revision!==revision||this.fileRequest!==request)return;console.error("project-files.file-read.failed",{errorType:error instanceof Error?error.name:typeof error}),this.state.previewError=`读取文件失败：${String(error)}`}finally{this.revision===revision&&this.fileRequest===request&&(this.state.fileLoading=!1,this.render())}}closeFile(){this.fileRequest+=1,this.state.submittingComment=!1,this.state.comment="",this.state.commentLine=null,this.state.selected=null,this.render()}startComment(line){this.composerWritable&&(this.state.comment="",this.state.commentLine=line,this.render())}cancelComment(){this.state.comment="",this.state.commentLine=null,this.render()}async addPath(entry){if(!this.composerWritable||this.state.addingPaths.has(entry.path))return;let revision=this.revision,addingPaths=this.state.addingPaths;addingPaths.add(entry.path),this.state.actionError="",this.state.actionNotice="",this.render(),console.info("project-files.composer-path-add.started",{targetType:entry.isDirectory?"directory":"file"});try{if(await this.api.addPath(pathRequest(entry)),this.revision!==revision)return;console.info("project-files.composer-path-add.completed",{targetType:entry.isDirectory?"directory":"file"}),this.state.actionNotice=`已将“${entry.name}”添加到会话`}catch(error){if(this.revision!==revision)return;console.error("project-files.composer-path-add.failed",{errorType:error instanceof Error?error.name:typeof error,targetType:entry.isDirectory?"directory":"file"}),this.state.actionError=`添加“${entry.name}”失败：${String(error)}`}finally{this.state.addingPaths===addingPaths&&(addingPaths.delete(entry.path),this.render())}}async submitComment(line,code){if(!this.composerWritable||!this.state.selected||this.state.submittingComment)return;let revision=this.revision,request=this.fileRequest,selected=this.state.selected,comment;try{comment=commentText(this.state.comment)}catch(error){this.state.actionError=String(error),this.render();return}try{if(this.state.actionError="",this.state.submittingComment=!0,this.render(),console.info("project-files.line-comment-add.started",{line}),await this.api.addLineComment({comment,expectedLine:code,line,path:this.state.selected.path}),!this.fileCurrent(revision,request,selected))return;console.info("project-files.line-comment-add.completed",{line}),this.cancelComment()}catch(error){if(!this.fileCurrent(revision,request,selected))return;console.error("project-files.line-comment-add.failed",{errorType:error instanceof Error?error.name:typeof error,line}),this.state.actionError=`添加第 ${line} 行评论失败：${String(error)}`}finally{this.fileCurrent(revision,request,selected)&&(this.state.submittingComment=!1,this.render())}}};function createProjectFilesController(host){let api={list(directory){return host.request("xsec.files.list",{directory:directory||void 0})},read(path){return host.request("xsec.files.read",{path})},addPath(entry){return host.request("xsec.workspace.composer.path.add",entry)},addLineComment(comment){return host.request("xsec.workspace.composer.line-comment.add",comment)}};return new ProjectFilesController(api)}export function activate(host){console.debug("project-files.activate",{apiVersion:host.apiVersion});let controller=createProjectFilesController(host);return{mount(root,context){return controller.mount(root,context)},update(context){return controller.update(context)},dispose(){return controller.dispose()}}}
