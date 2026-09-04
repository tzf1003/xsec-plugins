const TREE_METHOD="xsec.attack-path.tree.list";
const SUBAGENTS_METHOD="xsec.attack-path.subagents.list";
const OPEN_TOOL_METHOD="xsec.workspace.tool.open";
const SUBAGENT_PLUGIN_ID="com.xsec.workspace.sub-agent",SUBAGENT_DETAIL_TOOL_ID="subagent-detail",SVG_NS="http://www.w3.org/2000/svg";
const NODE_WIDTH=130,NODE_HEIGHT=58,X_GAP=150,Y_GAP=120,ROOT_GAP=80,PADDING=80;
const MIN_SCALE=.45,MAX_SCALE=1.8,ZOOM_STEP=.1,POLL_INTERVAL_MS=2_000,ROOT_TOP_OFFSET=36;
const MIN_STAGE_WIDTH=900,MIN_STAGE_HEIGHT=520,MIN_CURVE_HEIGHT=32,NODE_KINDS=["task","action","finding"];

function layoutTreeNodes(nodes,rootId){
  const positions=new Map();
  if(!nodes.length)return{positions,width:0,height:0};
  const ids=new Set(nodes.map((node)=>node.id)),children=new Map();
  for(const node of nodes)if(node.parent_id&&ids.has(node.parent_id))children.set(node.parent_id,[...(children.get(node.parent_id)??[]),node]);
  const roots=nodes.filter((node)=>!node.parent_id||!ids.has(node.parent_id)),preferred=roots.findIndex((node)=>node.id===rootId);
  if(preferred>0)roots.unshift(...roots.splice(preferred,1));
  let leaf=0;const visited=new Set();
  const place=(node,depth)=>{
    if(visited.has(node.id))return PADDING+NODE_WIDTH/2+leaf++*X_GAP;
    visited.add(node.id);const branch=children.get(node.id)??[];
    const center=branch.length?branch.reduce((sum,child)=>sum+place(child,depth+1),0)/branch.length:PADDING+NODE_WIDTH/2+leaf++*X_GAP;
    positions.set(node.id,{x:center-NODE_WIDTH/2,y:PADDING+depth*Y_GAP});return center;
  };
  const placeRoot=(node)=>{if(!visited.has(node.id)){place(node,0);leaf+=ROOT_GAP/X_GAP;}};
  roots.forEach(placeRoot);nodes.forEach(placeRoot);
  let width=0,height=0;positions.forEach((position)=>{width=Math.max(width,position.x+NODE_WIDTH);height=Math.max(height,position.y+NODE_HEIGHT);});
  return{positions,width:width+PADDING,height:height+PADDING};
}

function nodeKind(node,rootId){return!node.parent_id||node.parent_id===rootId?"task":node.status==="vuln"||node.kind==="vuln"?"finding":"action";}
function displayIds(nodes,rootId){
  const counts={task:0,action:0,finding:0},ids=new Map();
  for(const node of nodes){if(!node.parent_id){ids.set(node.id,"Root");continue;}const kind=nodeKind(node,rootId);ids.set(node.id,`${kind[0].toUpperCase()}${kind.slice(1)}_${String(++counts[kind]).padStart(3,"0")}`);}
  return ids;
}
function subagentForNode(node,subagents){
  const exact=node.subagent_id?subagents.find((candidate)=>candidate.id===node.subagent_id):undefined;
  return exact??subagents.find((candidate)=>candidate.node_id===node.id);
}
function graphModel(nodes,subagents){
  const rootId=nodes.find((node)=>!node.parent_id)?.id??nodes[0]?.id,layout=layoutTreeNodes(nodes,rootId);
  const positioned=nodes.map((node)=>({node,...(layout.positions.get(node.id)??{x:PADDING,y:PADDING})})),positions=new Map(positioned.map((position)=>[position.node.id,position]));
  const subagentsByNode=new Map(positioned.map(({node})=>[node.id,subagentForNode(node,subagents)]).filter(([,row])=>row)),counts={task:0,action:0,finding:0};
  for(const node of nodes)if(node.parent_id)counts[nodeKind(node,rootId)]++;
  return{rootId,positioned,positions,subagentsByNode,counts,stage:{width:Math.max(layout.width,MIN_STAGE_WIDTH),height:Math.max(layout.height,MIN_STAGE_HEIGHT)}};
}
function clampScale(value){return Math.min(MAX_SCALE,Math.max(MIN_SCALE,value));}
function record(value,label){if(!value||typeof value!=="object"||Array.isArray(value))throw new Error(`${label}无效`);return value;}
function optionalString(row,field,label){const value=row[field];if(value!==null&&value!==undefined&&typeof value!=="string")throw new Error(`${label}.${field} 无效`);return value;}
function validRow(row,key,index){
  const value=record(row,`攻击路径响应 ${key}[${index}]`),required=key==="nodes"?["id","title","kind","status"]:["id","role","status"],optional=key==="nodes"?["parent_id","subagent_id"]:["node_id","status_reason"];
  for(const field of required)if(typeof value[field]!=="string"||!value[field])throw new Error(`攻击路径响应 ${key}[${index}].${field} 无效`);
  optional.forEach((field)=>optionalString(value,field,`攻击路径响应 ${key}[${index}]`));return value;
}
function responseRows(result,key){const value=record(result,"攻击路径响应");if(!Array.isArray(value[key]))throw new Error(`攻击路径响应缺少 ${key} 数组`);return value[key].map((row,index)=>validRow(row,key,index));}
function workspaceContext(input){
  const workspace=input?.workspace??{},binding=workspace.binding??{},assignmentId=binding.assignmentId;
  if(assignmentId!==null&&assignmentId!==undefined&&(typeof assignmentId!=="string"||!assignmentId))throw new Error("攻击路径上下文的任务标识无效");
  return{assignmentId:assignmentId??null,visible:input?.visible!==false,mode:workspace.mode==="observe"?"observe":"interactive",dock:workspace.dock==="bottom"?"bottom":"side"};
}
function element(tag,className,text){const node=document.createElement(tag);if(className)node.className=className;if(text!==undefined)node.textContent=text;return node;}
function installStyles(){
  if(document.getElementById("xsec-attack-path-styles"))return;
  const style=element("style");style.id="xsec-attack-path-styles";
  style.textContent=`:root{color-scheme:dark;font-family:var(--xsec-font-family,Inter,"Segoe UI",sans-serif)}:root[data-xsec-theme="light"]{color-scheme:light}*{box-sizing:border-box}html,body,[data-xsec-plugin-root]{width:100%;height:100%;margin:0;overflow:hidden}button{font:inherit}.ap-root{display:flex;width:100%;height:100%;min-width:0;min-height:280px;flex-direction:column;background:#080b10;color:#d6deeb}.ap-head{display:flex;min-height:42px;align-items:center;gap:14px;padding:8px 12px;border-bottom:1px solid #232936;background:#0c1018}.ap-title{font-size:13px;font-weight:600;white-space:nowrap}.ap-legend{display:flex;min-width:0;align-items:center;gap:6px;margin-left:auto;color:#8b94a7;font-size:11px;white-space:nowrap}.ap-legend b{margin-right:6px;color:#e6e9ef}.ap-dot{width:8px;height:8px;border-radius:50%}.ap-dot.task{background:#5b74ff}.ap-dot.action{background:#2ecc9b}.ap-dot.finding{background:#f0a935}.ap-controls{display:flex;flex:0 0 auto;gap:4px}.ap-controls button,.ap-retry{height:26px;min-width:28px;padding:0 7px;border:1px solid #293144;border-radius:6px;background:#101522;color:#d6deeb;cursor:pointer}.ap-controls button:hover,.ap-retry:hover{border-color:#3a4560;background:#151b29}.ap-status{display:none;max-width:46%;overflow:hidden;padding:4px 8px;border:1px solid rgba(245,163,163,.35);border-radius:6px;background:#2b1118;color:#f5a3a3;font-size:11px;text-overflow:ellipsis;white-space:nowrap}.ap-status.show{display:block}.ap-retry.hidden{display:none}.ap-canvas{position:relative;min-height:0;flex:1;overflow:hidden;cursor:grab;touch-action:none;background:#080b10}.ap-canvas.dragging{cursor:grabbing}.ap-stage{position:absolute;top:0;left:0;transform-origin:0 0}.ap-links{position:absolute;top:0;left:0;overflow:visible;pointer-events:none}.ap-link{fill:none;stroke:#344057;stroke-width:1.25;stroke-linecap:round;stroke-dasharray:7 8;animation:ap-flow 1.2s linear infinite}.ap-link.task{stroke:#5b74ff}.ap-link.action{stroke:#2ecc9b}.ap-link.finding{stroke:#f0a935}.ap-node{position:absolute;top:0;left:0;width:130px;min-height:58px;padding:13px 10px 8px;border:1px solid #232936;border-radius:8px;background:#12151c;color:#d6deeb;cursor:pointer;text-align:center;user-select:none;transition:border-color .12s,background .12s,outline-color .12s}.ap-node:hover:not(:disabled){border-color:#3a4560}.ap-node:disabled{cursor:default;opacity:.78}.ap-node .ap-chip{position:absolute;top:-9px;left:10px;padding:1px 7px;border-radius:5px;color:#fff;font-size:10px;font-weight:700}.ap-node .ap-node-title{display:-webkit-box;overflow:hidden;font-size:12.5px;font-weight:600;line-height:1.35;-webkit-box-orient:vertical;-webkit-line-clamp:2}.ap-node .ap-id{display:block;margin-top:2px;color:#8b94a7;font-size:10.5px}.ap-node .ap-reason{display:block;overflow:hidden;margin-top:2px;color:#ffb86b;font-size:9.5px;text-overflow:ellipsis;white-space:nowrap}.ap-node.task{border-color:rgba(91,116,255,.5);background:rgba(91,116,255,.12)}.ap-node.task .ap-chip{background:#3f51c7}.ap-node.action{border-color:rgba(46,204,155,.45);background:rgba(46,204,155,.1)}.ap-node.action .ap-chip{background:#16765f}.ap-node.finding{border-color:rgba(240,169,53,.45);background:rgba(240,169,53,.1)}.ap-node.finding .ap-chip{background:#9a5d00}.ap-node.selected{outline:2px solid #5b74ff;outline-offset:2px}.ap-empty{display:grid;height:100%;place-content:center;justify-items:center;gap:10px;padding:28px;color:#8b94a7;text-align:center}.ap-empty strong{color:#d6deeb;font-size:14px}.ap-empty span{max-width:320px;font-size:12px;line-height:1.6}.ap-loading{width:28px;height:28px;border:2px solid #293144;border-top-color:#5b74ff;border-radius:50%;animation:ap-spin .8s linear infinite}@keyframes ap-flow{to{stroke-dashoffset:-15}}@keyframes ap-spin{to{transform:rotate(360deg)}}@media(prefers-reduced-motion:reduce){.ap-link,.ap-loading{animation:none}}@media(max-width:520px){.ap-head{align-items:flex-start;flex-wrap:wrap}.ap-legend{order:3;width:100%;margin-left:0}.ap-status{max-width:100%}}:root[data-xsec-theme="light"] .ap-root{background:#f7f8fb;color:#202737}:root[data-xsec-theme="light"] .ap-head{border-color:#dde2ea;background:#fff}:root[data-xsec-theme="light"] .ap-canvas{background:#f7f8fb}:root[data-xsec-theme="light"] .ap-title,:root[data-xsec-theme="light"] .ap-legend b,:root[data-xsec-theme="light"] .ap-empty strong{color:#202737}:root[data-xsec-theme="light"] .ap-controls button,:root[data-xsec-theme="light"] .ap-retry{border-color:#d7dce5;background:#fff;color:#35405a}:root[data-xsec-theme="light"] .ap-node{color:#202737}:root[data-xsec-theme="light"] .ap-node .ap-id{color:#667085}`;
  document.head.append(style);
}

export function activate(host){
  console.debug("attack-path.activate",{apiVersion:host.apiVersion});
  class AttackPathController{
  constructor(refresh){
    this.refresh=refresh;this.context=workspaceContext();this.nodes=[];this.subagents=[];this.model=graphModel([],[]);this.view={x:32,y:40,scale:1};
    this.generation=0;this.failed=false;this.loading=false;this.error=null;this.resetKey="";this.snapshot="";
    this.themeSubscription=host.onTheme((theme)=>this.applyTheme(theme));this.applyTheme({"color-mode":getComputedStyle(document.documentElement).getPropertyValue("--xsec-color-mode").trim()});
  }
  applyTheme(theme){document.documentElement.dataset.xsecTheme=theme?.["color-mode"]==="light"?"light":"dark";}
  async mount(root,context){this.root=root;this.buildShell();await this.update(context);console.info("attack-path.mounted",{hasAssignment:Boolean(this.context.assignmentId),mode:this.context.mode,dock:this.context.dock});this.timer=window.setInterval(()=>void this.refresh(this),POLL_INTERVAL_MS);}
  async update(context){
    const next=workspaceContext(context),changed=next.assignmentId!==this.context.assignmentId,visibilityChanged=next.visible!==this.context.visible;
    this.context=next;this.root.dataset.xsecSurface=`${next.mode}:${next.dock}`;
    if(changed||visibilityChanged)console.info("attack-path.context.changed",{hasAssignment:Boolean(next.assignmentId),visible:next.visible,mode:next.mode,dock:next.dock});
    if(changed)this.resetReadState();else if(visibilityChanged)this.cancelLoad();this.render();
  }
  async dispose(){console.debug("attack-path.disposed");this.disposed=true;this.generation++;window.clearInterval(this.timer);this.resizeObserver?.disconnect();this.themeSubscription.dispose();this.root.replaceChildren();}
  cancelLoad(){this.generation++;this.loading=false;}
  resetReadState(){
    this.generation++;this.failed=false;this.loading=false;this.error=null;this.nodes=[];this.subagents=[];this.selectedSubagentId=null;this.resetKey="";this.snapshot="";this.showMessage();
  }
  recordSnapshot(){const next=`${this.nodes.length}:${this.subagents.length}`;if(next===this.snapshot)return;this.snapshot=next;console.info("attack-path.snapshot.updated",{nodeCount:this.nodes.length,subagentCount:this.subagents.length});}
  buildShell(){
    installStyles();const shell=element("section","ap-root"),header=element("header","ap-head"),controls=element("span","ap-controls");shell.setAttribute("aria-label","攻击路径");
    this.status=element("span","ap-status");this.status.setAttribute("role","alert");this.retry=element("button","ap-retry hidden","重试");this.retry.type="button";this.retry.addEventListener("click",()=>this.retryLoad());this.legend=element("span","ap-legend");
    controls.append(this.zoomButton("−","缩小攻击路径",()=>this.zoomTo(this.view.scale-ZOOM_STEP)),this.zoomButton("100%","重置攻击路径视图",()=>this.resetView()),this.zoomButton("+","放大攻击路径",()=>this.zoomTo(this.view.scale+ZOOM_STEP)));
    header.append(element("span","ap-title","攻击路径"),this.status,this.retry,this.legend,controls);this.canvas=element("div","ap-canvas");this.installCanvasEvents();shell.append(header,this.canvas);this.root.replaceChildren(shell);
    this.resizeObserver=typeof ResizeObserver==="function"?new ResizeObserver(()=>this.applyTransform()):null;this.resizeObserver?.observe(this.canvas);
  }
  retryLoad(){console.info("attack-path.retry.requested");void this.refresh(this,true);}
  zoomButton(text,label,action){const button=element("button","",text);button.type="button";button.title=label;button.setAttribute("aria-label",label);button.addEventListener("click",action);if(text==="100%")this.zoomLabel=button;return button;}
  installCanvasEvents(){
    this.canvas.addEventListener("wheel",(event)=>this.onWheel(event),{passive:false});this.canvas.addEventListener("pointerdown",(event)=>this.startDrag(event));this.canvas.addEventListener("pointermove",(event)=>this.moveDrag(event));this.canvas.addEventListener("pointerup",(event)=>this.stopDrag(event));this.canvas.addEventListener("pointercancel",(event)=>this.stopDrag(event));
  }
  render(){
    if(this.error)return this.renderEmpty("攻击路径暂时不可用",`读取插件数据失败：${this.error}`);if(!this.context.assignmentId)return this.renderEmpty("该 Agent 未绑定任务");if(this.loading&&!this.nodes.length)return this.renderEmpty("正在读取攻击路径","正在同步节点与子 Agent 状态…",true);if(!this.nodes.length)return this.renderEmpty("暂无攻击路径节点");this.renderGraph();
  }
  renderEmpty(title,description,loading=false){const empty=element("div","ap-empty");if(loading)empty.append(element("span","ap-loading"));empty.append(element("strong","",title));if(description)empty.append(element("span","",description));this.canvas.replaceChildren(empty);this.legend.replaceChildren();}
  renderGraph(){
    this.model=graphModel(this.nodes,this.subagents);const ids=displayIds(this.nodes,this.model.rootId);this.legend.replaceChildren(...NODE_KINDS.flatMap((kind)=>[element("i",`ap-dot ${kind}`),document.createTextNode(`${kind[0].toUpperCase()}${kind.slice(1)} `),element("b","",String(this.model.counts[kind]))]));
    const stage=element("div","ap-stage");stage.style.width=`${this.model.stage.width}px`;stage.style.height=`${this.model.stage.height}px`;stage.append(this.links(),...this.model.positioned.map((position)=>this.nodeButton(position,ids)));this.canvas.replaceChildren(stage);this.resetIfNeeded();
  }
  links(){
    const svg=document.createElementNS(SVG_NS,"svg");svg.setAttribute("class","ap-links");svg.setAttribute("width",String(this.model.stage.width));svg.setAttribute("height",String(this.model.stage.height));
    for(const node of this.nodes.filter((candidate)=>candidate.parent_id)){
      const parent=this.model.positions.get(node.parent_id),child=this.model.positions.get(node.id);if(!parent||!child)continue;
      const startX=parent.x+NODE_WIDTH/2,startY=parent.y+NODE_HEIGHT,endX=child.x+NODE_WIDTH/2,endY=child.y,middleY=startY+Math.max(MIN_CURVE_HEIGHT,(endY-startY)/2),path=document.createElementNS(SVG_NS,"path");
      path.setAttribute("class",`ap-link ${nodeKind(node,this.model.rootId)}`);path.setAttribute("d",`M ${startX} ${startY} C ${startX} ${middleY}, ${endX} ${middleY}, ${endX} ${endY}`);svg.append(path);
    }return svg;
  }
  nodeButton(position,ids){
    const{node,x,y}=position,kind=nodeKind(node,this.model.rootId),subagent=this.model.subagentsByNode.get(node.id),selected=this.selectedSubagentId===subagent?.id,button=element("button",`ap-node ${kind}${selected?" selected":""}`),session=subagent?.acp_session_id??subagent?.session_id;
    button.type="button";button.style.transform=`translate(${x}px,${y}px)`;button.setAttribute("aria-label",`${kind} 节点：${node.title}`);button.setAttribute("aria-pressed",String(selected));button.title=subagent?`状态: ${subagent.status}${subagent.status_reason?`\n原因: ${subagent.status_reason}`:""}${session?`\nsession: ${session}`:""}`:"尚未派发子 Agent";
    button.append(element("span","ap-chip",`${kind[0].toUpperCase()}${kind.slice(1)}`),element("span","ap-node-title",node.title),element("span","ap-id",ids.get(node.id)??node.id));if(subagent?.status_reason)button.append(element("span","ap-reason",subagent.status_reason));if(!subagent)button.disabled=true;else button.addEventListener("click",()=>void this.openSubagent(subagent,node.title));return button;
  }
  async openSubagent(subagent,title){
    this.selectedSubagentId=subagent.id;this.renderGraph();console.info("attack-path.subagent.open.started");
    try{await this.onOpen(subagent,title);console.info("attack-path.subagent.open.completed");if(!this.error)this.showMessage();}catch(error){const message=error instanceof Error?error.message:String(error);console.error("attack-path.subagent.open.failed",{message});if(!this.error)this.showMessage(`无法打开子 Agent：${message}`);}
  }
  showMessage(message,retry=false){this.status.textContent=message??"";this.status.title=message??"";this.status.classList.toggle("show",Boolean(message));this.retry.classList.toggle("hidden",!retry);}
  resetIfNeeded(){const key=`${this.context.assignmentId}:${this.model.rootId??""}:${this.nodes.length}`;if(key===this.resetKey)return this.applyTransform();this.resetKey=key;requestAnimationFrame(()=>this.resetView());}
  resetView(){const root=this.model.positions.get(this.model.rootId);if(!root)return;const rect=this.canvas.getBoundingClientRect();this.view={x:rect.width/2-root.x-NODE_WIDTH/2,y:ROOT_TOP_OFFSET-root.y,scale:1};this.applyTransform();}
  zoomTo(nextScale,origin){const rect=this.canvas.getBoundingClientRect(),focus=origin??{x:rect.width/2,y:rect.height/2},scale=clampScale(nextScale),worldX=(focus.x-this.view.x)/this.view.scale,worldY=(focus.y-this.view.y)/this.view.scale;this.view={scale,x:focus.x-worldX*scale,y:focus.y-worldY*scale};this.applyTransform();}
  applyTransform(){const stage=this.canvas.querySelector(".ap-stage");if(stage)stage.style.transform=`translate(${this.view.x}px,${this.view.y}px) scale(${this.view.scale})`;this.zoomLabel.textContent=`${Math.round(this.view.scale*100)}%`;}
  onWheel(event){event.preventDefault();const rect=this.canvas.getBoundingClientRect();this.zoomTo(this.view.scale+(event.deltaY>0?-ZOOM_STEP:ZOOM_STEP),{x:event.clientX-rect.left,y:event.clientY-rect.top});}
  startDrag(event){if(event.button!==0||event.target.closest(".ap-node"))return;this.canvas.setPointerCapture(event.pointerId);this.canvas.classList.add("dragging");this.drag={id:event.pointerId,x:event.clientX,y:event.clientY,view:{...this.view}};}
  moveDrag(event){if(!this.drag||this.drag.id!==event.pointerId)return;this.view={...this.drag.view,x:this.drag.view.x+event.clientX-this.drag.x,y:this.drag.view.y+event.clientY-this.drag.y};this.applyTransform();}
  stopDrag(event){if(!this.drag||this.drag.id!==event.pointerId)return;if(this.canvas.hasPointerCapture(event.pointerId))this.canvas.releasePointerCapture(event.pointerId);this.canvas.classList.remove("dragging");this.drag=null;}
  }
  async function refreshController(controller,manual=false){
    if(controller.disposed||controller.loading||!controller.context.visible||!controller.context.assignmentId||(controller.failed&&!manual))return;
    controller.loading=true;controller.failed=false;controller.error=null;const request=++controller.generation;controller.render();
    try{
      const[tree,subagents]=await Promise.all([host.request(TREE_METHOD,{}),host.request(SUBAGENTS_METHOD,{})]);
      if(controller.disposed||request!==controller.generation)return;controller.nodes=responseRows(tree,"nodes");controller.subagents=responseRows(subagents,"subagents");controller.recordSnapshot();controller.showMessage();
    }catch(error){
      if(controller.disposed||request!==controller.generation)return;controller.nodes=[];controller.subagents=[];controller.snapshot="";controller.failed=true;controller.error=error instanceof Error?error.message:String(error);console.error("attack-path.load.failed",{message:controller.error});controller.showMessage(controller.error,true);
    }finally{if(request===controller.generation&&!controller.disposed){controller.loading=false;controller.render();}}
  }
  async function openSubagent(subagent,title){
    await host.request(OPEN_TOOL_METHOD,{pluginId:SUBAGENT_PLUGIN_ID,toolId:SUBAGENT_DETAIL_TOOL_ID,entityId:subagent.id,title});
  }
  const controller=new AttackPathController(refreshController);
  controller.onOpen=openSubagent;
  return{
    async mount(root,context){await controller.mount(root,context);await refreshController(controller);},
    async update(context){await controller.update(context);await refreshController(controller);},
    async dispose(){await controller.dispose();},
  };
}
