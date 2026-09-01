const LABEL={finding:"正式漏洞",evidence:"原始证据",report:"报告","shared-finding":"共享发现","passive-finding":"被动线索","task-conclusion":"任务结论"};
const ICON={finding:"◉",evidence:"◈",report:"▤","shared-finding":"◎","passive-finding":"◌","task-conclusion":"◇"};
const SOURCE={finding:"finding-detail",evidence:"evidence-detail",report:"report-detail","task-conclusion":"task-detail"};
const TITLE={"project-outcomes":"项目成果","finding-detail":"漏洞详情","report-detail":"报告详情","task-detail":"任务详情","evidence-detail":"证据详情"};
const FIELD={description:"说明",impact:"影响",reproduction_steps:"复现步骤",remediation:"修复建议",status:"状态",severity:"严重度",confidence:"置信度",endpoint:"端点",parameter:"参数",executive_summary:"执行摘要",scope:"范围",methodology:"方法",limitations:"限制",conclusion:"结论",filename:"文件名",kind:"类型",content_type:"内容类型",size_bytes:"大小",sha256:"SHA256",created_at:"创建时间",updated_at:"更新时间",assignment_id:"任务",run_id:"运行"};
const OUTCOME_LIMIT=500;
const PERCENT_SCALE=100;
const SEARCH_DEBOUNCE_MS=300;
const TASK_ID_DISPLAY_START=0;
const TASK_ID_DISPLAY_LENGTH=12;
const CSS=`:root{color:var(--xsec-text-primary,#20252b);background:var(--xsec-surface-base,#f7f8fa);font:13px/1.48 var(--xsec-font-family,system-ui,sans-serif)}*{box-sizing:border-box}body{margin:0}.app{min-height:100%;padding:14px}.heading,.actions,.scope,.row,.card-head,.card-copy,.details dl{display:flex}.heading,.actions{align-items:center;justify-content:space-between;gap:8px}.heading h1{margin:0;font-size:16px}.heading small,.muted,.meta,.notice{color:var(--xsec-text-secondary,#68707c)}.heading>span{display:grid;gap:2px}.icon-btn,.action,.scope button,.filter,.outcome-open,.add{font:inherit;color:inherit;border:1px solid var(--xsec-border,#d9dce1);background:var(--xsec-surface-container,#fff);border-radius:var(--xsec-radius-md,6px);cursor:pointer}.icon-btn,.add{width:32px;height:32px;padding:0;font-size:16px}.controls{display:grid;gap:9px;margin:14px 0}.scope{gap:0}.scope button{flex:1;border-radius:0;padding:7px}.scope button:first-child{border-radius:var(--xsec-radius-md,6px) 0 0 var(--xsec-radius-md,6px)}.scope button:last-child{border-radius:0 var(--xsec-radius-md,6px) var(--xsec-radius-md,6px) 0}.scope button[aria-pressed=true],.filter.is-active{color:#fff;background:var(--xsec-accent,#3977e8);border-color:var(--xsec-accent,#3977e8)}.scope button:disabled{opacity:.45;cursor:not-allowed}.search{width:100%;padding:8px 10px;color:inherit;border:1px solid var(--xsec-border,#d9dce1);border-radius:var(--xsec-radius-md,6px);background:var(--xsec-surface-container,#fff);font:inherit}.filters{display:flex;gap:6px;overflow:auto;padding-bottom:2px}.filter{white-space:nowrap;padding:5px 8px}.filter span{margin-left:5px;opacity:.72}.notice{min-height:20px;margin:0 0 8px}.notice.error{color:var(--xsec-status-error,#cf3d39)}.list{display:grid;gap:8px}.row{align-items:stretch;gap:6px}.outcome-open{display:grid;grid-template-columns:30px minmax(0,1fr);gap:9px;flex:1;min-width:0;padding:10px;text-align:left}.outcome-open:hover,.icon-btn:hover,.action:hover,.add:hover{background:var(--xsec-surface-hover,#f0f2f5)}.outcome-open:focus-visible,.icon-btn:focus-visible,.action:focus-visible,.add:focus-visible,.filter:focus-visible,.scope button:focus-visible{outline:2px solid var(--xsec-accent,#3977e8);outline-offset:2px}.outcome-icon{display:grid;place-items:center;width:30px;height:30px;border-radius:50%;color:var(--xsec-accent,#3977e8);background:var(--xsec-accent-soft,#e5efff);font-size:17px}.card-copy{display:grid;min-width:0;gap:3px}.card-head{align-items:center;gap:6px}.card-head strong,.meta{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.meta{font-size:12px}.tag{display:inline-block;width:max-content;max-width:100%;padding:1px 6px;border:1px solid var(--xsec-border,#d9dce1);border-radius:999px;color:var(--xsec-text-secondary,#68707c);font-size:11px}.severity{color:var(--xsec-status-error,#cf3d39);border-color:currentColor}.empty,.loading{padding:32px 12px;text-align:center;color:var(--xsec-text-secondary,#68707c)}.detail{display:grid;gap:13px}.back{display:flex;align-items:center;gap:8px;border:0;padding:0;background:none;color:var(--xsec-text-primary,#20252b);font:inherit;cursor:pointer}.back strong{display:block;font-size:16px}.detail-title small{display:block;color:var(--xsec-text-secondary,#68707c)}.actions{justify-content:flex-start}.action{padding:7px 10px}.action.primary{border-color:var(--xsec-accent,#3977e8);color:#fff;background:var(--xsec-accent,#3977e8)}.summary{margin:0;white-space:pre-wrap;word-break:break-word}.preview{max-width:100%;max-height:260px;border:1px solid var(--xsec-border,#d9dce1);border-radius:var(--xsec-radius-md,6px)}.code{margin:0;padding:10px;overflow:auto;border:1px solid var(--xsec-border,#d9dce1);border-radius:var(--xsec-radius-md,6px);background:var(--xsec-surface-subtle,#f3f4f6);white-space:pre-wrap;word-break:break-word}.details dl{display:grid;grid-template-columns:92px minmax(0,1fr);gap:7px 10px;margin:0}.details dt{color:var(--xsec-text-secondary,#68707c)}.details dd{margin:0;word-break:break-word}.raw summary{cursor:pointer}.raw pre{margin:8px 0 0}.panel-static-row{display:flex;justify-content:space-between;gap:8px;padding:10px;border:1px solid var(--xsec-border,#d9dce1);border-radius:var(--xsec-radius-md,6px);background:var(--xsec-surface-container,#fff)}.panel-static-row span{display:grid;gap:3px;min-width:0}.panel-static-row strong,.panel-static-row small{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.panel-static-row small{color:var(--xsec-text-secondary,#68707c)}`;

function el(tag,className,value){const node=document.createElement(tag);if(className)node.className=className;if(value!==undefined)node.textContent=value;return node}
function button(className,label,onClick){const node=el("button",className,label);node.type="button";node.addEventListener("click",onClick);return node}
function items(value){return Array.isArray(value)?value:Array.isArray(value?.items)?value.items:[]}
function text(value,empty="—"){return typeof value==="string"&&value.trim()?value:empty}
function time(value){if(value===null||value===undefined||value==="")return "—";const stamp=new Date(Number(value));return Number.isNaN(stamp.getTime())?"—":stamp.toLocaleString("zh-CN")}
function safe(value){if(value===null||value===undefined)return value;return JSON.parse(JSON.stringify(value,(key,item)=>key==="storage_path"?undefined:item))}
function failure(error){return text(error?.message,String(error))}
function invoke(host,options){
  const {method,params}=options;
  if(method==="xsec.outcomes.list")return host.request("xsec.outcomes.list",params);
  if(method==="xsec.outcomes.get")return host.request("xsec.outcomes.get",params);
  if(method==="xsec.outcomes.resolve")return host.request("xsec.outcomes.resolve",params);
  if(method==="xsec.outcomes.task.get")return host.request("xsec.outcomes.task.get",params);
  if(method==="xsec.outcomes.evidence.list")return host.request("xsec.outcomes.evidence.list",params);
  if(method==="xsec.outcomes.reference.add")return host.request("xsec.outcomes.reference.add",params);
  if(method==="xsec.workspace.tool.open")return host.request("xsec.workspace.tool.open",params);
  throw new Error("Unsupported project outcomes request: "+method);
}
function isOutcomesTool(state){return state.context.tool==="project-outcomes"}
function outcomeTitle(row){return text(row?.title,text(row?.outcome_id))}
function taskProgress(value){if(value===null||value===undefined||value==="")return undefined;const progress=Number(value);return Number.isFinite(progress)?Math.round(progress*PERCENT_SCALE)+"%":undefined}
function setNotice(state,message,error=false){state.nodes.notice.textContent=message;state.nodes.notice.className=error?"notice error":"notice"}
function ownsNotice(state,kind,revision){return state.noticeOwner?.kind===kind&&state.noticeOwner.revision===revision}
function hasActionNotice(state){return state.noticeOwner?.kind==="reference"||state.noticeOwner?.kind==="source"}
function claimActionNotice(state,kind){const navigationRevision=state.navigationRevision,revision=++state.referenceRevision,token=kind+":"+navigationRevision+":"+revision;state.pendingReferences.add(token);state.noticeOwner={kind,revision};return {kind,revision,token,navigationRevision}}
function finishActionNotice(state,claim,message,error=false){state.pendingReferences.delete(claim.token);if(message===undefined)return;if(claim.navigationRevision===state.navigationRevision&&claim.revision===state.referenceRevision&&ownsNotice(state,claim.kind,claim.revision))setNotice(state,message,error)}
function replaceContent(state,node){state.viewRevision+=1;state.nodes.content.replaceChildren(node)}
function contextInfo(context){const workspace=context?.workspace??{},binding=workspace.binding??{},entityId=context?.tool?.entityId;return{tool:context?.tool?.kind??"project-outcomes",mode:workspace.mode,entityId,assignmentId:binding.assignmentId,canAdd:workspace.canAddComposerReference===true,toolCall:workspace.session?.active_tool_calls?.[entityId]}}
function outcomeSource(context,row){const toolId=SOURCE[row.kind],entityId=row.kind==="task-conclusion"?row.assignment_id:row.entity_id;if(context.mode==="observe"&&toolId==="task-detail")return undefined;return toolId&&entityId?{toolId,entityId}:undefined}

function addReference(state,target,outcomeId){
  const params=target==="collection"?{target}:{target,outcomeId},claim=claimActionNotice(state,"reference");setNotice(state,"正在添加到对话…");
  console.info("project-outcomes.reference.started",{target});
  void state.invoke({method:"xsec.outcomes.reference.add",params}).then(()=>{console.info("project-outcomes.reference.completed",{target});finishActionNotice(state,claim,"已添加到对话")}).catch((error)=>{console.error("project-outcomes.reference.failed",{target,message:failure(error)});finishActionNotice(state,claim,"添加到对话失败："+failure(error),true)});
}
function openSource(state,row){
  const target=outcomeSource(state.context,row);if(!target)return;
  const claim=claimActionNotice(state,"source");
  console.info("project-outcomes.source-open.started",{toolId:target.toolId});
  void state.invoke({method:"xsec.workspace.tool.open",params:{pluginId:"com.xsec.workspace.project-outcomes",toolId:target.toolId,title:outcomeTitle(row),entityId:target.entityId}}).then(()=>{console.info("project-outcomes.source-open.completed",{toolId:target.toolId});finishActionNotice(state,claim,"")}).catch((error)=>{console.error("project-outcomes.source-open.failed",{toolId:target.toolId,message:failure(error)});finishActionNotice(state,claim,"打开来源失败："+failure(error),true)});
}
function renderFilters(state){
  if(!state.nodes.filters)return;const counts=state.list.reduce((result,row)=>{result[row.kind]=(result[row.kind]??0)+1;return result},{}),showCounts=state.kind==="all"&&!state.query.trim()&&state.list.length<OUTCOME_LIMIT,filters=el("div","filters"),buttons=new Map();
  for(const[kind,label]of[["all","全部"],...Object.entries(LABEL)]){const active=state.kind===kind,filter=button("filter"+(active?" is-active":""),label,()=>{state.kind=kind;showOutcomeList(state)});buttons.set(kind,filter);filter.setAttribute("aria-pressed",String(active));if(showCounts)filter.append(el("span","",String(kind==="all"?state.list.length:counts[kind]??0)));filters.append(filter)}
  state.nodes.filterButtons=buttons;
  state.nodes.filters.replaceChildren(filters);
}
function renderScope(state){
  if(!state.nodes.scope)return;const scope=state.nodes.scope;scope.replaceChildren();for(const[value,label]of[["project","整个项目"],["assignment","当前任务"]]){const item=button("",label,()=>{state.scope=value;showOutcomeList(state)});item.disabled=value==="assignment"&&!state.context.assignmentId;item.setAttribute("aria-pressed",String(state.scope===value));scope.append(item)}
}
function appendReferenceAction(state,article,row){const action=button("add","@",()=>addReference(state,"outcome",row.outcome_id));action.setAttribute("aria-label","添加成果 "+outcomeTitle(row)+" 到对话");article.append(action)}
function renderOutcomeRow(state,row){
  const article=el("article","row"),open=button("outcome-open","",()=>loadOutcomeDetail(state,row.outcome_id)),copy=el("span","card-copy"),head=el("span","card-head");
  const title=outcomeTitle(row);open.setAttribute("aria-label","查看成果 "+title);open.append(el("span","outcome-icon",ICON[row.kind]??"◇"));head.append(el("strong","",title),el("span",row.severity?"tag severity":"tag",row.severity??LABEL[row.kind]??"成果"));
  copy.append(head,el("span","meta",text(row.summary,text(row.source_label))),el("span","meta",(LABEL[row.kind]??"成果")+" · "+time(row.updated_at)));open.append(copy);article.append(open);if(state.context.canAdd)appendReferenceAction(state,article,row);return article;
}
function renderOutcomeList(state){
  const filtered=state.kind!=="all"||state.query.trim();renderFilters(state);const list=el("div","list"),rows=state.list;
  if(!rows.length)list.append(el("div","empty",filtered?"没有匹配的项目成果":"暂无项目成果"));for(const row of rows)list.append(renderOutcomeRow(state,row));replaceContent(state,list);
}
function renderPreview(detail){
  const preview=detail.preview;if(!preview||preview.kind==="unavailable")return preview?el("p","muted",text(preview.reason)):null;
  if(preview.kind==="image"&&/^image\/[a-z0-9.+-]+$/i.test(preview.mime_type)){const image=document.createElement("img");image.className="preview";image.alt=outcomeTitle(detail);image.src="data:"+preview.mime_type+";base64,"+preview.data_base64;return image}
  return preview.kind==="text"?el("pre","code",preview.text):null;
}
function appendDetailField(dl,label,value){if(value===null||value===undefined||value==="")return;const object=typeof value==="object",rendered=object?JSON.stringify(value,null,2):String(value);dl.append(el("dt","",label),el("dd",object?"code":"",rendered))}
function appendDetailFields(panel,detail){
  const facts=[["成果 ID",detail.outcome_id],["来源",detail.source_label],["更新时间",time(detail.updated_at)],["内容类型",detail.content_type],["大小",detail.size_bytes==null?null:String(detail.size_bytes)+" B"]];
  const fields=Object.entries(safe(detail.details)??{}).filter(([key,value])=>key!=="storage_path"&&value!==null&&value!==""&&value!==undefined).map(([key,value])=>[FIELD[key]??key,value]),section=el("section","details"),dl=el("dl");
  for(const[label,value]of[...facts,...fields])appendDetailField(dl,label,value);section.append(dl);panel.append(section);
}
function appendBackAction(panel,back,detail){
  const action=button("back","‹",back),title=el("span","detail-title");action.setAttribute("aria-label","返回项目成果");title.append(el("small","",detail.kind==="evidence"?"证据详情":"成果详情"),el("strong","",outcomeTitle(detail)));action.append(title);panel.append(action);
}
function appendDetailActions(state,panel,detail,options){
  if(!options.referenceable||!state.context.canAdd){if(options.sourceable&&outcomeSource(state.context,detail))appendSourceAction(state,panel,detail);return}
  const actions=el("div","actions");actions.append(button("action primary","添加到对话",()=>addReference(state,"outcome",detail.outcome_id)));if(options.sourceable&&outcomeSource(state.context,detail))actions.append(button("action","打开来源",()=>openSource(state,detail)));panel.append(actions);
}
function appendSourceAction(state,panel,detail){const actions=el("div","actions");actions.append(button("action","打开来源",()=>openSource(state,detail)));panel.append(actions)}
function appendBadges(panel,detail){const badges=el("div","actions");badges.append(el("span","tag",LABEL[detail.kind]??"成果"));if(detail.severity)badges.append(el("span","tag severity",detail.severity));if(detail.status)badges.append(el("span","tag",detail.status));panel.append(badges)}
function appendRawDetail(panel,details){const raw=el("details","raw");raw.append(el("summary","","查看结构化数据"),el("pre","code",JSON.stringify(safe(details)??{},null,2)));panel.append(raw)}
function renderOutcomeDetail(state,detail,options){
  const panel=el("article","detail");if(options.back)appendBackAction(panel,options.back,detail);appendDetailActions(state,panel,detail,options);appendBadges(panel,detail);if(detail.summary)panel.append(el("p","summary",detail.summary));
  const preview=renderPreview(detail);if(preview)panel.append(preview);appendDetailFields(panel,detail);appendRawDetail(panel,detail.details);replaceContent(state,panel);
}

function request(state,options){
  const revision=++state.revision;if(!options.preserveNotice)setNotice(state,options.notice??"");replaceContent(state,el("div","loading",options.loading));
  console.info("project-outcomes.request.started",{method:options.method});
  void state.invoke(options).then((value)=>{console.info("project-outcomes.request.completed",{method:options.method,count:items(value).length});if(revision===state.revision)options.success(value)}).catch((error)=>{console.error("project-outcomes.request.failed",{method:options.method,message:failure(error)});if(revision===state.revision)options.failure(error)});
}
function showFailure(state,message){if(!hasActionNotice(state))setNotice(state,message,true);replaceContent(state,el("div","empty",message))}
function cancelOutcomeSearch(state){if(state.searchTimer!==undefined){clearTimeout(state.searchTimer);state.searchTimer=undefined}}
function scheduleOutcomeSearch(state){cancelOutcomeSearch(state);state.revision+=1;state.searchTimer=setTimeout(()=>{state.searchTimer=undefined;loadOutcomes(state)},SEARCH_DEBOUNCE_MS)}
function loadOutcomes(state){
  cancelOutcomeSearch(state);
  const listRevision=++state.listRequestRevision,canOwnNotice=state.pendingReferences.size===0;if(canOwnNotice)state.noticeOwner={kind:"list",revision:listRevision};
  request(state,{method:"xsec.outcomes.list",params:{assignmentOnly:state.scope==="assignment",kinds:state.kind==="all"?undefined:[state.kind],query:state.query.trim()||undefined,limit:OUTCOME_LIMIT},loading:"正在读取项目成果…",notice:canOwnNotice?"正在读取项目成果…":undefined,preserveNotice:!canOwnNotice,success:(page)=>{state.list=items(page);if(ownsNotice(state,"list",listRevision))setNotice(state,"已加载 "+state.list.length+" 项真实成果");renderOutcomeList(state)},failure:(error)=>{if(ownsNotice(state,"list",listRevision))showFailure(state,"读取项目成果失败："+failure(error));else replaceContent(state,el("div","empty","读取项目成果失败："+failure(error)))}});
}
function syncScopeButtons(state){
  if(!state.nodes.scope)return;for(const[index,value]of["project","assignment"].entries()){const item=state.nodes.scope.children[index];if(item)item.setAttribute("aria-pressed",String(state.scope===value))}
}
function syncFilterButtons(state){
  if(!state.nodes.filterButtons)return;for(const[kind,item]of state.nodes.filterButtons){const active=state.kind===kind;item.classList.toggle("is-active",active);item.setAttribute("aria-pressed",String(active));item.querySelector("span")?.remove()}
}
function showOutcomeList(state){const navigate=state.panel!=="list";state.panel="list";if(navigate)build(state);else{syncScopeButtons(state);syncFilterButtons(state)}loadOutcomes(state)}
function loadOutcomeDetail(state,outcomeId){
  cancelOutcomeSearch(state);state.panel="detail";build(state);request(state,{method:"xsec.outcomes.get",params:{outcomeId},loading:"正在读取成果详情…",notice:"正在读取成果详情…",success:(detail)=>{if(!hasActionNotice(state))setNotice(state,"");renderOutcomeDetail(state,detail,{back:()=>showOutcomeList(state),referenceable:true,sourceable:true})},failure:(error)=>showFailure(state,"读取成果详情失败："+failure(error))});
}
function loadBoundDetail(state){
  request(state,{method:"xsec.outcomes.resolve",params:{},loading:"正在读取详情…",success:(detail)=>renderOutcomeDetail(state,detail,{referenceable:false,sourceable:false}),failure:(error)=>showFailure(state,"读取详情失败："+failure(error))});
}
function renderEvidenceRow(row){const article=el("article","panel-static-row"),copy=el("span","");copy.append(el("strong","",text(row.title)),el("small","",text(row.summary)));article.append(copy,el("span","tag",text(row.source_label)));return article}
function renderEvidenceList(state,evidence){const list=el("div","list");if(!evidence.length)list.append(el("div","empty","暂无可用证据"));for(const row of evidence)list.append(renderEvidenceRow(row));replaceContent(state,list)}
function loadEvidenceList(state){request(state,{method:"xsec.outcomes.evidence.list",params:{},loading:"正在读取证据…",success:(page)=>renderEvidenceList(state,items(page)),failure:(error)=>showFailure(state,"读取证据失败："+failure(error))})}
function renderTaskCall(state,call){
  const panel=el("article","detail"),badges=el("div","actions"),section=el("section","details"),dl=el("dl");panel.append(el("h2","",text(call.title??call.kind,"工具调用")));badges.append(el("span","tag",text(call.status)),el("span","tag",text(call.kind)));panel.append(badges);
  for(const[label,value]of[["ID",call.tool_call_id],["输入",call.raw_input],["输出",call.raw_output??call.content]])appendDetailField(dl,label,safe(value));section.append(dl);panel.append(section);replaceContent(state,panel);
}
function renderTaskDetail(state,task){
  const panel=el("article","detail"),badges=el("div","actions"),section=el("section","details"),dl=el("dl");panel.append(el("h2","","任务 "+text(task.id).slice(TASK_ID_DISPLAY_START,TASK_ID_DISPLAY_LENGTH)));badges.append(el("span","tag",text(task.status)));panel.append(badges);
  for(const[label,value]of[["进度",taskProgress(task.progress)],["摘要",task.summary],["绑定 run",task.run_id]])appendDetailField(dl,label,value);section.append(dl);panel.append(section);replaceContent(state,panel);
}
function loadTaskDetail(state){request(state,{method:"xsec.outcomes.task.get",params:{},loading:"正在读取任务详情…",success:(task)=>renderTaskDetail(state,task),failure:(error)=>showFailure(state,"读取任务详情失败："+failure(error))})}
function refreshView(state){
  if(isOutcomesTool(state))return showOutcomeList(state);if(state.context.toolCall)return renderTaskCall(state,state.context.toolCall);if(state.context.tool==="task-detail"&&state.context.entityId)return loadTaskDetail(state);if(state.context.entityId)return loadBoundDetail(state);if(state.context.tool==="evidence-detail")return loadEvidenceList(state);replaceContent(state,el("div","empty",state.context.tool==="task-detail"?"选中工具调用或任务事件后，会在此展示输入、输出与执行状态。":"请选择成果后查看详情。"));
}

function appendCollectionAction(state,actions){const collection=button("icon-btn","@",()=>addReference(state,"collection"));collection.setAttribute("aria-label","添加项目成果集合到对话");actions.append(collection)}
function appendHeader(state,app){
  const heading=el("header","heading"),copy=el("span",""),actions=el("div","actions");copy.append(el("h1","",TITLE[state.context.tool]??"项目成果"),el("small","","项目内共享 · 跨对话复用"));if(isOutcomesTool(state)&&state.context.canAdd)appendCollectionAction(state,actions);
  const refreshButton=button("icon-btn","↻",()=>refreshView(state));refreshButton.setAttribute("aria-label","刷新项目成果");actions.append(refreshButton);heading.append(copy,actions);app.append(heading);
}
function appendControls(state,app){
  const controls=el("section","controls"),scope=el("div","scope");state.nodes.scope=scope;renderScope(state);
  const search=document.createElement("input");search.className="search";search.placeholder="搜索成果标题、摘要或来源";search.value=state.query;search.addEventListener("input",()=>{state.query=search.value;scheduleOutcomeSearch(state)});state.nodes.filters=el("div","");controls.append(scope,search,state.nodes.filters);app.append(controls);
}
function build(state){state.viewRevision+=1;state.navigationRevision+=1;state.pendingReferences.clear();state.noticeOwner=undefined;state.root.replaceChildren(el("style","",CSS));const app=el("main","app");appendHeader(state,app);state.nodes.notice=el("p","notice");state.nodes.content=el("section","");state.nodes.filters=undefined;state.nodes.filterButtons=undefined;state.nodes.scope=undefined;if(isOutcomesTool(state)&&state.panel==="list")appendControls(state,app);app.append(state.nodes.notice,state.nodes.content);state.root.append(app)}
function update(state,context){cancelOutcomeSearch(state);state.revision+=1;state.context=contextInfo(context);state.panel="list";if(state.scope==="assignment"&&!state.context.assignmentId)state.scope="project";build(state);if(isOutcomesTool(state))loadOutcomes(state);else refreshView(state)}
function createController(host){
  const state={invoke:(options)=>invoke(host,options),root:null,list:[],query:"",kind:"all",scope:"project",panel:"list",revision:0,viewRevision:0,navigationRevision:0,referenceRevision:0,listRequestRevision:0,pendingReferences:new Set(),noticeOwner:undefined,searchTimer:undefined,nodes:{},context:contextInfo(host.context)};
  return{mount(root){console.info("project-outcomes.mount",{tool:state.context.tool});state.root=root;update(state,host.context)},update(context){update(state,context)},dispose(){console.debug("project-outcomes.dispose",{tool:state.context.tool});cancelOutcomeSearch(state);state.viewRevision+=1;state.navigationRevision+=1;state.pendingReferences.clear();state.noticeOwner=undefined;state.revision+=1;state.root?.replaceChildren()}};
}
export function activate(host){console.debug("project-outcomes.activate",{apiVersion:host.apiVersion});return createController(host)}
