import {validatePlan,removalRequest,removeWithBrowser} from './logic.mjs';
import {Bridge,matchingRequest,formatBytes} from './bridge.mjs';
const byId=id=>document.getElementById(id);
let plan=null,busy=false,removing=false,generation=0,bridge=null,pendingRequest=null,seenRequest=null,polling=false,inventory=null,page=0;
const status=text=>byId('status').textContent=text;
const requestStatus=text=>byId('request-status').textContent=text;
const selection=()=>({browser:byId('browser').value,profile:byId('native-profile').value});
const controls=['file','mode','confirm','profile','browser','native-profile','connect','scan','poll','reject','domain-filter'];
function request(){return removalRequest(plan,byId('mode').value,byId('confirm').value,byId('profile').checked);}
function update(){
  try{request();byId('remove').disabled=busy || !plan;}catch{byId('remove').disabled=true;}
  for(const id of controls)byId(id).disabled=busy;
  for(const id of ['scan','poll'])byId(id).disabled=busy || !bridge || bridge.closed;
  byId('reject').hidden=!pendingRequest;
  byId('disconnect').disabled=!bridge || bridge.closed || removing;
  byId('page-prev').disabled=busy || page===0;
  byId('page-next').disabled=busy || !inventory || (page+1)*100>=filteredDomains().length;
  for(const button of byId('domains').querySelectorAll('button'))button.disabled=busy || !bridge || bridge.closed;
}
function clearPlan(){plan=null;pendingRequest=null;byId('profile').checked=false;byId('confirm').value='';byId('mode').value='';byId('preview').textContent='尚未选择域名 / No domain selected';update();}
function showPlan(value,queued=null){
  plan=validatePlan(value);pendingRequest=queued;
  byId('profile').checked=false;byId('confirm').value='';byId('mode').value='';
  byId('preview').textContent=`${queued?'SweepX 待确认请求 / Pending SweepX request\n':''}${plan.browser} / ${plan.profile}\n${plan.domain}\n\n${plan.origins.join('\n')}\n\n当前个人资料由你确认。此操作覆盖选中 origins 的分区，不能按 bucket 删除。\nConfirm the active profile. Sizes do not prove reclaimable space.`;
  byId('preview').scrollIntoView({block:'nearest'});update();
}
async function perform(action){if(busy)return;busy=true;update();try{await action();}catch(e){status(`未确认完成 / Completion not confirmed: ${e.message}`);}finally{busy=false;update();}}
function renderInventory(data){
  inventory=data;page=0;renderDomains();
  byId('inventory-status').textContent=`${data.report.status==='ok'?'已完成 / Complete':'部分结果 / Partial'} · 逻辑大小 / Logical bytes · ${new Date().toLocaleTimeString()}\n${(data.report.issues || []).join('\n')}`;
  const categories=byId('categories');categories.replaceChildren();
  for(const row of data.categories){const tr=document.createElement('tr');for(const text of [`${row.profileName} / ${row.subsystem}`,formatBytes(row.subsystemBytes,row.sizeComplete),formatBytes(row.unattributedBytes,row.sizeComplete),(row.issues || []).join('; ')]){const td=document.createElement('td');td.textContent=text;tr.append(td);}categories.append(tr);}
}
function filteredDomains(){const text=byId('domain-filter').value.trim().toLowerCase();return inventory?.domains.filter(row=>row.domain.toLowerCase().includes(text)) || [];}
byId('domain-filter').addEventListener('input',()=>{page=0;renderDomains();});
function renderDomains(){
  const data=inventory;if(!data)return;const rows=filteredDomains();
  byId('page-label').textContent=`${rows.length? page+1:0} / ${Math.ceil(rows.length/100)} · ${rows.length} 个域名 / domains`;
  const domains=byId('domains');domains.replaceChildren();
  for(const row of rows.slice(page*100,(page+1)*100)){
    const tr=document.createElement('tr');
    for(const text of [row.domain,formatBytes(row.bytes,row.sizeComplete),String(row.storageItemCount)]){const td=document.createElement('td');td.textContent=text;tr.append(td);}
    const td=document.createElement('td'),button=document.createElement('button');button.textContent='详情与清理 / Review';
    button.addEventListener('click',()=>perform(async()=>{
      clearPlan();const {browser,profile}=selection();
      const details=data.origins.filter(r=>r.domain===row.domain);
      byId('details').textContent=details.map(r=>`${r.subsystem} · ${formatBytes(r.bytes,r.complete)}\n${r.storageKey}${r.bucketId!=null?`\nbucket ${r.bucketId} (${r.bucketName || '?'})`:''}`).join('\n\n');
      const response=await bridge.request('plan',{browser,profile,domain:row.domain});showPlan(response.plan);status('请核对明细和清理范围 / Review details and removal scope');
    }));td.append(button);tr.append(td);domains.append(tr);
  }
  update();
}
byId('page-prev').addEventListener('click',()=>{if(!busy && page>0){page--;renderDomains();}});
byId('page-next').addEventListener('click',()=>{if(!busy && inventory && (page+1)*100<filteredDomains().length){page++;renderDomains();}});
byId('disconnect').addEventListener('click',()=>{bridge?.close();byId('connection').textContent='已断开 / Disconnected';status('已请求取消，原生阻塞调用可能延迟结束 / Cancellation requested; a blocking native call may delay completion');update();});

async function poll(manual=false){
  if(!bridge || bridge.closed || busy || polling)return;
  if(pendingRequest){if(manual)byId('preview').scrollIntoView({block:'nearest'});return;}
  // Automatic checks must not replace a domain under review. An explicit check may
  // show a queued request, but still resets every removal confirmation in showPlan.
  if(plan && !manual)return;
  const currentBridge=bridge,{browser,profile}=selection();polling=true;
  const current=()=>bridge===currentBridge && !currentBridge.closed && selection().browser===browser && selection().profile===profile;
  try{
    const response=await currentBridge.request('pending',{browser,profile});
    if(!current())return;
    if(matchingRequest(response.request,browser,profile)){
      if(manual || response.request.requestId!==seenRequest){seenRequest=response.request.requestId;showPlan(response.request.plan,response.request);requestStatus('收到 SweepX 待确认请求 / Pending SweepX request received');status('收到 SweepX 请求，请确认后处理 / SweepX request received; review before applying');}
    }else requestStatus(`${browser} / ${profile}：暂无有效待确认请求 / No active pending request`);
  }catch(e){
    if(bridge===currentBridge && selection().browser===browser && selection().profile===profile)requestStatus(`读取待确认请求失败 / Could not check requests: ${e.message}`);
  }finally{polling=false;}
}
byId('connect').addEventListener('click',async()=>{await perform(async()=>{
  const previous=bridge;bridge=null;previous?.close();seenRequest=null;clearPlan();requestStatus('正在连接并检查请求 / Connecting and checking requests');
  // A delayed disconnect from the previous port must not overwrite the new connection.
  const connected=new Bridge(chrome.runtime,reason=>{if(bridge!==connected)return;byId('connection').textContent=`未连接 / Disconnected: ${reason}`;requestStatus(`连接已断开，无法检查请求 / Cannot check requests while disconnected: ${reason}`);update();});bridge=connected;
  const hello=await bridge.request('hello');if(hello.protocol!==1)throw new Error('Unsupported bridge version');
  byId('connection').textContent=`已连接 / Connected · SweepX ${hello.hostVersion}`;status('连接成功。选择当前浏览器和个人资料，再扫描。 / Select the active browser and profile, then scan.');
});await poll();});
byId('scan').addEventListener('click',()=>perform(async()=>{
  clearPlan();byId('details').textContent='';status('正在扫描，请保持此页打开… / Scanning; keep this page open…');
  const data=await bridge.request('scan',selection());renderInventory(data);status('扫描完成；无法归属域名的占用见分类表 / Scan complete; shared and unattributed bytes are in the categories table');
}));
byId('poll').addEventListener('click',()=>poll(true));
for(const id of ['browser','native-profile'])byId(id).addEventListener('change',()=>{generation++;seenRequest=null;inventory=null;page=0;clearPlan();byId('page-label').textContent='0 / 0';byId('domains').replaceChildren();byId('categories').replaceChildren();byId('details').textContent='';byId('inventory-status').textContent='个人资料已改变，请重新扫描 / Profile changed; rescan';});
byId('file').addEventListener('change',async()=>{
  const current=++generation;clearPlan();status('');
  try{const file=byId('file').files[0];if(!file || file.size>65536)throw new Error('计划文件缺失或超过 64 KiB / Plan exceeds 64 KiB');const value=JSON.parse(await file.text());if(current===generation)showPlan(value);}
  catch(e){if(current===generation)status(e.message);}
});
for(const id of ['mode','confirm','profile'])byId(id).addEventListener('input',update);
byId('reject').addEventListener('click',()=>perform(async()=>{const queued=pendingRequest;if(!queued)return;await bridge.request('complete',{request_id:queued.requestId,status:'rejected',mode:null});clearPlan();status('已拒绝，未清除 / Rejected; nothing removed');}));
byId('remove').addEventListener('click',()=>perform(async()=>{
  const removal=request(),queued=pendingRequest,mode=byId('mode').value;removing=true;update();status('浏览器正在清除，请保持此页打开… / Removing; keep this page open…');
  try{await removeWithBrowser(chrome.browsingData,removal);}catch(e){if(queued && bridge && !bridge.closed){try{await bridge.request('complete',{request_id:queued.requestId,status:'failed',mode});}catch{}}clearPlan();throw e;}finally{removing=false;update();}
  let delivery='';if(queued){try{await bridge.request('complete',{request_id:queued.requestId,status:'browser_completed',mode});delivery=' 已回传 SweepX / Reported to SweepX.';}catch(e){delivery=` 回传失败 / Report failed: ${e.message}`;}}
  clearPlan();status(`浏览器已完成请求。请重新扫描验证占用；网站可能重新创建数据。 / Browser request completed; rescan to verify.${delivery}`);
}));
// Poll only while the review tab is visible and idle. No background automatic deletion.
setInterval(()=>{if(!document.hidden)void poll();},5000);
window.addEventListener('beforeunload',()=>bridge?.close());update();
