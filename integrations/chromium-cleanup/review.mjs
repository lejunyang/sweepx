import {validatePlan,removalRequest,removeWithBrowser} from './logic.mjs';
const byId=id=>document.getElementById(id);
let plan=null,busy=false,generation=0;
function request() {return removalRequest(plan,byId('mode').value,byId('confirm').value,byId('profile').checked);}
function update() {
  try { request(); byId('remove').disabled=busy || !plan; }
  catch { byId('remove').disabled=true; }
}
byId('file').addEventListener('change', async () => {
  const current=++generation;plan=null;byId('profile').checked=false;byId('confirm').value='';byId('status').textContent='';update();
  try {
    const file=byId('file').files[0];
    if (!file || file.size>65536) throw new Error('计划文件缺失或超过 64 KiB / Plan exceeds 64 KiB');
    const next=validatePlan(JSON.parse(await file.text()));
    if (current!==generation) return;
    plan=next;
    byId('preview').textContent=`${plan.browser} / ${plan.profile}\n${plan.domain}\n\n${plan.origins.join('\n')}\n\n当前浏览器个人资料由你确认；扫描大小不能证明此次能释放多少空间。\nConfirm the active profile. Scan sizes do not prove reclaimable space.`;
  } catch(e) {if(current===generation)byId('preview').textContent=e.message;}
  update();
});
for(const id of ['mode','confirm','profile'])byId(id).addEventListener('input',update);
byId('remove').addEventListener('click', async () => {
  if(busy)return;
  let removal;
  try {removal=request();} catch(e){byId('status').textContent=e.message;return;}
  busy=true;update();for(const id of ['file','mode','confirm','profile'])byId(id).disabled=true;
  byId('status').textContent='浏览器正在清除，请保持此页打开… / Removing; keep this page open…';
  try {
    await removeWithBrowser(chrome.browsingData,removal);
    byId('status').textContent='浏览器已完成请求。请重新扫描确认占用；网站可能重新创建数据。 / Browser request completed. Rescan to verify.';
  } catch(e) {byId('status').textContent=`未确认完成 / Completion not confirmed: ${e.message}`;}
  finally {busy=false;plan=null;byId('profile').checked=false;byId('confirm').value='';for(const id of ['file','mode','confirm','profile'])byId(id).disabled=false;update();}
});
