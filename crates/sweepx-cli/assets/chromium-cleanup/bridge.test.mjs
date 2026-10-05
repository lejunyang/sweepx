import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {Bridge,matchingRequest,formatBytes} from './bridge.mjs';
function fixture(){
  let message,disconnected;
  const sent=[];
  const runtime={connectNative(name){assert.equal(name,'org.sweepx.browser_bridge');return {
    onMessage:{addListener(fn){message=fn;}},onDisconnect:{addListener(fn){disconnected=fn;}},
    postMessage(value){sent.push(value);},disconnect(){disconnected();}};}};
  const bridge=new Bridge(runtime);
  return {bridge,sent,receive:value=>message(value),disconnect:()=>disconnected()};
}
test('bundled public identity matches the native allowlist and needs no broad URL permission',()=>{
  const manifest=JSON.parse(readFileSync(new URL('./manifest.json',import.meta.url)));
  const hex=createHash('sha256').update(Buffer.from(manifest.key,'base64')).digest('hex').slice(0,32);
  const id=[...hex].map(c=>String.fromCharCode(97+parseInt(c,16))).join('');
  assert.equal(id,'bcidfcdfefinmefhopannchcnicdopad');
  assert.deepEqual(manifest.permissions,['browsingData','nativeMessaging']);
  assert.equal(manifest.host_permissions,undefined);
});
test('paged inventory stays unpublished until completion and rejects partial disconnects',async()=>{
  const f=fixture();let finished=false;
  const pending=f.bridge.request('scan',{browser:'edge',profile:'Default'}).then(r=>{finished=true;return r;});
  const id=f.sent[0].id;
  f.receive({id,kind:'start',report:{status:'partial',issues:['unknown']}});
  f.receive({id,kind:'rows',collection:'domains',rows:[{domain:'example.test',bytes:null}]});
  await Promise.resolve();assert.equal(finished,false);
  f.receive({id,kind:'done'});const result=await pending;
  assert.equal(result.report.status,'partial');assert.equal(result.domains[0].bytes,null);
  const unfinished=f.bridge.request('scan',{browser:'edge',profile:'Default'});
  f.disconnect();await assert.rejects(unfinished,/closed/);
});
test('protocol bounds reject malformed pages while ordinary refusals allow another request',async()=>{
  const f=fixture();const bad=f.bridge.request('scan');
  f.receive({id:f.sent[0].id,kind:'rows',collection:'domains',rows:[]});
  await assert.rejects(bad,/Invalid inventory/);assert.equal(f.bridge.closed,true);
  const next=fixture();const refused=next.bridge.request('plan',{domain:'unknown'});
  next.receive({id:next.sent[0].id,kind:'error',error:'incomplete'});
  await assert.rejects(refused,/incomplete/);assert.equal(next.bridge.closed,false);
  const hello=next.bridge.request('hello');next.receive({id:next.sent[1].id,kind:'hello',protocol:1});
  assert.equal((await hello).protocol,1);next.bridge.close();
});
test('pending requests require exact profile and unexpired binding; no delete is triggered',()=>{
  const request={schema:'sweepx.browser_bridge.request/v1',requestId:'r1',expiresAt:200,plan:{browser:'chrome',profile:'Default'}};
  assert.equal(matchingRequest(request,'chrome','Default',100),true);
  for(const args of [['edge','Default',100],['chrome','Profile 1',100],['chrome','Default',200]])assert.equal(matchingRequest(request,...args),false);
  assert.equal(formatBytes(null),'?');assert.equal(formatBytes('0'),'0 B');
  assert.equal(formatBytes('4269934835',false),'≥ 3.9 GiB');
  assert.equal(formatBytes('18446744073709551616'),'16777216.0 TiB');
});
