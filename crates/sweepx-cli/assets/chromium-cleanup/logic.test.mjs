import {test} from 'node:test';
import assert from 'node:assert/strict';
import {validatePlan,removalRequest,removeWithBrowser} from './logic.mjs';
const plan={schema:'sweepx.browser_cleanup.plan/v1',operation:'browser_managed_origin_removal',browser:'edge',profile:'Default',domain:'example.com',origins:['https://example.com','https://example.com:8443']};
test('exact origins preserve ports and require explicit scope and profile confirmation',()=>{
  const selected=validatePlan(plan);
  assert.deepEqual(selected.origins,plan.origins);
  for(const args of [['cache','wrong.example',true],['','example.com',true],['storage','example.com',false]])assert.throws(()=>removalRequest(selected,...args));
  const r=removalRequest(selected,'storage','example.com',true);
  assert.deepEqual(r.options,{since:0,origins:plan.origins,originTypes:{unprotectedWeb:true,protectedWeb:false,extension:false}});
  assert.deepEqual(r.types,{cache:true,cacheStorage:true,indexedDB:true,localStorage:true,serviceWorkers:true,fileSystems:true});
  assert.deepEqual(removalRequest(selected,'cache','example.com',true).types,{cache:true,cacheStorage:true});
});
test('foreign domains paths schemes credentials and empty wildcard selections are rejected',()=>{
  for(const origins of [[],['https://sub.example.com'],['https://example.com/'],['file:///example.com'],['https://user:pass@example.com'],['https://example.com/path']])assert.throws(()=>validatePlan({...plan,origins}));
  assert.throws(()=>validatePlan({...plan,profile:'../../wrong'}));
});
test('real API completion is awaited and failures cannot become success',async()=>{
  let finish,calls=0,completed=false;
  const req=removalRequest(validatePlan(plan),'cache','example.com',true);
  const pending=removeWithBrowser({remove:(options,types)=>{calls++;assert.deepEqual(options,req.options);assert.deepEqual(types,req.types);return new Promise(resolve=>finish=resolve);}},req).then(()=>completed=true);
  await Promise.resolve();assert.equal(completed,false);finish();await pending;assert.equal(calls,1);assert.equal(completed,true);
  await assert.rejects(removeWithBrowser({remove:async()=>{throw new Error('denied');}},req),/denied/);
  await assert.rejects(removeWithBrowser(null,req),/unavailable/);
});
