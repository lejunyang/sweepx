import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

// Exercise the shipped event handlers and Native Messaging adapter without a real
// browser or browsingData deletion. The DOM fixture only implements this page's
// ordinary element operations; responses come from a separately controlled port.
class Element {
  constructor(tag='div') {this.tag=tag;this.value='';this.checked=false;this.children=[];this.handlers=new Map();}
  addEventListener(event,handler) {this.handlers.set(event,handler);}
  async dispatch(event) {await this.handlers.get(event)?.();}
  append(...children) {this.children.push(...children);}
  replaceChildren(...children) {this.children=children;}
  querySelectorAll(tag) {return this.children.flatMap(child=>[...(child.tag===tag?[child]:[]),...child.querySelectorAll(tag)]);}
  scrollIntoView() {}
}
let generation=0;
const plan={schema:'sweepx.browser_cleanup.plan/v1',operation:'browser_managed_origin_removal',browser:'edge',profile:'Default',domain:'example.test',origins:['https://example.test'],recoverable:false,profileBinding:'explicit_user_confirmation_in_browser'};
function pending() {return {schema:'sweepx.browser_bridge.request/v1',requestId:'fixture-request',expiresAt:Math.floor(Date.now()/1000)+900,plan};}

async function page(run,{queued=null,pendingError=null}={}) {
  const names=['document','window','chrome','setInterval'];
  const originals=names.map(name=>Object.getOwnPropertyDescriptor(globalThis,name));
  const html=readFileSync(new URL('./review.html',import.meta.url),'utf8');
  const elements=new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(match=>[match[1],new Element()]));
  const element=id=>{assert.ok(elements.has(id),`Missing shipped element: ${id}`);return elements.get(id);};
  element('browser').value='edge';element('native-profile').value='Default';
  const sent=[],events=new Map(),disconnectEvents=[];let interval,removals=0;
  const runtime={connectNative(){let receive,disconnected;return {
    onMessage:{addListener(handler){receive=handler;}},
    onDisconnect:{addListener(handler){disconnected=handler;disconnectEvents.push(handler);}},
    disconnect(){disconnected();},
    postMessage(message){
      sent.push(message);
      const reply=value=>queueMicrotask(()=>receive({id:message.id,...value}));
      if(message.op==='hello')reply({kind:'hello',protocol:1,hostVersion:'fixture'});
      else if(message.op==='pending')reply(pendingError?{kind:'error',error:pendingError}:{kind:'pending',request:queued});
      else if(message.op==='plan')reply({kind:'plan',plan});
      else if(message.op==='scan'){
        reply({kind:'start',report:{status:'ok',issues:[]}});
        reply({kind:'rows',collection:'domains',rows:[{domain:'example.test',bytes:'7',sizeComplete:true,storageItemCount:1}]});
        reply({kind:'rows',collection:'origins',rows:[{domain:'example.test',storageKey:'https://example.test/',bytes:'7',complete:true,subsystem:'indexed_db'}]});
        reply({kind:'done'});
      }else throw new Error(`Unexpected native operation: ${message.op}`);
    }
  };}};
  globalThis.document={hidden:false,getElementById:element,createElement:tag=>new Element(tag)};
  globalThis.window={addEventListener(event,handler){events.set(event,handler);}};
  globalThis.chrome={runtime,browsingData:{async remove(){removals++;}}};
  globalThis.setInterval=handler=>{interval=handler;};
  try {
    await import(`./review.mjs?fixture=${++generation}`);
    await run({element,sent,interval:()=>interval(),disconnectEvents,setQueued:value=>{queued=value;},setPendingError:value=>{pendingError=value;}});
    assert.equal(removals,0,'Checking requests must never call browsingData.remove');
  } finally {
    events.get('beforeunload')?.();
    names.forEach((name,i)=>{if(originals[i])Object.defineProperty(globalThis,name,originals[i]);else delete globalThis[name];});
  }
}

test('connect checks a queued request and reconnect displays the same unhandled request',{timeout:5000},async()=>{
  await page(async({element,sent})=>{
    await element('connect').dispatch('click');
    assert.match(element('preview').textContent,/Pending SweepX request/);
    assert.equal(element('reject').hidden,false);
    await element('connect').dispatch('click');
    assert.match(element('preview').textContent,/Pending SweepX request/);
    assert.equal(sent.filter(message=>message.op==='pending').length,2);
    assert.equal(element('remove').disabled,true);
  },{queued:pending()});
});

test('delayed old-port disconnect cannot replace the new connection status',{timeout:5000},async()=>{
  await page(async({element,disconnectEvents})=>{
    await element('connect').dispatch('click');
    await element('connect').dispatch('click');
    disconnectEvents[0]();
    assert.match(element('connection').textContent,/Connected/);
    assert.match(element('request-status').textContent,/No active pending request/);
    assert.equal(element('scan').disabled,false);
  });
});

test('manual request check works during domain review while automatic checks preserve it',{timeout:5000},async()=>{
  await page(async({element,sent,interval,setQueued})=>{
    await element('connect').dispatch('click');
    await element('scan').dispatch('click');
    await element('domains').querySelectorAll('button')[0].dispatch('click');
    setQueued(pending());
    const before=sent.length;interval();
    assert.equal(sent.length,before,'Automatic poll must not replace a reviewed domain');
    await element('poll').dispatch('click');
    assert.equal(sent.at(-1).op,'pending');
    assert.match(element('preview').textContent,/Pending SweepX request/);
    assert.equal(element('profile').checked,false);
    assert.equal(element('mode').value,'');
    assert.equal(element('confirm').value,'');
    assert.equal(element('remove').disabled,true);
  });
});

test('request errors are visible and empty results identify the queried profile',{timeout:5000},async()=>{
  await page(async({element,setPendingError})=>{
    await element('connect').dispatch('click');
    assert.match(element('request-status').textContent,/Could not check requests: fixture_permission_denied/);
    assert.match(element('connection').textContent,/Connected/);
    setPendingError(null);
    await element('poll').dispatch('click');
    assert.match(element('request-status').textContent,/edge \/ Default/);
    assert.match(element('request-status').textContent,/No active pending request/);
    assert.equal(element('reject').hidden,true);
  },{pendingError:'fixture_permission_denied'});
});

test('empty manual check preserves the selected domain and a different profile request is ignored',{timeout:5000},async()=>{
  await page(async({element,setQueued})=>{
    await element('connect').dispatch('click');
    await element('scan').dispatch('click');
    await element('domains').querySelectorAll('button')[0].dispatch('click');
    const preview=element('preview').textContent;
    await element('poll').dispatch('click');
    assert.equal(element('preview').textContent,preview);
    setQueued({...pending(),plan:{...plan,profile:'Profile 1'}});
    await element('poll').dispatch('click');
    assert.equal(element('preview').textContent,preview);
    assert.equal(element('reject').hidden,true);
  });
});
