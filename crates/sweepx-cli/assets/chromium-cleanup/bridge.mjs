// Chrome owns the process and pipes. There is no network endpoint or detached daemon.
export const HOST='org.sweepx.browser_bridge';
export class Bridge {
  constructor(runtime, onDisconnect=()=>{}) {
    this.pending=new Map();this.next=0;this.closed=false;
    this.port=runtime.connectNative(HOST);
    this.port.onMessage.addListener(message=>this.receive(message));
    this.port.onDisconnect.addListener(()=>{const reason=runtime.lastError?.message || 'SweepX connection closed';this.fail(reason);onDisconnect(reason);});
  }
  fail(reason) {this.closed=true;for(const entry of this.pending.values()){clearTimeout(entry.timer);entry.reject(new Error(reason));}this.pending.clear();}
  close() {this.fail('SweepX connection closed');this.port.disconnect();}
  settle(id) {const entry=this.pending.get(id);if(entry)clearTimeout(entry.timer);this.pending.delete(id);}
  receive(message) {
    if(message?.kind==='fatal'){this.fail(message.error || 'SweepX protocol error');this.port.disconnect();return;}
    const entry=this.pending.get(message?.id);if(!entry)return;
    try {
      if(message.kind==='error'){this.settle(message.id);entry.reject(new Error(message.error));return;}
      if(entry.inventory) {
        if(message.kind==='start') {if(entry.started)throw new Error('Duplicate inventory start');entry.started=true;entry.result.report=message.report;}
        else if(message.kind==='rows') {
          if(!entry.started || !['domains','categories','origins'].includes(message.collection) || !Array.isArray(message.rows) || message.rows.length>20)throw new Error('Invalid inventory page');
          entry.bytes+=JSON.stringify(message.rows).length*2;entry.count+=message.rows.length;
          if(entry.bytes>32*1024*1024 || entry.count>20000)throw new Error('Inventory resource limit');
          entry.result[message.collection].push(...message.rows);
        } else if(message.kind==='done' && entry.started) {this.settle(message.id);entry.resolve(entry.result);}
        else throw new Error('Incomplete inventory protocol');
      } else {this.settle(message.id);entry.resolve(message);}
    } catch(e) {this.settle(message.id);entry.reject(e);this.close();}
  }
  request(op,args={}) {
    if(this.closed)return Promise.reject(new Error('SweepX is not connected'));
    if(this.pending.size>=4)return Promise.reject(new Error('Too many pending requests'));
    const id=`r${++this.next}`;
    return new Promise((resolve,reject)=>{
      const entry={resolve,reject,inventory:op==='scan',started:false,count:0,bytes:0,result:{report:null,domains:[],categories:[],origins:[]}};
      // Disconnect cancels cooperative native scanning; unfinished rows stay staged.
      entry.timer=setTimeout(()=>{this.settle(id);reject(new Error('SweepX request timed out'));this.close();},op==='scan'?150000:15000);
      this.pending.set(id,entry);try{this.port.postMessage({op,id,...args});}catch(e){this.settle(id);reject(e);}
    });
  }
}
export function matchingRequest(request,browser,profile,at=Date.now()/1000) {
  return request?.schema==='sweepx.browser_bridge.request/v1' && typeof request.requestId==='string' && request.requestId.length<=64 && Number.isSafeInteger(request.expiresAt) && request.expiresAt>at && request.plan?.browser===browser && request.plan?.profile===profile;
}
export function formatBytes(value,complete=true) {
  if(typeof value!=='string' || !/^\d+$/.test(value))return '?';
  const bytes=BigInt(value),units=['B','KiB','MiB','GiB','TiB'];let divisor=1n,i=0;
  while(i<4 && bytes>=divisor*1024n){divisor*=1024n;i++;}
  const amount=i===0?`${bytes}`:`${bytes/divisor}.${(bytes%divisor)*10n/divisor}`;
  return `${complete?'':'≥ '}${amount} ${units[i]}`;
}
