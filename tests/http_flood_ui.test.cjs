// Dependency-free renderer/control contract tests; real-browser checks supplement these.
const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const source=fs.readFileSync('backend/static/http_flood.js','utf8');

function harness({failPolling=false, failCommand=false, protocol='http:', authenticated=null}={}) {
  const nodes=new Map(), requests=[], intervals=[], sockets=[], timers=[], windowListeners={};
  class Element {
    constructor(){this.textContent='';this.dataset={};this.children=[];this.listeners={};this.value='';}
    setAttribute(key,value){this[key]=value;}
    replaceChildren(...children){this.children=children;}
    appendChild(child){this.children.push(child);}
    addEventListener(event,fn){this.listeners[event]=fn;}
    click(){return this.listeners.click();}
  }
  const get=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};
  class WebSocket {
    constructor(url){this.url=url;this.readyState=1;this.listeners={};sockets.push(this);}
    addEventListener(key,fn){this.listeners[key]=fn;}
    close(){this.readyState=3;}
  }
  const state={snapshot_at:100,run_id:'test',status:'ready',target:'/lab',target_origin:'http://127.0.0.1:8000',
    source_identity:'lab-flood',config:{rate:25,duration:8,concurrency:4},
    thresholds:{block_rps:12,warning_rps:5,window_seconds:2,block_seconds:10},
    flood:{generated:0,successful:0,blocked:0,failed:0,rejected:0},
    legitimate:{generated:0,successful:0,blocked:0,failed:0,latency_ms:null},
    samples:[],timeline:[],gatv2:{evidence:[],note:'No attributed model evidence'},
    detection_method:'Rule-Based HTTP Flood Detection',elapsed_seconds:0,total_rps:0,accepted_rps:0,blocked_rps:0};
  const context={document:{getElementById:get,createElement:()=>new Element(),createElementNS:()=>new Element()},
    WebSocket,location:{protocol,host:'127.0.0.1:8000'},AbortSignal:{timeout:()=>null},
    window:{addEventListener:(name,fn)=>windowListeners[name]=fn},setTimeout:(fn,delay)=>{const timer={fn,delay};timers.push(timer);return timer;},
    clearTimeout:timer=>{if(timer)timer.cancelled=true;},setInterval:fn=>intervals.push(fn),clearInterval(){},
    fetch:async(url,options={})=>{
      requests.push({url,options});
      if(options.method==='POST')return {ok:!failCommand,json:async()=>failCommand?{detail:'Local administrator authorization required.'}:state};
      if(failPolling)throw new Error('offline');
      return {ok:true,json:async()=>state};
    }};
  get('hf-rate').value='25'; get('hf-duration').value='8'; get('hf-concurrency').value='4';get('hf-token').value='test-token';
  if(authenticated!==null)context.window.SentinelAuth={canView:authenticated,authenticated,local:false,
    ready:Promise.resolve(),fetch:context.fetch};
  vm.runInNewContext(source,context);
  const tick=()=>new Promise(resolve=>setImmediate(resolve));
  const telemetry=patch=>sockets[0].listeners.message({data:JSON.stringify({type:'HTTP_FLOOD_TELEMETRY',...state,...patch})});
  return {get,requests,state,telemetry,tick,sockets,timers,windowListeners,context};
}

test('WebSocket telemetry renders actual graph values, alerts and availability failures',async()=>{
  const h=harness();await h.tick();
  h.telemetry({snapshot_at:101,status:'mitigation_active',detected:true,blocked:true,detection_rps:12,
    detected_at:100,block_remaining_seconds:9,started_at:100,running:true,total_rps:26,accepted_rps:1,blocked_rps:25,
    flood:{generated:50,successful:23,blocked:27,rejected:27,failed:0},
    legitimate:{generated:3,successful:2,blocked:0,failed:1,latency_ms:8},
    samples:[{timestamp:100,total_rps:26,accepted_rps:1,blocked_rps:25}]});
  assert.equal(h.get('hf-generated').textContent,'50');
  assert.equal(h.get('hf-blocked').textContent,'27');
  assert.equal(h.get('hf-chart').dataset.total,'26');
  assert.equal(h.get('hf-chart').dataset.accepted,'1');
  assert.equal(h.get('hf-chart').dataset.blocked,'25');
  assert.equal(h.get('hf-detection').hidden,false);
  assert.equal(h.get('hf-mitigation-title').textContent,'THREAT MITIGATED — SOURCE BLOCKED');
  assert.match(h.get('hf-health').textContent,/Availability issue/);
  assert.match(h.get('hf-health').textContent,/success rate 66.7%/);
  assert.equal(h.get('hf-start').disabled,true);
  assert.equal(h.get('hf-stop').disabled,false);
});

test('Start, Stop and Reset call protected APIs with actual configuration',async()=>{
  const h=harness();await h.tick();
  h.get('hf-start').click();await h.tick();
  const request=h.requests.find(r=>r.url.endsWith('/start'));
  assert.deepEqual(JSON.parse(request.options.body),{rate:25,duration:8,concurrency:4});
  assert.equal(request.options.headers['X-Admin-Token'],'test-token');
  h.get('hf-stop').click();await h.tick();
  h.get('hf-reset').click();await h.tick();
  assert.ok(h.requests.some(r=>r.url.endsWith('/stop')));
  assert.ok(h.requests.some(r=>r.url.endsWith('/reset')));
  assert.equal(h.get('hf-status').textContent,'READY');
});

test('Polling and authorization errors are visible; malformed WebSocket data is reported',async()=>{
  const h=harness({failPolling:true,failCommand:true});await h.tick();
  assert.match(h.get('hf-connection').textContent,/offline/);
  h.get('hf-start').click();await h.tick();
  assert.match(h.get('hf-error').textContent,/administrator authorization/);
  h.sockets[0].listeners.message({data:'not json'});
  assert.match(h.get('hf-connection').textContent,/Invalid telemetry/);
});

test('Older snapshots cannot replace current state and reset clears alerts',async()=>{
  const h=harness();await h.tick();
  h.telemetry({snapshot_at:103,status:'recovered',detected:true,recovered:true,stopped_at:102});
  h.telemetry({snapshot_at:102,status:'attack_running'});
  assert.equal(h.get('hf-status').textContent,'RECOVERED');
  h.telemetry({snapshot_at:104,status:'ready',detected:false});
  assert.equal(h.get('hf-status').textContent,'READY');
  assert.equal(h.get('hf-detection').hidden,true);
  assert.equal(h.get('hf-mitigation').hidden,true);
});

test('HTTPS uses WSS without credentials in URL and reconnect attempts are bounded',async()=>{
  const h=harness({protocol:'https:'});await h.tick();
  assert.equal(h.sockets[0].url,'wss://127.0.0.1:8000/ws/dashboard');
  for(let i=0;i<6;i++){
    const ws=h.sockets.at(-1);ws.readyState=3;ws.listeners.close();
    const timer=h.timers.shift();assert.ok(timer);assert.ok(timer.delay<=15000);timer.fn();
  }
  const last=h.sockets.at(-1);last.readyState=3;last.listeners.close();
  assert.equal(h.timers.length,0);assert.equal(h.sockets.length,7);
});

test('Remote viewers wait for authentication; session commands need no administrator token',async()=>{
  const h=harness({protocol:'https:',authenticated:false});await h.tick();
  assert.equal(h.sockets.length,0);assert.equal(h.requests.length,0);
  Object.assign(h.context.window.SentinelAuth,{canView:true,authenticated:true});
  h.windowListeners['sentinel-auth-changed']();await h.tick();
  assert.equal(h.sockets.length,1);
  h.get('hf-token').value='';h.get('hf-start').click();await h.tick();
  const command=h.requests.find(r=>r.url.endsWith('/start'));assert.ok(command);
  assert.equal(command.options.headers['X-Admin-Token'],undefined);
});
