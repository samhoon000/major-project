const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const source=fs.readFileSync('backend/static/demo_auth.js','utf8');

test('Authentication clears credentials, retains only CSRF in memory and revokes access on logout',async()=>{
  const nodes=new Map(),requests=[],events=[],classes=new Set();let signedIn=false;
  const get=id=>{
    if(!nodes.has(id))nodes.set(id,{value:'',listeners:{},addEventListener(name,fn){this.listeners[name]=fn;}});
    return nodes.get(id);
  };
  const window={dispatchEvent:event=>events.push(event),addEventListener(){}};
  const context={window,Headers,CustomEvent:class{constructor(type,options){this.type=type;this.detail=options.detail;}},
    document:{getElementById:get,body:{classList:{toggle(name,enabled){if(enabled)classes.add(name);else classes.delete(name);}}}},
    AbortSignal:{timeout:()=>null},localStorage:{setItem(){throw new Error('Persistent credentials forbidden');}},
    fetch:async(url,options={})=>{
      requests.push({url,options});
      if(url.endsWith('/login'))signedIn=true;
      if(url.endsWith('/logout'))signedIn=false;
      return {ok:true,status:200,headers:new Headers(signedIn?{'X-CSRF-Token':'test-csrf'}:{}),
        json:async()=>({authenticated:signedIn,local:false,remote_enabled:true,expires_in:signedIn?1800:0})};
    }};
  vm.runInNewContext(source,context);
  await window.SentinelAuth.ready;
  assert.equal(window.SentinelAuth.canView,false);assert.ok(classes.has('sentinel-locked'));
  get('hf-token').value='test-secret';await get('sentinel-login').listeners.click();
  assert.equal(get('hf-token').value,'');assert.equal(window.SentinelAuth.authenticated,true);
  await window.SentinelAuth.fetch('/api/attack-lab/http-flood/start',{method:'POST'});
  const command=requests.find(r=>r.url.endsWith('/start'));
  assert.equal(command.options.headers.get('X-CSRF-Token'),'test-csrf');
  assert.equal(command.options.headers.get('X-Admin-Token'),null);
  assert.equal(command.options.credentials,'same-origin');
  await assert.rejects(()=>window.SentinelAuth.fetch('https://elsewhere.example/api/start'));
  await get('sentinel-logout').listeners.click();
  assert.equal(window.SentinelAuth.canView,false);assert.ok(classes.has('sentinel-locked'));
  assert.ok(events.some(event=>event.type==='sentinel-auth-changed'&&event.detail.authenticated));
});
