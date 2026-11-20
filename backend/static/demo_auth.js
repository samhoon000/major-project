/* Same-origin HttpOnly sessions, memory-only CSRF token, no persistent credentials. */
(() => {
  'use strict';
  const $=id=>document.getElementById(id);
  let csrf='', authenticated=false, local=false;
  const channel=typeof BroadcastChannel==='undefined'?null:new BroadcastChannel('sentinel-auth');
  const state={canView:false,authenticated:false,local:false,ready:null,fetch:apiFetch};
  window.SentinelAuth=state;
  function apply(data) {
    authenticated=!!data.authenticated; local=!!data.local;
    Object.assign(state,{authenticated,local,canView:local||authenticated});
    document.body.classList.toggle('sentinel-locked',!state.canView);
    $('sentinel-logout').disabled=!authenticated;
    $('sentinel-auth-status').textContent=authenticated ? 'Authenticated · expires at '+new Date(Date.now()+data.expires_in*1000).toLocaleTimeString() :
      local ? 'Local viewing active. Authenticate or enter the token before using controls.' :
      data.remote_enabled ? 'Authentication required to view telemetry and control the local demonstration.' :
      'Remote control is disabled. Configure the public hostname and HTTP_FLOOD_REMOTE_ENABLED on the host.';
    window.dispatchEvent(new CustomEvent('sentinel-auth-changed',{detail:{authenticated,local,canView:state.canView}}));
  }
  async function apiFetch(url,options={}) {
    if(typeof url!=='string'||!url.startsWith('/api/'))throw new Error('Same-origin API path required');
    const headers=new Headers(options.headers||{});
    const method=(options.method||'GET').toUpperCase();
    if(csrf&&method!=='GET'&&method!=='HEAD')headers.set('X-CSRF-Token',csrf);
    const response=await fetch(url,{...options,headers,credentials:'same-origin'});
    if(response.status===401){csrf='';apply({authenticated:false,local,remote_enabled:true});}
    return response;
  }
  async function restore() {
    try {
      const response=await fetch('/api/auth/session',{credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(5000)});
      if(!response.ok)throw new Error('Session check HTTP '+response.status);
      csrf=response.headers.get('X-CSRF-Token')||'';
      apply(await response.json());
    } catch(error) {
      $('sentinel-auth-status').textContent='Session unavailable: '+error.message+' · use Authenticate to retry.';
    }
  }
  $('sentinel-login').addEventListener('click',async()=>{
    const button=$('sentinel-login');button.disabled=true;
    try {
      const response=await apiFetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({token:$('hf-token').value.trim()}),signal:AbortSignal.timeout(5000)});
      const data=await response.json();
      if(!response.ok)throw new Error(data.detail||'Authentication failed');
      csrf=response.headers.get('X-CSRF-Token')||'';
      $('hf-token').value='';
      await restore();
      if(channel)channel.postMessage('session-changed');
    } catch(error){$('sentinel-auth-status').textContent=error.message;} finally {button.disabled=false;}
  });
  $('sentinel-logout').addEventListener('click',async()=>{
    try {
      const response=await apiFetch('/api/auth/logout',{method:'POST',signal:AbortSignal.timeout(5000)});
      if(!response.ok)throw new Error('Sign out HTTP '+response.status);
      csrf='';$('hf-token').value='';await restore();if(channel)channel.postMessage('session-changed');
    } catch(error){$('sentinel-auth-status').textContent=error.message;}
  });
  state.restore=restore;
  if(channel)channel.onmessage=()=>restore();
  window.addEventListener('focus',()=>restore());
  window.addEventListener('pagehide',()=>{if(channel)channel.close();},{once:true});
  state.ready=restore();
})();
