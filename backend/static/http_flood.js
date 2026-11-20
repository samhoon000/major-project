/* Shared lab/dashboard renderer. All status and graph values come from backend telemetry. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  if (!$('http-flood-panel')) return;
  let latest = null, busy = false, lastSnapshot = 0, ownSocket = null, watchedSocket=null,
    reconnect = null, disposed = false, retries=0, refreshing=false;
  const MAX_RETRIES=6;
  const canView=()=>!window.SentinelAuth||window.SentinelAuth.canView;
  const apiFetch=(...args)=>window.SentinelAuth?window.SentinelAuth.fetch(...args):fetch(...args);
  const url = '/api/attack-lab/http-flood/';
  const labels = {ready:'READY', attack_running:'ATTACK RUNNING', mitigation_active:'MITIGATION ACTIVE',
    attack_stopped:'ATTACK STOPPED', recovered:'RECOVERED', error:'ERROR'};
  const text = (id, value) => { $(id).textContent = String(value); };
  const date = value => value ? new Date(value * 1000).toLocaleTimeString() : '—';
  function chart(state) {
    const svg = $('hf-chart'), ns = 'http://www.w3.org/2000/svg';
    svg.replaceChildren();
    const points = state.samples || [], now = state.snapshot_at;
    const high = Math.max(5, state.thresholds.block_rps * 1.3, ...points.map(p => p.total_rps));
    function add(tag, attrs, value) {
      const node = document.createElementNS(ns, tag);
      Object.entries(attrs).forEach(([key, val]) => node.setAttribute(key, String(val)));
      if (value !== undefined) node.textContent = value;
      svg.appendChild(node);
    }
    const y = value => 194 - Math.min(high, value) / high * 172;
    for (let i=0; i<=4; i++) {
      const value = high*i/4;
      add('line', {x1:46,y1:y(value),x2:880,y2:y(value),stroke:'#254035'});
      add('text', {x:39,y:y(value)+4,fill:'#a0bcaf','font-size':11,'text-anchor':'end'}, String(Math.round(value)));
    }
    for (let i=0; i<=6; i++) add('text', {x:46+i*139,y:216,fill:'#a0bcaf','font-size':11}, i===6?'now':String((i-6)*10)+'s');
    add('line', {x1:46,y1:y(state.thresholds.block_rps),x2:880,y2:y(state.thresholds.block_rps),stroke:'#f2c967','stroke-dasharray':'6 5'});
    [['total_rps','#71ceff'],['accepted_rps','#7df1ad'],['blocked_rps','#ff857b']].forEach(([key,color]) => {
      const coords = points.filter(p => p.timestamp >= now-60).map(p =>
        (46+Math.max(0,Math.min(60,p.timestamp-now+60))/60*834).toFixed(1)+','+y(p[key]).toFixed(1)).join(' ');
      add('polyline', {points:coords,fill:'none',stroke:color,'stroke-width':2.5});
    });
    svg.dataset.samples = String(points.length);
    svg.dataset.total = String(state.total_rps);
    svg.dataset.accepted = String(state.accepted_rps);
    svg.dataset.blocked = String(state.blocked_rps);
  }
  function render(state) {
    if (!state || !state.thresholds || state.snapshot_at < lastSnapshot) return;
    latest = state; lastSnapshot = state.snapshot_at;
    text('hf-status', labels[state.status] || state.status);
    text('hf-target', (state.target_origin || '(configured at start)') + state.target);
    text('hf-generated', state.flood.generated); text('hf-rps', state.total_rps);
    text('hf-success', state.flood.successful); text('hf-blocked', state.flood.blocked);
    text('hf-failed', state.flood.failed); text('hf-elapsed', state.elapsed_seconds+'s');
    $('hf-detection').hidden = !state.detected;
    $('hf-detection').dataset.active = String(state.blocked);
    text('hf-detection-detail', 'HIGH · '+date(state.detected_at)+' · '+state.source_identity+' · '+state.detection_rps+
      ' rolling req/s · '+state.detection_method);
    $('hf-mitigation').hidden = !state.detected;
    text('hf-mitigation-title', state.blocked ? 'THREAT MITIGATED — SOURCE BLOCKED' : state.recovered ? 'RECOVERED — SOURCE UNBLOCKED' : 'SOURCE UNBLOCKED');
    text('hf-mitigation-detail', 'Application-level HTTP 429 · Block duration '+state.thresholds.block_seconds+'s · '+
      state.block_remaining_seconds+'s remaining · '+state.flood.rejected+' rejected requests · '+labels[state.status]);
    text('hf-thresholds', 'Lines show observed arrivals over the last second. The dashed '+state.thresholds.block_rps+
      ' req/s threshold applies to the flood identity averaged over '+state.thresholds.window_seconds+
      ' seconds; warning '+state.thresholds.warning_rps+' req/s. Accepted + blocked = total.');
    const leg = state.legitimate;
    text('hf-leg-sent', leg.generated); text('hf-leg-success', leg.successful);
    text('hf-leg-blocked', leg.blocked); text('hf-leg-failed', leg.failed);
    text('hf-leg-latency', leg.latency_ms == null ? '—' : leg.latency_ms+' ms');
    const completed=leg.generated-(leg.in_flight||0);
    const successRate=leg.success_rate==null?(completed?leg.successful/completed:null):leg.success_rate;
    text('hf-health', !leg.generated ? 'Start normal traffic to measure availability.' :
      (leg.blocked || leg.failed ? 'Availability issue observed — inspect failure counts and event timeline.' :
      'No legitimate request failures or blocks observed'+(state.monitoring?' · monitor active':' · monitor stopped'))+
      (successRate==null?'':' · success rate '+(successRate*100).toFixed(1)+'%'));
    text('hf-method', state.detection_method);
    text('hf-gat', state.gatv2.note);
    $('hf-gat-results').replaceChildren(...state.gatv2.evidence.map(flow => {
      const p = document.createElement('p');
      p.textContent = 'Separate GATv2 evidence: '+flow.flow_id+' · '+flow.gatv2_prediction+
        ' · P(anomaly) '+flow.gatv2_anomaly_probability+
        (flow.gatv2_confidence==null?'':' · confidence '+(flow.gatv2_confidence*100).toFixed(2)+'%');
      return p;
    }));
    $('hf-timeline').replaceChildren(...state.timeline.map(event => {
      const li = document.createElement('li');
      li.textContent = date(event.timestamp)+' · '+event.type+' · '+event.message;
      return li;
    }));
    const reached = new Set(state.timeline.map(e => e.type));
    $('hf-phases').replaceChildren(...[
      ['READY',true],['ATTACK RUNNING',state.started_at != null],
      ['ATTACK DETECTED',state.detected],['MITIGATION ACTIVE',reached.has('HTTP_MITIGATION_ACTIVATED') || state.detected],
      ['ATTACK STOPPED',state.stopped_at != null],['RECOVERED',state.recovered]
    ].map(([label,done]) => {const span=document.createElement('span');span.textContent=label;span.className=done?'reached':'';return span;}));
    if ($('hf-start')) {
      $('hf-start').disabled = busy || state.running || state.started_at != null;
      $('hf-stop').disabled = busy || !state.running;
      $('hf-reset').disabled = busy || state.running;
      $('hf-unblock').disabled = busy || state.running || !state.blocked;
      $('hf-monitor').disabled = busy || state.monitoring;
    }
    if (state.error) text('hf-error', state.error);
    chart(state);
  }
  async function refresh() {
    if(!canView()||refreshing||disposed)return;
    refreshing=true;
    try {
      const response = await apiFetch(url+'state', {cache:'no-store',signal:AbortSignal.timeout(3000)});
      if (!response.ok) throw new Error('Telemetry HTTP '+response.status);
      render(await response.json());
      text('hf-connection', (ownSocket?.readyState===1 || (typeof socket!=='undefined' && socket?.readyState===1) ? 'WebSocket connected' :
        retries>=MAX_RETRIES?'WebSocket retries exhausted · polling fallback; authenticate or reload to retry':'Polling fallback')+' · '+new Date().toLocaleTimeString());
    } catch (error) { text('hf-connection', 'Telemetry unavailable: '+error.message+' · retrying'); }
    finally {refreshing=false;}
  }
  async function command(action) {
    if (busy) return;
    busy=true; if(latest)render(latest); text('hf-error','');
    try {
      const token = $('hf-token').value.trim();
      if (!token && !window.SentinelAuth?.authenticated) throw new Error('Authenticate or enter the administrator token first.');
      const config={rate:Number($('hf-rate').value),duration:Number($('hf-duration').value),concurrency:Number($('hf-concurrency').value)};
      const response=await apiFetch(url+action,{method:'POST',headers:{'Content-Type':'application/json',...(token?{'X-Admin-Token':token}:{})},
        body:action==='start'?JSON.stringify(config):undefined,signal:AbortSignal.timeout(5000)});
      const state=await response.json();
      if(!response.ok)throw new Error(typeof state.detail==='string'?state.detail:JSON.stringify(state.detail));
      render(state);
    } catch(error) {text('hf-error',error.message);} finally {busy=false;if(latest)render(latest);}
  }
  if ($('hf-start')) {
    [['hf-start','start'],['hf-stop','stop'],['hf-reset','reset'],['hf-monitor','monitor'],['hf-unblock','unblock']]
      .forEach(([id,action]) => $(id).addEventListener('click',()=>command(action)));
  }
  function receive(event) {
    if(!canView())return;
    try {const data=JSON.parse(event.data);if(data.type==='HTTP_FLOOD_TELEMETRY')render(data);}
    catch(error){text('hf-connection','Invalid telemetry: '+error.message);}
  }
  function connect() {
    if(disposed||!canView())return;
    const existing=typeof socket!=='undefined'?socket:null;
    if(!existing&&ownSocket&&ownSocket.readyState<=1)return;
    const ws=existing && existing.readyState<=1 ? existing : new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ws/dashboard');
    if(ws===watchedSocket)return;
    watchedSocket=ws;
    if(ws!==existing)ownSocket=ws;
    ws.addEventListener('message',receive);
    ws.addEventListener('open',()=>{retries=0;void refresh();});
    ws.addEventListener('close',()=>{
      text('hf-connection','WebSocket disconnected · polling fallback');
      if(!disposed&&canView()&&retries<MAX_RETRIES)reconnect=setTimeout(connect,Math.min(15000,1000*2**retries++));
    },{once:true});
    ws.addEventListener('error',()=>text('hf-connection','WebSocket error · polling fallback'));
  }
  window.addEventListener('sentinel-auth-changed',()=>{
    clearTimeout(reconnect);retries=0;
    if(canView()){connect();void refresh();}
    else {if(ownSocket)ownSocket.close();latest=null;lastSnapshot=0;}
  });
  if(window.SentinelAuth)window.SentinelAuth.ready.then(()=>{connect();void refresh();});
  else {connect();void refresh();}
  const poll=setInterval(refresh,1000);
  window.addEventListener('pagehide',()=>{disposed=true;clearInterval(poll);clearTimeout(reconnect);if(ownSocket)ownSocket.close();},{once:true});
})();
