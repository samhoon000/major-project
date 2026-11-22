(() => {
  const {id,node,status,metrics,facts,chart} = window.SentinelConsole;
  const appId = 'northfield-staging';
  let socket, retry, deadline, disposed = false;
  const appName = app => app === appId ? 'Northfield' : app;
  const legacySections = new Set([
    '#http-flood-panel','#topology','#flows','#activityGraph','#incidentPanel',
    '#events','#attackHistory','#interfaceInfo'
  ]);
  function forwardLegacySection() {
    if (location.hash === '#http-flood-panel' && id('launch-demo-lab')) {
      location.replace('/attack-lab');
      return true;
    }
    if (location.hash === '#userRows' || location.hash === '#blockedUsers') {
      location.replace('/dashboard/chat' + location.hash);
      return true;
    }
    if (location.hash === '#dashboardQrWrap') {
      location.replace('/dashboard/settings');
      return true;
    }
    if (!legacySections.has(location.hash)) return false;
    location.replace('/dashboard?view=legacy' + location.hash);
    return true;
  }
  if (forwardLegacySection()) return;
  window.addEventListener('hashchange',forwardLegacySection);

  function present(data, message) {
    const apps = data?.applications;
    const detection = data?.detection;
    const staging = data?.staging;
    const portal = apps?.find(app => app.id === appId);
    const receiver = staging?.channels?.find(channel => channel.app === appId);
    const now = Date.now() / 1000;
    const security = detection?.health?.status;
    const activeApps = detection?.overview?.active_apps || [];
    const protectedRules = receiver?.rules.filter(rule => rule.expires > now) || [];
    const applied = receiver?.delivery === 'receiving' && receiver.acknowledgment === 'applied';
    const system = !apps ? 'Unavailable' : security !== 'running' || staging?.unavailable ? 'Degraded' :
      portal?.status === 'receiving' ? 'Operational' : 'Awaiting telemetry';
    status('overview-connection', message || 'Application stream connected', data ? 'good' : '');
    const blockCount = staging && !staging.unavailable ?
      staging.channels.reduce((total, channel) => total + (channel.confirmed.blocked || 0) +
        (channel.confirmed.rate_limited || 0), 0) : null;
    metrics('overview-metrics', [['Monitored Applications',apps?.length],
      ['Active Threats · open alerts',detection?.overview?.active], ['Blocked Threats · retained receipts',blockCount],
      ['System Status',system]]);
    facts('overview-app', [
      ['Connection',portal ? portal.status === 'receiving' ? 'Collector receiving' : 'Stale telemetry' : 'Awaiting signed telemetry'],
      ['Security',!detection?.overview ? 'Unknown' : activeApps.includes(appId) ? 'Active alert' : 'No active alerts'],
      ['Activity',portal ? portal.requests_per_minute + ' requests in the last minute' : '—'],
      ['Mitigation',!receiver ? 'Unknown' : protectedRules.length && applied ? 'Active · acknowledged' :
        protectedRules.length ? 'Awaiting confirmation' : 'None active']
    ]);
    const alerts = (detection?.alerts || []).filter(alert => alert.status !== 'false_positive');
    const receipts = (staging?.channels || []).flatMap(channel => channel.receipts
      .filter(receipt => receipt.request_id && ['blocked','rate_limited'].includes(receipt.outcome))
      .map(receipt => [receipt.timestamp,'Request blocked', channel.app]));
    const recent = [
      ...alerts.map(alert => [alert.last_seen / 1000,'Threat detected',alert.app,
        [alert.severity, alert.rule, alert.status].filter(Boolean).join(' · ')]),
      ...(data?.protection?.decisions || []).filter(decision => decision.expires)
        .map(decision => [decision.created / 1000,'Mitigation proposed',decision.app]),
      ...(staging?.audit || []).filter(item => item.operation === 'approve')
        .map(item => [item.timestamp,'Mitigation approved',item.app]),
      ...receipts,
      ...(staging?.channels || []).flatMap(channel => (channel.recoveries || [])
        .map(item => [item.timestamp / 1000,'Access restored', channel.app]))
    ].sort((a,b) => b[0] - a[0]);
    const cut = now - 1800;
    const samples = Array.from({length:6},() => [0,0]);
    for (const [timestamp, name] of recent) {
      const bin = Math.floor((timestamp - cut) / 300);
      if (!samples[bin]) continue;
      if (name === 'Threat detected') samples[bin][0]++;
      if (name === 'Request blocked') samples[bin][1]++;
    }
    const graphReady = Boolean(detection?.overview && staging && !staging.unavailable);
    if (graphReady) chart(id('overview-chart'),samples,['#f9c37a','#ffa2a7'],{windowLabel:'30 min ago',kind:'bars'});
    else id('overview-chart').replaceChildren();
    id('overview-chart').style.display = graphReady ? '' : 'none';
    id('overview-activity').textContent = !graphReady ? 'Waiting for application evidence.' :
      samples.some(([detections, blocks]) => detections || blocks) ? '' : 'No detections or confirmed blocks in this window.';
    id('overview-events').replaceChildren(...recent.slice(0,5).map(([timestamp, name, app, details]) => {
      const item = node('li');
      const time = new Date(timestamp * 1000);
      item.append(node('span',[name, appName(app), details].filter(Boolean).join(' · ')),node('time',time.toLocaleString()));
      return item;
    }));
    if (!recent.length) id('overview-events').append(node('li', data ? 'No security events recorded.' : 'Waiting for telemetry.'));
  }

  function connect() {
    if (disposed) return;
    const {local,remoteConsole,authenticated} = window.SentinelAuth;
    const permitted = local || remoteConsole;
    id('overview-monitor').hidden = !permitted;
    if (!permitted || !authenticated) {
      socket?.close();
      socket = null;
      present(null, permitted ? 'Operator sign-in required' : 'Application telemetry is local only');
      return;
    }
    if (socket) return;
    const url = new URL('/ws/monitored-applications',location.href);
    url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const stream = new WebSocket(url);
    socket = stream;
    const watch = () => { clearTimeout(deadline); deadline = setTimeout(() => stream.close(),12000); };
    watch();
    stream.onmessage = event => {
      if (socket !== stream) return;
      watch();
      const data = JSON.parse(event.data);
      present(data.type === 'snapshot' ? data : null, data.type === 'unavailable' ? 'Telemetry storage unavailable' : '');
    };
    stream.onclose = () => {
      if (disposed || socket !== stream) return;
      clearTimeout(deadline);
      socket = null;
      present(null,'Stream disconnected · reconnecting');
      retry = setTimeout(async () => { await window.SentinelAuth.restore(); connect(); },3000);
    };
  }
  present(null,'Checking operator session');
  window.addEventListener('sentinel-auth-changed',connect);
  window.SentinelAuth.ready.then(connect);
  window.addEventListener('pagehide',() => { disposed = true; clearTimeout(deadline); clearTimeout(retry); socket?.close(); });
})();

(() => {
  const {id, status, metrics, facts, chart, poll, read} = window.SentinelConsole;
  const local = Boolean(id('launch-demo-lab'));
  const history = new Map();
  const pipeline = id('overview-pipeline').children;
  let network, lab, stream, streamOpen = false, retry, disposed = false, priorAnomalies;

  function render() {
    const capture = network?.capture;
    const running = capture === 'running';
    const predictions = network?.gatv2_analyses;
    const suspicious = network?.gatv2_network_anomalies;
    const completed = network?.completed_flows?.length;
    const alerts = lab?.timeline || [];
    const alert = alerts.find(event => event.type === 'HTTP_SECURITY_ALERT');
    const rule = alerts.find(event => event.type === 'HTTP_MITIGATION_ACTIVATED');
    const verified = alerts.find(event => event.type === 'HTTP_PROTECTION_VERIFIED');
    const captureStatus = running ? 'Running' : capture === 'starting' ? 'Starting' : 'Unavailable';
    const modelStatus = network?.gatv2 === 'available' ? 'Loaded' : 'Unavailable';
    const mitigationStatus = lab?.blocked ? 'HTTP restriction active' : verified ? 'HTTP rejection verified' :
      network?.quarantine_count ? 'Network quarantine active' : lab ? 'HTTP guard available' : 'Awaiting evidence';
    const stages = [
      [network?.packets > 0, network?.packets > 0 ? 'Packets observed' : 'Waiting for packets'],
      [running, captureStatus],
      [completed > 0, completed > 0 ? 'Flows available' : 'Waiting for flows'],
      [modelStatus === 'Loaded', modelStatus],
      [suspicious > 0 || Boolean(alert), suspicious > 0 || alert ? 'Activity flagged' : 'No evidence yet'],
      [Boolean(alert), alert ? 'HTTP alert recorded' : 'See application events'],
      [Boolean(lab?.blocked || verified || network?.quarantine_count), mitigationStatus]
    ];
    stages.forEach(([complete, label], index) => {
      pipeline[index].dataset.complete = complete;
      pipeline[index].querySelector('span').textContent = label;
    });
    metrics('overview-network-metrics', [
      ['Packets captured', running || network?.packets ? network.packets : null],
      ['Completed flows · retained', network && (running || completed) ? completed : null],
      ['AI predictions', modelStatus === 'Loaded' ? predictions : null],
      ['Suspicious flows', modelStatus === 'Loaded' ? suspicious : null],
      ['Active local restrictions', network ? network.quarantine_count + Number(Boolean(lab?.blocked)) : null],
      ['Local HTTP 429 responses', lab?.flood?.blocked]
    ]);
    facts('overview-health', [
      ['Packet capture', captureStatus],
      ['Capture interface', network?.selected_adapter_name || network?.interface],
      ['GATv2 model', modelStatus],
      ['Dashboard event stream', local ? streamOpen ? 'Connected' : 'Connecting or unavailable' : 'See application stream'],
      ['Response policy', mitigationStatus],
      ['Quarantined nodes', network?.quarantined_ips?.join(', ') || '—']
    ]);
    id('overview-classification').textContent = predictions > 0 && suspicious != null ?
      `GATv2 binary classification · ${predictions - suspicious} benign · ${suspicious} suspicious` :
      'Awaiting GATv2 classifications.';
    id('overview-network-current').textContent = running ?
      `${network.packets_per_second} packets/s · ${network.bytes_per_second} bytes/s · ${completed} retained completed flows` :
      'Waiting for active packet capture.';
    if (local) {
      id('overview-http').hidden = false;
      status('overview-http-status', lab?.blocked ? 'Restriction active' : verified ? 'HTTP 429 verified' :
        lab?.running ? 'Observing requests' : lab ? 'Awaiting evidence' : 'Local evidence unavailable',
      lab?.blocked ? 'warn' : verified ? 'good' : '');
      const time = value => new Date(value * 1000).toLocaleTimeString();
      facts('overview-http-evidence', [
        ['Security alert', alert ? `${alert.severity} · ${alert.alert_id} · ${time(alert.timestamp)}` : 'No current-run alert'],
        ['Source and identity', alert ? `${alert.detection_method} · ${alert.source_identity}` : null],
        ['Automatic mitigation', rule ? `${lab.blocked ? 'Active' : 'Expired'} · ${rule.target} · ${time(rule.expires_at)}` : 'Pending'],
        ['Verified enforcement', verified ? `HTTP ${verified.status_code} observed at ${time(verified.timestamp)}` : 'Pending']
      ]);
    }
  }

  function applyLab(snapshot) {
    if (!lab || snapshot.snapshot_at >= lab.snapshot_at) lab = snapshot;
  }

  function connectEvents() {
    if (!local || disposed) return;
    const url = new URL('/ws/dashboard', location.href);
    url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    stream = new WebSocket(url);
    stream.onopen = () => { streamOpen = true; render(); };
    stream.onmessage = event => {
      const data = JSON.parse(event.data);
      if (data.type !== 'HTTP_FLOOD_TELEMETRY' || data.profile !== 'policy-verification') return;
      applyLab(data);
      render();
    };
    stream.onclose = () => {
      streamOpen = false;
      if (!disposed) { render(); retry = setTimeout(connectEvents, 3000); }
    };
  }

  poll(async signal => {
    network = await read('/api/network/state', signal);
    if (local) {
      try { applyLab(await read('/api/attack-lab/verification', signal)); }
      catch { if (!streamOpen) lab = null; }
    }
    if (disposed) return;
    const bucket = Math.floor(Date.now() / 2500);
    const anomalies = network.gatv2_network_anomalies;
    if (network.capture === 'running') {
      const delta = priorAnomalies != null && anomalies >= priorAnomalies ? anomalies - priorAnomalies : null;
      history.set(bucket, [network.packets_per_second, network.bytes_per_second / 1024, delta]);
    }
    priorAnomalies = anomalies;
    for (const index of history.keys()) if (index < bucket - 23) history.delete(index);
    const plot = id('overview-network-chart');
    plot.hidden = !history.size;
    if (history.size) {
      const samples = Array.from({length: 24}, (_, index) => history.get(bucket - 23 + index) || []);
      chart(plot, samples, ['#62d9ce', '#9aafff', '#ffc37a'], {windowLabel: '60 s ago'});
    }
    render();
  }, () => { network = null; id('overview-network-chart').hidden = true; render(); });
  window.SentinelAuth.ready.then(connectEvents);
  window.addEventListener('pagehide', () => { disposed = true; clearTimeout(retry); stream?.close(); });
})();
