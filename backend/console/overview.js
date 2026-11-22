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
      ...alerts.map(alert => [alert.last_seen / 1000,'Threat detected',alert.app]),
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
    id('overview-events').replaceChildren(...recent.slice(0,5).map(([timestamp, name, app]) => {
      const item = node('li');
      const time = new Date(timestamp * 1000);
      item.append(node('span',name + ' · ' + appName(app)),node('time',time.toLocaleString()));
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
