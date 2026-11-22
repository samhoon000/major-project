  {
    const appId = 'northfield-staging';
    const panel = byId('northfield-monitor');
    const chart = byId('nf-traffic');
    const series = [
      ['normal', '#69d7ae'], ['suspicious', '#ffc66d'],
      ['blocked', '#ff878e'], ['other', '#94a9c8']
    ];
    const totals = point => series.reduce((count, [name]) => count + point[name], 0);
    const liveTime = timestamp => new Date(timestamp).toLocaleTimeString();
    let controlsKey = '';
    preferredApp = appId;

    function svg(tag, attributes, value) {
      const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
      for (const [key, attribute] of Object.entries(attributes)) node.setAttribute(key, attribute);
      if (value !== undefined) node.textContent = value;
      return node;
    }

    function badge(id, message, state) {
      const node = byId(id);
      if (node.textContent !== message) node.textContent = message;
      node.dataset.state = state || '';
    }

    function renderChart(traffic, marks) {
      const {points, start, end} = traffic;
      const base = 235;
      const width = 780;
      const left = 55;
      const height = 205;
      const ceiling = Math.max(4, Math.ceil(Math.max(...points.map(totals)) / 4) * 4);
      const unit = height / ceiling;
      const bar = width / points.length;
      const nodes = [];
      for (let step = 0; step <= 4; step++) {
        const y = base - height * step / 4;
        nodes.push(svg('line', {x1:left, y1:y, x2:left + width, y2:y, stroke:'#455b78'}));
        nodes.push(svg('text', {x:left - 10, y:y + 5, 'text-anchor':'end'}, ceiling * step / 4));
      }
      points.forEach((point, index) => {
        let bottom = base;
        const x = left + bar * index;
        for (const [name, fill] of series) {
          if (point[name] === 0) continue;
          const segment = unit * point[name];
          bottom -= segment;
          const rect = svg('rect', {x, y:bottom, width:bar - 1, height:segment, fill, 'data-series':name});
          rect.append(svg('title', {}, liveTime((start + index) * 1000) + ' · ' + name + ' · ' + point[name]));
          nodes.push(rect);
        }
      });
      const total = points.map((point,index) => (left + bar * (index + .5)) + ',' + (base - unit * totals(point)));
      nodes.push(svg('polyline',{points:total.join(' '),fill:'none',stroke:'#edf4ff','stroke-width':1.4}));
      for (const mark of marks) {
        const x = left + width * (mark.timestamp / 1000 - start) / (end - start);
        nodes.push(svg('line', {x1:x, y1:25, x2:x, y2:base, stroke:mark.color,
          'stroke-width':2, 'stroke-dasharray':'4 4'}));
      }
      for (const [fraction, caption] of [[0,'120 s ago'], [.5,'60 s ago'], [1,'Now']]) {
        nodes.push(svg('text', {x:left + width * fraction, y:264,
          'text-anchor':fraction === 0 ? 'start' : fraction === 1 ? 'end' : 'middle'}, caption));
      }
      chart.replaceChildren(...nodes);
    }

    function policy(view, now) {
      const channel = view?.channels?.find(item => item.app === appId && item.environment === 'staging');
      const rules = channel?.rules.filter(rule => rule.expires > now) || [];
      const pending = view?.pending?.filter(item => item.app === appId && item.expires > now * 1000) || [];
      const ready = channel?.delivery === 'receiving';
      const applied = ready && channel.enabled && channel.acknowledgment === 'applied';
      let state = 'Waiting for policy receiver';
      if (channel) {
        if (!ready) state = 'Receiver stale · enforcement unconfirmed';
        else if (channel.acknowledgment === 'pending') state = 'Waiting for Northfield acknowledgment';
        else if (!channel.enabled) state = 'Staging enforcement disabled';
        else if (applied && rules.length) state = 'Active · ' + rules.length + ' acknowledged';
        else if (pending.length) state = 'Proposal awaiting operator approval';
        else state = 'No active mitigation';
        state += ' · revision ' + channel.revision;
      }
      badge('nf-policy-status', state);
      const key = JSON.stringify([ready, applied, channel?.revision, rules, pending]);
      if (key === controlsKey) return channel;
      controlsKey = key;
      const controls = [];
      const feedback = byId('nf-policy-feedback');
      if (ready && !channel.enabled && channel.acknowledgment === 'disabled' && channel.can_enable) {
        controls.push(stagingButton('Enable staging', appId, 'enable', null, feedback));
      }
      if (applied && pending.length === 1) {
        const [proposal] = pending;
        const button = stagingButton('Approve Block', appId, 'approve', proposal.id, feedback);
        button.title = proposal.route + ' · ' + proposal.subject;
        controls.push(button);
      }
      if (rules.length === 1) {
        controls.push(stagingButton('Restore Access', appId, 'revoke', rules[0].id, feedback));
      }
      if (pending.length > 1 || rules.length > 1) {
        const link = element('a', 'Review policy scopes');
        link.href = '#staging-policies';
        link.onclick = () => { byId('advanced-mode').open = true; };
        controls.push(link);
      }
      byId('nf-policy-controls').replaceChildren(...controls);
      return channel;
    }

    function student(side, event, channel) {
      const status = byId('nf-' + side + '-status');
      const detail = byId('nf-' + side + '-detail');
      status.textContent = event ? 'HTTP ' + event.status : 'No observation';
      const name = side === 'first' ? 'Student 1' : 'Student 2';
      if (!event) {
        detail.textContent = name + ' · last course-access response';
        return;
      }
      const recovery = channel?.recoveries.find(item => item.request_id === event.request_id);
      const receipt = channel?.receipts.find(item => item.request_id === event.request_id);
      const outcome = recovery ? 'Verified recovery' :
        receipt?.outcome === 'rate_limited' ? 'Rate limit verified' :
        receipt?.outcome === 'blocked' ? 'Policy block verified' :
        event.status >= 200 && event.status < 300 ? 'Allowed' : 'Access response observed';
      const proof = recovery || receipt;
      const link = element('a', 'Request evidence');
      link.href = '#activity';
      link.onclick = () => {
        byId('advanced-mode').open = true;
        const input = byId('compare-' + side);
        input.closest('details').open = true;
        input.value = event.request_id;
        input.dispatchEvent(new Event('input'));
      };
      detail.replaceChildren(name + ' · ' + outcome + ' · ' + localTime(event.timestamp) + ' · ',
        ...(proof ? ['revision ' + proof.revision + ' · '] : []), link);
    }

    function timeline(data, traffic, channel, app) {
      const now = traffic?.end ?? Date.now() / 1000;
      const rules = channel?.rules.filter(rule => rule.expires > now) || [];
      const acknowledged = channel?.delivery === 'receiving' && channel.acknowledgment === 'applied';
      const recoveries = channel?.recoveries || [];
      const currentAlert = traffic?.alerts.find(alert => ['open','acknowledged'].includes(alert.status));
      const recentRecovery = recoveries[0];
      const decisions = (data?.protection?.decisions || []).filter(item => item.app === appId);
      const decision = decisions.find(item => rules.some(rule => rule.id === item.id)) ||
        decisions.find(item => currentAlert && item.evidence?.signals?.some(signal => signal.alert_id === currentAlert.id)) ||
        decisions.find(item => !currentAlert && item.id === recentRecovery?.rule_id);
      const appAlert = currentAlert || traffic?.alerts.find(alert =>
        decision?.evidence?.signals?.some(signal => signal.alert_id === alert.id));
      const pending = data?.staging?.pending.filter(item => item.app === appId) || [];
      const method = appAlert ? data.detection?.rules?.[appAlert.rule] || label(appAlert.rule) : '';
      const allActive = acknowledged ? rules.length : channel?.delivery === 'receiving' ? 0 : null;
      const recovered = Boolean(decision && !rules.some(rule => rule.id === decision.id) &&
        recoveries.some(item => item.rule_id === decision.id));
      const active = Boolean(decision && acknowledged && rules.some(rule => rule.id === decision.id));
      const normal = traffic && app?.status === 'receiving' && data?.detection?.health?.status === 'running' &&
        !traffic.active_alerts && !rules.length;
      byId('nf-policy-evidence').textContent = [
        method || (data?.detection?.health?.status === 'running' ? 'No current detection' : 'Detection unavailable'),
        pending.length ? pending.length + ' awaiting approval' : ''
      ].filter(Boolean).join(' · ');
      const stages = [['Normal',normal], ['Threat Detected',Boolean(appAlert || decision?.evidence?.signals?.length)],
        ['Mitigation Active',active], ['Recovered',recovered]];
      byId('nf-timeline').replaceChildren(...stages.map(([title,complete]) => {
        const item = element('li',title + (complete ? ' ✓' : ''));
        item.dataset.complete = Boolean(complete);
        return item;
      }));
      return {allActive,currentAlert,normal};
    }

    renderNorthfield = (data, reason) => {
      panel.hidden = !window.SentinelAuth.authenticated;
      byId('connection').hidden = !panel.hidden;
      if (panel.hidden) byId('nf-policy-feedback').textContent = '';
      const app = data?.applications?.find(item => item.id === appId);
      const traffic = data?.northfield;
      badge('nf-connection', reason || (data?.type === 'unavailable' ? 'Telemetry storage unavailable' :
        app?.status === 'receiving' ? 'Connected' :
        app ? 'Stale telemetry' : 'Waiting for collector'), app?.status === 'receiving' ? 'good' : '');
      byId('nf-last-observed').textContent = app?.events.length ?
        'Last observed request · ' + localTime(app.events[0].timestamp) : 'Last observed request unavailable';
      const channel = policy(data?.staging, traffic?.end ?? Date.now() / 1000);
      student('first', traffic?.students[0], channel);
      student('second', traffic?.students[1], channel);
      const alerts = traffic?.alerts || [];
      const {allActive,currentAlert,normal} = timeline(data,traffic,channel,app);
      badge('nf-threat',allActive ? 'Protected' : currentAlert ? 'Threat detected' : normal ? 'Normal' : 'Security status unavailable',
        allActive || normal ? 'good' : currentAlert ? 'critical' : '');

      const points = traffic?.points;
      const count = (items, key) => items.reduce((total, item) => total + item[key], 0);
      const active = Boolean(points && app);
      cards('nf-metrics', [
        ['Requests · last minute', app?.requests_per_minute ?? '—'],
        ['Detected threats · active alerts', traffic?.active_alerts ?? '—'],
        ['Confirmed blocks · last 2 min', active ? count(points, 'blocked') : '—'],
        ['Active mitigations',allActive ?? '—']
      ]);
      const threshold = traffic?.threshold;
      byId('nf-threshold').textContent = threshold ?
        'Staging rule · ' + threshold.count + ' requests in ' + threshold.seconds + ' s · one student and course-access route' : '';
      chart.style.display = active ? '' : 'none';
      if (!active) {
        chart.replaceChildren();
        byId('nf-markers').replaceChildren();
        byId('nf-chart-status').textContent = reason || 'Waiting for signed Northfield traffic and evidence storage.';
        return;
      }
      const marks = [
        ...alerts.filter(alert => alert.status !== 'false_positive').map(alert =>
          ({timestamp:alert.last_seen, name:'Detection signal', color:'#ffc66d'})),
        ...traffic.applied.map(item =>
          ({timestamp:item.timestamp * 1000, name:'Mitigation applied · rev ' + item.revision, color:'#ff878e'})),
        ...(channel?.recoveries || []).map(item =>
          ({timestamp:item.timestamp, name:'Recovery verified · rev ' + item.revision, color:'#69d7ae'}))
      ].filter(mark => mark.timestamp >= traffic.start * 1000 && mark.timestamp < traffic.end * 1000)
        .sort((first, second) => first.timestamp - second.timestamp);
      renderChart(traffic, marks);
      byId('nf-chart-status').textContent = points.some(totals) ?
        'HTTP 429 responses · ' + count(points,'rate_limited') + ' in the last two minutes.' :
        'Zero observed requests in this window.';
      byId('nf-markers').replaceChildren(...marks.slice(-6).map(mark =>
        element('li', liveTime(mark.timestamp) + ' · ' + mark.name)));
    };
  }
