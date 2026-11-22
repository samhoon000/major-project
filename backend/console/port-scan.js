(() => {
  const {id, node, status, metrics, facts, chart} = window.SentinelConsole;
  const lab = id('port-scan-lab');
  const plot = id('port-scan-chart');
  const endpoint = '/api/attack-lab/port-scan';
  const time = timestamp => new Date(timestamp * 1000).toLocaleTimeString();
  let disposed = false, timer;

  function render(state) {
    const capture = state.capture === 'running' ? 'Capture active' :
      state.capture === 'starting' ? 'Capture starting' : 'Capture unavailable';
    const source = state.sources[0];
    const identifiers = [['Observation ID', source?.observation_id], ['Alert ID', source?.alert_id]];
    if (lab) {
      status('port-scan-lab-status', state.capture === 'running' && source ? source.status : capture,
        state.active_mitigations ? 'warn' : '');
      facts('port-scan-lab-facts', [
        ['Capture interface', state.interface],
        ['TCP attempts observed', state.capture === 'running' ? state.total_attempts : null],
        ['Distinct destination ports', state.capture === 'running' ? state.unique_ports : null],
        ['Active alerts', state.active_alerts],
        ['Active endpoint restrictions', state.active_mitigations],
        ...identifiers
      ]);
    }
    if (!plot) return;
    const live = state.capture === 'running';
    status('port-scan-capture', state.interface ? capture + ' · ' + state.interface : capture, live ? 'good' : '');
    metrics('port-scan-metrics', [
      ['TCP attempts observed', live ? state.total_attempts : null], ['Unique destination ports', live ? state.unique_ports : null],
      ['Failed connections', live ? state.total_failed : null], ['Attempts per second', live ? state.attempts_per_second : null],
      ['Suspicious sources', live ? state.suspicious_sources : null], ['Active alerts', state.active_alerts],
      ['Active mitigations', state.active_mitigations], ['Last detection', state.last_detection ? time(state.last_detection) : null]
    ]);
    id('port-scan-chart-note').textContent = live ?
      'Each sample shows counts from the preceding ' + state.window_seconds + ' seconds.' : 'Waiting for active packet capture.';
    plot.hidden = !live || !state.samples.length;
    if (!plot.hidden) {
      const end = Math.floor(state.samples.at(-1).timestamp);
      const start = Math.max(Math.floor(state.samples[0].timestamp), end - 59);
      const buckets = new Map(state.samples.map(sample => [Math.floor(sample.timestamp), sample]));
      const series = Array.from({length:end - start + 1}, (_, index) => {
        const sample = buckets.get(start + index);
        return sample ? [sample.attempts, sample.unique_ports, sample.failed_attempts] : [];
      });
      const markers = state.events.filter(event => event.type === 'detected' && event.timestamp >= start
        && event.timestamp < end + 1).map(event => ({
        index: event.timestamp - start - .5, label: 'Port scan detected · ' + time(event.timestamp)
      }));
      chart(plot, series, ['#71ceff', '#7df1ad', '#ff857b'],
        {windowLabel: time(start), endLabel: time(end + 1), markers});
    }
    facts('port-scan-evidence', [
      ['Detection source', 'TCP port scan detector'],
      ['Pair threshold', state.distinct_threshold + ' distinct ports and ' + state.failed_port_threshold + ' refused ports'],
      ['Observed source', source?.source], ['Observed target', source?.destination],
      ['Ports in window', source ? source.unique_ports + ' distinct · ' + source.failed_ports + ' refused' : null],
      ['State', source?.status ?? (live ? 'Normal' : null)], ...identifiers,
      ['Enforcement', source?.restricted ? 'Dedicated HTTP endpoint only' : 'No active endpoint restriction for this pair'],
      ['Verification', source?.verified ? 'HTTP 429 issued' : 'Awaiting evidence']
    ]);
    id('port-scan-events').replaceChildren(...state.events.slice(-12).map(event => {
      const item = node('li');
      item.append(node('span', event.message + ' · ' + event.source + ' → ' + event.destination),
        node('time', time(event.timestamp)));
      return item;
    }));
    if (!state.events.length) id('port-scan-events').append(node('li', 'Waiting for captured TCP activity.'));
  }

  async function refresh() {
    try {
      const response = await fetch(endpoint, {cache: 'no-store', signal: AbortSignal.timeout(3000)});
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const snapshot = await response.json();
      if (!disposed) render(snapshot);
    } catch {
      if (!disposed) status(lab ? 'port-scan-lab-status' : 'port-scan-capture', 'Telemetry unavailable');
    } finally {
      if (!disposed) timer = setTimeout(refresh, 1000);
    }
  }

  const check = id('port-scan-check');
  check?.addEventListener('click', async () => {
    check.disabled = true;
    try {
      const response = await fetch(endpoint + '/verify', {method: 'POST', signal: AbortSignal.timeout(4000)});
      if (response.status === 429) {
        const result = await response.json();
        id('port-scan-feedback').textContent = 'HTTP 429 · verified alert ' + result.alert_id + '.';
      } else {
        id('port-scan-feedback').textContent = response.ok ? 'HTTP 200 · endpoint currently allows this client.' :
          'Endpoint check returned HTTP ' + response.status;
      }
    } catch {
      id('port-scan-feedback').textContent = 'Could not reach the dedicated endpoint.';
    } finally {
      check.disabled = false;
    }
  });
  window.addEventListener('pagehide', () => { disposed = true; clearTimeout(timer); });
  void refresh();
})();
