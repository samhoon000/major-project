(() => {
  const {id, node, status, metrics, facts} = window.SentinelConsole;
  const auth = window.SentinelAuth;
  const canControl = () => auth.local && auth.authenticated;
  const endpoint = '/api/attack-lab/verification';
  const stages = ['HTTP_TRAFFIC_OBSERVED', 'HTTP_FLOOD_ATTACK_DETECTED', 'HTTP_SECURITY_ALERT',
    'HTTP_MITIGATION_ACTIVATED', 'HTTP_PROTECTION_VERIFIED'];
  const readable = {
    HTTP_TRAFFIC_OBSERVED: 'Traffic observed at the isolated endpoint',
    HTTP_RATE_WARNING: 'Request rate reached the warning threshold',
    HTTP_FLOOD_ATTACK_DETECTED: 'HTTP flood detector flagged the request rate',
    HTTP_SECURITY_ALERT: 'Security alert generated',
    HTTP_MITIGATION_ACTIVATED: 'Temporary restriction applied automatically',
    HTTP_PROTECTION_VERIFIED: 'Subsequent HTTP 429 response verified',
    HTTP_REQUESTS_REJECTED: 'Server recorded rejected requests',
    HTTP_REQUEST_FAILED: 'Request failed',
    HTTP_FLOOD_STOPPED: 'Request dispatch ended',
    HTTP_SOURCE_UNBLOCKED: 'Temporary restriction expired'
  };
  let snapshot, available = false, busy = false, error = '', timer, disposed = false, pending;
  let stream, reconnect, retries = 0;
  const time = timestamp => new Date(timestamp * 1000).toLocaleTimeString();
  const ms = value => value == null ? null : value + ' ms';
  const timeline = id('lab-lifecycle').children;
  const rate = id('hf-rate');
  const requestCount = id('hf-request-count');
  const concurrency = id('hf-concurrency');

  function render() {
    const data = snapshot;
    const running = data?.running;
    const locked = !canControl() || busy || !available;
    id('lab-start').disabled = locked || Boolean(data?.started_at);
    id('lab-stop').disabled = locked || !running;
    id('lab-reset').disabled = locked || !data?.started_at;
    requestCount.disabled = locked || Boolean(data?.started_at);
    id('lab-admin-note').hidden = canControl();
    if (data?.started_at) {
      rate.value = data.config.rate;
      requestCount.value = data.request_count;
      concurrency.value = data.config.concurrency;
    }
    status('lab-status', !available ? 'Local service unavailable' : running ? 'Check running' :
      data?.outcome === 'stopped' ? 'Stopped' : data?.error ? 'Check failed' :
      data?.stopped_at ? 'Check finished' : 'Local service ready',
    !available ? '' : data?.error ? 'bad' : running ? 'warn' : 'good');
    id('lab-error').hidden = !error && !data?.error;
    id('lab-error').textContent = error || data?.error || '';
    const events = data?.timeline || [];
    const evidence = stages.map(type => events.find(event => event.type === type));
    const [, detection, alert, rule, verified] = evidence;
    evidence.forEach((event, index) => {
      timeline[index].dataset.complete = Boolean(event);
      timeline[index].querySelector('span').textContent = event ? time(event.timestamp) : 'Pending';
    });

    const counts = data?.flood;
    const selectedCount = data?.started_at ? data.request_count :
      requestCount.validity.valid ? requestCount.valueAsNumber : null;
    const completed = counts ? counts.generated - counts.in_flight : null;
    metrics('lab-metrics', [
      ['Selected request count', selectedCount],
      ['Requests attempted', counts?.generated], ['Accepted · HTTP 200', counts?.successful],
      ['Rejected · HTTP 429', counts?.blocked], ['Failed or cancelled', counts?.failed],
      ['Requests in the last second', available ? data?.total_rps : null],
      ['Completed attempts', completed], ['Mean response latency', ms(data?.latency_average_ms)]
    ]);
    facts('lab-evidence', [
      ['Detection', detection ? 'Threshold reached' : data?.stopped_at ? 'Threshold not reached' : 'Waiting for detection'],
      ['Detection threshold', data?.thresholds ? data.thresholds.block_rps + ' requests/s over a ' +
        data.thresholds.window_seconds + ' s window' : null],
      ['Source', detection ? data.detection_method : null],
      ['Evidence', detection ? detection.observed_rps + ' requests/s over a ' + data.thresholds.window_seconds + ' s window' : null],
      ['Security alert', alert ? alert.severity + ' · ' + alert.alert_id : 'Pending'],
      ['Automatic mitigation', rule ? data.blocked ? 'Active' : 'Expired' : 'Pending'],
      ['Scope', rule ? 'This lab client and isolated endpoint' : null],
      ['Expiration', rule ? time(rule.expires_at) : null],
      ['Verified HTTP rejection', verified ? 'HTTP ' + verified.status_code + ' · Too Many Requests' : 'Pending']
    ]);
    id('lab-events').replaceChildren(...events.filter(event => readable[event.type]).slice(-10).map(event => {
      const row = node('li');
      row.append(node('span', event.type === 'HTTP_REQUEST_FAILED' ? event.message : readable[event.type]),
        node('time', time(event.timestamp)));
      return row;
    }));
    if (!id('lab-events').children.length) id('lab-events').append(node('li', 'Waiting for backend events.'));
    id('lab-result').hidden = !data?.stopped_at;
    if (data?.stopped_at) {
      id('lab-result-message').textContent = verified ? 'Automatic protection verified through a subsequent HTTP 429 response.' :
        'The run ended before automatic protection was verified.';
      facts('lab-result-facts', [
        ['Selected request count', selectedCount], ['Attempted', counts.generated], ['Completed attempts', completed],
        ['HTTP 200', counts.successful], ['HTTP 429', counts.blocked],
        ['Failed or cancelled', counts.failed], ['Mean response latency', ms(data.latency_average_ms)],
        ['Peak sampled requests/s', data.peak_rps],
        ['Elapsed time', data.elapsed_seconds + ' s']
      ]);
    }
  }

  async function read(url, options) {
    const response = await auth.fetch(url, {cache: 'no-store', signal: AbortSignal.timeout(4000), ...options});
    if (!response.ok) {
      const info = await response.json().catch(() => ({}));
      const detail = info.detail;
      throw new Error(typeof detail === 'string' ? detail : Array.isArray(detail) ?
        detail.map(item => item.loc.at(-1) + ' · ' + item.msg).join('. ') : 'HTTP ' + response.status);
    }
    return response.json();
  }

  function schedule() {
    if (!disposed) timer = setTimeout(refresh, 1000);
  }

  function accept(data) {
    if (!snapshot || data.snapshot_at >= snapshot.snapshot_at) snapshot = data;
    available = true;
  }

  async function refresh() {
    if (disposed || busy) return;
    pending = new AbortController();
    try {
      accept(await read(endpoint, {signal: AbortSignal.any([pending.signal, AbortSignal.timeout(3000)])}));
    } catch {
      if (!busy && stream?.readyState !== WebSocket.OPEN) available = false;
    } finally {
      pending = null;
      if (!disposed && !busy) { render(); schedule(); }
    }
  }

  async function command(action) {
    if (!canControl() || busy || action === 'start' && !requestCount.reportValidity()) return;
    const options = {method: 'POST'};
    if (action === 'start') {
      options.headers = {'Content-Type': 'application/json'};
      options.body = JSON.stringify({request_count: requestCount.valueAsNumber});
    }
    busy = true;
    error = '';
    clearTimeout(timer);
    pending?.abort();
    render();
    try {
      accept(await read(endpoint + '/' + action, options));
    } catch (failure) {
      error = failure.message;
    } finally {
      busy = false;
      render();
      schedule();
    }
  }

  function connect() {
    if (disposed) return;
    const url = new URL('/ws/dashboard', location.href);
    url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    stream = new WebSocket(url);
    stream.addEventListener('open', () => { retries = 0; });
    stream.addEventListener('message', event => {
      try {
        const data = JSON.parse(event.data);
        if (data.type !== 'HTTP_FLOOD_TELEMETRY' || data.profile !== 'policy-verification' || busy) return;
        accept(data);
        render();
      } catch {
        // The periodic HTTP snapshot remains available if a stream message is invalid.
      }
    });
    stream.addEventListener('close', () => {
      if (!disposed && retries < 6) reconnect = setTimeout(connect, Math.min(15000, 1000 * 2 ** retries++));
    });
  }

  for (const action of ['start', 'stop', 'reset']) {
    id('lab-' + action).addEventListener('click', () => command(action));
  }
  requestCount.addEventListener('input', render);
  window.addEventListener('sentinel-auth-changed', render);
  window.addEventListener('pagehide', () => {
    disposed = true;
    clearTimeout(timer);
    clearTimeout(reconnect);
    pending?.abort();
    stream?.close();
  });
  render();
  connect();
  void refresh();
})();
