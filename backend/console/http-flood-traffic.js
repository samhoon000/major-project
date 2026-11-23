(() => {
  const {id, poll, read} = window.SentinelConsole;
  const threshold = id('hf-thresholds');
  const status = id('hf-traffic-status');
  let stream, reconnect, latest = 0, lastSocketUpdate = -Infinity, disposed = false;

  function setStatus(message) {
    if (status.textContent !== message) status.textContent = message;
  }

  function render(state, transport) {
    if (state.type !== 'HTTP_POLICY_TRAFFIC' || state.snapshot_at < latest) return;
    latest = state.snapshot_at;
    window.SentinelHTTPFloodChart(state);
    id('hf-current-rate').textContent = state.buckets.at(-1).total_rps;
    id('hf-window-total').textContent = state.totals.total;
    id('hf-window-accepted').textContent = state.totals.accepted;
    id('hf-window-blocked').textContent = state.totals.blocked;
    id('hf-window-run').textContent = state.run_id ?? '—';
    id('hf-host-count').textContent = state.sources?.['host-loopback'] ?? '—';
    id('hf-browser-count').textContent = state.sources?.['cloudflare-browser'] ?? '—';
    const {block_rps, window_seconds} = state.thresholds;
    const rule = `The dashed ${block_rps} req/s threshold applies to the detector’s rolling ${window_seconds}-second window. ` +
      'The traffic lines count observed HTTP 200 and 429 responses by arrival second.';
    if (threshold.textContent !== rule) threshold.textContent = rule;
    setStatus(transport);
  }

  function connect() {
    if (disposed) return;
    const url = new URL('/ws/dashboard?view=http-flood-traffic', location.href);
    url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    stream = new WebSocket(url);
    stream.addEventListener('message', event => {
      try {
        const state = JSON.parse(event.data);
        if (state.type !== 'HTTP_POLICY_TRAFFIC') return;
        render(state, 'Live');
        lastSocketUpdate = performance.now();
      } catch {
        // Polling supplies the current snapshot if the stream message is invalid.
      }
    });
    stream.addEventListener('close', () => {
      lastSocketUpdate = -Infinity;
      if (!disposed) {
        setStatus('Reconnecting');
        reconnect = setTimeout(connect, 3000);
      }
    });
  }

  const socketFresh = () => performance.now() - lastSocketUpdate < 2500;
  poll(async signal => {
    if (socketFresh()) return;
    render(await read('/api/attack-lab/verification/traffic', signal), 'Live · HTTP fallback');
  }, () => {
    if (!socketFresh()) setStatus(latest ? 'Connection interrupted · showing last update' : 'Lab telemetry unavailable');
  }, 1000);
  window.addEventListener('pagehide', () => {
    disposed = true;
    clearTimeout(reconnect);
    stream?.close();
  });
  connect();
})();
