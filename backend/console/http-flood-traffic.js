(() => {
  const {id, poll, read} = window.SentinelConsole;
  const note = id('hf-thresholds');
  let stream, reconnect, latest = 0, disposed = false;

  function render(state) {
    if (state.profile !== 'policy-verification' || state.snapshot_at < latest) return;
    latest = state.snapshot_at;
    window.SentinelHTTPFloodChart(state);
    const {block_rps, window_seconds} = state.thresholds;
    note.textContent = 'Lines show observed arrivals over the last second. The dashed ' +
      block_rps + ' req/s threshold applies to the test client averaged over ' +
      window_seconds + ' seconds. Accepted + blocked = total.';
  }

  function connect() {
    if (disposed) return;
    const url = new URL('/ws/dashboard', location.href);
    url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    stream = new WebSocket(url);
    stream.addEventListener('message', event => {
      try {
        const state = JSON.parse(event.data);
        if (state.type === 'HTTP_FLOOD_TELEMETRY') render(state);
      } catch {
        // Polling supplies the current snapshot if the stream message is invalid.
      }
    });
    stream.addEventListener('close', () => {
      if (!disposed) reconnect = setTimeout(connect, 3000);
    });
  }

  poll(async signal => render(await read('/api/attack-lab/verification', signal)), () => {
    if (stream?.readyState !== WebSocket.OPEN) note.textContent = 'Local lab telemetry unavailable.';
  }, 1000);
  window.addEventListener('pagehide', () => {
    disposed = true;
    clearTimeout(reconnect);
    stream?.close();
  });
  connect();
})();
