(() => {
  'use strict';

  const {id, node, status, facts, poll, read} = window.SentinelConsole;
  const endpoint = '/api/attack-lab/northfield-probe';
  const time = seconds => seconds ? new Date(seconds * 1000).toLocaleTimeString() : '—';
  const percent = value => typeof value === 'number' ? `${(value * 100).toFixed(2)}%` : '—';
  const outcomes = {waiting:'Waiting to send', running:'Waiting for HTTP headers', responded:'Response received',
    timed_out:'Timed out', connection_failed:'Connection failed', cancelled:'Cancelled'};
  let current;
  let updating = false;

  function render(data, message) {
    current = data;
    const run = data?.runs[0];
    const flow = run?.flows.find(item => item.network_inference);
    const inference = flow?.network_inference;
    const wait = Math.ceil(data?.cooldown_seconds ?? 0);
    status('probe-state', message ?? `Capture ${data.capture} · GATv2 ${data.model}`, data?.capture === 'running' ? 'good' : '');
    id('probe-start').disabled = !data || data.running || wait > 0 || updating;
    id('probe-start').textContent = wait && !data?.running ? `Check again in ${wait} s` : 'Check Northfield Health';
    id('probe-stop').disabled = !data?.running || updating;
    id('probe-reset').disabled = !data?.runs.length || updating;
    facts('probe-http', [['Endpoint', 'GET 127.0.0.1:8000/health'], ['Last response', run?.status ? `HTTP ${run.status}` : outcomes[run?.result]],
      ['Time to HTTP headers', run?.latency_ms == null ? null : `${run.latency_ms} ms`], ['Request ID', run?.request_id],
      ['Observed at', time(run?.finished_at)]]);
    facts('probe-capture', [['Interface', data?.interface], ['Capture detail', data?.capture_error || null],
      ['Packets captured · runtime', data?.packets], ['Graphs analyzed · runtime', data?.graphs],
      ['Latest matched inference', inference ? `${inference.prediction} · ${percent(inference.anomaly_probability)} anomaly score` : null],
      ['Inference timestamp', time(inference?.timestamp)], ['Saved threshold', percent(inference?.threshold)]]);
    const rows = (data?.runs ?? []).map(entry => {
      const row = node('tr');
      const flowCell = node('td');
      const modelCell = node('td');
      for (const item of entry.flows) {
        const details = `${item.source_ip}:${item.source_port} → ${item.destination_ip}:${item.destination_port}`;
        flowCell.append(node('div', details), node('div', `${item.total_packets} packets · ${item.total_bytes} bytes · ${(item.duration * 1000).toFixed(2)} ms`), node('code', item.flow_id));
        const model = item.network_inference;
        if (model) {
          modelCell.append(node('div', `${model.source} · ${model.prediction} · ${percent(model.anomaly_probability)}`),
            node('div', `${time(model.timestamp)} · ${model.nodes} nodes · ${model.edges} edges`), node('code', model.graph_id));
        } else modelCell.append(node('div', item.gatv2_status ?? 'Awaiting flow completion'));
      }
      if (!entry.flows.length) {
        flowCell.textContent = 'No matching packet evidence yet';
        modelCell.textContent = '—';
      }
      const response = entry.status ? `HTTP ${entry.status} · ${entry.latency_ms} ms` : outcomes[entry.result];
      row.append(node('td', entry.id), node('td', response), flowCell, modelCell);
      return row;
    });
    if (!rows.length) {
      const row = node('tr');
      const cell = node('td', 'Run a health check to record an observation.');
      cell.colSpan = 4;
      row.append(cell);
      rows.push(row);
    }
    id('probe-runs').replaceChildren(...rows);
  }

  async function refresh(signal) {
    if (!window.SentinelAuth.authenticated) {
      render(undefined, 'Sign in as a local operator');
      return;
    }
    const data = await read(endpoint, signal);
    if (window.SentinelAuth.authenticated) render(data);
  }

  async function command(action) {
    updating = true;
    render(current);
    try {
      const response = await window.SentinelAuth.fetch(`${endpoint}/${action}`, {
        method:'POST', signal:AbortSignal.timeout(5000),
      });
      if (!response.ok) throw new Error((await response.json()).detail || `HTTP ${response.status}`);
      await refresh(AbortSignal.timeout(5000));
      status('probe-feedback', action === 'start' ? 'Waiting for the response and matching capture.' : '');
    } catch (error) {
      status('probe-feedback', error.message, 'warn');
    } finally {
      updating = false;
      if (current) render(current);
    }
  }

  id('probe-start').addEventListener('click', () => void command('start'));
  id('probe-stop').addEventListener('click', () => void command('stop'));
  id('probe-reset').addEventListener('click', () => void command('reset'));
  render(undefined, 'Sign in as a local operator');
  poll(refresh, message => render(undefined, message), 1500);
})();
