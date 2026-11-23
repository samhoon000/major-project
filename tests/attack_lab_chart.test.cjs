const {test} = require('node:test');
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const vm = require('node:vm');

const renderer = readFileSync('backend/console/http-flood-chart.js', 'utf8');
const monitor = readFileSync('backend/console/http-flood-traffic.js', 'utf8');
const lab = readFileSync('backend/console/attack-lab.js', 'utf8');

function snapshot(now, entries = {}) {
  const first = Math.floor(now - 60);
  const totals = {total: 0, accepted: 0, blocked: 0};
  const buckets = Array.from({length: 61}, (_, i) => {
    const timestamp = first + i;
    const [accepted, blocked] = entries[timestamp] ?? [0, 0];
    totals.total += accepted + blocked;
    totals.accepted += accepted;
    totals.blocked += blocked;
    return {timestamp, total_rps: accepted + blocked, accepted_rps: accepted, blocked_rps: blocked};
  });
  return {type: 'HTTP_POLICY_TRAFFIC', snapshot_at: now, window_seconds: 60, buckets, totals,
    thresholds: {block_rps: 0.75, window_seconds: 4}};
}

function svgNode(tag, attributes = {}, textContent) {
  return {
    tag, attributes, textContent, children: [],
    append(...nodes) { this.children.push(...nodes); },
    replaceChildren(...nodes) { this.children = nodes; },
    setAttribute(key, value) { this.attributes[key] = value; }
  };
}

test('idle buckets form a flat line and real bucket positions move left until expired', () => {
  const plot = svgNode('svg');
  const window = {SentinelConsole: {id: () => plot, svg: svgNode}};
  vm.runInNewContext(renderer, {window});
  const draw = window.SentinelHTTPFloodChart;
  const series = plot.children.filter(child => child.tag === 'polyline');
  const coordinates = line => line.attributes.points.split(' ');

  draw(snapshot(100.5));
  for (const line of series) {
    assert.equal(coordinates(line)[0], '46.0,194.0');
    assert.equal(coordinates(line).at(-1), '880.0,194.0');
    assert.ok(coordinates(line).every(point => point.endsWith(',194.0')));
  }

  const history = {100: [2, 5]};
  draw(snapshot(100.5, history));
  const ticks = plot.children[0].children.filter(node => node.tag === 'text').map(node => node.textContent);
  assert.deepEqual(ticks, [0, 2, 4, 6, 8, 10]);
  const threshold = plot.children.find(child => child.attributes['stroke-dasharray'] === '6 5');
  assert.equal(threshold.attributes.y1, 194 - 0.75 / 10 * 172);
  assert.deepEqual(series.map(line => coordinates(line).at(-1)), ['880.0,73.6', '880.0,159.6', '880.0,108.0']);
  draw(snapshot(101.5, history));
  assert.ok(coordinates(series[0]).includes('873.1,73.6'));
  assert.equal(coordinates(series[0]).at(-1), '880.0,194.0');
  draw(snapshot(161.5, history));
  assert.ok(coordinates(series[0]).every(point => point.endsWith(',194.0')));
  assert.deepEqual(plot.children.filter(child => child.tag === 'polyline'), series);
});

test('monitor renders an initial HTTP window, resumes with WebSocket, and keeps the newest snapshot', async () => {
  const elements = new Map();
  const sockets = [];
  const drawings = [];
  const windowEvents = {};
  let tick, nextConnect, now = 0, server = snapshot(100.5, {99: [2, 3]});
  const id = name => {
    if (!elements.has(name)) elements.set(name, {textContent: ''});
    return elements.get(name);
  };
  const window = {
    addEventListener(event, callback) { windowEvents[event] = callback; },
    SentinelHTTPFloodChart(state) { drawings.push(state.snapshot_at); },
    SentinelConsole: {
      id,
      poll(callback, _unavailable, interval) { assert.equal(interval, 1000); tick = callback; },
      async read(path) { assert.equal(path, '/api/attack-lab/verification/traffic'); return server; }
    }
  };
  class WebSocket {
    listeners = {};
    constructor(url) {
      assert.equal(url.href, 'ws://127.0.0.1:18001/ws/dashboard?view=http-flood-traffic');
      sockets.push(this);
    }
    addEventListener(event, callback) { this.listeners[event] = callback; }
    sendSnapshot(state) { this.listeners.message({data: JSON.stringify(state)}); }
    close() { this.listeners.close(); }
  }
  vm.runInNewContext(monitor, {
    window, URL, WebSocket, location: new URL('http://127.0.0.1:18001/dashboard/applications'),
    performance: {now: () => now}, setTimeout(callback) { nextConnect = callback; }, clearTimeout() {}
  });

  await tick();
  assert.equal(id('hf-window-total').textContent, 5);
  assert.equal(id('hf-window-accepted').textContent, 2);
  assert.equal(id('hf-window-blocked').textContent, 3);
  assert.equal(id('hf-traffic-status').textContent, 'Live · HTTP fallback');
  sockets[0].sendSnapshot(snapshot(101.5, {99: [2, 3], 101: [1, 0]}));
  assert.equal(id('hf-current-rate').textContent, 1);
  assert.match(id('hf-thresholds').textContent, /0.75 req\/s.*rolling 4-second window/);
  await tick();
  assert.deepEqual(drawings, [100.5, 101.5]);
  now += 3000;
  await tick();
  assert.deepEqual(drawings, [100.5, 101.5]);

  sockets[0].close();
  server = snapshot(102.5, {99: [2, 3], 101: [1, 0]});
  await tick();
  nextConnect();
  sockets[1].sendSnapshot(snapshot(103.5, {99: [2, 3], 101: [1, 0]}));
  assert.deepEqual(drawings, [100.5, 101.5, 102.5, 103.5]);
  assert.equal(id('hf-current-rate').textContent, 0);
  assert.equal(id('hf-window-total').textContent, 6);
  assert.equal(id('hf-traffic-status').textContent, 'Live');
  windowEvents.pagehide();
});

test('authenticated Cloudflare lab submits sequenced same-origin browser samples', async () => {
  const runId = '0123456789abcdef';
  const requests = [];
  const elements = new Map();
  const callbacks = {};
  let metrics, resolveSamples;
  const samples = new Promise(resolve => { resolveSamples = resolve; });
  const run = {run_id: runId, snapshot_at: 2, started_at: 2, running: true, owns_run: true,
    request_count: 5, config: {rate: 1, concurrency: 1}, timeline: [], run_source: 'cloudflare-browser',
    flood: {generated: 0, in_flight: 0, successful: 0, blocked: 0}};
  function id(name) {
    if (!elements.has(name)) {
      const element = Object.assign(svgNode('div'), {dataset: {}, handlers: {}, validity: {valid: true},
        valueAsNumber: 5, addEventListener(event, listener) { this.handlers[event] = listener; },
        reportValidity() { return true; }});
      if (name === 'lab-lifecycle') {
        element.children = Array.from({length: 5}, () => ({dataset: {}, querySelector() { return {}; }}));
      }
      elements.set(name, element);
    }
    return elements.get(name);
  }
  const auth = {local: false, remoteConsole: true, authenticated: false, async fetch(path, options) {
    const url = new URL(path, 'https://demo.example');
    const json = (body, status = 200) => ({ok: status < 300, status, json: async () => body});
    if (path === '/api/attack-lab/verification') return json({snapshot_at: 1, timeline: []});
    requests.push({url, method: options.method});
    if (url.pathname.endsWith('/start')) return json(run);
    const sequence = Number(url.searchParams.get('sequence'));
    if (sequence === 5) resolveSamples();
    return json({run_id: runId, sequence}, sequence >= 3 ? 429 : 200);
  }};
  const window = {SentinelAuth: auth, SentinelConsole: {id, node: svgNode, status() {},
    metrics(_, values) { metrics = values; }, facts() {}},
    addEventListener(name, callback) { callbacks[name] = callback; }};
  class WebSocket {
    constructor(url) { assert.equal(url.href, 'wss://demo.example/ws/dashboard?view=http-policy-run'); }
    addEventListener() {}
  }
  vm.runInNewContext(lab, {window, document: {body: {dataset: {labMode: 'browser'}}},
    location: new URL('https://demo.example/attack-lab'), URL, URLSearchParams, AbortSignal, AbortController, WebSocket,
    setTimeout(callback, interval) { if (interval === 1150) queueMicrotask(callback); }, clearTimeout() {}});
  await new Promise(setImmediate);
  assert.equal(id('lab-start').disabled, true);
  auth.authenticated = true;
  callbacks['sentinel-auth-changed']();
  assert.equal(id('lab-start').disabled, false);
  id('lab-start').handlers.click();
  await samples;
  assert.equal(requests[0].url.pathname, '/api/attack-lab/http-verification/start');
  assert.equal(requests[0].url.searchParams.get('request_count'), '5');
  const samplesSent = requests.slice(1);
  assert.ok(samplesSent.every(({url, method}) => url.origin === 'https://demo.example' &&
    url.pathname === '/api/attack-lab/http-verification/request' && method === 'POST' &&
    url.searchParams.get('run_id') === runId));
  assert.deepEqual(samplesSent.map(({url}) => Number(url.searchParams.get('sequence'))), [1, 2, 3, 4, 5]);
  assert.ok(metrics.some(([label]) => label === 'Mean server processing latency'));
});
