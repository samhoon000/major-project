const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

test('Port Scan Activity renders the observed series and marker at the detection time', async () => {
  const nodes = new Map(['port-scan-chart', 'port-scan-chart-note', 'port-scan-events', 'port-scan-lab'].map(name =>
    [name, {replaceChildren(...children) { this.children = children; }, append(...children) { this.children = children; }}]));
  let rendered;
  const renderedFacts = new Map();
  const snapshot = {
    capture: 'running', samples: [
      {timestamp: 100.1, attempts: 2, unique_ports: 2, failed_attempts: 1},
      {timestamp: 102.1, attempts: 8, unique_ports: 8, failed_attempts: 3}
    ],
    events: [{type: 'detected', timestamp: 101.5, source: '192.0.2.10', destination: '192.0.2.20',
      message: 'Distinct-port and refused-port thresholds met.'}],
    sources: [{observation_id: 'observation-1', alert_id: 'alert-1'}],
    window_seconds: 30, distinct_threshold: 8, failed_port_threshold: 3
  };
  const context = {
    window: {
      SentinelConsole: {
        id: name => nodes.get(name), node: (tag, text) => ({tag, text, append(...children) { this.children = children; }}),
        status() {}, metrics() {}, facts(name, values) { renderedFacts.set(name, new Map(values)); },
        chart: (target, samples, colors, options) => { rendered = {samples, colors, options}; }
      },
      addEventListener() {}
    },
    fetch: async () => ({ok: true, json: async () => snapshot}),
    AbortSignal: {timeout: () => null},
    setTimeout() {}, clearTimeout() {}
  };
  vm.runInNewContext(fs.readFileSync('backend/console/port-scan.js', 'utf8'), context);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(JSON.stringify(rendered.samples), '[[2,2,1],[],[8,8,3]]');
  assert.equal(rendered.options.markers[0].index, 1);
  assert.match(nodes.get('port-scan-events').children[0].children[0].text, /192.0.2.10 → 192.0.2.20/);
  for (const panel of ['port-scan-lab-facts', 'port-scan-evidence']) {
    assert.equal(renderedFacts.get(panel).get('Observation ID'), 'observation-1');
    assert.equal(renderedFacts.get(panel).get('Alert ID'), 'alert-1');
  }
});
