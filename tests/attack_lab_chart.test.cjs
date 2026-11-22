const {test} = require('node:test');
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const vm = require('node:vm');

const standalone = readFileSync('backend/console/http-flood-chart.js', 'utf8').replaceAll('\r', '');
const legacy = readFileSync('backend/static/http_flood.js', 'utf8').replaceAll('\r', '');
const chartFunction = source => source.match(/  function chart\(state\) \{[\s\S]*?\n  \}/)[0];

test('Monitored Applications keeps the original SVG renderer and the last-minute chart window', () => {
  assert.equal(chartFunction(standalone), chartFunction(legacy));
  const plot = {
    dataset: {},
    children: [],
    replaceChildren() { this.children.length = 0; },
    appendChild(child) { this.children.push(child); }
  };
  const context = {
    window: {},
    document: {
      getElementById(id) { assert.equal(id, 'hf-chart'); return plot; },
      createElementNS(_, tag) {
        return {tag, attributes: {}, setAttribute(key, value) { this.attributes[key] = value; }};
      }
    }
  };
  vm.runInNewContext(standalone, context);
  const chart = context.window.SentinelHTTPFloodChart;
  const state = {
    snapshot_at: 100, total_rps: 1, accepted_rps: 0, blocked_rps: 1, thresholds: {block_rps: 0.75},
    samples: [
      {timestamp: 39, total_rps: 2, accepted_rps: 2, blocked_rps: 0},
      {timestamp: 70, total_rps: 1, accepted_rps: 1, blocked_rps: 0},
      {timestamp: 100, total_rps: 1, accepted_rps: 0, blocked_rps: 1}
    ]
  };
  chart(state);
  const series = () => plot.children.filter(child => child.tag === 'polyline').map(child => child.attributes);
  assert.deepEqual(series().map(line => [line.stroke, line.points]), [
    ['#71ceff', '463.0,159.6 880.0,159.6'],
    ['#7df1ad', '463.0,159.6 880.0,194.0'],
    ['#ff857b', '463.0,194.0 880.0,159.6']
  ]);
  const threshold = plot.children.find(child => child.attributes.stroke === '#f2c967');
  assert.equal(threshold.attributes['stroke-dasharray'], '6 5');
  chart({...state, samples: [], total_rps: 0, accepted_rps: 0, blocked_rps: 0});
  assert.equal(plot.dataset.samples, '0');
  assert.ok(series().every(line => line.points === ''));
});
