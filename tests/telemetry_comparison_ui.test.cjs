const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');

const dashboard = fs.readFileSync('backend/telemetry/dashboard.html', 'utf8');
const comparison = dashboard.slice(dashboard.indexOf('  function renderComparison('),
  dashboard.indexOf('  function render()'));

test('signed comparison requires matching application, request and recovery scope', () => {
  const nodes = new Map();
  const byId = id => {
    if (!nodes.has(id)) nodes.set(id, {
      value: '',
      replaceChildren(...children) { this.children = children; },
      append(child) { this.children.push(child); },
    });
    return nodes.get(id);
  };
  const blocked = {request_id: 'one', subject: 'student-a', method: 'POST', route: '/access', status: 429, timestamp: 1};
  const restored = {...blocked, request_id: 'two', status: 204, timestamp: 2};
  const app = {id: 'northfield-staging', events: [blocked, restored]};
  const receipt = {request_id: 'one', outcome: 'rate_limited', revision: 2};
  const recovery = {...restored, revision: 3};
  const comparisonChannels = [
    {app: 'other-staging', receipts: [receipt], recoveries: [recovery]},
    {app: app.id, receipts: [], recoveries: [{...recovery, subject: 'student-b'}]},
  ];
  const context = vm.createContext({
    byId, comparisonChannels, app, localTime: String,
    element: (_tag, value) => value,
  });
  vm.runInContext(comparison, context);
  byId('compare-first').value = 'one';
  byId('compare-second').value = 'two';
  const first = byId('compare-first-result');
  const second = byId('compare-second-result');
  vm.runInContext('renderComparison(app)', context);
  assert.ok(first.children.includes('HTTP 429'));
  assert.ok(first.children.includes('1'));
  assert.equal(first.children.length, 5);
  assert.equal(second.children.length, 5);

  comparisonChannels[1].receipts = [receipt];
  comparisonChannels[1].recoveries = [recovery];
  vm.runInContext('renderComparison(app)', context);
  assert.ok(first.children.includes('Signed enforcement receipt · Revision 2'));
  assert.ok(second.children.includes('Verified recovery · Revision 3'));
  vm.runInContext('renderComparison(undefined)', context);
  assert.equal(byId('compare-first').value, '');
  assert.equal(first.textContent, 'Enter a request ID.');
});
