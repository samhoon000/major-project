const {test} = require('node:test');
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const vm = require('node:vm');

const chat = readFileSync('backend/chat_service.py', 'utf8');
const invitationScript = chat.slice(chat.indexOf('let inviteLink = null;'), chat.indexOf("const openInviteBtn = $('openInviteBtn');"));

function harness() {
  const elements = new Map();
  const copied = [];
  let now = 0;
  let request;
  let requests = 0;
  function id(name) {
    if (!elements.has(name)) {
      const attributes = new Map();
      const listeners = {};
      elements.set(name, {
        listeners, parentElement: {hidden: true}, assignments: [], textContent: '', complete: true, naturalWidth: 160,
        getAttribute(key) { return attributes.get(key); },
        removeAttribute(key) { attributes.delete(key); },
        set src(value) { attributes.set('src', value); this.assignments.push(value); },
        set href(value) { attributes.set('href', value); },
        addEventListener(event, fn) { listeners[event] = fn; }
      });
    }
    return elements.get(name);
  }
  const window = {};
  vm.runInNewContext(invitationScript + '\nwindow.refreshInvite = refreshTunnelState;', {
    window, $: id, AbortController, Date: {now: () => now},
    fetch: () => { requests++; return request(); },
    setTimeout() {}, clearTimeout() {}, navigator: {clipboard: {async writeText(value) { copied.push(value); }}}
  });
  return {
    id, copied, window, get requests() { return requests; }, advance(ms) { now += ms; },
    respond(data) { request = () => Promise.resolve({ok: true, json: () => Promise.resolve(data)}); },
    fail() { request = () => Promise.reject(new Error('network unavailable')); },
    pending(fn) { request = fn; }
  };
}

const first = {active_joining_url: 'https://first-demo.example/chat', qr_url: '/api/tunnel/qr.svg?v=first',
  joining_mode: 'public_https', sharing_state: 'connected', share_valid_for: 90};
const second = {...first, active_joining_url: 'https://second-demo.example/chat', qr_url: '/api/tunnel/qr.svg?v=second'};

test('a failed status poll retains the same QR and Copy Link until the bounded grace expires', async () => {
  const app = harness();
  const qr = app.id('onboardingQrImg');
  app.respond(first);
  await app.window.refreshInvite();
  qr.listeners.load();
  app.fail();
  app.advance(20000);
  await app.window.refreshInvite();
  assert.equal(qr.parentElement.hidden, false);
  assert.deepEqual(qr.assignments, [first.qr_url]);
  assert.equal(app.id('onboardingAccessBadge').textContent, 'Checking connection');
  await app.window.copyJoinUrl('onboardingCopyBtn');
  assert.deepEqual(app.copied, [first.active_joining_url]);
  app.advance(70000);
  await app.window.refreshInvite();
  assert.equal(qr.parentElement.hidden, true);
  assert.equal(app.id('onboardingCopyBtn').disabled, true);
  assert.match(app.id('onboardingAccessBadge').textContent, /Disconnected/);
});

test('status polling is single-flight and a verified URL change replaces both QR and link', async () => {
  const app = harness();
  let settle;
  app.pending(() => new Promise(resolve => { settle = resolve; }));
  const inFlight = app.window.refreshInvite();
  await app.window.refreshInvite();
  assert.equal(app.requests, 1);
  settle({ok: true, json: () => Promise.resolve(first)});
  await inFlight;
  const qr = app.id('inviteQrImg');
  qr.listeners.load();
  app.respond({...first, sharing_state: 'reconnecting'});
  await app.window.refreshInvite();
  assert.deepEqual(qr.assignments, [first.qr_url]);
  app.respond(second);
  await app.window.refreshInvite();
  assert.deepEqual(qr.assignments, [first.qr_url, second.qr_url]);
  qr.listeners.error();
  assert.equal(qr.parentElement.hidden, true);
  await app.window.refreshInvite();
  qr.listeners.load();
  assert.equal(qr.parentElement.hidden, false);
  assert.equal(app.id('inviteUrlText').getAttribute('href'), second.active_joining_url);
  await app.window.copyJoinUrl('inviteCopyBtn');
  assert.deepEqual(app.copied, [second.active_joining_url]);
  app.respond({sharing_state: 'disconnected', share_valid_for: 0});
  await app.window.refreshInvite();
  assert.equal(qr.parentElement.hidden, true);
  assert.equal(app.id('inviteCopyBtn').disabled, true);
});
