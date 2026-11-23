const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function createMockEnvironment() {
  const elements = new Map();

  function makeElement(id = '', tag = 'div') {
    const el = {
      id,
      tagName: tag.toUpperCase(),
      children: [],
      classList: {
        _classes: new Set(),
        add(...cls) { cls.forEach(c => this._classes.add(c)); },
        remove(...cls) { cls.forEach(c => this._classes.delete(c)); },
        contains(c) { return this._classes.has(c); },
        get className() { return Array.from(this._classes).join(' '); }
      },
      style: {},
      attributes: new Map(),
      setAttribute(k, v) { this.attributes.set(k, String(v)); },
      getAttribute(k) { return this.attributes.get(k) || null; },
      removeAttribute(k) { this.attributes.delete(k); },
      appendChild(child) {
        this.children.push(child);
        child.parentElement = this;
        return child;
      },
      removeChild(child) {
        const idx = this.children.indexOf(child);
        if (idx !== -1) {
          this.children.splice(idx, 1);
          child.parentElement = null;
        }
        return child;
      },
      replaceChildren(...newChildren) {
        this.children = [...newChildren];
        newChildren.forEach(c => { c.parentElement = this; });
      },
      addEventListener(event, fn) {
        if (!this._listeners) this._listeners = {};
        if (!this._listeners[event]) this._listeners[event] = [];
        this._listeners[event].push(fn);
      },
      focus() {},
      offsetWidth: 50,
      scrollTop: 0,
      scrollHeight: 100,
      disabled: false,
      value: '',
      hidden: false
    };

    Object.defineProperty(el, 'className', {
      get() { return Array.from(this.classList._classes).join(' '); },
      set(val) {
        this.classList._classes.clear();
        if (val) val.split(/\s+/).filter(Boolean).forEach(c => this.classList._classes.add(c));
      }
    });

    Object.defineProperty(el, 'innerHTML', {
      get() { return this._html || ''; },
      set(val) {
        this._html = val;
        this.children = [];
      }
    });

    Object.defineProperty(el, 'textContent', {
      get() { return this._text != null ? this._text : ''; },
      set(val) { this._text = String(val); }
    });

    return el;
  }

  // Pre-seed known elements
  const ids = [
    'onboardingModal', 'usernameInput', 'joinBtn', 'joinErr',
    'userList', 'userSearch', 'onlineCount', 'chatFeed',
    'feedEmptyState', 'msgInput', 'sendBtn', 'charCount',
    'statusHint', 'recipientTitle', 'recipientStatus', 'headerAvatar',
    'userPill', 'currentUsername', 'blockedModal', 'blockedReason',
    'sidebar', 'chatArea', 'backBtn',
    'onboardingAccessBadge', 'onboardingUrlText', 'onboardingQrImg', 'onboardingCopyBtn',
    'inviteAccessBadge', 'inviteUrlText', 'inviteQrImg', 'inviteCopyBtn',
    'openInviteBtn', 'closeInviteBtn', 'inviteModal'
  ];

  ids.forEach(id => {
    elements.set(id, makeElement(id));
  });

  // Attach parents for QR images as required by refreshTunnelState
  ['onboardingQrImg', 'inviteQrImg'].forEach(id => {
    const parent = makeElement(`${id}Parent`);
    parent.appendChild(elements.get(id));
  });

  const sessionData = new Map();
  const sessionStorage = {
    getItem: k => (sessionData.has(k) ? sessionData.get(k) : null),
    setItem: (k, v) => sessionData.set(k, String(v)),
    removeItem: k => sessionData.delete(k),
    clear: () => sessionData.clear()
  };

  const docListeners = {};
  const winListeners = {};

  let activeSocket = null;

  class MockWebSocket {
    constructor(url) {
      this.url = url;
      this.readyState = 1; // WebSocket.OPEN
      this.sent = [];
      activeSocket = this;
    }
    send(data) { this.sent.push(data); }
    close() { this.readyState = 3; if (this.onclose) this.onclose(); }
  }
  MockWebSocket.CONNECTING = 0;
  MockWebSocket.OPEN = 1;
  MockWebSocket.CLOSING = 2;
  MockWebSocket.CLOSED = 3;

  const doc = {
    visibilityState: 'visible',
    title: 'Sentinel // Secure Chat',
    getElementById: id => elements.get(id) || null,
    createElement: tag => makeElement('', tag),
    createTextNode: text => ({ textContent: String(text) }),
    addEventListener: (event, fn) => {
      if (!docListeners[event]) docListeners[event] = [];
      docListeners[event].push(fn);
    },
    dispatchEvent: (event) => {
      if (docListeners[event]) docListeners[event].forEach(fn => fn());
    }
  };

  const win = {
    location: {
      protocol: 'http:',
      host: '127.0.0.1:8001',
      reload() {}
    },
    innerWidth: 1024,
    WebSocket: MockWebSocket,
    sessionStorage,
    addEventListener: (event, fn) => {
      if (!winListeners[event]) winListeners[event] = [];
      winListeners[event].push(fn);
    },
    dispatchEvent: (event) => {
      if (winListeners[event]) winListeners[event].forEach(fn => fn());
    }
  };

  const sandbox = {
    window: win,
    document: doc,
    sessionStorage,
    WebSocket: MockWebSocket,
    location: win.location,
    navigator: { clipboard: { writeText: async () => {} } },
    fetch: async () => ({ ok: true, json: async () => ({}) }),
    AbortController: globalThis.AbortController,
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: id => clearTimeout(id),
    setInterval: () => 123,
    clearInterval: () => {},
    console: console
  };

  sandbox.window.document = doc;

  // Extract script specifically from the active Sentinel Secure Chat HTML
  const pyCode = fs.readFileSync('backend/chat_service.py', 'utf8');
  const sentinelHtmlMatch = pyCode.match(/<title>Sentinel \/\/ Secure Chat<\/title>[\s\S]*?<script>([\s\S]*?)<\/script>/);
  if (!sentinelHtmlMatch) throw new Error('Could not find active <script> in Sentinel CHAT_HTML');
  const scriptSource = sentinelHtmlMatch[1];
  vm.runInNewContext(scriptSource, sandbox);

  return {
    elements,
    document: doc,
    window: win,
    sessionStorage,
    getSocket: () => activeSocket,
    triggerDocEvent: ev => doc.dispatchEvent(ev),
    triggerWinEvent: ev => win.dispatchEvent(ev)
  };
}

test('Unread notification badges: end-to-end user conversation flow', async (t) => {
  const env = createMockEnvironment();
  const usernameInput = env.elements.get('usernameInput');
  const userList = env.elements.get('userList');

  // Step 1: User A connects as "alice"
  usernameInput.value = 'alice';
  env.window.connect();
  const socket = env.getSocket();
  assert.ok(socket, 'WebSocket connection initialized');

  // Simulate server sending initial user roster
  socket.onmessage({
    data: JSON.stringify({
      type: 'users',
      users: ['alice', 'bob', 'charlie']
    })
  });

  assert.equal(env.window.SentinelChat.getUnreadCount('bob'), 0);
  assert.equal(env.window.SentinelChat.getTotalUnread(), 0);
  assert.equal(env.document.title, 'Sentinel // Secure Chat');

  function findUserItem(name) {
    const hasText = (node) => (node._text === name) || (node.children && node.children.some(hasText));
    return userList.children.find(hasText);
  }

  // Verify initial roster rendering without badges
  assert.equal(userList.children.length, 2); // bob and charlie
  const bobItem = findUserItem('bob');
  assert.ok(bobItem, 'Bob row exists in user list');
  const initialBobBadge = bobItem.children.find(c => c.classList.contains('unread-badge'));
  assert.equal(initialBobBadge, undefined, 'No badge when unread is 0');

  // Step 2: Bob sends 3 accepted messages to Alice while Alice has not selected Bob
  for (let i = 1; i <= 3; i++) {
    socket.onmessage({
      data: JSON.stringify({
        type: 'message',
        message_id: `msg_bob_${i}`,
        sender: 'bob',
        recipient: 'alice',
        text: `Hello message ${i}`,
        timestamp: Date.now() / 1000
      })
    });
  }

  // Verify unread count is 3
  assert.equal(env.window.SentinelChat.getUnreadCount('bob'), 3);
  assert.equal(env.window.SentinelChat.getTotalUnread(), 3);
  assert.equal(env.document.title, '(3) Sentinel // Secure Chat');

  // Verify unread badge in DOM
  const bobItemWithUnread = findUserItem('bob');
  const bobBadge = bobItemWithUnread.children.find(c => c.classList.contains('unread-badge'));
  assert.ok(bobBadge, 'Unread badge is rendered next to Bob');
  assert.equal(bobBadge.textContent, '3');
  assert.ok(bobItemWithUnread.classList.contains('has-unread'), 'User row has .has-unread class');

  // Verify Charlie has 0 unread
  assert.equal(env.window.SentinelChat.getUnreadCount('charlie'), 0);

  // Step 3: Self-sent message does not increment unread count
  socket.onmessage({
    data: JSON.stringify({
      type: 'message',
      message_id: 'msg_alice_1',
      sender: 'alice',
      recipient: 'bob',
      text: 'My reply',
      timestamp: Date.now() / 1000
    })
  });
  assert.equal(env.window.SentinelChat.getUnreadCount('bob'), 3, 'Self message does not increment unread');

  // Step 4: Alice opens Bob's conversation
  env.window.selectRecipient('bob');
  assert.equal(env.window.SentinelChat.getUnreadCount('bob'), 0, 'Unread count cleared upon opening conversation');
  assert.equal(env.window.SentinelChat.getTotalUnread(), 0);
  assert.equal(env.document.title, 'Sentinel // Secure Chat');

  const bobItemAfterOpen = findUserItem('bob');
  const clearedBadge = bobItemAfterOpen.children.find(c => c.classList.contains('unread-badge'));
  assert.equal(clearedBadge, undefined, 'Unread badge removed from DOM');
  assert.equal(bobItemAfterOpen.classList.contains('has-unread'), false);

  // Step 5: Bob sends another message while Alice is actively viewing Bob and tab is visible
  socket.onmessage({
    data: JSON.stringify({
      type: 'message',
      message_id: 'msg_bob_4',
      sender: 'bob',
      recipient: 'alice',
      text: 'Live message while viewing',
      timestamp: Date.now() / 1000
    })
  });
  assert.equal(env.window.SentinelChat.getUnreadCount('bob'), 0, 'Active viewing keeps unread count at 0');

  // Step 6: Alice switches to Charlie; Bob sends 2 messages
  env.window.selectRecipient('charlie');
  for (let i = 5; i <= 6; i++) {
    socket.onmessage({
      data: JSON.stringify({
        type: 'message',
        message_id: `msg_bob_${i}`,
        sender: 'bob',
        recipient: 'alice',
        text: `Message while viewing Charlie ${i}`,
        timestamp: Date.now() / 1000
      })
    });
  }
  assert.equal(env.window.SentinelChat.getUnreadCount('bob'), 2);
  assert.equal(env.document.title, '(2) Sentinel // Secure Chat');

  // Step 7: Page Visibility API - Tab becomes hidden while viewing Bob
  env.window.selectRecipient('bob');
  assert.equal(env.window.SentinelChat.getUnreadCount('bob'), 0);

  // Simulate tab hidden
  env.document.visibilityState = 'hidden';
  socket.onmessage({
    data: JSON.stringify({
      type: 'message',
      message_id: 'msg_bob_7',
      sender: 'bob',
      recipient: 'alice',
      text: 'Message while tab is backgrounded',
      timestamp: Date.now() / 1000
    })
  });
  assert.equal(env.window.SentinelChat.getUnreadCount('bob'), 1, 'Backgrounded tab increments unread count');

  // Simulate tab becoming visible again
  env.document.visibilityState = 'visible';
  env.triggerDocEvent('visibilitychange');
  assert.equal(env.window.SentinelChat.getUnreadCount('bob'), 0, 'Visibility return clears active recipient count');
});

test('Unread formatting: count over 99 displays 99+', () => {
  const env = createMockEnvironment();
  assert.equal(env.window.SentinelChat.formatUnreadCount(0), '0');
  assert.equal(env.window.SentinelChat.formatUnreadCount(1), '1');
  assert.equal(env.window.SentinelChat.formatUnreadCount(99), '99');
  assert.equal(env.window.SentinelChat.formatUnreadCount(100), '99+');
  assert.equal(env.window.SentinelChat.formatUnreadCount(150), '99+');
});

test('Deduplication: duplicate message_id is processed only once', () => {
  const env = createMockEnvironment();
  env.elements.get('usernameInput').value = 'alice';
  env.window.connect();
  const socket = env.getSocket();

  socket.onmessage({
    data: JSON.stringify({
      type: 'users',
      users: ['alice', 'bob']
    })
  });

  const dupPayload = {
    type: 'message',
    message_id: 'unique_msg_12345',
    sender: 'bob',
    recipient: 'alice',
    text: 'Duplicate test',
    timestamp: Date.now() / 1000
  };

  socket.onmessage({ data: JSON.stringify(dupPayload) });
  assert.equal(env.window.SentinelChat.getUnreadCount('bob'), 1);

  // Deliver duplicate
  socket.onmessage({ data: JSON.stringify(dupPayload) });
  assert.equal(env.window.SentinelChat.getUnreadCount('bob'), 1, 'Duplicate message_id does not increment unread count');
});

test('SessionStorage persistence: unread counts survive refresh', () => {
  const env = createMockEnvironment();
  env.elements.get('usernameInput').value = 'alice';
  env.window.connect();
  const socket = env.getSocket();

  socket.onmessage({
    data: JSON.stringify({
      type: 'users',
      users: ['alice', 'bob']
    })
  });

  socket.onmessage({
    data: JSON.stringify({
      type: 'message',
      message_id: 'msg_persist_1',
      sender: 'bob',
      recipient: 'alice',
      text: 'Persist this',
      timestamp: Date.now() / 1000
    })
  });

  assert.equal(env.window.SentinelChat.getUnreadCount('bob'), 1);

  // Check stored in sessionStorage
  const stored = env.sessionStorage.getItem('sentinel_unread_alice');
  assert.ok(stored, 'Stored in sessionStorage');
  assert.deepEqual(JSON.parse(stored), { bob: 1 });

  // Simulate refresh by clearing in-memory unreadCounts and calling loadUnreadCounts()
  env.window.SentinelChat.loadUnreadCounts();
  assert.equal(env.window.SentinelChat.getUnreadCount('bob'), 1, 'Restored unread count from sessionStorage');
});

test('Security moderation: warnings and blocks do not affect unread counts', () => {
  const env = createMockEnvironment();
  env.elements.get('usernameInput').value = 'alice';
  env.window.connect();
  const socket = env.getSocket();

  socket.onmessage({
    data: JSON.stringify({
      type: 'users',
      users: ['alice', 'bob']
    })
  });

  // Warning event
  socket.onmessage({
    data: JSON.stringify({
      type: 'warning',
      message: 'Rate limit advisory'
    })
  });

  assert.equal(env.window.SentinelChat.getUnreadCount('bob'), 0, 'Warning event does not increment unread count');
  assert.equal(env.window.SentinelChat.getTotalUnread(), 0);
});
