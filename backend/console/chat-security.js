(() => {
  const {id, node, status, metrics, facts, chart} = window.SentinelConsole;
  const auth = window.SentinelAuth;
  const eventTypes = {
    warning: ['Warning issued', 'Warning', 'warn'],
    message_blocked: ['Message rejected', 'Rejected', 'bad'],
    blocked: ['User blocked', 'Blocked', 'bad'],
    admin_unblocked: ['User unblocked', 'Restored', 'good']
  };
  const colors = ['#a6ceff', '#f9c37a', '#ffa2a7'];
  const compactChart = window.matchMedia('(max-width: 650px)');
  const details = id('chat-details');
  const pending = new Set();
  let snapshot, selected, opener, socket, retry, deadline, attempts = 0, disposed = false;
  let usersKey, eventsKey, blockedKey;

  function label(text, tone) {
    const element = node('span', text);
    element.className = 'chat-label';
    element.dataset.tone = tone;
    return element;
  }

  function renderEvents(target, events, empty) {
    target.replaceChildren(...events.map(event => {
      const [title, state, tone] = eventTypes[event.type];
      const item = node('li');
      const text = node('div');
      const time = new Date(event.timestamp * 1000);
      const date = node('time', time.toLocaleTimeString());
      date.dateTime = time.toISOString();
      date.title = time.toLocaleString();
      text.append(node('strong', title + (event.username ? ' · ' + event.username : '')),
        node('p', event.reason || (event.type === 'admin_unblocked' ? 'Operator restored access.' : '')));
      const metadata = node('div');
      metadata.className = 'chat-event-meta';
      metadata.append(date, label(state, tone));
      item.append(text, metadata);
      return item;
    }));
    if (!events.length) target.append(node('li', empty));
  }

  function emptyMessage(empty) {
    return snapshot ? empty : 'Waiting for live chat data.';
  }

  function showDetails(username, source) {
    selected = username;
    opener = source;
    renderDetails();
    details.showModal();
  }

  function renderDetails() {
    const user = snapshot?.users.find(user => user.username === selected);
    const blocked = snapshot?.blocked.find(user => user.username === selected);
    id('chat-details-title').textContent = selected;
    facts('chat-user-details', [
      ['Connection', !snapshot ? 'Unknown' : user ? 'Connected' : 'Offline'],
      ['Client IP', user?.client_ip],
      ['Messages inspected', (user || blocked)?.messages],
      ['Messages / second', user?.rate],
      ['Rate warning', user && !user.block_reason ? (user.warning ? 'Active' : 'None') : '—'],
      ['Block status', !snapshot ? 'Unknown' : blocked || user?.block_reason ? 'Blocked' : 'Clear'],
      ['Block reason', blocked?.reason || user?.block_reason]
    ]);
    renderEvents(id('chat-user-events'),
      (snapshot?.events || []).filter(event => event.username === selected).slice(0, 5),
      emptyMessage('No retained moderation events for this user.'));
  }

  function renderUsers(users) {
    const target = id('userRows');
    const focused = target.contains(document.activeElement) ? document.activeElement.dataset.username : null;
    target.replaceChildren(...users.map(user => {
      const row = node('tr');
      const risk = node('td');
      risk.append(user.block_reason ? label('Blocked', 'bad') :
        user.warning ? label('Warning', 'warn') : label('Normal', 'good'));
      const action = node('td');
      const button = node('button', 'Details');
      button.type = 'button';
      button.className = 'console-button chat-small';
      button.dataset.username = user.username;
      button.setAttribute('aria-label', 'Details for ' + user.username);
      button.onclick = () => showDetails(user.username, button);
      action.append(button);
      row.append(node('td', user.username), node('td', user.client_ip || '—'), node('td', 'Connected'),
        node('td', user.messages), node('td', user.rate), risk, action);
      return row;
    }));
    if (!users.length) {
      const row = node('tr');
      const cell = node('td', emptyMessage('No chat users connected.'));
      cell.colSpan = 7;
      row.append(cell);
      target.append(row);
    }
    if (focused) {
      const replacement = [...target.querySelectorAll('button')].find(button => button.dataset.username === focused);
      (replacement || target.closest('.console-table')).focus({preventScroll: true});
    }
  }

  async function unblock(username, button) {
    if (!auth.authenticated || !window.confirm('Unblock ' + username + ' and allow this account to reconnect?')) return;
    pending.add(username);
    status('chat-feedback', 'Restoring access for ' + username + '…');
    button.disabled = true;
    try {
      const response = await auth.fetch('/api/admin/unblock/' + encodeURIComponent(username),
        {method: 'POST', signal: AbortSignal.timeout(5000)});
      if (!response.ok) throw new Error('HTTP ' + response.status);
      status('chat-feedback', username + ' unblocked.', 'good');
    } catch (error) {
      status('chat-feedback', 'Could not unblock ' + username + ' · ' + error.message, 'bad');
    } finally {
      pending.delete(username);
      blockedKey = undefined;
      renderBlocked();
    }
  }

  function renderBlocked() {
    const blocked = snapshot?.blocked || [];
    const key = JSON.stringify([Boolean(snapshot), blocked, auth.authenticated]);
    if (key === blockedKey) return;
    blockedKey = key;
    id('chat-operator').hidden = !blocked.length || auth.authenticated;
    id('chat-blocked').replaceChildren(...blocked.map(user => {
      const item = node('li');
      const summary = node('div');
      summary.append(node('strong', user.username));
      if (user.reason) summary.append(node('p', user.reason));
      const actions = node('div');
      actions.className = 'console-actions';
      const inspect = node('button', 'Details');
      inspect.type = 'button';
      inspect.className = 'console-button chat-small';
      inspect.onclick = () => showDetails(user.username, inspect);
      actions.append(inspect);
      if (auth.authenticated) {
        const button = node('button', 'Unblock');
        button.type = 'button';
        button.className = 'console-button chat-small';
        button.disabled = pending.has(user.username);
        button.onclick = () => unblock(user.username, button);
        actions.append(button);
      }
      item.append(summary, actions);
      return item;
    }));
    if (!blocked.length) id('chat-blocked').append(node('li', emptyMessage('No accounts blocked.')));
  }

  function renderActivity() {
    const graph = id('chat-chart');
    const samples = snapshot?.samples || [];
    const bins = [];
    for (let index = 0; index < samples.length; index += 5) {
      const observed = samples.slice(index, index + 5).filter(sample => sample[0] !== null);
      bins.push(observed.length ?
        colors.map((_, series) => observed.reduce((sum, sample) => sum + sample[series], 0)) :
        [null, null, null]);
    }
    const observed = samples.filter(sample => sample[0] !== null);
    graph.toggleAttribute('hidden', !observed.length);
    if (observed.length) {
      const total = colors.map((_, index) => observed.reduce((sum, sample) => sum + sample[index], 0));
      graph.setAttribute('aria-label', 'Last 60 seconds. ' + total[0] + ' inspected, ' + total[1] +
        ' suspicious, ' + total[2] + ' rejected.');
      const compact = compactChart.matches;
      graph.setAttribute('viewBox', compact ? '0 0 350 165' : '0 0 920 215');
      chart(graph, bins, colors, {windowLabel: '60 sec ago', kind: 'bars', compact});
    } else {
      graph.replaceChildren();
    }
    id('chat-chart-note').textContent = !observed.length ? 'Waiting for live activity data.' :
      observed.some(sample => sample.some(Boolean)) ? '' : 'No messages observed in this window.';
  }

  function render(data, connection) {
    const previous = snapshot;
    snapshot = data;
    if (Boolean(previous) !== Boolean(data)) {
      status('chat-service', data ? 'Available' : 'Unknown', data ? 'good' : '');
    }
    if (!data || !previous) {
      status('chat-connection', data ? 'Connected' : connection, data ? 'good' : '');
    }
    const updated = id('chat-updated');
    if (data) {
      const time = new Date(data.timestamp * 1000);
      updated.textContent = time.toLocaleTimeString();
      updated.dateTime = time.toISOString();
    }
    const users = data?.users || [];
    metrics('chat-metrics', [
      ['Connected Users', data && users.length],
      ['Messages / Second', data?.rate],
      ['Suspicious Users', data?.suspicious],
      ['Blocked Users', data && data.blocked.length]
    ]);
    renderActivity();
    const nextUsers = JSON.stringify([Boolean(data), users]);
    if (nextUsers !== usersKey) {
      usersKey = nextUsers;
      renderUsers(users);
    }
    const events = data?.events || [];
    const nextEvents = JSON.stringify([Boolean(data), events]);
    if (nextEvents !== eventsKey) {
      eventsKey = nextEvents;
      const empty = emptyMessage('No moderation events recorded.');
      renderEvents(id('chat-events'), events.slice(0, 5), empty);
      renderEvents(id('chat-log'), events, empty);
    }
    renderBlocked();
    if (details.open) renderDetails();
  }

  function stop() {
    const previous = socket;
    socket = null;
    clearTimeout(retry);
    clearTimeout(deadline);
    previous?.close();
  }

  function connect() {
    if (disposed) return;
    if (!auth.canView) {
      stop();
      attempts = 0;
      if (details.open) details.close();
      id('chat-feedback').textContent = '';
      render(null, 'Operator sign-in required');
      return;
    }
    if (socket) {
      renderBlocked();
      return;
    }
    clearTimeout(retry);
    const url = new URL('/ws/dashboard?view=chat-security', location.href);
    url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const stream = new WebSocket(url);
    socket = stream;
    const watch = () => {
      clearTimeout(deadline);
      deadline = setTimeout(() => stream.close(), 8000);
    };
    watch();
    stream.onmessage = event => {
      if (socket !== stream || !auth.canView) return;
      try {
        const data = JSON.parse(event.data);
        if (data.type !== 'chat_security') return;
        render(data);
        watch();
        attempts = 0;
      } catch {
        stream.close();
      }
    };
    stream.onclose = () => {
      if (disposed || socket !== stream) return;
      stop();
      render(null, 'Offline · reconnecting');
      retry = setTimeout(connect, Math.min(15000, 1000 * 2 ** Math.min(attempts++, 4)));
    };
  }

  details.addEventListener('close', () => {
    const replacement = [...id('userRows').querySelectorAll('button')].find(button => button.dataset.username === selected);
    (opener?.isConnected ? opener : replacement || id('userRows').closest('.console-table')).focus();
    selected = opener = null;
  });
  render(null, 'Connecting');
  compactChart.addEventListener('change', renderActivity);
  window.addEventListener('sentinel-auth-changed', connect);
  auth.ready.then(connect);
  window.addEventListener('pagehide', () => { disposed = true; stop(); });
})();
