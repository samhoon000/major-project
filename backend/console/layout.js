(() => {
  const id = name => document.getElementById(name);
  function node(tag, text) {
    const result = document.createElement(tag);
    if (text != null) result.textContent = text;
    return result;
  }
  function svg(tag, attributes, text) {
    const result = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [name, value] of Object.entries(attributes)) result.setAttribute(name, value);
    if (text != null) result.textContent = text;
    return result;
  }
  function status(name, text, tone = '') {
    id(name).textContent = text;
    id(name).dataset.tone = tone;
  }
  function metrics(name, values) {
    id(name).replaceChildren(...values.map(([label, value]) => {
      const card = node('div');
      card.append(node('dt', label), node('dd', value ?? '—'));
      return card;
    }));
  }
  function facts(name, values) {
    id(name).replaceChildren(...values.flatMap(([key, value]) => [node('dt',key), node('dd',value ?? '—')]));
  }
  function chart(target, samples, colors, {windowLabel, kind = 'line', compact = false}) {
    const left = compact ? 30 : 65, top = 23, width = compact ? 310 : 820;
    const height = compact ? 105 : 145, base = top + height;
    const max = Math.max(1, Math.ceil(Math.max(0, ...samples.flat().filter(Number.isFinite))));
    const limit = max <= 2 ? max : Math.ceil(max / 4) * 4;
    const marks = [];
    for (const value of new Set([0, Math.floor(limit / 2), limit])) {
      const y = base - value / limit * height;
      marks.push(svg('line',{x1:left,x2:left+width,y1:y,y2:y,stroke:'#39516d'}));
      marks.push(svg('text',{x:left-10,y:y+5,'text-anchor':'end'},value));
    }
    const step = width / Math.max(1, samples.length);
    colors.forEach((color, index) => {
      if (kind === 'bars') {
        const bar = (step - 4) / colors.length;
        samples.forEach((sample, i) => {
          const value = sample[index];
          if (!value) return;
          const size = value / limit * height;
          const column = svg('rect',{x:left+i*step+index*bar+2,y:base-size,width:bar,height:size,fill:color});
          column.append(svg('title',{},value));
          marks.push(column);
        });
      } else {
        let path = '', pen = 'M';
        samples.forEach((sample, i) => {
          if (sample[index] == null) { pen = 'M'; return; }
          const x = left + step * (i + .5), y = base - sample[index] / limit * height;
          path += pen + x + ' ' + y + ' ';
          pen = 'L';
          marks.push(svg('circle',{cx:x,cy:y,r:2.7,fill:color}));
        });
        marks.push(svg('path',{d:path,fill:'none',stroke:color,'stroke-width':2.5}));
      }
    });
    const axisY = compact ? base + 25 : 201;
    marks.push(svg('text',{x:left,y:axisY},windowLabel));
    marks.push(svg('text',{x:left+width,y:axisY,'text-anchor':'end'},'Now'));
    target.replaceChildren(...marks);
  }
  function poll(callback, unavailable, interval = 2500) {
    let pending, timer, disposed = false;
    async function tick() {
      if (disposed || pending) return;
      clearTimeout(timer);
      if (!window.SentinelAuth.canView) { unavailable('Sign in to view telemetry'); return; }
      pending = new AbortController();
      try { await callback(AbortSignal.any([pending.signal, AbortSignal.timeout(5000)])); }
      catch { if (!disposed) unavailable('Connection unavailable'); }
      finally {
        pending = null;
        if (!disposed) timer = setTimeout(tick, interval);
      }
    }
    window.addEventListener('sentinel-auth-changed', () => {
      if (!window.SentinelAuth.canView) unavailable('Sign in to view telemetry');
      void tick();
    });
    window.SentinelAuth.ready.then(tick);
    window.addEventListener('pagehide', () => { disposed = true; pending?.abort(); clearTimeout(timer); });
  }
  async function read(url, signal) {
    const response = await window.SentinelAuth.fetch(url,{cache:'no-store',signal});
    if (!response.ok) throw new Error('HTTP ' + response.status);
    return response.json();
  }
  window.addEventListener('sentinel-auth-changed', event => {
    const operator = id('console-operator');
    operator.dataset.signedIn = event.detail.authenticated;
    operator.textContent = event.detail.authenticated ? 'Operator signed in' : 'Operator sign-in';
  });
  window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
  window.SentinelConsole = {id,node,svg,status,metrics,facts,chart,poll,read};
})();
