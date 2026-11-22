/* Historical renderer from feature/sentinel-http-demo (cb37f89). */
(() => {
  const $ = id => document.getElementById(id);
  function chart(state) {
    const svg = $('hf-chart'), ns = 'http://www.w3.org/2000/svg';
    svg.replaceChildren();
    const points = state.samples || [], now = state.snapshot_at;
    const high = Math.max(5, state.thresholds.block_rps * 1.3, ...points.map(p => p.total_rps));
    function add(tag, attrs, value) {
      const node = document.createElementNS(ns, tag);
      Object.entries(attrs).forEach(([key, val]) => node.setAttribute(key, String(val)));
      if (value !== undefined) node.textContent = value;
      svg.appendChild(node);
    }
    const y = value => 194 - Math.min(high, value) / high * 172;
    for (let i=0; i<=4; i++) {
      const value = high*i/4;
      add('line', {x1:46,y1:y(value),x2:880,y2:y(value),stroke:'#254035'});
      add('text', {x:39,y:y(value)+4,fill:'#a0bcaf','font-size':11,'text-anchor':'end'}, String(Math.round(value)));
    }
    for (let i=0; i<=6; i++) add('text', {x:46+i*139,y:216,fill:'#a0bcaf','font-size':11}, i===6?'now':String((i-6)*10)+'s');
    add('line', {x1:46,y1:y(state.thresholds.block_rps),x2:880,y2:y(state.thresholds.block_rps),stroke:'#f2c967','stroke-dasharray':'6 5'});
    [['total_rps','#71ceff'],['accepted_rps','#7df1ad'],['blocked_rps','#ff857b']].forEach(([key,color]) => {
      const coords = points.filter(p => p.timestamp >= now-60).map(p =>
        (46+Math.max(0,Math.min(60,p.timestamp-now+60))/60*834).toFixed(1)+','+y(p[key]).toFixed(1)).join(' ');
      add('polyline', {points:coords,fill:'none',stroke:color,'stroke-width':2.5});
    });
    svg.dataset.samples = String(points.length);
    svg.dataset.total = String(state.total_rps);
    svg.dataset.accepted = String(state.accepted_rps);
    svg.dataset.blocked = String(state.blocked_rps);
  }
  window.SentinelHTTPFloodChart = chart;
})();
