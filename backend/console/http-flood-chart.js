(() => {
  const {id, svg} = window.SentinelConsole;
  const chart = id('hf-chart');
  const left = 46, right = 880, top = 22, base = 194;
  const grid = svg('g', {});
  const thresholdLine = svg('line', {x1: left, x2: right, stroke: '#f2c967', 'stroke-dasharray': '6 5'});
  const series = [
    ['total_rps', '#71ceff', 4], ['accepted_rps', '#7df1ad', 2.5], ['blocked_rps', '#ff857b', 2.5]
  ].map(([key, color, width]) => ({key, line: svg('polyline', {
    fill: 'none', stroke: color, 'stroke-width': width, 'stroke-linejoin': 'round'
  })}));
  chart.append(grid, thresholdLine, ...series.map(({line}) => line));
  for (let i = 0; i <= 6; i++) {
    chart.append(svg('text', {
      x: left + i * (right - left) / 6, y: 216, fill: '#a0bcaf', 'font-size': 11,
      'text-anchor': i === 0 ? 'start' : i === 6 ? 'end' : 'middle'
    }, i === 6 ? 'Now' : `${(i - 6) * 10}s`));
  }

  let scale;
  window.SentinelHTTPFloodChart = state => {
    const {buckets, snapshot_at: now, window_seconds: seconds, thresholds} = state;
    const peak = Math.max(thresholds.block_rps, ...buckets.map(bucket => bucket.total_rps));
    const step = Math.max(1, Math.ceil(peak / 5));
    const y = value => base - value / (5 * step) * (base - top);
    const x = timestamp => left + (timestamp - (now - seconds)) / seconds * (right - left);
    if (step !== scale) {
      const marks = [];
      for (let i = 0; i <= 5; i++) {
        const value = i * step;
        const row = y(value);
        marks.push(svg('line', {x1: left, x2: right, y1: row, y2: row, stroke: '#254035'}));
        marks.push(svg('text', {x: 39, y: row + 4, fill: '#a0bcaf', 'font-size': 11, 'text-anchor': 'end'}, value));
      }
      grid.replaceChildren(...marks);
      scale = step;
    }
    const thresholdY = y(thresholds.block_rps);
    thresholdLine.setAttribute('y1', thresholdY);
    thresholdLine.setAttribute('y2', thresholdY);
    for (const {key, line} of series) {
      const points = buckets.flatMap(bucket => {
        const start = x(Math.max(now - seconds, bucket.timestamp));
        const end = x(Math.min(now, bucket.timestamp + 1));
        const row = y(bucket[key]).toFixed(1);
        return [`${start.toFixed(1)},${row}`, `${end.toFixed(1)},${row}`];
      });
      line.setAttribute('points', points.join(' '));
    }
  };
})();
