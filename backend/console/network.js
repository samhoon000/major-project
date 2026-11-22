(() => {
  const {id,node,svg,status,metrics,facts,chart,poll,read} = window.SentinelConsole;
  const interval = 2.5;
  const samples = new Map();
  let previousTopology = '';
  const observedAt = stamp => stamp ? new Date(stamp * 1000).toLocaleTimeString() : '—';
  const score = value => typeof value === 'number' ? (value * 100).toFixed(1) + '%' : '—';
  const label = value => value === 'ATTACK' ? 'Suspicious' : value === 'BENIGN' ? 'Benign' : 'Not analyzed';

  function topology(flows, message) {
    const available = flows.filter(flow => flow.source_ip && flow.destination_ip);
    const pairMap = new Map();
    for (const flow of available) {
      const key = flow.source_ip + ' → ' + flow.destination_ip;
      const existing = pairMap.get(key);
      if (!existing || existing.gatv2_prediction !== 'ATTACK' && flow.gatv2_prediction === 'ATTACK') pairMap.set(key,flow);
    }
    const visible = [...pairMap.values()].slice(0,9);
    const key = JSON.stringify([message,visible.map(flow => [flow.source_ip,flow.destination_ip,flow.gatv2_prediction,flow.protocol])]);
    if (previousTopology === key) return;
    previousTopology = key;
    const surface = id('network-topology');
    surface.replaceChildren();
    surface.style.display = visible.length ? '' : 'none';
    id('network-selection').textContent = visible.length ? 'Select a host or connection for details.' : message || 'No captured flows yet.';
    if (!visible.length) return;
    const nodes = (field,x) => [...new Set(visible.map(flow => flow[field]))]
      .map((address,index,items) => ({address,x,y:50 + (index + 1) * 245 / (items.length + 1)}));
    const sources = nodes('source_ip',105), destinations = nodes('destination_ip',665);
    surface.append(svg('text',{x:105,y:27,'text-anchor':'middle'},'Sources'),
      svg('text',{x:665,y:27,'text-anchor':'middle'},'Destinations'));
    function selectable(shape, text) {
      shape.setAttribute('tabindex','0');
      shape.setAttribute('role','button');
      shape.setAttribute('aria-label',text);
      const select = () => { id('network-selection').textContent = text; };
      shape.addEventListener('click',select);
      shape.addEventListener('keydown',event => {
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(); }
      });
      surface.append(shape);
    }
    for (const flow of visible) {
      const source = sources.find(item => item.address === flow.source_ip);
      const destination = destinations.find(item => item.address === flow.destination_ip);
      const anomaly = flow.gatv2_prediction === 'ATTACK';
      const line = svg('line',{x1:source.x,y1:source.y,x2:destination.x,y2:destination.y,
        stroke:anomaly ? '#ffa2a7' : '#79aadc','stroke-width':anomaly ? 5 : 3});
      selectable(line,source.address + ' → ' + destination.address + ' · ' + (flow.protocol || 'Flow') + ' · ' + label(flow.gatv2_prediction));
    }
    for (const [group, hosts] of [['Source',sources],['Destination',destinations]]) {
      hosts.forEach(({address,x,y},index) => {
        selectable(svg('circle',{cx:x,cy:y,r:15,fill:'#223955',stroke:'#a6ceff','stroke-width':2}),group + ' · ' + address);
        surface.append(svg('text',{x,y:y+5,'text-anchor':'middle'},index + 1));
      });
    }
  }

  function render(data, message) {
    const running = data?.capture === 'running';
    const model = data?.gatv2 === 'available';
    const capture = !data ? message : running ? 'Capture active' : data.capture === 'starting' ? 'Capture starting' : 'Capture inactive';
    status('network-connection',capture,running ? 'good' : '');
    const completed = (data?.completed_flows || []).slice().reverse().map(flow => {
      const inference = flow.network_inference;
      return inference ? {...flow, gatv2_status:'analyzed', gatv2_prediction:inference.prediction,
        gatv2_analyzed_at:inference.timestamp, gatv2_anomaly_probability:inference.anomaly_probability,
        gatv2_threshold:inference.threshold, graph_nodes:inference.nodes, graph_edges:inference.edges} : flow;
    });
    const latest = completed.find(flow => flow.gatv2_status === 'analyzed');
    const predictions = data?.gatv2_analyses;
    const suspicious = data?.gatv2_network_anomalies ?? data?.gatv2_anomalies;
    const stages = [
      [data?.packets > 0, data?.packets > 0 ? data.packets + ' captured' : 'Waiting for packets'],
      [completed.length > 0, completed.length ? completed.length + ' completed · retained' : 'Waiting for flows'],
      [data?.gatv2_graphs > 0, data?.gatv2_graphs > 0 ? data.gatv2_graphs + ' built' : 'Waiting for graphs'],
      [model, model ? 'Model loaded' : 'Unavailable'],
      [predictions > 0, predictions > 0 ? (predictions - suspicious) + ' benign · ' + suspicious + ' suspicious' : 'Waiting for predictions']
    ];
    stages.forEach(([complete, text], index) => {
      const stage = id('network-pipeline').children[index];
      stage.dataset.complete = complete;
      stage.querySelector('span').textContent = text;
    });
    metrics('network-metrics',[['Packets per second',running ? data.packets_per_second : null],
      ['Bytes per second',running ? data.bytes_per_second : null], ['Active flows',data?.active_flows?.length],
      ['AI predictions',model ? predictions : null]]);
    status('network-prediction',latest ? label(latest.gatv2_prediction) : 'No inference observed',
      latest?.gatv2_prediction === 'ATTACK' ? 'warn' : latest ? 'good' : '');
    facts('network-model',[['Model',!data ? 'Unknown' : model ? 'Online' : 'Offline'],
      ['Last inference',observedAt(latest?.gatv2_analyzed_at)],['Graph ID',latest?.network_inference?.graph_id],
      ['Graph nodes / edges',latest?.graph_nodes != null ? latest.graph_nodes + ' / ' + latest.graph_edges : null],
      ['Flow',latest ? latest.source_ip + ' → ' + latest.destination_ip + ' · ' + latest.protocol : null],
      ['Anomaly probability',score(latest?.gatv2_anomaly_probability)],['Threshold',score(latest?.gatv2_threshold ?? data?.gatv2_threshold)]]);
    const end = Math.floor(Date.now() / (interval * 1000));
    if (running) samples.set(end,[data.packets_per_second, data.bytes_per_second / 1024]);
    for (const tick of samples.keys()) if (tick < end - 23) samples.delete(tick);
    if (!data) samples.clear();
    const points = Array.from({length:24},(_,index) => samples.get(end - 23 + index) || []);
    const plot = id('network-chart');
    plot.style.display = samples.size ? '' : 'none';
    if (samples.size) chart(plot,points,['#62d9ce','#9aafff'],{windowLabel:'60 s ago'});
    else plot.replaceChildren();
    id('network-chart-status').textContent = running ? data.packets_per_second === 0 ? 'No packets in the latest sample.' : '' :
      'Waiting for active capture.';
    const flows = [...(data?.active_flows || []),...completed];
    topology(flows,message);
    id('network-anomalies').replaceChildren(...completed.filter(flow => flow.gatv2_prediction === 'ATTACK').slice(0,5)
      .map(flow => node('li','Suspicious flow · ' + score(flow.gatv2_anomaly_probability) + ' anomaly probability · ' + observedAt(flow.gatv2_analyzed_at))));
    if (!id('network-anomalies').children.length) id('network-anomalies').append(node('li',data ? 'No model anomalies recorded.' : message));
    id('network-flows').replaceChildren(...flows.slice(0,25).map(flow => {
      const row = node('tr');
      const endpoint = (host, port) => port == null ? host : `${host}:${port}`;
      row.append(...[endpoint(flow.source_ip, flow.source_port), endpoint(flow.destination_ip, flow.destination_port),
        flow.protocol, flow.total_packets, flow.total_bytes,
        typeof flow.duration === 'number' ? `${(flow.duration * 1000).toFixed(2)} ms` : null,
        label(flow.gatv2_prediction)]
        .map(value => node('td',value ?? '—')));
      return row;
    }));
  }
  render(null,'Checking connection');
  poll(async signal => {
    const data = await read('/api/network/state',signal);
    if (window.SentinelAuth.canView) render(data);
  },message => render(null,message));
})();
