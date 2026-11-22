(() => {
  const {id,status,facts,poll,read} = window.SentinelConsole;
  let joining = null;
  function render(network,tunnel,message) {
    joining = tunnel?.active_joining_url || null;
    status('settings-health',message || 'Connection data available',message ? '' : 'good');
    facts('capture-settings', [['Capture',network?.capture],['Interface',network?.adapter_name || network?.interface],
      ['Selection',network?.selection_mode],['Capture filter',network?.capture_filter]]);
    const loopback = tunnel?.local_ip === '127.0.0.1';
    facts('connection-settings',[['Cloudflare Tunnel',tunnel?.status],['Public URL',tunnel?.public_url],
      [loopback ? 'Local only' : 'Local LAN',tunnel?.local_url],['Active chat URL',joining]]);
    facts('diagnostic-settings',[['Capture detail',network?.capture_error || network?.selection_reason],
      ['GATv2 detail',network?.gatv2_error],['Tunnel detail',tunnel?.error || tunnel?.readiness_note]]);
    id('settings-copy').disabled = !joining;
    id('settings-legacy-graph').hidden = !window.SentinelAuth.local;
    const share = id('settings-share');
    share.hidden = !joining;
    if (!joining) {
      share.open = false;
      id('settings-qr').removeAttribute('src');
    }
  }
  id('settings-share').addEventListener('toggle',event => {
    if (event.target.open && joining) id('settings-qr').src = '/api/tunnel/qr.svg';
  });
  id('settings-copy').onclick = async () => {
    try {
      await navigator.clipboard.writeText(joining);
      status('settings-feedback','Chat link copied','good');
    } catch {
      status('settings-feedback','Copy the active chat URL from Connectivity.');
    }
  };
  render(null,null,'Checking connection');
  poll(async signal => {
    const [network,tunnel] = await Promise.allSettled([
      read('/api/network/state',signal),read('/api/tunnel/state',signal)
    ]);
    if (!window.SentinelAuth.canView) return;
    render(network.value,tunnel.value,network.status !== 'fulfilled' || tunnel.status !== 'fulfilled' ? 'Some connection data unavailable' : '');
  },message => render(null,null,message),5000);
})();
