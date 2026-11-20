"""Shared HTTP lab panel for the existing Attack Lab and live dashboard."""
from pathlib import Path

SCRIPT_PATH = Path(__file__).parent / "static" / "http_flood.js"


def http_flood_panel(controls=False):
    controls_html = """
<div class="hf-controls">
<label>Requests / second<input id="hf-rate" type="number" value="25" min="1" max="50" step="1"></label>
<label>Duration (seconds)<input id="hf-duration" type="number" value="8" min="1" max="20" step="1"></label>
<label>Concurrency<input id="hf-concurrency" type="number" value="4" min="1" max="8" step="1"></label>
</div>
<div class="hf-actions"><button id="hf-monitor">Start normal traffic</button><button id="hf-start">Start Attack</button>
<button id="hf-stop" disabled>Stop Attack</button><button id="hf-unblock">Unblock source</button>
<button id="hf-reset">Reset demonstration</button></div>
<p class="hf-muted">Controls require administrator authentication. Requests run on the host and target only its dedicated loopback endpoint.
Maximum 50 req/s, 20 seconds, 8 concurrent, 1,000 requests. Normal monitor stops after 120 seconds.</p>
""" if controls else ""
    return """
<style>
.hf{margin:18px 0;padding:22px;border:1px solid #315348;border-radius:12px;background:#091511;color:#dceee7;font:13px system-ui,sans-serif;text-align:left;box-sizing:border-box}
.hf *{box-sizing:border-box}.hf h2{font-size:20px;margin:4px 0 10px}.hf h3{font-size:14px;margin:14px 0 8px}.hf p{line-height:1.6}.hf-muted{color:#9cb9ae;font-size:12px}.hf-head{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}.hf-badge{border:1px solid #34745b;border-radius:20px;padding:7px 12px;color:#78e9ae;font-weight:bold;align-self:start}.hf-controls{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.hf label{display:block;font-size:12px;color:#9cb9ae}.hf input{display:block;width:100%;margin-top:6px;background:#07100d;color:#e5f7ef;border:1px solid #38594c;border-radius:6px;padding:10px;font:inherit}.hf-actions{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0}.hf button{border:1px solid #407e62;border-radius:6px;background:#163c2b;color:#dbffe9;padding:10px 14px;font:inherit;cursor:pointer}.hf button:disabled{opacity:.4;cursor:default}.hf #hf-stop{border-color:#da8572;background:#542b27}.hf-stats{display:grid;grid-template-columns:repeat(6,1fr);gap:9px;margin:14px 0}.hf-stat{background:#0e211a;border:1px solid #254a3a;padding:12px;border-radius:7px}.hf-stat b{display:block;font:23px ui-monospace,monospace;margin-top:7px;color:#79ebbb}.hf-alert{padding:14px;border-left:4px solid #fbbe59;background:#332519;margin:12px 0;line-height:1.7}.hf-alert[data-active=true]{border-color:#ff796f;background:#381e21}.hf-alert strong{display:block}.hf-error{color:#ffada4;min-height:20px;margin:8px 0}.hf svg{display:block;width:100%;height:auto;background:#07100d;border:1px solid #254a3a;border-radius:8px}.hf-legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;margin:10px 0}.hf-table{width:100%;font-size:12px;min-width:0;border-collapse:collapse}.hf-table th,.hf-table td{padding:9px;border-bottom:1px solid #254a3a;text-align:left;white-space:normal}.hf-timeline{max-height:230px;overflow:auto;padding-left:22px;line-height:1.65}.hf code{overflow-wrap:anywhere}.hf a{color:#86dfff}.hf-health{font-size:13px;color:#a5c7bb}.hf-progress{display:flex;gap:8px;flex-wrap:wrap;font-size:11px;margin:12px 0}.hf-progress span{border:1px solid #38594c;border-radius:4px;padding:5px 8px}.hf-progress .reached{color:#84f0b7;border-color:#47b57e}@media(max-width:750px){.hf{padding:14px}.hf-controls{grid-template-columns:1fr 1fr}.hf-stats{grid-template-columns:repeat(3,1fr)}}
</style>
<section class="hf" id="http-flood-panel" aria-labelledby="hf-heading">
<div class="hf-head"><div><div class="hf-muted">SENTINEL // CONTROLLED APPLICATION-LAYER DEFENSE</div><h2 id="hf-heading">HTTP Flood (Application-Layer DoS)</h2></div><span class="hf-badge" id="hf-status">CONNECTING</span></div>
<p>Observe a real HTTP request spike, automatic rate-based detection, selective rejection, and recovery.</p>
<div class="hf-muted">Target: <code id="hf-target">Dedicated loopback test endpoint</code> · Source: <b>lab-flood</b></div>
""" + controls_html + """
<div class="hf-progress" id="hf-phases"></div>
<div id="hf-error" class="hf-error" role="status"></div><div class="hf-muted" id="hf-connection">Connecting telemetry…</div>
<div class="hf-stats">
<div class="hf-stat">Generated<b id="hf-generated">0</b></div><div class="hf-stat">Current req/s<b id="hf-rps">0</b></div>
<div class="hf-stat">Successful<b id="hf-success">0</b></div><div class="hf-stat">HTTP 429<b id="hf-blocked">0</b></div>
<div class="hf-stat">Failed<b id="hf-failed">0</b></div><div class="hf-stat">Elapsed<b id="hf-elapsed">0s</b></div></div>
<div class="hf-alert" id="hf-detection" hidden><strong>HTTP FLOOD ATTACK DETECTED</strong><span id="hf-detection-detail"></span></div>
<div class="hf-alert" id="hf-mitigation" hidden><strong id="hf-mitigation-title">THREAT MITIGATED — SOURCE BLOCKED</strong><span id="hf-mitigation-detail"></span></div>
<h3>Observed requests per second</h3><div class="hf-legend"><span style="color:#71ceff">● Total attempts</span><span style="color:#7df1ad">● Accepted</span><span style="color:#ff857b">● Blocked (429)</span><span style="color:#f2c967">– Detection threshold</span></div>
<svg id="hf-chart" viewBox="0 0 900 230" role="img" aria-label="Actual total, accepted and blocked HTTP requests per second"></svg>
<p class="hf-muted" id="hf-thresholds"></p>
<h3>Independent legitimate client — same host, same endpoint</h3><p class="hf-health" id="hf-health">Start normal traffic in the Attack Lab to measure availability.</p>
<table class="hf-table"><thead><tr><th>Requests sent</th><th>Successful</th><th>Blocked</th><th>Failed</th><th>Latest latency</th></tr></thead><tbody><tr><td id="hf-leg-sent">0</td><td id="hf-leg-success">0</td><td id="hf-leg-blocked">0</td><td id="hf-leg-failed">0</td><td id="hf-leg-latency">—</td></tr></tbody></table>
<h3>Detection evidence</h3><p id="hf-method">Rule-Based HTTP Flood Detection</p><p class="hf-muted" id="hf-gat"></p><div id="hf-gat-results"></div>
<h3>Security event timeline</h3><ol class="hf-timeline" id="hf-timeline"></ol>
<p class="hf-muted">Only the isolated flood identity is rate limited. Dashboard, chat, and Windows Firewall quarantine are outside this lab's mitigation boundary.
<a href="/attack-lab" target="_blank">Attack Lab ↗</a> · <a href="/dashboard" target="_blank">Live dashboard ↗</a></p>
</section><script src="/api/attack-lab/http-flood/ui.js" defer></script>
"""
