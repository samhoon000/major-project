"""Shared sign-in panel; credentials are never rendered into HTML."""


def security_panel():
    return """
<style>
.sentinel-auth{padding:16px;margin:16px 0;border:1px solid #38594c;border-radius:9px;background:#0c1c15;color:#dceee7;font:13px system-ui;text-align:left}
.sentinel-auth label{display:inline-block;margin:8px 12px 8px 0}.sentinel-auth input{font:inherit;padding:9px;background:#07100d;color:#dceee7;border:1px solid #38594c;border-radius:5px;min-width:240px}
.sentinel-auth button{font:inherit;cursor:pointer;padding:9px 13px;margin:4px;border:1px solid #478365;border-radius:5px;background:#163c2b;color:#dceee7}
.sentinel-auth p{margin:8px 0;line-height:1.6}.sentinel-auth [role=status]{color:#a8d9c0}
body.sentinel-locked #http-flood-panel,body.sentinel-locked .panel,body.sentinel-locked .stat,body.sentinel-locked .banner{display:none}
</style>
<section class="sentinel-auth" aria-label="Administrator sign-in">
<strong>Secure demonstration access</strong><p>Remote viewers and controllers authenticate here. Sessions expire after 30 minutes.</p>
<label>Administrator token <input id="hf-token" type="password" autocomplete="off" placeholder="ADMIN_TOKEN — never saved in this browser"></label>
<button id="sentinel-login" type="button">Authenticate</button><button id="sentinel-logout" type="button" disabled>Sign out</button>
<p id="sentinel-auth-status" role="status">Checking session…</p>
</section><script src="/api/auth/ui.js"></script>
"""
