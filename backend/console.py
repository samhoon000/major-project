"""Server-rendered Sentinel console and shared navigation."""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from backend.network.northfield_probe import enabled as network_probe_enabled
from backend.security.demo_access import (
    boundary, demo_security, is_remote_operator_console,
)
from backend.security_ui import security_panel

router = APIRouter()
FILES = Path(__file__).with_name("console")
NAVIGATION = (
    ("overview", "/dashboard", "Overview"),
    ("network", "/dashboard/network", "Network Analysis"),
    ("applications", "/dashboard/applications", "Monitored Applications"),
    ("chat-security", "/dashboard/chat", "Chat Security"),
    ("settings", "/dashboard/settings", "Settings"),
)


def navigation(request, active):
    local = boundary(request).local
    operator_console = is_remote_operator_console(request) and demo_security.can_view(request)
    links = []
    for key, url, name in NAVIGATION:
        if key == "applications" and not (local or operator_console):
            continue
        current = ' aria-current="page"' if key == active else ""
        links.append(f'<a href="{url}"{current}>{name}</a>')
    return (
        '<aside class="console-nav"><a class="console-brand" href="/dashboard">Sentinel</a>'
        '<nav aria-label="Sentinel navigation">' + "".join(links) + '</nav>'
        '<a id="console-operator" href="/dashboard/settings#operator">Operator session</a></aside>'
    )


def wrap_existing(request, active, document, *, auth_loaded=False):
    style = (FILES / "layout.css").read_text(encoding="utf-8")
    common = (FILES / "layout.js").read_text(encoding="utf-8")
    session = "" if auth_loaded else '<script src="/api/auth/ui.js"></script>'
    return document.replace(
        "<main>", f"<style>{style}</style>{navigation(request, active)}{session}<script>{common}</script><main>", 1
    )


def page(request, name):
    body = (FILES / f"{name}.html").read_text(encoding="utf-8")
    script = (FILES / f"{name}.js").read_text(encoding="utf-8")
    auth = security_panel() if name == "settings" else ""
    if name == "overview" and boundary(request).local:
        body = body.replace("<!-- local lab -->",
                            '<a class="console-button console-primary" id="launch-demo-lab" href="/attack-lab">Launch Demo Lab</a>')
        if network_probe_enabled():
            body = body.replace("<!-- northfield evidence -->",
                                '<a class="console-link" href="/attack-lab?view=northfield">Northfield Network Evidence</a>')
    title = next((label for key, _, label in NAVIGATION if key == name), "Chat Security")
    document = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Sentinel</title></head><body><main>
{body.replace("<!-- operator -->", auth)}</main><script>{script}</script></body></html>"""
    return HTMLResponse(wrap_existing(request, name, document, auth_loaded=bool(auth)),
                        headers={"Cache-Control": "no-store"})


@router.get("/dashboard/network")
async def network_page(request: Request):
    return page(request, "network")


@router.get("/dashboard/settings")
async def settings_page(request: Request):
    return page(request, "settings")


@router.get("/dashboard/chat")
async def chat_security_page(request: Request):
    return page(request, "chat-security")


@router.get("/dashboard/chat-security", include_in_schema=False)
async def legacy_chat_security_page():
    return RedirectResponse("/dashboard/chat", status_code=307)
