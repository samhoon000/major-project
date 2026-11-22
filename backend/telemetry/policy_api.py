"""Independent signed policy channel, bound to a loopback origin."""

import asyncio
import hmac
import json
import os
import re
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from pydantic import ValidationError
from starlette.requests import ClientDisconnect
from starlette.responses import JSONResponse, Response

from . import protection, staging_policy, store
from .policy_wire import APP, MAX_BYTES, SYNC_PATH, Sync, channel_environment, sign


def channels_from_environment():
    channels = {}
    for environment in ("staging", "production"):
        raw = json.loads(os.getenv(f"HTTP_{environment.upper()}_POLICY_KEYS", "{}"))
        if not isinstance(raw, dict) or any(
            not re.fullmatch(APP, app) or channel_environment(app) != environment
            or not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key) for app, key in raw.items()
        ):
            raise ValueError("Configure environment-specific policy channel keys")
        channels.update({app: bytes.fromhex(key) for app, key in raw.items()})
    if not 1 <= len(channels) <= 16 or len(set(channels.values())) != len(channels):
        raise ValueError("Configure distinct policy channel keys")
    return channels


def create_app(path=None, keys=None, clock=time.time, *, public_host=None, allow_production=None):
    @asynccontextmanager
    async def lifespan(app):
        app.state.keys = channels_from_environment() if keys is None else keys
        app.state.public_host = public_host or os.getenv("HTTP_POLICY_PUBLIC_HOST")
        production = any(channel_environment(app) == "production" for app in app.state.keys)
        if production and (not app.state.public_host or not re.fullmatch(
            r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", app.state.public_host
        )):
            raise ValueError("A dedicated HTTPS hostname is required for production policy delivery")
        opt_in = os.getenv("HTTP_POLICY_ALLOW_PRODUCTION") == "true" if allow_production is None else allow_production
        app.state.database = path or store.database_path()
        await asyncio.to_thread(protection.initialize, app.state.database)
        await asyncio.to_thread(staging_policy.initialize, app.state.database, app.state.keys, opt_in)
        yield

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)

    @app.exception_handler(405)
    async def unsupported_method(_request, _error):
        return JSONResponse({"detail": "Not found"}, status_code=404)

    @app.post(SYNC_PATH)
    async def sync(request: Request):
        if (not request.client or request.client.host != "127.0.0.1" or request.url.query
                or request.scope.get("raw_path") != SYNC_PATH.encode()):
            raise HTTPException(404)
        forwarded = any(header in request.headers for header in ("forwarded", "x-forwarded-for", "cf-connecting-ip"))
        public = request.headers.getlist("host") == [app.state.public_host]
        if forwarded and not public:
            raise HTTPException(404)
        body = bytearray()
        values = request.headers.getlist("x-policy-signature")
        if (len(values) != 1 or not re.fullmatch(r"[0-9a-f]{64}", values[0])
                or request.headers.get("content-type") != "application/json"):
            raise HTTPException(401)
        try:
            async with asyncio.timeout(3):
                async for chunk in request.stream():
                    if len(body) + len(chunk) > MAX_BYTES:
                        raise HTTPException(413)
                    body.extend(chunk)
            envelope = Sync.model_validate_json(body)
        except (ValidationError, TimeoutError, ClientDisconnect):
            raise HTTPException(401) from None
        if (envelope.environment == "production") != public:
            raise HTTPException(404)
        now = int(clock())
        key = app.state.keys.get(envelope.app)
        payload = bytes(body)
        if (not key or abs(now - envelope.timestamp) > 30
                or not hmac.compare_digest(values[0], sign(key, "sync", envelope.nonce, payload))):
            raise HTTPException(401)
        policy, status = await asyncio.to_thread(staging_policy.exchange, app.state.database, envelope, now)
        if policy is None:
            raise HTTPException(status)
        wire = policy.model_dump_json().encode()
        return Response(wire, media_type="application/json", headers={
            "Cache-Control": "no-store", "X-Policy-Signature": sign(key, "snapshot", envelope.nonce, wire),
        })

    return app


app = create_app()
