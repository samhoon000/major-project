"""Run with uvicorn backend.telemetry.api:app on a dedicated loopback port."""

import asyncio
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.requests import ClientDisconnect

from . import store
from .policy_wire import APP as ATTRIBUTED_APP
from .schemas import APP_PATTERN, INGEST_PATH, MAX_BYTES, UUID_PATTERN, Batch


def load_keys():
    raw = json.loads(os.getenv("HTTP_TELEMETRY_KEYS", "{}"))
    if not isinstance(raw, dict) or not 1 <= len(raw) <= 32:
        raise ValueError("HTTP_TELEMETRY_KEYS must configure 1–32 application deployments")
    if any(not re.fullmatch(APP_PATTERN, app) or not isinstance(secret, str)
           or not re.fullmatch(r"[a-f0-9]{64}", secret) for app, secret in raw.items()):
        raise ValueError("Invalid telemetry application ID or HMAC key")
    if len(set(raw.values())) != len(raw):
        raise ValueError("Each application deployment requires a distinct HMAC key")
    return {app: bytes.fromhex(secret) for app, secret in raw.items()}


def signature(secret, app, timestamp, nonce, body):
    fields = ("POST", INGEST_PATH, app, timestamp, nonce, hashlib.sha256(body).hexdigest())
    return hmac.new(secret, "\n".join(fields).encode("ascii"), hashlib.sha256).hexdigest()


async def read_body(request):
    body = bytearray()
    async with asyncio.timeout(5):
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_BYTES:
                raise HTTPException(413, "Batch too large")
            body.extend(chunk)
    return bytes(body)


def create_app(path=None, keys=None, clock=time.time):
    @asynccontextmanager
    async def lifespan(app):
        app.state.keys = load_keys() if keys is None else keys
        app.state.path = path if path is not None else store.database_path()
        await asyncio.to_thread(store.initialize, app.state.path)
        await asyncio.to_thread(store.maintain, app.state.path, int(clock()))

        async def cleanup():
            while True:
                await asyncio.sleep(60)
                try:
                    await asyncio.to_thread(store.maintain, app.state.path, int(clock()))
                except sqlite3.OperationalError:
                    # Retry on the next pass if the database is temporarily busy.
                    continue

        task = asyncio.create_task(cleanup())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None,
                  redirect_slashes=False)

    @app.exception_handler(405)
    async def unsupported_method(_request, _error):
        return JSONResponse({"detail": "Not found"}, status_code=404)

    @app.post(INGEST_PATH)
    async def ingest(request: Request):
        if request.scope["query_string"] or request.scope.get("raw_path", b"") != INGEST_PATH.encode():
            raise HTTPException(404)
        headers = request.headers
        names = ("x-telemetry-app", "x-telemetry-timestamp", "x-telemetry-nonce", "x-telemetry-signature")
        if any(len(headers.getlist(name)) != 1 for name in names):
            raise HTTPException(401, "Invalid telemetry credentials")
        app_id, timestamp, nonce, mac = (headers[name] for name in names)
        secret = app.state.keys.get(app_id)
        now = int(clock())
        if (secret is None or not re.fullmatch(r"[0-9]{10}", timestamp)
                or abs(now - int(timestamp)) > store.REPLAY_WINDOW
                or not re.fullmatch(UUID_PATTERN, nonce) or not re.fullmatch(r"[0-9a-f]{64}", mac)):
            raise HTTPException(401, "Invalid telemetry credentials")
        if headers.get("content-type") != "application/json":
            raise HTTPException(415, "Expected application/json")
        try:
            body = await read_body(request)
        except (TimeoutError, ClientDisconnect):
            raise HTTPException(408, "Incomplete telemetry body") from None
        if not hmac.compare_digest(mac, signature(secret, app_id, timestamp, nonce, body)):
            raise HTTPException(401, "Invalid telemetry credentials")
        now = int(clock())
        if abs(now - int(timestamp)) > store.REPLAY_WINDOW:
            raise HTTPException(401, "Expired telemetry signature")
        try:
            batch = Batch.model_validate_json(body)
        except ValidationError:
            raise HTTPException(422, "Invalid telemetry batch") from None
        if any(not (now - 86400) * 1000 <= event.timestamp < (now + 121) * 1000 for event in batch.events):
            raise HTTPException(422, "Invalid telemetry event timestamp")
        if not re.fullmatch(ATTRIBUTED_APP, app_id) and any(event.subject for event in batch.events):
            raise HTTPException(422, "Attribution requires an environment-scoped application ID")
        try:
            inserted = await asyncio.to_thread(store.accept, app.state.path, app_id, nonce,
                                               int(timestamp), now, batch)
        except store.Replay:
            raise HTTPException(409, "Telemetry replay") from None
        except store.QuotaExceeded:
            raise HTTPException(429, "Telemetry quota exceeded", headers={"Retry-After": "5"}) from None
        except sqlite3.OperationalError:
            raise HTTPException(503, "Telemetry storage unavailable") from None
        return {"accepted": inserted, "duplicates": len(batch.events) - inserted}

    return app


app = create_app()
