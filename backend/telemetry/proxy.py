"""Loopback origin for a tunnel that serves only the telemetry POST."""

import asyncio
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from starlette.requests import ClientDisconnect
from starlette.responses import JSONResponse, Response

from .api import read_body
from .schemas import INGEST_PATH

FORWARDED_HEADERS = {
    b"content-type", b"x-telemetry-app", b"x-telemetry-timestamp",
    b"x-telemetry-nonce", b"x-telemetry-signature",
}


def create_proxy(transport=None):
    @asynccontextmanager
    async def lifespan(app):
        async with httpx.AsyncClient(base_url="http://127.0.0.1:8091", timeout=5,
                                     follow_redirects=False, trust_env=False, transport=transport) as client:
            app.state.collector = client
            yield

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None,
                  openapi_url=None, redirect_slashes=False)

    @app.exception_handler(405)
    async def unsupported_method(_request, _error):
        return JSONResponse({"detail": "Not found"}, status_code=404)

    @app.post(INGEST_PATH)
    async def forward(request: Request):
        if request.scope["query_string"] or request.scope.get("raw_path") != INGEST_PATH.encode():
            raise HTTPException(404)
        try:
            body = await read_body(request)
        except (TimeoutError, ClientDisconnect):
            raise HTTPException(408, "Incomplete telemetry body") from None
        headers = [(key, value) for key, value in request.headers.raw if key in FORWARDED_HEADERS]
        try:
            async with asyncio.timeout(5):
                response = await app.state.collector.post(INGEST_PATH, content=body, headers=headers)
        except (TimeoutError, httpx.RequestError):
            raise HTTPException(503, "Telemetry collector unavailable") from None
        response_headers = {"Cache-Control": "no-store"}
        for name in ("content-type", "retry-after"):
            if name in response.headers:
                response_headers[name] = response.headers[name]
        return Response(response.content, status_code=response.status_code, headers=response_headers)

    return app


app = create_proxy()
