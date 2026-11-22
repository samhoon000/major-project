"""Start the Sentinel demonstration on a single loopback listener."""

import argparse
from contextlib import asynccontextmanager

import uvicorn
from starlette.routing import Router

from app import app, load_dataset, stop_http_flood_simulation
from backend.network.runtime import network_runtime


@asynccontextmanager
async def demo_lifespan(_):
    load_dataset()
    await network_runtime.start()
    try:
        yield
    finally:
        await stop_http_flood_simulation()
        await network_runtime.stop()


lifespan = Router(lifespan=demo_lifespan)


async def local_app(scope, receive, send):
    application = lifespan if scope["type"] == "lifespan" else app
    await application(scope, receive, send)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8001)
    port = parser.parse_args().port
    if not 1 <= port <= 65535:
        parser.error("--port must be in 1–65535")
    print(f"Dashboard http://127.0.0.1:{port}/dashboard")
    print(f"Attack Lab http://127.0.0.1:{port}/attack-lab")
    uvicorn.run(local_app, host="127.0.0.1", port=port, proxy_headers=False)
