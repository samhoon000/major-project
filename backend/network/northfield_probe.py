"""One read-only loopback health request and its independently observed flow."""

import asyncio
import os
import time
from collections import deque
from uuid import uuid4

import httpx


HEALTH_URL = "http://127.0.0.1:8000/health"
COOLDOWN = 15
DEADLINE = 3
MAX_BODY_BYTES = 4096
FLOW_FIELDS = ("flow_id", "source_ip", "source_port", "destination_ip", "destination_port", "protocol",
               "start_time", "last_seen", "duration", "total_packets", "total_bytes", "features",
               "gatv2_status", "network_inference")


def enabled():
    return os.getenv("SENTINEL_NORTHFIELD_PROBE") == "1"


def matches_flow(run, flow):
    if not run.get("client") or not run.get("server") or flow["protocol"] != "TCP":
        return False
    endpoints = {(flow["source_ip"], flow["source_port"]), (flow["destination_ip"], flow["destination_port"])}
    return (endpoints == {tuple(run["client"]), tuple(run["server"])}
            and run["started_at"] <= flow["start_time"] <= run["finished_at"])


def socket_address(stream, name):
    address = stream.get_extra_info(name) if stream else None
    if isinstance(address, tuple) and len(address) == 2:
        return address
    return None


class NorthfieldProbe:
    def __init__(self):
        self.runs = deque(maxlen=4)
        self.task = None
        self.next_probe = 0.0

    def start(self):
        if (self.task and not self.task.done()) or time.monotonic() < self.next_probe:
            return None
        self.next_probe = time.monotonic() + COOLDOWN
        run = {"id": str(uuid4()), "result": "waiting"}
        self.runs.appendleft(run)
        self.task = asyncio.create_task(self.request(run), name="northfield-health-probe")
        return run["id"]

    async def request(self, run):
        run.update(result="running", started_at=time.time())
        try:
            async with asyncio.timeout(DEADLINE):
                async with httpx.AsyncClient(trust_env=False, follow_redirects=False) as client:
                    started = time.perf_counter()
                    async with client.stream("GET", HEALTH_URL, headers={"Connection": "close"}) as response:
                        stream = response.extensions.get("network_stream")
                        run.update(
                            client=socket_address(stream, "client_addr"), server=socket_address(stream, "server_addr"),
                            request_id=response.headers.get("x-request-id"), status=response.status_code,
                            latency_ms=round((time.perf_counter() - started) * 1000, 2), result="responded",
                        )
                        # Drain the small health body so the captured socket can close normally.
                        received = 0
                        async for chunk in response.aiter_raw():
                            received += len(chunk)
                            if received > MAX_BODY_BYTES:
                                break
        except (TimeoutError, httpx.TimeoutException):
            run["result"] = "timed_out"
        except httpx.HTTPError:
            run["result"] = "connection_failed"
        except asyncio.CancelledError:
            run["result"] = "cancelled"
            raise
        finally:
            run["finished_at"] = time.time()

    async def stop(self):
        if self.task and not self.task.done():
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
            if self.runs and self.runs[0]["result"] == "waiting":
                self.runs[0]["result"] = "cancelled"

    async def reset(self):
        await self.stop()
        self.runs.clear()

    def snapshot(self, network):
        completed = network["completed_flows"]
        active = network["active_flows"]
        runs = []
        for run in self.runs:
            # A tuple is only available after receiving HTTP headers; wait for the run to finish.
            flows = [flow for flow in (*completed, *active) if "finished_at" in run and matches_flow(run, flow)]
            runs.append({**run, "flows": [{key: flow.get(key) for key in FLOW_FIELDS} for flow in flows]})
        return {
            "runs": runs, "capture": network["capture"], "capture_error": network["capture_error"],
            "interface": network["interface"], "packets": network["packets"],
            "graphs": network["gatv2_graphs"], "model": network["gatv2"],
            "running": bool(self.task and not self.task.done()),
            "cooldown_seconds": max(0, self.next_probe - time.monotonic()),
        }


northfield_probe = NorthfieldProbe()
