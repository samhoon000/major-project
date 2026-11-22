"""Start the isolated Northfield and Sentinel showcase on this computer."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

import httpx


ROOT = Path(__file__).resolve().parent
NORTHFIELD = ROOT / ".northfield-local"
APP = "northfield-staging"
PORTAL = "http://127.0.0.1:8011"
SENTINEL = "http://127.0.0.1:8012"
STAGING_VIEW = f"/dashboard/applications?app={APP}"
COLLECTOR_PORT = 8191
POLICY_PORT = 8193
STUDENT = "showcase-student@example.com"
SECOND_STUDENT = "showcase-second@example.com"


def check_ports():
    for port in (8011, 8012, COLLECTOR_PORT, POLICY_PORT):
        with socket.socket() as listener:
            try:
                listener.bind(("127.0.0.1", port))
            except OSError:
                raise RuntimeError(f"Loopback port {port} is in use. Stop the program using it and retry.") from None


def verify_observation(path, request_id):
    if not path.is_file():
        return False
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)) as db:
        row = db.execute("SELECT event FROM events WHERE app=? AND request_id=?", (APP, request_id)).fetchone()
    if not row:
        return False
    event = json.loads(row[0])
    if event["status"] == 200 and event["auth"] == "authenticated":
        return event.get("subject")
    return None


class Showcase:
    def __init__(self, directory):
        self.directory = directory
        self.children = []

    def run(self, name, command, folder, env, *, background=False):
        log = self.directory / f"{name}.log"
        with log.open("wb") as output:
            process = subprocess.Popen(command, cwd=folder, env=env, stdout=output, stderr=subprocess.STDOUT)
        self.children.append((process, name, log))
        if not background:
            if process.wait():
                raise RuntimeError(f"{name} failed. Check {log}.")
            self.children.pop()

    def check_children(self):
        for process, name, log in self.children:
            if process.poll() is not None:
                raise RuntimeError(f"{name} exited with code {process.returncode}. Check {log}.")

    def wait_for(self, label, condition, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.check_children()
            try:
                result = condition()
                if result:
                    return result
            except (httpx.TransportError, sqlite3.OperationalError):
                pass
            time.sleep(0.25)
        raise RuntimeError(f"{label} did not become ready. Check the logs in {self.directory}.")

    def close(self):
        for process, _, _ in reversed(self.children):
            if process.poll() is None:
                process.terminate()
        for process, _, _ in reversed(self.children):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def serve(showcase, name, module, port, folder, env, *args):
    showcase.run(name, [sys.executable, "-m", "uvicorn", module, "--host", "127.0.0.1",
                        "--port", str(port), "--no-proxy-headers", "--no-access-log", *args],
                 folder, env, background=True)


def start(showcase, *, show_credentials):
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    frontend = NORTHFIELD / "frontend"
    backend = NORTHFIELD / "backend"
    if not npm or not (frontend / "node_modules").is_dir() or not backend.is_dir():
        raise RuntimeError("The Northfield checkout, Node.js, and installed frontend dependencies are required.")
    check_ports()
    directory = showcase.directory
    ledger = directory / "sentinel.sqlite3"
    telemetry, policy, subject, jwt, operator, first_password, second_password = (
        secrets.token_hex(32) for _ in range(7)
    )
    sentinel_env = os.environ | {
        "HTTP_TELEMETRY_DB": str(ledger), "HTTP_TELEMETRY_KEYS": json.dumps({APP: telemetry}),
        "HTTP_STAGING_POLICY_KEYS": json.dumps({APP: policy}), "HTTP_PRODUCTION_POLICY_KEYS": "{}",
        "HTTP_POLICY_ALLOW_PRODUCTION": "false", "HTTP_POLICY_PUBLIC_HOST": "",
        "PORT": SENTINEL.rsplit(":", 1)[1], "SENTINEL_LOOPBACK_ONLY": "true",
        "HTTP_SHOWCASE_SUBJECT": "", "HTTP_SHOWCASE_COURSE": "", "HTTP_SHOWCASE_SESSIONS": "",
        "HTTP_DETECTION_CONFIG": "", "HTTP_PROTECTION_CONFIG": "", "ADMIN_TOKEN": operator,
        "CLOUDFLARE_TUNNEL_TOKEN": "", "CLOUDFLARE_TUNNEL_MODE": "disabled",
        "CLOUDFLARE_PUBLIC_HOSTNAME": "", "DASHBOARD_REMOTE_ENABLED": "false",
        "HTTP_FLOOD_REMOTE_ENABLED": "false", "NETWORK_AUTO_QUARANTINE": "false",
    }
    northfield_env = os.environ | {
        "APP_ENV": "development", "DATABASE_URL": "", "SQLITE_PATH": str(directory / "portal.sqlite3"),
        "JWT_SECRET": jwt, "SESSION_CROSS_SITE": "false", "ALLOWED_ORIGINS": PORTAL,
        "SEED_DEMO_DATA": "true", "DEMO_ADMIN_EMAIL": "showcase-admin@example.com",
        "DEMO_ADMIN_PASSWORD": secrets.token_hex(32), "DEMO_STUDENT_EMAIL": STUDENT,
        "DEMO_STUDENT_PASSWORD": first_password, "TELEMETRY_APP_ID": APP,
        "TELEMETRY_COLLECTOR_URL": f"http://127.0.0.1:{COLLECTOR_PORT}/v1/http-events",
        "TELEMETRY_HMAC_KEY": telemetry, "PROTECTION_SUBJECT_KEY": subject, "PROTECTION_HMAC_KEY": policy,
        "PROTECTION_URL": f"http://127.0.0.1:{POLICY_PORT}/v1/policy/sync",
        "PROTECTION_PRODUCTION_ENABLED": "false", "PROTECTION_SYNC_ONLY": "false",
        "PROTECTION_STATE_PATH": str(directory / "policy.sqlite3"), "VITE_API_BASE_URL": "/api",
    }
    if deps := os.environ.get("NORTHFIELD_STAGING_DEPS"):
        inherited = northfield_env.get("PYTHONPATH")
        northfield_env["PYTHONPATH"] = os.pathsep.join(filter(None, (str(Path(deps).resolve()), inherited)))

    print(f"Preparing isolated SQLite and the local frontend. Logs are in {directory}.", flush=True)
    showcase.run("northfield-bootstrap", [sys.executable, "-m", "app.bootstrap"], backend, northfield_env)
    showcase.run("northfield-build", [npm, "run", "build", "--offline"], frontend, northfield_env)
    serve(showcase, "collector", "backend.telemetry.api:app", COLLECTOR_PORT, ROOT, sentinel_env, "--ws", "none")
    serve(showcase, "policy", "backend.telemetry.policy_api:app", POLICY_PORT, ROOT, sentinel_env, "--ws", "none")
    module = [sys.executable, "-m", "backend.telemetry.protection"]
    showcase.run("shadow-mode", [*module, "--mode", "shadow"], ROOT, sentinel_env)
    serve(showcase, "northfield", "app.main:create_app", 8011, backend, northfield_env, "--factory")
    with (httpx.Client(timeout=2, trust_env=False) as client,
          httpx.Client(timeout=2, trust_env=False) as second_client):
        showcase.wait_for("Northfield database", lambda: client.get(PORTAL + "/health").status_code == 200)
        showcase.wait_for("Northfield frontend", lambda: 'id="root"' in client.get(PORTAL).text)
        registration = second_client.post(PORTAL + "/api/auth/register", json={
            "email": SECOND_STUDENT, "student_id": "SHOWCASE-SECOND", "full_name": "Showcase Student Two",
            "password": second_password, "confirm_password": second_password,
        })
        if registration.status_code != 201:
            raise RuntimeError(f"Creating the disposable second student returned HTTP {registration.status_code}.")
        login = client.post(PORTAL + "/api/auth/login", json={"email": STUDENT, "password": first_password})
        if login.status_code != 200:
            raise RuntimeError(f"Demo student login returned HTTP {login.status_code}.")
        enrollment = client.get(PORTAL + "/api/courses/enrolled")
        if enrollment.status_code != 200 or not enrollment.json():
            raise RuntimeError(f"Could not find an enrolled course for the first student. HTTP {enrollment.status_code}.")
        shared_course = enrollment.json()[0]
        second_enrollment = second_client.post(
            f"{PORTAL}/api/courses/{shared_course['id']}/enroll",
            headers={"X-CSRF-Token": registration.json()["csrf_token"]},
        )
        if second_enrollment.status_code != 201:
            raise RuntimeError(f"Could not enroll the second demo student. HTTP {second_enrollment.status_code}.")
        observations = [session.get(PORTAL + "/api/auth/me") for session in (client, second_client)]
        if any(response.status_code != 200 or "x-request-id" not in response.headers for response in observations):
            raise RuntimeError("The authenticated readiness request failed.")
        request_id, second_request_id = (response.headers["x-request-id"] for response in observations)

        def verified_students():
            subjects = [verify_observation(ledger, item) for item in (request_id, second_request_id)]
            return subjects if all(subjects) and subjects[0] != subjects[1] else None

        demo_subject, second_subject = showcase.wait_for("Signed Northfield telemetry", verified_students)
        demo_policy = directory / "showcase-policy.toml"
        demo_policy.write_text(f'showcase_subject = "{demo_subject}"\nproposed_requests_per_minute = 1\n'
                               'rate_limit_seconds = 110\n', encoding="utf-8")
        sentinel_env.update(
            HTTP_SHOWCASE_SUBJECT=demo_subject,
            HTTP_SHOWCASE_SECOND_SUBJECT=second_subject,
            HTTP_SHOWCASE_COURSE=str(shared_course["id"]),
            HTTP_PROTECTION_CONFIG=str(demo_policy),
        )
        demo_sessions = json.dumps([
            [client.cookies["portal"], login.json()["csrf_token"]],
            [second_client.cookies["portal"], registration.json()["csrf_token"]],
        ])
        showcase.run("detection", [sys.executable, "-m", "backend.telemetry.detection"], ROOT, sentinel_env, background=True)
        showcase.run("protection", module, ROOT, sentinel_env, background=True)
        serve(showcase, "sentinel", "app:app", 8012, ROOT, sentinel_env | {"HTTP_SHOWCASE_SESSIONS": demo_sessions})
        showcase.wait_for("Sentinel dashboard", lambda: client.get(SENTINEL + STAGING_VIEW).status_code == 200,
                          seconds=60)
        dashboard = client.get(SENTINEL + STAGING_VIEW)
        lab = client.get(SENTINEL + "/attack-lab")
        if (dashboard.headers.get("content-security-policy") != "frame-ancestors 'self'"
                or 'id="northfield-monitor"' not in dashboard.text
                or lab.status_code != 200 or f'href="{STAGING_VIEW}"' not in lab.text):
            raise RuntimeError("Northfield monitoring or the Attack Lab link is unavailable.")
    print(f"Signed telemetry verified for request {request_id}.")
    print(f"Northfield             {PORTAL}")
    print(f"Shared student course  {PORTAL}/courses/{shared_course['id']}")
    print(f"Monitored Applications {SENTINEL}{STAGING_VIEW}")
    print(f"Attack Lab             {SENTINEL}/attack-lab")
    if show_credentials:
        print(f"Sentinel operator token {operator}")
        print(f"Northfield student     {STUDENT}  {first_password}")
        print(f"Second student         {SECOND_STUDENT}  {second_password}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify startup and stop the demo services.")
    args = parser.parse_args()
    base = ROOT / "data"
    base.mkdir(exist_ok=True)
    showcase = Showcase(Path(tempfile.mkdtemp(prefix="showcase-", dir=base)))
    try:
        start(showcase, show_credentials=not args.check)
        if not args.check:
            print("Press Ctrl+C to stop the local services.", flush=True)
            while True:
                showcase.check_children()
                time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping showcase services.")
    except (RuntimeError, OSError, httpx.HTTPError) as error:
        print(f"Showcase startup or service failure. {error}", file=sys.stderr)
        return 1
    finally:
        showcase.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
