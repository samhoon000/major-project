import json
import time
from uuid import uuid4

from fastapi.testclient import TestClient

from backend.telemetry import detection, northfield_monitor, staging_policy, store
from backend.telemetry.api import create_app
from backend.telemetry.replay import deliver, request
from backend.telemetry.rules import SHOWCASE_APP, SHOWCASE_ROUTE


def test_graph_preserves_signed_counts_and_requires_explicit_evidence(tmp_path, monkeypatch):
    path = tmp_path / "traffic.sqlite3"
    detection.initialize(path)
    staging_policy.initialize(path, {SHOWCASE_APP})
    now = int(time.time())
    timestamp = (now - 1) * 1000
    subject = "s1_" + "1" * 64
    monkeypatch.setenv("HTTP_SHOWCASE_SUBJECT", subject)

    normal = [request("/api/auth/me", timestamp=timestamp) for _ in range(30)]
    flagged = request(SHOWCASE_ROUTE, method="POST", timestamp=timestamp, status=204) | {"subject": subject}
    limits = [request("/api/example", timestamp=timestamp, status=429) for _ in range(2)]
    unrelated = request("/api/students", timestamp=timestamp, status=403)
    key = b"a" * 32
    with TestClient(create_app(path, {SHOWCASE_APP: key})) as collector:
        deliver(collector, SHOWCASE_APP, key, [*normal, flagged, *limits, unrelated])

    alert_id = str(uuid4())
    with store.connect(path) as db:
        db.execute("INSERT INTO http_alerts VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
            alert_id, SHOWCASE_APP, "showcase_course_access", "", "low", "open",
            timestamp, timestamp, timestamp, timestamp,
            json.dumps({"requests": [{"request_id": flagged["request_id"]}]}),
        ))
        db.execute("INSERT INTO http_policy_receipts VALUES (?,?,?,?,?,?)", (
            SHOWCASE_APP, str(uuid4()), limits[0]["request_id"], now - 1, "rate_limited", "{}",
        ))
    view = northfield_monitor.snapshot(path, now)
    assert len(view["points"]) == 120
    assert all(not any(point.values()) for point in view["points"][:-1])
    assert view["points"][-1] == {
        "normal": 30, "suspicious": 1, "blocked": 1, "other": 2, "rate_limited": 2,
    }
    assert view["students"][0]["request_id"] == flagged["request_id"]
    assert view["students"][1] is None

    with store.connect(path) as db:
        db.execute("UPDATE http_alerts SET status='false_positive' WHERE id=?", (alert_id,))
    view = northfield_monitor.snapshot(path, now)
    assert view["points"][-1]["suspicious"] == 0
    assert view["points"][-1]["normal"] == 31
