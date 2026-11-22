from fastapi.testclient import TestClient
import pytest
from starlette.websockets import WebSocketDisconnect

from app import app
from backend.chat_monitoring import ChatMonitoring
from backend.chat_service import state


def test_activity_counts_each_decision_and_observed_rejection_without_message_contents():
    now = 100.0
    monitor = ChatMonitoring(lambda: now)
    for action in ("ALLOW", "WARN", "BLOCK_MESSAGE", "BLOCK_USER"):
        monitor.record("threat_decision", {"action": action, "sender": "alice"}, now)
    monitor.record("message_blocked", {"sender": "alice", "text": "private message"}, now)
    monitor.record("blocked", {"username": "alice", "message_id": "id"}, now)
    monitor.record("blocked", {"username": "bob"}, now)  # No chat message was rejected here.
    for _ in range(501):
        monitor.record("gatv2_analysis", {}, now)
    now += 1
    snapshot = monitor.snapshot()
    assert len(snapshot["samples"]) == 60
    assert snapshot["samples"][-1] == [4, 3, 2]
    assert snapshot["samples"][-2] == [None, None, None]
    assert [item["type"] for item in snapshot["events"]] == [
        "blocked", "blocked", "message_blocked", "warning",
    ]
    assert "private message" not in str(snapshot)
    now += 60
    assert all(sample == [0, 0, 0] for sample in monitor.snapshot()["samples"])
    assert not monitor.activity


def test_chat_route_and_monitor_socket_preserve_dashboard_contract(monkeypatch):
    monkeypatch.setattr(state, "monitoring", ChatMonitoring())
    client = TestClient(app, base_url="http://localhost", client=("127.0.0.1", 51000))
    page = client.get("/dashboard/chat")
    assert page.status_code == 200
    assert '<a href="/dashboard/chat" aria-current="page">Chat Security</a>' in page.text
    assert 'href="/chat"' in page.text
    assert 'id="userRows"' not in client.get("/dashboard").text
    old = client.get("/dashboard/chat-security", follow_redirects=False)
    assert old.status_code == 307 and old.headers["location"] == "/dashboard/chat"

    headers = {"origin": "http://localhost"}
    dashboard = "ws://localhost/ws/dashboard"
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(dashboard + "?view=chat-security", headers={"origin": "https://other.example"}):
            pytest.fail("Cross-origin monitoring connection was accepted")

    with client.websocket_connect(dashboard, headers=headers) as legacy:
        assert legacy.receive_json()["type"] == "snapshot"
    with client.websocket_connect(dashboard + "?view=chat-security", headers=headers) as monitor:
        snapshot = monitor.receive_json()
        assert snapshot["type"] == "chat_security"
        assert snapshot["users"] == []
        with client.websocket_connect("ws://localhost/ws/chat/monitor-reader", headers=headers) as reader:
            reader.receive_json()
            with client.websocket_connect("ws://localhost/ws/chat/monitor-writer", headers=headers) as writer:
                writer.receive_json()
                reader.receive_json()
                writer.send_json({"recipient": "monitor-reader", "text": "Hello from the test"})
                assert reader.receive_json()["text"] == "Hello from the test"
                for _ in range(3):
                    snapshot = monitor.receive_json()
                    if any(sample[0] for sample in snapshot["samples"]):
                        break
                assert {user["username"]: user["messages"] for user in snapshot["users"]} == {
                    "monitor-reader": 0, "monitor-writer": 1,
                }
                assert sum(sample[0] or 0 for sample in snapshot["samples"]) == 1
                assert "Hello from the test" not in str(snapshot)
        for _ in range(3):
            snapshot = monitor.receive_json()
            if not snapshot["users"]:
                break
        assert snapshot["users"] == []
