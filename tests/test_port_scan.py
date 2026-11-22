"""In-memory packet fixtures for passive detection logic."""
from scapy.layers.inet import IP, TCP

from backend.network.capture import parse_scapy_packet
from backend.network.port_scan import PortScanMonitor, ScanPolicy


def tcp(source, destination, source_port, destination_port, flags="S", seq=100, ack=0):
    return parse_scapy_packet(IP(src=source, dst=destination) /
                             TCP(sport=source_port, dport=destination_port, flags=flags, seq=seq, ack=ack))


def observed_attempt(monitor, source, destination, sport, dport, result="RA"):
    opening = tcp(source, destination, sport, dport)
    monitor.observe(opening)
    monitor.observe(opening)
    answer = tcp(destination, source, dport, sport, flags=result, ack=101)
    monitor.observe(answer)
    monitor.observe(answer)


def test_distinct_ports_and_refusals_are_required_and_grouped():
    monitor = PortScanMonitor(ScanPolicy(distinct_ports=3, failed_ports=2))
    for sport in range(48000, 48007):
        observed_attempt(monitor, "192.0.2.10", "192.0.2.20", sport, 443)
    single = monitor.snapshot()
    assert single["total_attempts"] == single["total_failed"] == 7
    assert single["unique_ports"] == 1 and single["active_alerts"] == 0

    for dport in (80, 443, 8443):
        observed_attempt(monitor, "192.0.2.11", "192.0.2.20", 48100, dport, result="SA")
    observed_attempt(monitor, "192.0.2.12", "192.0.2.20", 48101, 81)
    observed_attempt(monitor, "192.0.2.12", "192.0.2.21", 48102, 82)
    assert monitor.snapshot()["active_alerts"] == 0

    observed_attempt(monitor, "192.0.2.10", "192.0.2.20", 48103, 80)
    assert monitor.snapshot()["sources"][0]["status"] == "Suspicious"
    observed_attempt(monitor, "192.0.2.10", "192.0.2.20", 48104, 8443)
    observed_attempt(monitor, "192.0.2.10", "192.0.2.20", 48105, 8080)
    monitor.sample()
    confirmed = monitor.snapshot()
    assert confirmed["active_alerts"] == 1 and confirmed["active_mitigations"] == 0
    alerts = [event for event in confirmed["events"] if event["type"] == "alert"]
    assert len(alerts) == 1 and alerts[0]["source"] == "192.0.2.10"
    assert confirmed["samples"][-1]["failed_attempts"] == confirmed["total_failed"]


def test_window_and_restriction_expiry_do_not_realert_same_activity():
    clock = [10]
    monitor = PortScanMonitor(ScanPolicy(window_seconds=5, distinct_ports=3, failed_ports=2,
                                         restriction_seconds=2), clock=lambda: clock[0], wall_clock=lambda: clock[0])
    localhost = "127.0.0.1"
    pair = (localhost, localhost)
    for dport in (80, 81, 82):
        observed_attempt(monitor, localhost, localhost, 48200, dport)
    alert_id = monitor.restriction(pair)
    assert alert_id
    monitor.record_rejection(pair, alert_id)
    monitor.record_rejection(pair, alert_id)
    clock[0] += 2
    assert monitor.restriction(pair) is None
    assert monitor.snapshot()["sources"][0]["status"] == "Recovered"
    observed_attempt(monitor, localhost, localhost, 48200, 83)
    assert monitor.restriction(pair) is None
    clock[0] += 5
    data = monitor.snapshot()
    assert data["attempts"] == data["unique_ports"] == data["active_alerts"] == 0
    assert [event["type"] for event in data["events"]].count("verified") == 1
    for dport in (80, 81, 82):
        observed_attempt(monitor, localhost, localhost, 48200, dport)
    assert monitor.restriction(pair) != alert_id


def test_unmatched_resets_and_unanswered_connections_are_not_refusals():
    monitor = PortScanMonitor(ScanPolicy(distinct_ports=2, failed_ports=1))
    source, target = "192.0.2.10", "192.0.2.20"
    monitor.observe(tcp(source, target, 48300, 80))
    monitor.observe(tcp(source, target, 48301, 81))
    monitor.observe(tcp(target, source, 80, 48300, flags="RA", ack=202))
    monitor.observe(tcp(target, source, 81, 48302, flags="RA", ack=101))
    snapshot = monitor.snapshot()
    assert snapshot["attempts"] == 2
    assert snapshot["failed_attempts"] == snapshot["active_alerts"] == 0


def test_reused_tcp_tuple_with_new_sequence_is_a_distinct_attempt():
    monitor = PortScanMonitor()
    source, target = "192.0.2.10", "192.0.2.20"
    for sequence in (100, 200):
        monitor.observe(tcp(source, target, 48300, 80, seq=sequence))
        monitor.observe(tcp(target, source, 80, 48300, flags="RA", ack=sequence + 1))
    data = monitor.snapshot()
    assert data["attempts"] == data["failed_attempts"] == 2
    assert data["unique_ports"] == 1
