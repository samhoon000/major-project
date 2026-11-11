import asyncio

from backend.security.threat_engine import ThreatEngine


def evaluate(engine, msg=0.0, url=0.0, behavior=0.0, network=None):
    return asyncio.run(engine.evaluate_message_event(
        "test-user", "192.0.2.9",
        {"message_risk": msg, "indicators": ["message"] if msg else []},
        {"url_risk": url, "indicators": ["url"] if url else []},
        {"behavior_risk": behavior, "indicators": ["behavior"] if behavior else []},
        network,
    ))


def test_network_unavailable_is_explicit_and_other_signals_remain_actionable():
    result = evaluate(ThreatEngine(), msg=0.3, network=None)
    assert result["network_signal_available"] is False
    assert result["signals"]["network_signal_available"] is False
    assert result["signals"]["message_risk"] == 0.3
    assert result["final_risk"] > 0


def test_network_signal_available_participates_without_alone_blocking():
    result = evaluate(ThreatEngine(), network={"available": True, "anomaly_probability": 0.95,
                                                "is_anomaly": True, "confidence": 95})
    assert result["network_signal_available"] is True
    assert result["signals"]["gatv2_network_risk"] == 0.95
    assert result["action"] != "BLOCK_USER"


def test_combined_signals_reject_message_and_strong_behavior_blocks_user():
    combined = evaluate(ThreatEngine(), msg=0.8, url=0.9, behavior=0.8,
                        network={"available": True, "anomaly_probability": 0.8,
                                 "is_anomaly": True, "confidence": 80})
    assert combined["action"] in {"BLOCK_MESSAGE", "BLOCK_USER"}
    assert combined["final_risk"] > 0.6
    blocked = evaluate(ThreatEngine(), behavior=1.0)
    assert blocked["action"] == "BLOCK_USER"
