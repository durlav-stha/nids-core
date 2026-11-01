"""
Unit tests for the NIDS sliding-window detection algorithm.
Validates benign traffic thresholds, attack triggers, and time-based window pruning.
"""

import time
import pytest
import config
import engine


@pytest.fixture(autouse=True)
def reset_engine_state():
    """Fixture that clears engine memory before every single test run."""
    engine.ip_flow_tracker.clear()
    engine.last_seen.clear()
    engine.last_alert_time.clear()
    engine.aggregated_metrics["alerts"].clear()
    engine.aggregated_metrics["total_packets"] = 0


def test_benign_traffic_no_alert():
    """Verify that probing fewer ports than SCAN_THRESHOLD produces zero alerts."""
    test_ip = "192.168.1.100"
    base_time = time.time()

    # Simulate 5 connection attempts (threshold is 15)
    for port in range(80, 85):
        engine.evaluate_stateful_scan(test_ip, port, base_time)

    assert len(engine.aggregated_metrics["alerts"]) == 0


def test_port_scan_triggers_alert():
    """Verify that hitting exactly SCAN_THRESHOLD unique ports fires an alert."""
    test_ip = "10.0.0.99"
    base_time = time.time()

    # Simulate probing 15 unique destination ports
    for port in range(1, config.SCAN_THRESHOLD + 1):
        engine.evaluate_stateful_scan(test_ip, port, base_time)

    assert len(engine.aggregated_metrics["alerts"]) == 1
    alert = engine.aggregated_metrics["alerts"][0]
    assert alert["rule"] == "HORIZONTAL_TCP_PORT_SCAN"
    assert alert["source_ip"] == test_ip
    assert alert["severity"] == "CRITICAL"


def test_sliding_window_pruning():
    """Verify that probes outside the TIME_WINDOW are evicted and do not trigger false alerts."""
    test_ip = "172.16.0.5"
    base_time = 1000.0  # Simulated epoch time

    # Step 1: Send 10 probes at base_time
    for port in range(1, 11):
        engine.evaluate_stateful_scan(test_ip, port, base_time)

    # Step 2: Advance time past the 5-second window (6 seconds later)
    later_time = base_time + config.TIME_WINDOW + 1.0

    # Step 3: Send 5 more probes
    for port in range(11, 16):
        engine.evaluate_stateful_scan(test_ip, port, later_time)

    # Even though 15 total ports were hit across history, only 5 occurred within the window
    assert len(engine.aggregated_metrics["alerts"]) == 0