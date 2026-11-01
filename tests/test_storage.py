"""
Unit tests for data storage integrity and fault tolerance.
Verifies that corrupted, partial, or missing state files do not crash consumers.
"""

import os
import json
import unittest.mock as mock
import pytest
import config
import engine
import app


def safe_load_metrics(filepath):
    """
    Consumer utility function: attempts to parse metrics.json.
    Returns a default fallback dictionary if the file is missing or corrupted.
    """
    default_state = {
        "schema_version": config.SCHEMA_VERSION,
        "last_updated": 0,
        "total_packets": 0,
        "tcp_count": 0,
        "udp_count": 0,
        "icmp_count": 0,
        "other_count": 0,
        "tracked_ips": 0,
        "alerts": []
    }

    if not os.path.exists(filepath):
        return default_state

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        # Gracefully handle half-written files or disk read issues
        return default_state


def test_safe_load_missing_file(tmp_path):
    """Ensure non-existent files return default state without raising FileNotFoundError."""
    missing_file = tmp_path / "does_not_exist.json"
    data = safe_load_metrics(str(missing_file))

    assert data["total_packets"] == 0
    assert data["schema_version"] == config.SCHEMA_VERSION


def test_safe_load_corrupted_file(tmp_path):
    """Ensure malformed or partially written JSON is caught without raising JSONDecodeError."""
    corrupt_file = tmp_path / "corrupt.json"
    # Write broken, invalid JSON bytes
    corrupt_file.write_text('{"total_packets": 500, "status": "par', encoding="utf-8")

    data = safe_load_metrics(str(corrupt_file))

    assert data["total_packets"] == 0
    assert isinstance(data["alerts"], list)


def test_safe_load_valid_file(tmp_path):
    """Ensure correctly written metrics are properly loaded into memory."""
    valid_file = tmp_path / "valid.json"
    payload = {
        "schema_version": "1.0.0",
        "last_updated": 1700000000,
        "total_packets": 120,
        "tcp_count": 80,
        "udp_count": 40,
        "icmp_count": 0,
        "other_count": 0,
        "tracked_ips": 2,
        "alerts": []
    }
    valid_file.write_text(json.dumps(payload), encoding="utf-8")

    data = safe_load_metrics(str(valid_file))

    assert data["total_packets"] == 120
    assert data["tcp_count"] == 80


def test_ntfs_winerror5_retry_resilience(tmp_path):
    """Verify engine.atomic_write_metrics and app.safe_load_metrics recover from transient NTFS [WinError 5] locks."""
    temp_file = str(tmp_path / "metrics.json.tmp")
    target_file = str(tmp_path / "metrics.json")
    snapshot = {
        "schema_version": config.SCHEMA_VERSION,
        "last_updated": 1793203000.0,
        "total_packets": 42,
        "tcp_count": 30,
        "udp_count": 12,
        "icmp_count": 0,
        "other_count": 0,
        "tracked_ips": 1,
        "alerts": []
    }

    orig_replace = os.replace
    attempts = {"count": 0}

    def transient_locked_replace(src, dst):
        attempts["count"] += 1
        if attempts["count"] <= 2:
            raise PermissionError(13, "Access is denied", src, 5, dst)
        return orig_replace(src, dst)

    with mock.patch("os.replace", side_effect=transient_locked_replace):
        engine.atomic_write_metrics(snapshot, temp_file, target_file)

    assert attempts["count"] == 3
    loaded = app.safe_load_metrics(target_file)
    assert loaded["total_packets"] == 42
    assert loaded["tcp_count"] == 30


def test_packet_handler_port_scan_no_deadlock():
    """Verify packet_handler -> evaluate_stateful_scan -> register_alert does not deadlock on lock re-acquisition."""
    from scapy.all import IP, TCP

    engine.ip_flow_tracker.clear()
    engine.last_seen.clear()
    engine.last_alert_time.clear()
    engine.aggregated_metrics["alerts"].clear()
    engine.aggregated_metrics["total_packets"] = 0
    engine.aggregated_metrics["tcp_count"] = 0

    for port in range(9000, 9000 + config.SCAN_THRESHOLD + 5):
        pkt = IP(src="192.168.1.120", dst="192.168.1.1") / TCP(dport=port, flags="S")
        engine.packet_handler(pkt)

    assert engine.aggregated_metrics["total_packets"] == config.SCAN_THRESHOLD + 5
    assert len(engine.aggregated_metrics["alerts"]) == 1
    assert engine.aggregated_metrics["alerts"][0]["rule"] == "HORIZONTAL_TCP_PORT_SCAN"

