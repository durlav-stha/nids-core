#!/usr/bin/env python3
"""
Autonomous NIDS Core Engine - Ingestion and Stateful Detection.
Captures network traffic via Scapy and tracks connection states in memory.
"""

import os
import time
import json
import random
import threading
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Import centralized configuration (thresholds, window sizes, file names)
import config

# Resolve state file path relative to project root so execution from C:\Windows\system32
# in an elevated Administrator shell always writes to the workspace metrics.json
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESOLVED_STATE_FILE = (
    config.STATE_FILE
    if os.path.isabs(config.STATE_FILE)
    else os.path.join(BASE_DIR, config.STATE_FILE)
)

# ----------------- 1. IN-MEMORY STATE TRACKING -----------------

# Maps each Source IP to a list of its targeted ports and timestamps:
# Format: { "192.168.1.50": [(destination_port, timestamp), ...] }
ip_flow_tracker = defaultdict(list)

# Records the last active timestamp for each IP (used to evict dead IPs from RAM)
last_seen = {}

# Records the last alert timestamp per (IP, alert_type) to prevent alert flooding
last_alert_time = defaultdict(float)

# Re-entrant mutual exclusion lock (RLock) to synchronize data access between
# sniffer and file writer threads without deadlocking when packet_handler()
# holds the lock and triggers evaluate_stateful_scan() -> register_alert().
lock = threading.RLock()

# Central telemetry dictionary that holds real-time stats for the dashboard
aggregated_metrics = {
    "schema_version": config.SCHEMA_VERSION,
    "last_updated": time.time(),    # Live boot timestamp prevents false 'stale' warnings
    "total_packets": 0,
    "tcp_count": 0,
    "udp_count": 0,
    "icmp_count": 0,
    "other_count": 0,
    "tracked_ips": 0,
    "alerts": []                    # Bounded list of recent security incidents
}

# ----------------- 2. ALERT DISPATCH & DEDUPLICATION -----------------

def register_alert(alert_type, src_ip, details, severity="HIGH"):
    """
    Registers a security incident with duplicate suppression and bounded history.
    """
    current_time = time.time()

    # 1. Deduplication check: Suppress duplicate alerts for the same IP within cooldown
    if current_time - last_alert_time[(src_ip, alert_type)] < config.ALERT_COOLDOWN:
        return

    # Update last recorded alert timestamp for this (IP, alert) pair
    last_alert_time[(src_ip, alert_type)] = current_time

    # 2. Build structured alert record
    alert_event = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "rule": alert_type,
        "source_ip": src_ip,
        "severity": severity,
        "explanation": details
    }

    # 3. Thread-safe insertion into the shared metrics dictionary
    with lock:
        # Prepend the newest alert to the top of the list
        aggregated_metrics["alerts"].insert(0, alert_event)

        # Enforce memory bounds: Keep only the most recent 50 alerts
        if len(aggregated_metrics["alerts"]) > 50:
            aggregated_metrics["alerts"].pop()

        aggregated_metrics["last_updated"] = current_time

    # 4. Immediate console alert banner
    print(f"\n[ALERT - {severity}] {alert_type} | Source: {src_ip} | {details}\n", flush=True)

# ----------------- 3. STATEFUL INSPECTION LOGIC -----------------

def evaluate_stateful_scan(src_ip, dst_port, current_time):
    """
    Evaluates whether a source IP is conducting a horizontal port scan
    using a sliding time-window algorithm.
    """
    # 1. Slide the window: Retain only connection attempts within the last TIME_WINDOW seconds
    history = ip_flow_tracker[src_ip]
    ip_flow_tracker[src_ip] = [
        (port, ts) for port, ts in history
        if current_time - ts <= config.TIME_WINDOW
    ]

    # 2. Append the current probe: store (destination_port, timestamp)
    ip_flow_tracker[src_ip].append((dst_port, current_time))

    # 3. Update the activity heartbeat for RAM eviction tracking
    last_seen[src_ip] = current_time

    # 4. Extract unique destination ports probed during this active window
    unique_ports = {port for port, ts in ip_flow_tracker[src_ip]}

    # 5. Evaluate against configurable threshold
    if len(unique_ports) >= config.SCAN_THRESHOLD:
        register_alert(
            alert_type="HORIZONTAL_TCP_PORT_SCAN",
            src_ip=src_ip,
            details=f"Probed {len(unique_ports)} unique ports in {config.TIME_WINDOW}s window.",
            severity="CRITICAL"
        )

# ----------------- 4. INGESTION, EVICTION & ATOMIC EXPORT -----------------

def packet_handler(packet):
    """
    Lightweight callback executed on every captured network frame.
    Updates protocol telemetry and routes TCP connection attempts for analysis.
    """
    # Filter: Process only Layer 3 IP traffic
    if not packet.haslayer(IP):
        return

    now = time.time()
    src_ip = packet[IP].src

    # Synchronize state modification with thread lock
    with lock:
        aggregated_metrics["total_packets"] += 1

        # Protocol accounting and deep packet inspection
        if packet.haslayer(TCP):
            aggregated_metrics["tcp_count"] += 1
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags

            # Bitwise check: SYN flag is set (0x02) and ACK flag is NOT set (0x10)
            # This isolates connection initiations (reconnaissance scans and handshakes)
            if flags & 0x02 and not (flags & 0x10):
                evaluate_stateful_scan(src_ip, dst_port, now)

        elif packet.haslayer(UDP):
            aggregated_metrics["udp_count"] += 1
        elif packet.haslayer(ICMP):
            aggregated_metrics["icmp_count"] += 1
        else:
            aggregated_metrics["other_count"] += 1

        aggregated_metrics["tracked_ips"] = len(ip_flow_tracker)


def atomic_write_metrics(snapshot, temp_file, target_file, max_retries=6):
    """
    Serializes telemetry state to disk with non-blocking exponential backoff and jitter
    to eliminate Windows NTFS concurrent file lock errors ([WinError 5] / [WinError 32])
    when the frontend dashboard concurrently reads metrics.json.
    """
    payload = json.dumps(snapshot, indent=2)

    # Step 1: Write serialized JSON to temporary file and close descriptor immediately
    for attempt in range(max_retries):
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(payload)
                f.flush()
            break
        except (PermissionError, OSError):
            if attempt == max_retries - 1:
                raise
            backoff = (0.008 * (2 ** attempt)) + random.uniform(0.001, 0.006)
            time.sleep(backoff)

    # Step 2: Atomic swap via os.replace with exponential backoff + jitter
    for attempt in range(max_retries):
        try:
            os.replace(temp_file, target_file)
            return
        except (PermissionError, OSError):
            if attempt < max_retries - 1:
                backoff = (0.008 * (2 ** attempt)) + random.uniform(0.001, 0.006)
                time.sleep(backoff)
            else:
                # Fallback for persistent NTFS MoveFileExW lock contention:
                # write directly to target_file with retry so heartbeat is never dropped.
                for fb_attempt in range(max_retries):
                    try:
                        with open(target_file, "w", encoding="utf-8") as f:
                            f.write(payload)
                            f.flush()
                        return
                    except (PermissionError, OSError):
                        if fb_attempt == max_retries - 1:
                            raise
                        time.sleep((0.008 * (2 ** fb_attempt)) + random.uniform(0.001, 0.006))


def memory_cleanup_and_export_loop():
    """
    Background worker loop:
    1. Evicts inactive IP sessions from RAM to prevent unbounded memory growth.
    2. Writes telemetry atomically using a temporary file swap to eliminate race conditions.
    """
    temp_file = f"{RESOLVED_STATE_FILE}.tmp"

    while True:
        loop_start = time.time()

        with lock:
            # 1. RAM Eviction: Identify and purge IPs that have been idle past timeout
            inactive_ips = [
                ip for ip, ts in last_seen.items()
                if loop_start - ts > config.IP_INACTIVITY_TIMEOUT
            ]
            for ip in inactive_ips:
                ip_flow_tracker.pop(ip, None)
                last_seen.pop(ip, None)

            # 2. Update telemetry heartbeat and active session count
            aggregated_metrics["tracked_ips"] = len(ip_flow_tracker)
            aggregated_metrics["last_updated"] = time.time()

            # Capture an in-memory snapshot while holding lock so disk I/O and
            # NTFS lock retries never block packet_handler() during traffic bursts
            snapshot = {
                **aggregated_metrics,
                "alerts": list(aggregated_metrics["alerts"])
            }

        # 3. Atomic file serialization with NTFS lock retry/backoff outside the packet lock
        try:
            atomic_write_metrics(snapshot, temp_file, RESOLVED_STATE_FILE)
        except Exception as e:
            print(f"[!] Serialization failure: {e}", flush=True)

        # Export rate: ~1 update per second (compensating for any retry backoff duration)
        elapsed = time.time() - loop_start
        time.sleep(max(0.1, 1.0 - elapsed))


def _disable_windows_console_quickedit():
    """
    Prevents Windows Console QuickEdit Mode from freezing the process when a user
    clicks inside the Administrator PowerShell window.
    """
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            stdin_handle = kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(stdin_handle, ctypes.byref(mode)):
                # Clear ENABLE_QUICK_EDIT_MODE (0x0040) and set ENABLE_EXTENDED_FLAGS (0x0080)
                new_mode = (mode.value & ~0x0040) | 0x0080
                kernel32.SetConsoleMode(stdin_handle, new_mode)
        except Exception:
            pass


def main():
    _disable_windows_console_quickedit()
    print("=" * 65, flush=True)
    print(" [*] Autonomous NIDS: Core Engine Initialized", flush=True)
    print(f" [*] Streaming state atomically to: {RESOLVED_STATE_FILE}", flush=True)
    print(f" [*] Kernel Filter (BPF): {config.BPF_FILTER}", flush=True)
    print(" [*] Press Ctrl+C in PyCharm to terminate.", flush=True)
    print("=" * 65, flush=True)

    # Write an immediate initial heartbeat before sniff() blocks
    initial_snapshot = {
        **aggregated_metrics,
        "last_updated": time.time(),
        "alerts": list(aggregated_metrics["alerts"]),
    }
    try:
        atomic_write_metrics(initial_snapshot, f"{RESOLVED_STATE_FILE}.tmp", RESOLVED_STATE_FILE)
    except Exception:
        pass

    # Launch background memory manager and state exporter thread
    exporter_worker = threading.Thread(target=memory_cleanup_and_export_loop, daemon=True)
    exporter_worker.start()

    # Launch continuous capture loop
    sniff(
        filter=config.BPF_FILTER,
        prn=packet_handler,
        iface=config.CAPTURE_INTERFACE,
        store=0
    )


if __name__ == "__main__":
    main()
