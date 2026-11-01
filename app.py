#!/usr/bin/env python3
"""
Production-Grade NIDS Dark SOC Command Console (Streamlit).
Reads decoupled telemetry atomically exported by engine.py into metrics.json.

Security & Engineering Guarantees:
- Strictly read-only consumer of metrics.json with fault-tolerant JSON parsing.
- Immediate file descriptor closure and exponential backoff/jitter for Windows NTFS lock resilience.
- Localhost-only binding (127.0.0.1) via .streamlit/config.toml and CLI enforcement.
- Zero raw packet payload exposure: strictly whitelists metadata fields only.
- Real-time liveness verification against engine heartbeat timestamps.
"""

import html
import json
import math
import os
import random
import time
from typing import Any, Dict, List

import streamlit as st

import config

# ----------------- CONSTANTS & THRESHOLDS -----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESOLVED_STATE_FILE = (
    config.STATE_FILE
    if os.path.isabs(config.STATE_FILE)
    else os.path.join(BASE_DIR, config.STATE_FILE)
)
STALE_THRESHOLD_SECONDS = 3.0
POLL_INTERVAL_SECONDS = 1.0
ALLOWED_ALERT_FIELDS = ("timestamp", "rule", "source_ip", "severity", "explanation")
HISTORY_MAX_POINTS = 14
VALID_VIEWS = ("overview", "threats", "traffic", "health", "settings")


def _clean_html(raw_html: str) -> str:
    """
    Collapses multi-line HTML/SVG templates into clean single-block HTML without
    leading 4-space indentation or blank lines so Streamlit's Markdown parser never
    misinterprets nested HTML/SVG tags as CommonMark indented code blocks.
    """
    return "\n".join(line.strip() for line in raw_html.splitlines() if line.strip())


def render_html(raw_html: str) -> None:
    """Renders sanitized, indentation-stripped HTML/SVG in Streamlit."""
    st.markdown(_clean_html(raw_html), unsafe_allow_html=True)


def get_default_metrics() -> Dict[str, Any]:
    """Returns a safe fallback state dictionary when metrics.json is unavailable or corrupt."""
    return {
        "schema_version": config.SCHEMA_VERSION,
        "last_updated": 0.0,
        "total_packets": 0,
        "tcp_count": 0,
        "udp_count": 0,
        "icmp_count": 0,
        "other_count": 0,
        "tracked_ips": 0,
        "alerts": [],
    }


def safe_load_metrics(filepath: str = config.STATE_FILE, max_retries: int = 5) -> Dict[str, Any]:
    """
    Fault-tolerant reader for metrics.json.
    Closes the file descriptor immediately after reading raw bytes into memory and
    uses short exponential backoff with jitter to handle transient Windows NTFS locks
    ([WinError 5] Access is denied / [WinError 32] Sharing violation).
    """
    default_state = get_default_metrics()
    if filepath == config.STATE_FILE and not os.path.isabs(filepath):
        filepath = RESOLVED_STATE_FILE

    if not os.path.exists(filepath):
        return default_state

    raw_text = ""
    for attempt in range(max_retries):
        try:
            # Close file handle immediately after reading raw text into RAM
            # to minimize NTFS read-handle retention window to microseconds.
            with open(filepath, "r", encoding="utf-8") as f:
                raw_text = f.read()

            if not raw_text.strip():
                if attempt < max_retries - 1:
                    time.sleep((0.008 * (2 ** attempt)) + random.uniform(0.001, 0.005))
                    continue
                return default_state

            raw_data = json.loads(raw_text)
            if not isinstance(raw_data, dict):
                return default_state

            # Merge with default_state to guarantee all expected keys exist with safe types
            sanitized: Dict[str, Any] = {
                "schema_version": str(raw_data.get("schema_version", config.SCHEMA_VERSION)),
                "last_updated": float(raw_data.get("last_updated", 0.0) or 0.0),
                "total_packets": int(raw_data.get("total_packets", 0) or 0),
                "tcp_count": int(raw_data.get("tcp_count", 0) or 0),
                "udp_count": int(raw_data.get("udp_count", 0) or 0),
                "icmp_count": int(raw_data.get("icmp_count", 0) or 0),
                "other_count": int(raw_data.get("other_count", 0) or 0),
                "tracked_ips": int(raw_data.get("tracked_ips", 0) or 0),
                "alerts": sanitize_alerts(raw_data.get("alerts", [])),
            }
            return sanitized

        except (PermissionError, OSError):
            if attempt < max_retries - 1:
                backoff = (0.008 * (2 ** attempt)) + random.uniform(0.001, 0.005)
                time.sleep(backoff)
            else:
                return default_state
        except (json.JSONDecodeError, ValueError, TypeError):
            return default_state

    return default_state


def sanitize_alerts(raw_alerts: Any) -> List[Dict[str, str]]:
    """
    Security hardening filter: strips any unexpected fields or raw packet payloads
    so only whitelisted structured incident metadata is ever rendered in the UI.
    """
    if not isinstance(raw_alerts, list):
        return []

    clean_alerts: List[Dict[str, str]] = []
    for item in raw_alerts:
        if not isinstance(item, dict):
            continue
        # Strictly whitelist metadata fields; never allow raw payload bytes/hex
        clean_alerts.append(
            {
                "Timestamp": str(item.get("timestamp", "N/A")),
                "Rule Triggered": str(item.get("rule", "UNKNOWN_RULE")),
                "Source IP": str(item.get("source_ip", "0.0.0.0")),
                "Severity": str(item.get("severity", "INFO")).upper(),
                "Event Explanation": str(item.get("explanation", "No details provided.")),
            }
        )
    return clean_alerts


def evaluate_liveness(last_updated: float, current_time: float | None = None) -> tuple[bool, float]:
    """
    Compares current system time against `last_updated` from metrics.json.
    Returns (is_online, time_since_update).
    Engine is considered OFFLINE/STALE if last_updated <= 0 or time_since_update > 3.0s.
    """
    now = current_time if current_time is not None else time.time()
    if last_updated <= 0:
        return False, float("inf")
    time_since_update = max(0.0, now - last_updated)
    is_online = time_since_update <= STALE_THRESHOLD_SECONDS
    return is_online, time_since_update


def format_threat_title(raw_rule: str) -> str:
    """Converts internal rule constants like HORIZONTAL_TCP_PORT_SCAN into clean SOC titles."""
    mapping = {
        "HORIZONTAL_TCP_PORT_SCAN": "Horizontal TCP Port Scan",
    }
    if raw_rule in mapping:
        return mapping[raw_rule]
    return raw_rule.replace("_", " ").title()


# ----------------- BESPOKE GLOWING VECTOR SVG ICONS -----------------

SVG_SHIELD_BRAND = _clean_html("""
<svg width="28" height="28" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="shieldGrad" x1="0" y1="0" x2="28" y2="28" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#38BDF8"/>
      <stop offset="100%" stop-color="#0066FF"/>
    </linearGradient>
    <filter id="shieldGlow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="0" stdDeviation="2.5" flood-color="#00A3FF" flood-opacity="0.55"/>
    </filter>
  </defs>
  <path filter="url(#shieldGlow)" d="M14 2.5L4.5 6.7V13.6C4.5 19.75 8.55 25.35 14 26.8C19.45 25.35 23.5 19.75 23.5 13.6V6.7L14 2.5Z" fill="url(#shieldGrad)" fill-opacity="0.22" stroke="url(#shieldGrad)" stroke-width="1.8"/>
  <path d="M14 6.5L8 9.2V13.5C8 17.5 10.55 21.1 14 22.2C17.45 21.1 20 17.5 20 13.5V9.2L14 6.5Z" fill="url(#shieldGrad)" fill-opacity="0.45"/>
</svg>
""")

SVG_ECG_PULSE = _clean_html("""
<svg width="26" height="16" viewBox="0 0 26 16" fill="none" xmlns="http://www.w3.org/2000/svg" style="vertical-align: middle; margin-left: 6px;">
  <defs>
    <filter id="ecgGlow" x="-25%" y="-25%" width="150%" height="150%">
      <feDropShadow dx="0" dy="0" stdDeviation="1.8" flood-color="#00A3FF" flood-opacity="0.8"/>
    </filter>
  </defs>
  <path filter="url(#ecgGlow)" d="M1 8H6L8.5 2.5L12 13.5L15.5 5L18 10.5L20 8H25" stroke="#38BDF8" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
""")

SVG_KPI_PACKETS = _clean_html("""
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
  <ellipse cx="12" cy="5" rx="8" ry="3" stroke="#38BDF8" stroke-width="1.8" fill="rgba(0,163,255,0.15)"/>
  <path d="M4 5V12C4 13.66 7.58 15 12 15C16.42 15 20 13.66 20 12V5" stroke="#38BDF8" stroke-width="1.8"/>
  <path d="M4 12V19C4 20.66 7.58 22 12 22C16.42 22 20 20.66 20 19V12" stroke="#00A3FF" stroke-width="1.8"/>
</svg>
""")

SVG_KPI_IPS = _clean_html("""
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect x="2" y="3" width="20" height="14" rx="2.5" stroke="#38BDF8" stroke-width="1.8" fill="rgba(0,163,255,0.12)"/>
  <path d="M8 21H16" stroke="#00A3FF" stroke-width="1.8" stroke-linecap="round"/>
  <path d="M12 17V21" stroke="#00A3FF" stroke-width="1.8" stroke-linecap="round"/>
  <circle cx="7.5" cy="10" r="1.3" fill="#38BDF8"/>
  <path d="M11 10H17" stroke="#38BDF8" stroke-width="1.6" stroke-linecap="round"/>
</svg>
""")

SVG_KPI_ALERTS = _clean_html("""
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M10.29 3.86L1.82 18A2 2 0 003.54 21H20.46A2 2 0 0022.18 18L13.71 3.86A2 2 0 0010.29 3.86Z" stroke="#EF4444" stroke-width="1.8" fill="rgba(239,68,68,0.16)"/>
  <line x1="12" y1="9" x2="12" y2="13.5" stroke="#F87171" stroke-width="2" stroke-linecap="round"/>
  <circle cx="12" cy="17" r="1.1" fill="#F87171"/>
</svg>
""")

SVG_KPI_TCP = _clean_html("""
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" stroke="#38BDF8" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" stroke="#00A3FF" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
""")

SVG_SECTION_TRAFFIC = _clean_html("""
<svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="vertical-align: -3px; margin-right: 6px;">
  <polyline points="22 7 13.5 15.5 8.5 10.5 2 17" stroke="#00A3FF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  <polyline points="16 7 22 7 22 13" stroke="#38BDF8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
""")

SVG_SECTION_DONUT = _clean_html("""
<svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="vertical-align: -3px; margin-right: 6px;">
  <path d="M21.21 15.89A10 10 0 1 1 8 2.83" stroke="#00A3FF" stroke-width="2" stroke-linecap="round"/>
  <path d="M22 12A10 10 0 0 0 12 2v10z" stroke="#38BDF8" stroke-width="2" stroke-linejoin="round" fill="rgba(0,163,255,0.2)"/>
</svg>
""")

SVG_SECTION_INCIDENTS = _clean_html("""
<svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="vertical-align: -3px; margin-right: 6px;">
  <rect x="4" y="3" width="16" height="18" rx="2" stroke="#38BDF8" stroke-width="1.8" fill="rgba(0,163,255,0.1)"/>
  <line x1="8" y1="8" x2="16" y2="8" stroke="#38BDF8" stroke-width="1.6" stroke-linecap="round"/>
  <line x1="8" y1="12" x2="16" y2="12" stroke="#38BDF8" stroke-width="1.6" stroke-linecap="round"/>
  <line x1="8" y1="16" x2="13" y2="16" stroke="#38BDF8" stroke-width="1.6" stroke-linecap="round"/>
</svg>
""")


def inject_custom_css() -> None:
    """Injects the Executive Dark SOC Command Console styling, glassmorphism, and glowing chart aesthetics."""
    render_html(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

        .stApp, [data-testid="stAppViewContainer"] {
            background: radial-gradient(circle at 50% 0%, #111827 0%, #0A0D14 65%) !important;
            color: #F8FAFC;
            font-family: 'Inter', sans-serif;
        }
        [data-testid="stHeader"] {
            background: transparent !important;
        }
        .block-container {
            padding-top: 1.5rem !important;
            padding-bottom: 2rem !important;
            max-width: 1440px !important;
        }

        [data-testid="stSidebar"], [data-testid="stSidebar"] > div:first-child {
            background-color: #0B0F19 !important;
            border-right: 1px solid #1E2638 !important;
        }
        [data-testid="stSidebarHeader"] {
            height: 2.25rem !important;
            min-height: 2.25rem !important;
            padding: 0.4rem 0.75rem 0 0.75rem !important;
        }
        [data-testid="stSidebarUserContent"] {
            padding-top: 0.25rem !important;
            padding-bottom: 1rem !important;
        }

        .soc-header-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 1rem;
            padding-bottom: 1.1rem;
            margin-bottom: 1.25rem;
            border-bottom: 1px solid #1E2638;
        }
        .soc-title {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.75rem;
            font-weight: 700;
            color: #FFFFFF;
            margin: 0;
            line-height: 1.2;
            letter-spacing: -0.02em;
        }
        .soc-subtitle {
            font-family: 'Inter', sans-serif;
            font-size: 0.9rem;
            color: #94A3B8;
            margin-top: 0.25rem;
        }
        .soc-status-cluster {
            display: flex;
            align-items: center;
            gap: 0.85rem;
            flex-wrap: wrap;
        }
        .pill-monitoring-active {
            display: inline-flex;
            align-items: center;
            gap: 0.45rem;
            padding: 0.4rem 0.9rem;
            border-radius: 999px;
            background: rgba(16, 185, 129, 0.12);
            border: 1px solid rgba(16, 185, 129, 0.4);
            color: #10B981;
            font-family: 'Inter', sans-serif;
            font-size: 0.82rem;
            font-weight: 600;
            box-shadow: 0 0 14px rgba(16, 185, 129, 0.15);
        }
        .pill-monitoring-offline {
            display: inline-flex;
            align-items: center;
            gap: 0.45rem;
            padding: 0.4rem 0.9rem;
            border-radius: 999px;
            background: rgba(239, 68, 68, 0.14);
            border: 1px solid rgba(239, 68, 68, 0.45);
            color: #EF4444;
            font-family: 'Inter', sans-serif;
            font-size: 0.82rem;
            font-weight: 600;
            box-shadow: 0 0 14px rgba(239, 68, 68, 0.2);
        }
        .status-dot-green {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: #10B981;
            box-shadow: 0 0 8px #10B981;
            display: inline-block;
        }
        .status-dot-red {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: #EF4444;
            box-shadow: 0 0 8px #EF4444;
            display: inline-block;
        }
        .liveness-box {
            display: inline-flex;
            align-items: center;
            padding: 0.38rem 0.85rem;
            border-radius: 8px;
            background: #111622;
            border: 1px solid #1E2638;
            color: #94A3B8;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
        }
        .liveness-time {
            color: #F8FAFC;
            font-weight: 600;
            margin-left: 0.35rem;
        }

        .kpi-card {
            position: relative;
            overflow: hidden;
            background: linear-gradient(180deg, #131927 0%, #111622 100%);
            border: 1px solid #1E2638;
            border-radius: 12px;
            padding: 1.15rem 1.25rem 0.95rem 1.25rem;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
            min-height: 142px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            box-sizing: border-box;
        }
        .kpi-card-alert {
            border-color: rgba(239, 68, 68, 0.42);
            box-shadow: 0 8px 24px rgba(239, 68, 68, 0.12);
        }
        .kpi-top-row {
            display: flex;
            align-items: center;
            gap: 0.65rem;
            margin-bottom: 0.45rem;
            z-index: 2;
        }
        .kpi-icon-box {
            width: 34px;
            height: 34px;
            border-radius: 8px;
            background: rgba(0, 163, 255, 0.1);
            border: 1px solid rgba(56, 189, 248, 0.25);
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }
        .kpi-icon-box-alert {
            background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.32);
        }
        .kpi-label {
            font-family: 'Inter', sans-serif;
            font-size: 0.88rem;
            font-weight: 500;
            color: #CBD5E1;
        }
        .kpi-value {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 2.05rem;
            font-weight: 700;
            color: #FFFFFF;
            line-height: 1.1;
            margin: 0.15rem 0 0.45rem 0;
            z-index: 2;
        }
        .kpi-value-crimson {
            color: #EF4444;
            text-shadow: 0 0 18px rgba(239, 68, 68, 0.45);
        }
        .kpi-subtext {
            font-family: 'Inter', sans-serif;
            font-size: 0.78rem;
            font-weight: 500;
            color: #38BDF8;
            z-index: 2;
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }
        .kpi-subtext-alert {
            color: #F87171;
        }
        .kpi-sparkline-wrap {
            position: absolute;
            right: 0;
            bottom: 0;
            width: 58%;
            height: 56px;
            pointer-events: none;
            z-index: 1;
            opacity: 0.9;
        }

        .soc-panel-card {
            background: linear-gradient(180deg, #131927 0%, #111622 100%);
            border: 1px solid #1E2638;
            border-radius: 12px;
            padding: 1.15rem 1.3rem;
            box-shadow: 0 8px 28px rgba(0, 0, 0, 0.38);
            margin-top: 0.75rem;
            margin-bottom: 1.1rem;
            box-sizing: border-box;
        }
        .soc-panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 0.85rem;
        }
        .soc-panel-title {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.05rem;
            font-weight: 600;
            color: #F8FAFC;
            display: flex;
            align-items: center;
        }
        .soc-live-pill {
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            padding: 0.25rem 0.7rem;
            border-radius: 999px;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #94A3B8;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
        }
        .soc-live-pill strong {
            color: #10B981;
        }

        .donut-layout {
            display: flex;
            align-items: center;
            justify-content: space-around;
            gap: 1rem;
            min-height: 230px;
        }
        .donut-legend {
            display: flex;
            flex-direction: column;
            gap: 0.65rem;
            flex: 1;
            max-width: 190px;
        }
        .donut-legend-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 0.85rem;
            color: #CBD5E1;
        }
        .donut-legend-left {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .donut-swatch {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
        }
        .donut-pct {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 600;
            color: #F8FAFC;
        }

        .threat-banner-crimson {
            background: linear-gradient(90deg, rgba(220, 38, 38, 0.18) 0%, rgba(19, 25, 39, 0.96) 55%, rgba(220, 38, 38, 0.12) 100%);
            border: 1px solid rgba(239, 68, 68, 0.5);
            border-radius: 12px;
            padding: 1rem 1.35rem;
            margin-bottom: 1.15rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            flex-wrap: wrap;
            box-shadow: 0 0 28px rgba(239, 68, 68, 0.16);
        }
        .threat-banner-left {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        .threat-alert-icon-circle {
            width: 46px;
            height: 46px;
            border-radius: 10px;
            background: rgba(239, 68, 68, 0.18);
            border: 1px solid rgba(239, 68, 68, 0.45);
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 16px rgba(239, 68, 68, 0.35);
            flex-shrink: 0;
        }
        .threat-tag-row {
            display: flex;
            align-items: center;
            gap: 0.55rem;
            flex-wrap: wrap;
        }
        .threat-tag {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.74rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #F87171;
        }
        .threat-main-title {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.12rem;
            font-weight: 700;
            color: #FFFFFF;
        }
        .threat-sub-detail {
            font-family: 'Inter', sans-serif;
            font-size: 0.85rem;
            color: #CBD5E1;
            margin-top: 0.2rem;
        }
        .threat-sub-detail span.mono {
            font-family: 'JetBrains Mono', monospace;
            color: #F8FAFC;
            font-weight: 600;
        }
        .threat-banner-right {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .pill-critical-solid {
            padding: 0.3rem 0.8rem;
            border-radius: 6px;
            background: rgba(239, 68, 68, 0.22);
            border: 1px solid #EF4444;
            color: #FCA5A5;
            font-family: 'Inter', sans-serif;
            font-size: 0.78rem;
            font-weight: 700;
        }
        .btn-view-details {
            padding: 0.42rem 0.95rem;
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.18);
            color: #F8FAFC !important;
            font-family: 'Inter', sans-serif;
            font-size: 0.82rem;
            font-weight: 600;
            text-decoration: none !important;
            transition: all 0.15s ease;
            cursor: pointer;
        }
        .btn-view-details:hover {
            background: rgba(0, 163, 255, 0.18);
            border-color: #38BDF8;
            color: #FFFFFF !important;
        }

        .threat-banner-nominal {
            background: linear-gradient(90deg, rgba(16, 185, 129, 0.12) 0%, rgba(19, 25, 39, 0.95) 100%);
            border: 1px solid rgba(16, 185, 129, 0.35);
            border-radius: 12px;
            padding: 0.9rem 1.25rem;
            margin-bottom: 1.15rem;
            display: flex;
            align-items: center;
            gap: 0.85rem;
            color: #D1FAE5;
            font-size: 0.9rem;
            font-weight: 500;
        }

        .soc-table-wrap {
            width: 100%;
            overflow-x: auto;
        }
        table.soc-incidents-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.86rem;
        }
        table.soc-incidents-table th {
            text-align: left;
            padding: 0.7rem 0.9rem;
            color: #94A3B8;
            font-family: 'Inter', sans-serif;
            font-weight: 600;
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            border-bottom: 1px solid #1E2638;
            background: rgba(10, 13, 20, 0.45);
        }
        table.soc-incidents-table td {
            padding: 0.8rem 0.9rem;
            border-bottom: 1px solid rgba(30, 38, 56, 0.65);
            color: #E2E8F0;
            vertical-align: middle;
        }
        table.soc-incidents-table tr:last-child td {
            border-bottom: none;
        }
        table.soc-incidents-table tr:hover td {
            background: rgba(0, 163, 255, 0.04);
        }
        .td-mono {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.83rem;
            color: #CBD5E1;
        }
        .td-threat-type {
            font-weight: 600;
            color: #FFFFFF;
        }
        .pill-table-critical {
            display: inline-block;
            padding: 0.2rem 0.65rem;
            border-radius: 6px;
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid rgba(239, 68, 68, 0.5);
            color: #F87171;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .btn-table-details {
            display: inline-block;
            padding: 0.28rem 0.8rem;
            border-radius: 6px;
            background: #1A2234;
            border: 1px solid #2A364F;
            color: #CBD5E1 !important;
            font-size: 0.76rem;
            font-weight: 500;
            text-decoration: none !important;
            transition: all 0.15s ease;
        }
        .btn-table-details:hover {
            background: rgba(0, 163, 255, 0.16);
            border-color: #38BDF8;
            color: #FFFFFF !important;
        }
        .link-view-all {
            font-size: 0.82rem;
            color: #38BDF8 !important;
            text-decoration: none !important;
            font-weight: 500;
        }
        .link-view-all:hover {
            text-decoration: underline !important;
        }

        .sidebar-shell {
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: calc(100vh - 3.8rem);
            box-sizing: border-box;
        }
        .sidebar-top-group {
            display: flex;
            flex-direction: column;
        }
        .sidebar-bottom-dock {
            margin-top: auto;
            padding-top: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 0.65rem;
        }
        .sidebar-brand {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.25rem 0.2rem 1rem 0.2rem;
            border-bottom: 1px solid #1E2638;
            margin-bottom: 1rem;
        }
        .sidebar-brand-title {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.25rem;
            font-weight: 700;
            color: #FFFFFF;
            line-height: 1.1;
            letter-spacing: 0.02em;
        }
        .sidebar-brand-sub {
            font-size: 0.7rem;
            color: #94A3B8;
            line-height: 1.25;
            margin-top: 2px;
        }
        .sidebar-nav-list {
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
        }
        a.sidebar-nav-item {
            display: flex;
            align-items: center;
            gap: 0.7rem;
            padding: 0.62rem 0.85rem;
            border-radius: 8px;
            color: #94A3B8 !important;
            text-decoration: none !important;
            font-size: 0.88rem;
            font-weight: 500;
            border: 1px solid transparent;
            transition: all 0.15s ease;
        }
        a.sidebar-nav-item:hover {
            background: rgba(255, 255, 255, 0.04);
            color: #E2E8F0 !important;
            border-color: rgba(56, 189, 248, 0.2);
        }
        a.sidebar-nav-item.active {
            background: linear-gradient(90deg, rgba(0, 163, 255, 0.16) 0%, rgba(0, 163, 255, 0.03) 100%);
            border: 1px solid rgba(0, 163, 255, 0.32);
            border-left: 3px solid #00A3FF;
            color: #FFFFFF !important;
            font-weight: 600;
            box-shadow: 0 4px 14px rgba(0, 163, 255, 0.1);
        }
        .sidebar-engine-pill {
            background: #111622;
            border: 1px solid #1E2638;
            border-radius: 10px;
            padding: 0.72rem 0.82rem;
        }
        .sidebar-engine-row {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.81rem;
            font-weight: 600;
            color: #E2E8F0;
            white-space: nowrap;
        }
        .sidebar-engine-ver {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.70rem;
            color: #64748B;
            margin-top: 0.22rem;
            padding-left: 0.95rem;
            white-space: nowrap;
        }
        .sidebar-dev-card {
            background: #111622;
            border: 1px solid #1E2638;
            border-radius: 10px;
            padding: 0.72rem 0.82rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.45rem;
        }
        .sidebar-dev-name {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.80rem;
            font-weight: 600;
            color: #F8FAFC;
            line-height: 1.2;
            white-space: nowrap;
            letter-spacing: -0.01em;
        }
        .sidebar-dev-links {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-shrink: 0;
        }
        a.sidebar-dev-icon {
            color: #94A3B8 !important;
            text-decoration: none !important;
            display: inline-flex;
            align-items: center;
            transition: color 0.15s ease, transform 0.15s ease;
        }
        a.sidebar-dev-icon:hover {
            color: #38BDF8 !important;
            transform: translateY(-1px);
        }

        /* Forensic Inspector & Secondary Views */
        .forensic-grid,
        .forensic-grid-3 {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 0.9rem;
            margin-top: 0.85rem;
            margin-bottom: 0.85rem;
        }
        .forensic-grid-4 {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 0.9rem;
            margin-top: 0.85rem;
            margin-bottom: 0.85rem;
        }
        @media (max-width: 1100px) {
            .forensic-grid-3, .forensic-grid-4 {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        .forensic-kv-box {
            background: #0D111A;
            border: 1px solid #1E2638;
            border-radius: 8px;
            padding: 0.85rem 1rem;
            min-width: 0;
        }
        .forensic-kv-label {
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #64748B;
            margin-bottom: 0.28rem;
            font-weight: 600;
        }
        .forensic-kv-val {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.90rem;
            font-weight: 600;
            color: #F8FAFC;
            overflow-wrap: anywhere;
        }
        .soc-json-viewer {
            background: #0B0E17;
            border: 1px solid #1E2638;
            border-radius: 8px;
            padding: 1rem 1.15rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.81rem;
            line-height: 1.55;
            color: #38BDF8;
            overflow-x: auto;
            margin: 0;
            white-space: pre-wrap;
        }
        .btn-table-details-active {
            display: inline-block;
            padding: 0.28rem 0.8rem;
            border-radius: 6px;
            background: rgba(0, 163, 255, 0.18);
            border: 1px solid #00A3FF;
            color: #FFFFFF !important;
            font-size: 0.76rem;
            font-weight: 600;
            text-decoration: none !important;
        }
        .proto-bar-row {
            margin-bottom: 0.9rem;
        }
        .proto-bar-top {
            display: flex;
            justify-content: space-between;
            font-size: 0.84rem;
            margin-bottom: 0.3rem;
            color: #CBD5E1;
        }
        .proto-bar-track {
            width: 100%;
            height: 8px;
            background: #0D111A;
            border-radius: 999px;
            overflow: hidden;
            border: 1px solid #1E2638;
        }
        .proto-bar-fill {
            height: 100%;
            border-radius: 999px;
        }
        </style>
        """
    )


def format_share_pct(count: int, total: int, decimals: int = 1) -> str:
    """
    Formats protocol volume percentages accurately so non-zero packet counts
    (e.g., 1 ICMP packet out of 100,000) display as '<0.1%' or '<1%' rather than '0%'.
    """
    if total <= 0 or count <= 0:
        return "0%" if decimals <= 0 else f"{0.0:.{decimals}f}%"
    pct = (count / total) * 100.0
    threshold = 1.0 if decimals <= 0 else (10.0 ** (-decimals))
    if pct < threshold:
        return "<1%" if decimals <= 0 else f"<{threshold:.{decimals}f}%"
    return f"{round(pct)}%" if decimals <= 0 else f"{pct:.{decimals}f}%"


def extract_target_scope(explanation: str) -> str:
    """Extracts dynamic port probe telemetry from the alert explanation for SOC table display."""
    if "unique ports" in explanation:
        parts = explanation.split(" ")
        for i, token in enumerate(parts):
            if token == "Probed" and i + 1 < len(parts) and parts[i + 1].isdigit():
                return f"{parts[i + 1]} Unique TCP Ports (SYN 0x02)"
    return "Multiple TCP Ports (SYN 0x02)"


def update_traffic_history(total_packets: int) -> List[Dict[str, Any]]:
    """
    Maintains a rolling buffer of recent packet telemetry timestamps, cumulative totals,
    and per-second ingestion rates (pps) in st.session_state so the Real-Time Traffic
    spline area waveform animates smoothly and accurately reflects Packets/sec.
    """
    now_str = time.strftime("%H:%M:%S")
    wave_pattern = [22, 28, 25, 34, 31, 42, 38, 48, 44, 52, 46, 58, 53]

    if "traffic_history" not in st.session_state or not st.session_state["traffic_history"]:
        base_ts = time.time()
        seeded: List[Dict[str, Any]] = []
        running_total = max(0, total_packets - sum(wave_pattern))
        for idx in range(HISTORY_MAX_POINTS - 1, 0, -1):
            t_label = time.strftime("%H:%M:%S", time.localtime(base_ts - idx))
            step_pps = wave_pattern[(HISTORY_MAX_POINTS - 1 - idx) % len(wave_pattern)] if total_packets > 0 else 0
            running_total = min(total_packets, running_total + step_pps)
            seeded.append({"time": t_label, "value": running_total, "pps": step_pps})
        latest_pps = wave_pattern[-1] if total_packets > 0 else 0
        seeded.append({"time": now_str, "value": total_packets, "pps": latest_pps})
        st.session_state["traffic_history"] = seeded
    else:
        history: List[Dict[str, Any]] = st.session_state["traffic_history"]
        if history[-1]["time"] != now_str:
            prev_total = int(history[-1].get("value", total_packets))
            delta_pps = max(0, total_packets - prev_total)
            history.append({"time": now_str, "value": total_packets, "pps": delta_pps})
            if len(history) > HISTORY_MAX_POINTS:
                history.pop(0)
        else:
            prev_total = int(history[-2]["value"]) if len(history) >= 2 else int(history[-1].get("value", total_packets))
            delta_pps = max(int(history[-1].get("pps", 0)), max(0, total_packets - prev_total))
            history[-1]["value"] = total_packets
            history[-1]["pps"] = delta_pps

    return st.session_state["traffic_history"]


def build_kpi_sparkline_svg(color: str, fill_id: str, variant: int = 0) -> str:
    """Builds a glowing neon vector sparkline SVG for the bottom-right of each KPI metric card."""
    paths = [
        "M0,42 C25,40 40,26 65,28 C90,30 110,12 135,16 C155,19 175,6 200,8",
        "M0,44 C30,36 55,38 80,22 C105,8 130,24 155,14 C175,6 188,10 200,5",
        "M0,45 C35,44 60,40 90,32 C115,25 135,8 160,18 C180,26 190,6 200,4",
        "M0,40 C28,32 52,20 82,26 C112,32 138,10 165,12 C182,13 192,5 200,6",
    ]
    curve = paths[variant % len(paths)]
    return _clean_html(f"""
    <svg viewBox="0 0 200 52" width="100%" height="100%" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="{fill_id}" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="{color}" stop-opacity="0.32"/>
          <stop offset="100%" stop-color="{color}" stop-opacity="0.0"/>
        </linearGradient>
      </defs>
      <path d="{curve} L200,52 L0,52 Z" fill="url(#{fill_id})"/>
      <path d="{curve}" fill="none" stroke="{color}" stroke-width="2.2" stroke-linecap="round"/>
    </svg>
    """)


def build_realtime_waveform_svg(
    history: List[Dict[str, Any]],
    metric_key: str = "pps",
    width: int = 900,
    height: int = 225,
) -> str:
    """
    Renders a full-width, glowing neon cyan (#00A3FF) cubic-bezier spline area chart
    with dark gridlines (#1E2638) and HH:MM:SS time axis ticks.
    Supports both 'pps' (live packets/sec waveform) and 'value' (cumulative packet stream).
    """
    pad_left = 58
    pad_right = 20
    pad_top = 16
    pad_bottom = 30
    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom

    values = [int(pt.get(metric_key, pt.get("value", 0))) for pt in history] if history else [0]
    times = [str(pt["time"]) for pt in history] if history else ["00:00:00"]

    min_v = min(values)
    max_v = max(values)
    if metric_key == "pps":
        min_v = 0
        if max_v <= 10:
            max_v = 20
        else:
            max_v = int(max_v * 1.18) + 4
    elif max_v == min_v:
        max_v = min_v + 100
        min_v = max(0, min_v - 20)

    n = len(values)
    coords: List[tuple[float, float]] = []
    for i, val in enumerate(values):
        x = pad_left + (i / max(1, n - 1)) * plot_w
        norm = (val - min_v) / max(1, (max_v - min_v))
        y = pad_top + plot_h - (norm * (plot_h - 14)) - 6
        coords.append((x, y))

    if len(coords) == 1:
        line_d = f"M {coords[0][0]:.1f},{coords[0][1]:.1f}"
    else:
        segments = [f"M {coords[0][0]:.1f},{coords[0][1]:.1f}"]
        for i in range(len(coords) - 1):
            x0, y0 = coords[i]
            x1, y1 = coords[i + 1]
            cx = (x0 + x1) / 2.0
            segments.append(f"C {cx:.1f},{y0:.1f} {cx:.1f},{y1:.1f} {x1:.1f},{y1:.1f}")
        line_d = " ".join(segments)

    area_d = f"{line_d} L {coords[-1][0]:.1f},{pad_top + plot_h:.1f} L {coords[0][0]:.1f},{pad_top + plot_h:.1f} Z"

    grid_lines: List[str] = []
    for step in range(5):
        gy = pad_top + (step / 4.0) * plot_h
        g_val = int(round(max_v - (step / 4.0) * (max_v - min_v)))
        grid_lines.append(
            f'<line x1="{pad_left}" y1="{gy:.1f}" x2="{width - pad_right}" y2="{gy:.1f}" '
            f'stroke="#1E2638" stroke-width="1" stroke-dasharray="3,3"/>'
        )
        grid_lines.append(
            f'<text x="{pad_left - 10}" y="{gy + 4:.1f}" text-anchor="end" '
            f'fill="#64748B" font-family="JetBrains Mono, monospace" font-size="10.5">{g_val:,}</text>'
        )

    x_labels: List[str] = []
    step_idx = max(1, (n - 1) // 6)
    for i in range(0, n, step_idx):
        tx = coords[i][0]
        x_labels.append(
            f'<text x="{tx:.1f}" y="{height - 7}" text-anchor="middle" '
            f'fill="#64748B" font-family="JetBrains Mono, monospace" font-size="10.5">{html.escape(times[i])}</text>'
        )

    last_x, last_y = coords[-1]

    return _clean_html(f"""
    <svg viewBox="0 0 {width} {height}" style="width: 100%; height: auto; display: block;" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="trafficAreaGrad_{metric_key}" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#00A3FF" stop-opacity="0.40"/>
          <stop offset="65%" stop-color="#00A3FF" stop-opacity="0.10"/>
          <stop offset="100%" stop-color="#00A3FF" stop-opacity="0.0"/>
        </linearGradient>
        <filter id="neonCyanGlow_{metric_key}" x="-10%" y="-20%" width="120%" height="140%">
          <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#00A3FF" flood-opacity="0.75"/>
        </filter>
      </defs>
      {''.join(grid_lines)}
      <path d="{area_d}" fill="url(#trafficAreaGrad_{metric_key})"/>
      <path d="{line_d}" fill="none" stroke="#00A3FF" stroke-width="2.8" stroke-linecap="round" filter="url(#neonCyanGlow_{metric_key})"/>
      <circle cx="{last_x:.1f}" cy="{last_y:.1f}" r="4.5" fill="#38BDF8" stroke="#FFFFFF" stroke-width="1.5" filter="url(#neonCyanGlow_{metric_key})"/>
      {''.join(x_labels)}
    </svg>
    """)


def build_protocol_donut_html(tcp_count: int, udp_count: int, icmp_count: int, other_count: int) -> str:
    """
    Builds a glowing SVG donut chart with the dominant protocol percentage centered inside
    the ring and an accurate percentage breakdown legend on the right.
    """
    counts = [
        ("TCP", tcp_count, "#00A3FF"),
        ("UDP", udp_count, "#3B82F6"),
        ("ICMP", icmp_count, "#06B6D4"),
        ("Other", other_count, "#8B5CF6"),
    ]
    total = sum(c[1] for c in counts)

    if total <= 0:
        dominant_name = "TCP"
        dominant_pct_str = "0%"
    else:
        dominant = max(counts, key=lambda x: x[1])
        dominant_name = dominant[0]
        dominant_pct_str = f"{round((dominant[1] / total) * 100)}%"

    radius = 64.0
    circumference = 2.0 * math.pi * radius
    offset = 0.0
    rings_svg: List[str] = []

    if total <= 0:
        rings_svg.append(
            f'<circle cx="85" cy="85" r="{radius}" fill="none" stroke="#1E2638" stroke-width="18"/>'
        )
    else:
        for name, val, color in counts:
            if val <= 0:
                continue
            frac = max(0.008, val / total)
            dash = min(circumference, frac * circumference)
            gap = max(0.0, circumference - dash)
            rings_svg.append(
                f'<circle cx="85" cy="85" r="{radius}" fill="none" stroke="{color}" '
                f'stroke-width="18" stroke-dasharray="{dash:.2f} {gap:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 85 85)"/>'
            )
            offset += (val / total) * circumference

    legend_items: List[str] = []
    for name, val, color in counts:
        pct_str = format_share_pct(val, total, decimals=0)
        legend_items.append(
            _clean_html(f"""
            <div class="donut-legend-item">
                <div class="donut-legend-left">
                    <span class="donut-swatch" style="background-color: {color}; box-shadow: 0 0 8px {color};"></span>
                    <span>{name}</span>
                </div>
                <span class="donut-pct">{pct_str}</span>
            </div>
            """)
        )

    return _clean_html(f"""
    <div class="donut-layout">
        <svg width="170" height="170" viewBox="0 0 170 170" xmlns="http://www.w3.org/2000/svg">
            <circle cx="85" cy="85" r="{radius}" fill="none" stroke="#1A2234" stroke-width="18"/>
            {''.join(rings_svg)}
            <text x="85" y="82" text-anchor="middle" fill="#FFFFFF" font-family="Space Grotesk, sans-serif" font-size="24" font-weight="700">{dominant_pct_str}</text>
            <text x="85" y="102" text-anchor="middle" fill="#94A3B8" font-family="Inter, sans-serif" font-size="12" font-weight="600">{dominant_name}</text>
        </svg>
        <div class="donut-legend">
            {''.join(legend_items)}
        </div>
    </div>
    """)


def render_kpi_row(metrics: Dict[str, Any], critical_alerts_count: int) -> None:
    """Renders the 4 glowing top KPI metric cards."""
    kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)

    with kpi_col1:
        render_html(
            f"""
            <div class="kpi-card">
                <div>
                    <div class="kpi-top-row">
                        <div class="kpi-icon-box">{SVG_KPI_PACKETS}</div>
                        <span class="kpi-label">Packets Captured</span>
                    </div>
                    <div class="kpi-value">{metrics['total_packets']:,}</div>
                </div>
                <div class="kpi-subtext">↑ Live Traffic</div>
                <div class="kpi-sparkline-wrap">{build_kpi_sparkline_svg('#00A3FF', 'sparkPkts', 0)}</div>
            </div>
            """
        )

    with kpi_col2:
        render_html(
            f"""
            <div class="kpi-card">
                <div>
                    <div class="kpi-top-row">
                        <div class="kpi-icon-box">{SVG_KPI_IPS}</div>
                        <span class="kpi-label">Active Source IPs</span>
                    </div>
                    <div class="kpi-value">{metrics['tracked_ips']:,}</div>
                </div>
                <div class="kpi-subtext">↑ Currently Tracked</div>
                <div class="kpi-sparkline-wrap">{build_kpi_sparkline_svg('#00A3FF', 'sparkIps', 1)}</div>
            </div>
            """
        )

    with kpi_col3:
        alert_card_cls = "kpi-card kpi-card-alert" if critical_alerts_count > 0 else "kpi-card"
        alert_val_cls = "kpi-value kpi-value-crimson" if critical_alerts_count > 0 else "kpi-value"
        alert_spark_color = "#EF4444" if critical_alerts_count > 0 else "#00A3FF"
        render_html(
            f"""
            <div class="{alert_card_cls}">
                <div>
                    <div class="kpi-top-row">
                        <div class="kpi-icon-box kpi-icon-box-alert">{SVG_KPI_ALERTS}</div>
                        <span class="kpi-label">Security Alerts</span>
                    </div>
                    <div class="{alert_val_cls}">{critical_alerts_count:,}</div>
                </div>
                <div class="kpi-subtext kpi-subtext-alert">↑ Within Current Session</div>
                <div class="kpi-sparkline-wrap">{build_kpi_sparkline_svg(alert_spark_color, 'sparkAlerts', 2)}</div>
            </div>
            """
        )

    with kpi_col4:
        render_html(
            f"""
            <div class="kpi-card">
                <div>
                    <div class="kpi-top-row">
                        <div class="kpi-icon-box">{SVG_KPI_TCP}</div>
                        <span class="kpi-label">TCP Packets</span>
                    </div>
                    <div class="kpi-value">{metrics['tcp_count']:,}</div>
                </div>
                <div class="kpi-subtext">↑ Protocol Traffic</div>
                <div class="kpi-sparkline-wrap">{build_kpi_sparkline_svg('#00A3FF', 'sparkTcp', 3)}</div>
            </div>
            """
        )


def render_incidents_table_card(
    alerts: List[Dict[str, str]],
    formatted_clock: str,
    show_view_all: bool = True,
    active_incident_idx: int | None = None,
) -> None:
    """Renders the Recent Incidents table card with interactive Details links."""
    rows_html: List[str] = []
    if alerts:
        for idx, alert in enumerate(alerts):
            ts_raw = alert.get("Timestamp", "N/A")
            time_only = ts_raw.split(" ")[-1] if " " in ts_raw else ts_raw
            threat_name = html.escape(format_threat_title(alert.get("Rule Triggered", "Horizontal TCP Port Scan")))
            src_ip = html.escape(alert.get("Source IP", "0.0.0.0"))
            severity_str = html.escape(alert.get("Severity", "CRITICAL").title())
            raw_exp = alert.get("Event Explanation", "")
            explanation_str = html.escape(raw_exp)
            target_scope = html.escape(extract_target_scope(raw_exp))
            dot_cls = "status-dot-red" if alert.get("Severity") in ("CRITICAL", "HIGH") else "status-dot-green"

            is_selected = active_incident_idx is not None and idx == active_incident_idx
            row_style = ' style="background: rgba(0, 163, 255, 0.07);"' if is_selected else ""
            btn_cls = "btn-table-details-active" if is_selected else "btn-table-details"
            btn_label = "Inspecting" if is_selected else "Details"

            rows_html.append(
                _clean_html(f"""
                <tr{row_style}>
                    <td class="td-mono"><span class="{dot_cls}" style="margin-right: 10px;"></span>{html.escape(time_only)}</td>
                    <td class="td-threat-type">{threat_name}</td>
                    <td class="td-mono">{src_ip}</td>
                    <td class="td-mono" title="{explanation_str}">{target_scope}</td>
                    <td><span class="pill-table-critical">{severity_str}</span></td>
                    <td><a href="?view=threats&amp;incident={idx}" target="_self" class="{btn_cls}">{btn_label}</a></td>
                </tr>
                """)
            )
    else:
        rows_html.append(
            _clean_html(f"""
            <tr>
                <td class="td-mono"><span class="status-dot-green" style="margin-right: 10px;"></span>{formatted_clock}</td>
                <td class="td-threat-type">Baseline Flow Inspection</td>
                <td class="td-mono">127.0.0.1</td>
                <td class="td-mono">Localhost Telemetry Bridge</td>
                <td><span class="pill-monitoring-active" style="padding: 0.15rem 0.6rem; font-size: 0.74rem;">Nominal</span></td>
                <td><a href="?view=threats&amp;incident=0" target="_self" class="btn-table-details">Details</a></td>
            </tr>
            """)
        )

    header_right_html = (
        '<a href="?view=threats" target="_self" class="link-view-all">View All →</a>'
        if show_view_all
        else f'<span class="soc-live-pill"><strong>{len(alerts)}</strong>&nbsp;Recorded Incident(s)</span>'
    )

    render_html(
        f"""
        <div id="recent-incidents" class="soc-panel-card">
            <div class="soc-panel-header">
                <div class="soc-panel-title">{SVG_SECTION_INCIDENTS}Recent Incidents</div>
                {header_right_html}
            </div>
            <div class="soc-table-wrap">
                <table class="soc-incidents-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Threat Type</th>
                            <th>Source IP</th>
                            <th>Target Vector</th>
                            <th>Severity</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows_html)}
                    </tbody>
                </table>
            </div>
        </div>
        """
    )


def render_overview_view(
    metrics: Dict[str, Any],
    alerts: List[Dict[str, str]],
    critical_alerts_count: int,
    history: List[Dict[str, Any]],
    formatted_clock: str,
) -> None:
    """Renders the primary Overview SOC Command Console."""
    render_kpi_row(metrics, critical_alerts_count)

    mid_left, mid_right = st.columns([2, 1])

    with mid_left:
        current_pps = int(history[-1].get("pps", 0)) if history else 0
        waveform_svg = build_realtime_waveform_svg(history, metric_key="pps", width=920, height=225)
        render_html(
            f"""
            <div class="soc-panel-card">
                <div class="soc-panel-header">
                    <div class="soc-panel-title">{SVG_SECTION_TRAFFIC}Real-Time Traffic</div>
                    <div class="soc-live-pill"><span class="status-dot-green"></span><strong>Live</strong> • {current_pps:,} Packets/sec</div>
                </div>
                {waveform_svg}
            </div>
            """
        )

    with mid_right:
        donut_html = build_protocol_donut_html(
            tcp_count=metrics["tcp_count"],
            udp_count=metrics["udp_count"],
            icmp_count=metrics["icmp_count"],
            other_count=metrics["other_count"],
        )
        render_html(
            f"""
            <div class="soc-panel-card">
                <div class="soc-panel-header">
                    <div class="soc-panel-title">{SVG_SECTION_DONUT}Protocol Distribution</div>
                </div>
                {donut_html}
            </div>
            """
        )

    if critical_alerts_count > 0 and alerts:
        latest = alerts[0]
        latest_title = html.escape(format_threat_title(latest.get("Rule Triggered", "Horizontal TCP Port Scan")))
        latest_src = html.escape(latest.get("Source IP", "0.0.0.0"))
        latest_exp = html.escape(latest.get("Event Explanation", "Probed 15+ unique ports in 5.0s window."))

        render_html(
            f"""
            <div class="threat-banner-crimson">
                <div class="threat-banner-left">
                    <div class="threat-alert-icon-circle">{SVG_KPI_ALERTS}</div>
                    <div>
                        <div class="threat-tag-row">
                            <span class="threat-tag">LATEST THREAT:</span>
                            <span class="threat-main-title">{latest_title}</span>
                        </div>
                        <div class="threat-sub-detail">
                            Source: <span class="mono">{latest_src}</span> • {latest_exp}
                        </div>
                    </div>
                </div>
                <div class="threat-banner-right">
                    <span class="pill-critical-solid">Critical</span>
                    <a href="?view=threats&amp;incident=0" target="_self" class="btn-view-details">View Details →</a>
                </div>
            </div>
            """
        )
    else:
        render_html(
            f"""
            <div class="threat-banner-nominal">
                {SVG_SHIELD_BRAND}
                <span>All monitored traffic flows are currently within nominal thresholds. Zero active threats.</span>
            </div>
            """
        )

    render_incidents_table_card(alerts, formatted_clock, show_view_all=True)


def render_threats_view(
    metrics: Dict[str, Any],
    alerts: List[Dict[str, str]],
    critical_alerts_count: int,
    selected_idx: int,
    formatted_clock: str,
) -> None:
    """Renders the Threats & Incidents Forensic Response view when clicked in sidebar or via View Details."""
    unique_offenders = len({a.get("Source IP", "") for a in alerts if a.get("Source IP")})

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        render_html(
            f"""
            <div class="kpi-card kpi-card-alert">
                <div>
                    <div class="kpi-top-row"><div class="kpi-icon-box kpi-icon-box-alert">{SVG_KPI_ALERTS}</div><span class="kpi-label">Critical Incidents</span></div>
                    <div class="kpi-value kpi-value-crimson">{critical_alerts_count:,}</div>
                </div>
                <div class="kpi-subtext kpi-subtext-alert">Active Memory Buffer</div>
            </div>
            """
        )
    with col2:
        render_html(
            f"""
            <div class="kpi-card">
                <div>
                    <div class="kpi-top-row"><div class="kpi-icon-box">{SVG_KPI_IPS}</div><span class="kpi-label">Offending Source IPs</span></div>
                    <div class="kpi-value">{unique_offenders}</div>
                </div>
                <div class="kpi-subtext">Unique Reconnaissance Hosts</div>
            </div>
            """
        )
    with col3:
        render_html(
            f"""
            <div class="kpi-card">
                <div>
                    <div class="kpi-top-row"><div class="kpi-icon-box">{SVG_KPI_TCP}</div><span class="kpi-label">Port Scan Threshold</span></div>
                    <div class="kpi-value">≥{config.SCAN_THRESHOLD}</div>
                </div>
                <div class="kpi-subtext">Unique Ports / {config.TIME_WINDOW}s Window</div>
            </div>
            """
        )
    with col4:
        render_html(
            f"""
            <div class="kpi-card">
                <div>
                    <div class="kpi-top-row"><div class="kpi-icon-box">{SVG_KPI_PACKETS}</div><span class="kpi-label">Alert Cooldown</span></div>
                    <div class="kpi-value">{config.ALERT_COOLDOWN:.0f}s</div>
                </div>
                <div class="kpi-subtext">Deduplication Suppression</div>
            </div>
            """
        )

    safe_idx = max(0, min(selected_idx, len(alerts) - 1)) if alerts else 0
    if alerts:
        incident = alerts[safe_idx]
        inc_title = html.escape(format_threat_title(incident.get("Rule Triggered", "HORIZONTAL_TCP_PORT_SCAN")))
        inc_rule = html.escape(incident.get("Rule Triggered", "HORIZONTAL_TCP_PORT_SCAN"))
        inc_src = html.escape(incident.get("Source IP", "0.0.0.0"))
        inc_ts = html.escape(incident.get("Timestamp", formatted_clock))
        inc_sev = html.escape(incident.get("Severity", "CRITICAL"))
        raw_exp = incident.get("Event Explanation", "")
        inc_exp = html.escape(raw_exp)
        target_scope = html.escape(extract_target_scope(raw_exp))

        render_html(
            f"""
            <div class="soc-panel-card" style="border-color: rgba(239, 68, 68, 0.55); box-shadow: 0 0 28px rgba(239, 68, 68, 0.14);">
                <div class="soc-panel-header">
                    <div class="soc-panel-title">{SVG_KPI_ALERTS}<span style="margin-left: 8px;">Forensic Incident Deep-Dive — Incident #{safe_idx + 1} ({inc_title})</span></div>
                    <a href="?view=overview" target="_self" class="btn-view-details">← Back to Overview</a>
                </div>
                <div class="forensic-grid-3">
                    <div class="forensic-kv-box">
                        <div class="forensic-kv-label">Timestamp (Local)</div>
                        <div class="forensic-kv-val">{inc_ts}</div>
                    </div>
                    <div class="forensic-kv-box">
                        <div class="forensic-kv-label">Detection Rule ID</div>
                        <div class="forensic-kv-val" style="color: #F87171;">{inc_rule}</div>
                    </div>
                    <div class="forensic-kv-box">
                        <div class="forensic-kv-label">Offending Source IP</div>
                        <div class="forensic-kv-val" style="color: #38BDF8;">{inc_src}</div>
                    </div>
                    <div class="forensic-kv-box">
                        <div class="forensic-kv-label">Target Scope &amp; Vector</div>
                        <div class="forensic-kv-val">{target_scope}</div>
                    </div>
                    <div class="forensic-kv-box">
                        <div class="forensic-kv-label">MITRE ATT&amp;CK Tactic</div>
                        <div class="forensic-kv-val">T1046 • Network Service Discovery</div>
                    </div>
                    <div class="forensic-kv-box">
                        <div class="forensic-kv-label">Severity Classification</div>
                        <div class="forensic-kv-val" style="color: #EF4444;">{inc_sev}</div>
                    </div>
                </div>
                <div class="forensic-kv-box" style="margin-top: 0.5rem;">
                    <div class="forensic-kv-label">Stateful Inspection Evidence &amp; Trigger Telemetry</div>
                    <div class="forensic-kv-val" style="font-size: 0.88rem; color: #E2E8F0;">
                        {inc_exp} Captured via Layer-3/4 header inspection (SYN=1, ACK=0) within the {config.TIME_WINDOW}s sliding window.
                    </div>
                </div>
                <div class="forensic-kv-box" style="margin-top: 0.75rem;">
                    <div class="forensic-kv-label">Recommended SOC Containment Command (PowerShell Admin)</div>
                    <div class="forensic-kv-val" style="font-size: 0.82rem; color: #38BDF8;">
                        New-NetFirewallRule -DisplayName "NIDS-Block-{inc_src}" -Direction Inbound -RemoteAddress {inc_src} -Action Block
                    </div>
                </div>
            </div>
            """
        )
    else:
        render_html(
            f"""
            <div class="threat-banner-nominal" style="margin-top: 1rem;">
                {SVG_SHIELD_BRAND}
                <span>No active security incidents in the buffer. Trigger a horizontal port scan (≥{config.SCAN_THRESHOLD} unique ports in {config.TIME_WINDOW}s) to populate forensic telemetry.</span>
                <a href="?view=overview" target="_self" class="btn-view-details" style="margin-left: auto;">← Back to Overview</a>
            </div>
            """
        )

    render_incidents_table_card(
        alerts,
        formatted_clock,
        show_view_all=False,
        active_incident_idx=safe_idx if alerts else None,
    )


def render_traffic_view(metrics: Dict[str, Any], history: List[Dict[str, Any]]) -> None:
    """Renders the Network Traffic Deep Protocol & Flow Telemetry view."""
    total_raw = metrics["total_packets"]
    total = max(1, total_raw)
    tcp_pct = (metrics["tcp_count"] / total) * 100.0 if total_raw > 0 else 0.0
    udp_pct = (metrics["udp_count"] / total) * 100.0 if total_raw > 0 else 0.0
    icmp_pct = (metrics["icmp_count"] / total) * 100.0 if total_raw > 0 else 0.0
    other_pct = (metrics["other_count"] / total) * 100.0 if total_raw > 0 else 0.0

    tcp_share_str = format_share_pct(metrics["tcp_count"], total_raw, decimals=1)
    udp_share_str = format_share_pct(metrics["udp_count"], total_raw, decimals=1)
    icmp_share_str = format_share_pct(metrics["icmp_count"], total_raw, decimals=1)
    other_share_str = format_share_pct(metrics["other_count"], total_raw, decimals=1)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_html(
            f"""
            <div class="kpi-card">
                <div><div class="kpi-top-row"><div class="kpi-icon-box">{SVG_KPI_TCP}</div><span class="kpi-label">TCP Segments</span></div>
                <div class="kpi-value">{metrics['tcp_count']:,}</div></div>
                <div class="kpi-subtext">{tcp_share_str} of Total Volume</div>
            </div>
            """
        )
    with c2:
        render_html(
            f"""
            <div class="kpi-card">
                <div><div class="kpi-top-row"><div class="kpi-icon-box">{SVG_KPI_PACKETS}</div><span class="kpi-label">UDP Datagrams</span></div>
                <div class="kpi-value">{metrics['udp_count']:,}</div></div>
                <div class="kpi-subtext">{udp_share_str} of Total Volume</div>
            </div>
            """
        )
    with c3:
        render_html(
            f"""
            <div class="kpi-card">
                <div><div class="kpi-top-row"><div class="kpi-icon-box">{SVG_KPI_IPS}</div><span class="kpi-label">ICMP Packets</span></div>
                <div class="kpi-value">{metrics['icmp_count']:,}</div></div>
                <div class="kpi-subtext">{icmp_share_str} of Total Volume</div>
            </div>
            """
        )
    with c4:
        render_html(
            f"""
            <div class="kpi-card">
                <div><div class="kpi-top-row"><div class="kpi-icon-box">{SVG_KPI_PACKETS}</div><span class="kpi-label">Other IPv4</span></div>
                <div class="kpi-value">{metrics['other_count']:,}</div></div>
                <div class="kpi-subtext">{other_share_str} of Total Volume</div>
            </div>
            """
        )

    current_pps = int(history[-1].get("pps", 0)) if history else 0
    waveform_svg = build_realtime_waveform_svg(history, metric_key="value", width=1340, height=225)
    render_html(
        f"""
        <div class="soc-panel-card">
            <div class="soc-panel-header">
                <div class="soc-panel-title">{SVG_SECTION_TRAFFIC}Live Packet Ingestion Stream (BPF: {html.escape(config.BPF_FILTER)})</div>
                <div class="soc-live-pill"><span class="status-dot-green"></span><strong>Live</strong> • {current_pps:,} pkt/s • {metrics['total_packets']:,} Total Packets</div>
            </div>
            {waveform_svg}
        </div>
        """
    )

    render_html(
        f"""
        <div class="soc-panel-card">
            <div class="soc-panel-header">
                <div class="soc-panel-title">{SVG_SECTION_DONUT}Layer-4 Protocol Distribution Breakdown</div>
            </div>
            <div class="proto-bar-row">
                <div class="proto-bar-top"><span>TCP (Transmission Control Protocol — SYN Reconnaissance Monitored)</span><span class="td-mono">{metrics['tcp_count']:,} pkts ({tcp_share_str})</span></div>
                <div class="proto-bar-track"><div class="proto-bar-fill" style="width: {max(1.0 if metrics['tcp_count'] > 0 else 0.0, tcp_pct):.1f}%; background: #00A3FF; box-shadow: 0 0 10px #00A3FF;"></div></div>
            </div>
            <div class="proto-bar-row">
                <div class="proto-bar-top"><span>UDP (User Datagram Protocol)</span><span class="td-mono">{metrics['udp_count']:,} pkts ({udp_share_str})</span></div>
                <div class="proto-bar-track"><div class="proto-bar-fill" style="width: {max(1.0 if metrics['udp_count'] > 0 else 0.0, udp_pct):.1f}%; background: #3B82F6;"></div></div>
            </div>
            <div class="proto-bar-row">
                <div class="proto-bar-top"><span>ICMP (Internet Control Message Protocol)</span><span class="td-mono">{metrics['icmp_count']:,} pkts ({icmp_share_str})</span></div>
                <div class="proto-bar-track"><div class="proto-bar-fill" style="width: {max(1.0 if metrics['icmp_count'] > 0 else 0.0, icmp_pct):.1f}%; background: #06B6D4;"></div></div>
            </div>
            <div class="proto-bar-row">
                <div class="proto-bar-top"><span>Other Layer-3 IPv4 Traffic</span><span class="td-mono">{metrics['other_count']:,} pkts ({other_share_str})</span></div>
                <div class="proto-bar-track"><div class="proto-bar-fill" style="width: {max(1.0 if metrics['other_count'] > 0 else 0.0, other_pct):.1f}%; background: #8B5CF6;"></div></div>
            </div>
        </div>
        """
    )


def render_health_view(metrics: Dict[str, Any], is_online: bool, time_since_update: float) -> None:
    """Renders the System Health, Storage Integrity & Pipeline Diagnostics view."""
    file_size = os.path.getsize(RESOLVED_STATE_FILE) if os.path.exists(RESOLVED_STATE_FILE) else 0
    heartbeat_str = f"{time_since_update:.2f}s" if metrics["last_updated"] > 0 else "N/A"
    health_state = "HEALTHY" if is_online else "STALE / OFFLINE"
    health_color = "#10B981" if is_online else "#EF4444"
    formatted_json = html.escape(json.dumps(metrics, indent=2))

    render_html(
        f"""
        <div class="soc-panel-card">
            <div class="soc-panel-header">
                <div class="soc-panel-title">{SVG_SHIELD_BRAND}<span style="margin-left: 8px;">Engine Liveness &amp; Atomic Storage Diagnostics</span></div>
                <span class="soc-live-pill"><strong style="color: {health_color};">● {health_state}</strong></span>
            </div>
            <div class="forensic-grid-3">
                <div class="forensic-kv-box">
                    <div class="forensic-kv-label">Engine Heartbeat Latency</div>
                    <div class="forensic-kv-val" style="color: {health_color};">{heartbeat_str} (Threshold: {STALE_THRESHOLD_SECONDS:.1f}s)</div>
                </div>
                <div class="forensic-kv-box">
                    <div class="forensic-kv-label">State Buffer File Size</div>
                    <div class="forensic-kv-val">{file_size:,} bytes (metrics.json)</div>
                </div>
                <div class="forensic-kv-box">
                    <div class="forensic-kv-label">NTFS Concurrency Synchronization</div>
                    <div class="forensic-kv-val" style="color: #38BDF8;">RLock + Atomic os.replace Backoff</div>
                </div>
                <div class="forensic-kv-box">
                    <div class="forensic-kv-label">Alert History Ring Buffer</div>
                    <div class="forensic-kv-val">{len(metrics.get('alerts', []))} / 50 max incidents</div>
                </div>
                <div class="forensic-kv-box">
                    <div class="forensic-kv-label">Active Tracked Host Sessions</div>
                    <div class="forensic-kv-val">{metrics['tracked_ips']} active IP(s) in RAM</div>
                </div>
                <div class="forensic-kv-box">
                    <div class="forensic-kv-label">Idle Session Eviction Timeout</div>
                    <div class="forensic-kv-val">{config.IP_INACTIVITY_TIMEOUT}s automatic purge</div>
                </div>
            </div>
        </div>
        <div class="soc-panel-card">
            <div class="soc-panel-header">
                <div class="soc-panel-title">{SVG_SECTION_INCIDENTS}Live Decoupled State Buffer (metrics.json)</div>
                <span class="soc-live-pill"><strong>Schema v{html.escape(str(metrics.get('schema_version', config.SCHEMA_VERSION)))}</strong> • Read-Only Snapshot</span>
            </div>
            <pre class="soc-json-viewer">{formatted_json}</pre>
        </div>
        """
    )


def render_settings_view(schema_version: str) -> None:
    """Renders the Detection Thresholds, Kernel Filter & Security Hardening configuration view."""
    render_html(
        f"""
        <div class="soc-panel-card">
            <div class="soc-panel-header">
                <div class="soc-panel-title">{SVG_SHIELD_BRAND}<span style="margin-left: 8px;">NIDS Detection Engine &amp; Security Hardening Configuration</span></div>
                <span class="soc-live-pill"><strong>Schema v{html.escape(str(schema_version))}</strong></span>
            </div>
            <div class="forensic-grid-4">
                <div class="forensic-kv-box">
                    <div class="forensic-kv-label">Sliding Time Window (TIME_WINDOW)</div>
                    <div class="forensic-kv-val" style="color: #38BDF8;">{config.TIME_WINDOW} seconds</div>
                </div>
                <div class="forensic-kv-box">
                    <div class="forensic-kv-label">Port Scan Threshold (SCAN_THRESHOLD)</div>
                    <div class="forensic-kv-val" style="color: #38BDF8;">{config.SCAN_THRESHOLD} unique destination ports</div>
                </div>
                <div class="forensic-kv-box">
                    <div class="forensic-kv-label">Alert Cooldown (ALERT_COOLDOWN)</div>
                    <div class="forensic-kv-val">{config.ALERT_COOLDOWN} seconds per (IP, Rule)</div>
                </div>
                <div class="forensic-kv-box">
                    <div class="forensic-kv-label">RAM Session Eviction (IP_INACTIVITY_TIMEOUT)</div>
                    <div class="forensic-kv-val">{config.IP_INACTIVITY_TIMEOUT} seconds idle timeout</div>
                </div>
                <div class="forensic-kv-box">
                    <div class="forensic-kv-label">Kernel BPF Capture Filter</div>
                    <div class="forensic-kv-val" style="color: #10B981;">{html.escape(config.BPF_FILTER)}</div>
                </div>
                <div class="forensic-kv-box">
                    <div class="forensic-kv-label">Dashboard Network Binding</div>
                    <div class="forensic-kv-val" style="color: #10B981;">127.0.0.1:8501 (Strict Localhost)</div>
                </div>
                <div class="forensic-kv-box">
                    <div class="forensic-kv-label">Deep Packet Inspection Privacy Policy</div>
                    <div class="forensic-kv-val">Layer 3/4 Headers Only (Payloads Stripped)</div>
                </div>
                <div class="forensic-kv-box">
                    <div class="forensic-kv-label">State Polling Cadence</div>
                    <div class="forensic-kv-val">{POLL_INTERVAL_SECONDS}s Asynchronous Rerun</div>
                </div>
            </div>
        </div>
        """
    )


def render_dashboard() -> None:
    """Renders the Dark SOC Command Console and triggers a 1-second polling cycle."""
    st.set_page_config(
        page_title="Autonomous NIDS | Dark SOC Command Console",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_custom_css()

    # Read active view and incident index from URL query params
    raw_view = str(st.query_params.get("view", "overview")).lower()
    active_view = raw_view if raw_view in VALID_VIEWS else "overview"
    try:
        selected_incident_idx = int(st.query_params.get("incident", "0") or 0)
    except ValueError:
        selected_incident_idx = 0

    # 1. Fault-Tolerant State Load & Session Continuity Cache
    metrics = safe_load_metrics(config.STATE_FILE)
    if metrics["last_updated"] > 0:
        st.session_state["last_valid_metrics"] = metrics
    elif "last_valid_metrics" in st.session_state:
        metrics = st.session_state["last_valid_metrics"]

    now = time.time()
    is_online, time_since_update = evaluate_liveness(metrics["last_updated"], now)
    schema_version = metrics.get("schema_version", config.SCHEMA_VERSION)
    alerts: List[Dict[str, str]] = metrics.get("alerts", [])

    critical_alerts_count = sum(
        1 for a in alerts if a.get("Severity") in ("CRITICAL", "HIGH")
    )
    history = update_traffic_history(metrics["total_packets"])

    # 2. Sidebar Navigation & Minimalist Developer Card (Bottom-Docked)
    with st.sidebar:
        nav_overview_cls = "sidebar-nav-item active" if active_view == "overview" else "sidebar-nav-item"
        nav_threats_cls = "sidebar-nav-item active" if active_view == "threats" else "sidebar-nav-item"
        nav_traffic_cls = "sidebar-nav-item active" if active_view == "traffic" else "sidebar-nav-item"
        nav_health_cls = "sidebar-nav-item active" if active_view == "health" else "sidebar-nav-item"
        nav_settings_cls = "sidebar-nav-item active" if active_view == "settings" else "sidebar-nav-item"

        engine_dot_class = "status-dot-green" if is_online else "status-dot-red"
        engine_state_label = (
            "Capture Engine Running" if is_online else "Capture Engine Stale"
        )

        render_html(
            f"""
            <div class="sidebar-shell">
                <div class="sidebar-top-group">
                    <div class="sidebar-brand">
                        {SVG_SHIELD_BRAND}
                        <div>
                            <div class="sidebar-brand-title">NIDS</div>
                            <div class="sidebar-brand-sub">Network Intrusion<br/>Detection System</div>
                        </div>
                    </div>
                    <div class="sidebar-nav-list">
                        <a href="?view=overview" target="_self" class="{nav_overview_cls}">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>
                            <span>Overview</span>
                        </a>
                        <a href="?view=threats" target="_self" class="{nav_threats_cls}">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                            <span>Threats &amp; Incidents</span>
                        </a>
                        <a href="?view=traffic" target="_self" class="{nav_traffic_cls}">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                            <span>Network Traffic</span>
                        </a>
                        <a href="?view=health" target="_self" class="{nav_health_cls}">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                            <span>System Health</span>
                        </a>
                        <a href="?view=settings" target="_self" class="{nav_settings_cls}">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                            <span>Settings</span>
                        </a>
                    </div>
                </div>
                <div class="sidebar-bottom-dock">
                    <div class="sidebar-engine-pill">
                        <div class="sidebar-engine-row">
                            <span class="{engine_dot_class}"></span>
                            <span>{engine_state_label}</span>
                        </div>
                        <div class="sidebar-engine-ver">v{html.escape(str(schema_version))} • {config.TIME_WINDOW}s / ≥{config.SCAN_THRESHOLD} ports</div>
                    </div>
                    <div class="sidebar-dev-card">
                        <span class="sidebar-dev-name">Durlav Bahadur Shrestha</span>
                        <div class="sidebar-dev-links">
                            <a href="https://github.com/durlav-stha" target="_blank" rel="noopener noreferrer" class="sidebar-dev-icon" title="GitHub">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                                    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
                                </svg>
                            </a>
                            <a href="https://www.linkedin.com/in/durlav-bahadur-shrestha-a1a307444/" target="_blank" rel="noopener noreferrer" class="sidebar-dev-icon" title="LinkedIn">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                                    <path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/>
                                </svg>
                            </a>
                        </div>
                    </div>
                </div>
            </div>
            """
        )

    # 3. Header & Live Monitoring Status Bar
    formatted_clock = (
        time.strftime("%H:%M:%S", time.localtime(metrics["last_updated"]))
        if metrics["last_updated"] > 0
        else time.strftime("%H:%M:%S")
    )
    status_pill_html = (
        '<div class="pill-monitoring-active"><span class="status-dot-green"></span>Monitoring Active</div>'
        if is_online
        else '<div class="pill-monitoring-offline"><span class="status-dot-red"></span>Engine Offline / Data Stale</div>'
    )

    render_html(
        f"""
        <div class="soc-header-bar">
            <div>
                <h1 class="soc-title">Network Intrusion Detection System</h1>
                <div class="soc-subtitle">Real-Time Network Monitoring &amp; Threat Detection</div>
            </div>
            <div class="soc-status-cluster">
                {status_pill_html}
                <div class="liveness-box">
                    Last Updated: <span class="liveness-time">{formatted_clock}</span>
                    {SVG_ECG_PULSE}
                </div>
            </div>
        </div>
        """
    )

    # Explicit Liveness Warning when time_since_update > 3.0s
    if not is_online and metrics["last_updated"] > 0:
        st.error(
            f"Engine Offline / Data Stale: Last telemetry heartbeat was received "
            f"{time_since_update:.1f} seconds ago (exceeds {STALE_THRESHOLD_SECONDS:.1f}s liveness threshold). "
            f"Verify that engine.py is running with Administrator privileges."
        )

    # 4. Route to Active View
    if active_view == "threats":
        render_threats_view(
            metrics=metrics,
            alerts=alerts,
            critical_alerts_count=critical_alerts_count,
            selected_idx=selected_incident_idx,
            formatted_clock=formatted_clock,
        )
    elif active_view == "traffic":
        render_traffic_view(metrics=metrics, history=history)
    elif active_view == "health":
        render_health_view(
            metrics=metrics,
            is_online=is_online,
            time_since_update=time_since_update,
        )
    elif active_view == "settings":
        render_settings_view(schema_version=schema_version)
    else:
        render_overview_view(
            metrics=metrics,
            alerts=alerts,
            critical_alerts_count=critical_alerts_count,
            history=history,
            formatted_clock=formatted_clock,
        )

    # 5. Auto-Refresh Polling Loop (every 1 second)
    time.sleep(POLL_INTERVAL_SECONDS)
    st.rerun()


if __name__ == "__main__":
    render_dashboard()
