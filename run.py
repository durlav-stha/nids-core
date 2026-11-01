#!/usr/bin/env python3
"""
Autonomous NIDS — Unified Process Supervisor & Service Orchestrator (run.py).
Launches and supervises both the Scapy packet capture engine (engine.py) and
the Streamlit Dark SOC Command Console (app.py) in a single coordinated lifecycle.
"""

import os
import signal
import subprocess
import sys
import time
from typing import List, Optional

import config

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENGINE_SCRIPT = os.path.join(BASE_DIR, "engine.py")
DASHBOARD_SCRIPT = os.path.join(BASE_DIR, "app.py")
STATE_FILE_PATH = (
    config.STATE_FILE
    if os.path.isabs(config.STATE_FILE)
    else os.path.join(BASE_DIR, config.STATE_FILE)
)
TEMP_STATE_FILE_PATH = f"{STATE_FILE_PATH}.tmp"
BOOTSTRAP_DELAY_SECONDS = 1.5
SUPERVISOR_POLL_SECONDS = 0.5
SHUTDOWN_TIMEOUT_SECONDS = 5.0


def resolve_venv_executables() -> tuple[str, List[str]]:
    """
    Resolves the project virtual environment Python and Streamlit executables.
    Prefers .venv\\Scripts\\python.exe and .venv\\Scripts\\streamlit.exe on Windows,
    falling back gracefully to sys.executable if invoked from an external environment.
    """
    venv_scripts = os.path.join(BASE_DIR, ".venv", "Scripts")
    venv_python = os.path.join(venv_scripts, "python.exe")
    venv_streamlit = os.path.join(venv_scripts, "streamlit.exe")

    python_exe = venv_python if os.path.exists(venv_python) else sys.executable

    if os.path.exists(venv_streamlit):
        streamlit_cmd = [
            venv_streamlit,
            "run",
            DASHBOARD_SCRIPT,
            "--server.address",
            "127.0.0.1",
            "--server.headless",
            "true",
        ]
    else:
        streamlit_cmd = [
            python_exe,
            "-m",
            "streamlit",
            "run",
            DASHBOARD_SCRIPT,
            "--server.address",
            "127.0.0.1",
            "--server.headless",
            "true",
        ]

    return python_exe, streamlit_cmd


def is_windows_admin() -> bool:
    """Checks whether the current process holds Windows Administrator privileges."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def terminate_process(proc: Optional[subprocess.Popen], name: str) -> None:
    """
    Gracefully terminates a child process and waits for exit, escalating to kill()
    only if the process fails to exit within SHUTDOWN_TIMEOUT_SECONDS.
    """
    if proc is None or proc.poll() is not None:
        return

    print(f"[*] Stopping {name} (PID: {proc.pid})...", flush=True)
    try:
        proc.terminate()
        proc.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        print(f"[!] {name} did not exit within {SHUTDOWN_TIMEOUT_SECONDS}s; forcing kill...", flush=True)
        try:
            proc.kill()
            proc.wait(timeout=2.0)
        except Exception:
            pass
    except Exception as exc:
        print(f"[!] Error while stopping {name}: {exc}", flush=True)


def cleanup_lingering_temp_files() -> None:
    """Removes any residual metrics.json.tmp file after engine shutdown to prevent stale locks."""
    if os.path.exists(TEMP_STATE_FILE_PATH):
        try:
            os.remove(TEMP_STATE_FILE_PATH)
        except OSError:
            pass


def supervise_services() -> int:
    """
    Spawns engine.py and the Streamlit SOC dashboard, supervises both processes,
    and guarantees clean teardown on Ctrl+C or unexpected child exit.
    """
    python_exe, streamlit_cmd = resolve_venv_executables()

    print("=" * 68, flush=True)
    print(" [*] Autonomous NIDS — Unified SOC Service Orchestrator", flush=True)
    print("=" * 68, flush=True)
    print(f" [*] Workspace Root : {BASE_DIR}", flush=True)
    print(f" [*] Python Runtime : {python_exe}", flush=True)
    print(f" [*] State Bridge   : {STATE_FILE_PATH}", flush=True)

    if not is_windows_admin():
        print(
            " [!] WARNING: Current shell is NOT elevated as Administrator.\n"
            "     Scapy/Npcap raw socket sniffing requires Administrator privileges.",
            flush=True,
        )

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    engine_proc: Optional[subprocess.Popen] = None
    dashboard_proc: Optional[subprocess.Popen] = None

    try:
        # 1. Spawn engine.py as a non-blocking background subprocess
        print("\n[1/2] Launching NIDS Packet Capture & Detection Engine (engine.py)...", flush=True)
        engine_proc = subprocess.Popen(
            [python_exe, ENGINE_SCRIPT],
            cwd=BASE_DIR,
            env=env,
        )

        # 2. Wait 1.5 seconds for initial telemetry initialization and metrics.json bootstrap
        print(
            f"[*] Waiting {BOOTSTRAP_DELAY_SECONDS}s for telemetry initialization and metrics.json bootstrap...",
            flush=True,
        )
        time.sleep(BOOTSTRAP_DELAY_SECONDS)

        if engine_proc.poll() is not None:
            print(
                f"[!] engine.py exited prematurely with code {engine_proc.returncode}. "
                "Verify Administrator privileges and Npcap installation.",
                flush=True,
            )
            return engine_proc.returncode or 1

        # 3. Spawn the Streamlit SOC dashboard as a second subprocess
        print("[2/2] Launching Dark SOC Command Console (http://127.0.0.1:8501)...", flush=True)
        dashboard_proc = subprocess.Popen(
            streamlit_cmd,
            cwd=BASE_DIR,
            env=env,
        )

        print("-" * 68, flush=True)
        print(" [+] NIDS Control Plane Online: http://127.0.0.1:8501", flush=True)
        print(" [+] Press Ctrl+C once in this terminal to stop all services cleanly.", flush=True)
        print("-" * 68, flush=True)

        # 4. Supervision loop: monitor both child processes
        while True:
            engine_status = engine_proc.poll()
            dashboard_status = dashboard_proc.poll()

            if engine_status is not None:
                print(
                    f"\n[!] Capture Engine (engine.py) terminated unexpectedly (exit code: {engine_status}).",
                    flush=True,
                )
                return engine_status or 1

            if dashboard_status is not None:
                print(
                    f"\n[!] Streamlit Dashboard (app.py) exited (exit code: {dashboard_status}).",
                    flush=True,
                )
                return dashboard_status or 0

            time.sleep(SUPERVISOR_POLL_SECONDS)

    except KeyboardInterrupt:
        print("\n[*] KeyboardInterrupt (Ctrl+C) received. Initiating graceful shutdown...", flush=True)
        return 0
    finally:
        # 5. Graceful shutdown of both child processes (dashboard first, then engine)
        terminate_process(dashboard_proc, "Streamlit SOC Dashboard (app.py)")
        terminate_process(engine_proc, "NIDS Capture Engine (engine.py)")
        cleanup_lingering_temp_files()
        print("[+] All NIDS child processes terminated and NTFS file handles released.", flush=True)


def main() -> None:
    """Entry point with CLI argument support for dry validation."""
    if "--check" in sys.argv:
        python_exe, streamlit_cmd = resolve_venv_executables()
        print(f"Python: {python_exe}")
        print(f"Streamlit Command: {' '.join(streamlit_cmd)}")
        sys.exit(0)

    # Register SIGTERM handler so external stop signals trigger the same finally block
    def _handle_sigterm(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _handle_sigterm)
    sys.exit(supervise_services())


if __name__ == "__main__":
    main()
