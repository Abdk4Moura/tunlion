#!/usr/bin/env python3
"""Report sustained host memory pressure before the OOM killer fires.

Driven by a systemd timer. This monitor only reads /proc and takes one `ps`
snapshot; that constraint is deliberate so the warning itself cannot amplify
pressure on a host already running low. It reports, but never kills or
restarts, a process: choosing whose build to stop is an operator decision.

The high-severity condition requires BOTH `MemAvailable` and `SwapFree` to be
below their thresholds. `MemAvailable` governs whether the NEXT ALLOCATION has
room. Low `SwapFree` on its own is a LEADING indicator and can coexist with
ample reclaimable memory: on 2026-08-04 the monitor observed swap free at 1 MiB
alongside available memory at 1167 MiB and then 2229 MiB, with zero OOM kills.
A swap-only WARNING is wanted and is deliberately absent because no calibrated
threshold exists for it yet. The follow-up needs observations of SwapFree during
a period that ends in an OOM kill. The journal still contains the 2026-08-02
OOM events, but no SwapFree/MemAvailable readings were logged alongside them,
so it supplies an OOM event without the threshold calibration data.
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.environ.get(
    "MEMORY_MONITOR_STATE", os.path.expanduser("~/.cache/filament-memory-pressure.json")
)
ALERT_TO = os.environ.get("MONITOR_ALERT_TO", "cadaynstudio@gmail.com")
ALERT_FROM = os.environ.get("MONITOR_ALERT_FROM", "Filament Monitor <monitor@send.autumated.com>")
RESEND_KEY_FILE = os.environ.get("RESEND_KEY_FILE", os.path.expanduser("~/secret_keys/resend_api_key"))
TIMEOUT = int(os.environ.get("MONITOR_TIMEOUT", "10"))
AVAILABLE_LIMIT_MB = int(os.environ.get("MEMORY_AVAILABLE_LIMIT_MB", "1024"))
SWAP_FREE_LIMIT_MB = int(os.environ.get("MEMORY_SWAP_FREE_LIMIT_MB", "1024"))
PRESSURE_THRESHOLD = int(os.environ.get("MEMORY_PRESSURE_THRESHOLD", "2"))


def read_meminfo(path="/proc/meminfo"):
    values = {}
    with open(path) as f:
        for line in f:
            key, _, rest = line.partition(":")
            if not _:
                continue
            fields = rest.strip().split()
            if fields and fields[0].isdigit():
                values[key] = int(fields[0]) * (1024 if len(fields) > 1 and fields[1] == "kB" else 1)
    return values


def read_process_snapshot():
    """Return top RSS consumers and whether a Rust build is running."""
    result = subprocess.run(
        ["ps", "-eo", "pid=,comm=,rss="], capture_output=True, text=True, check=False
    )
    rows = []
    build_running = False
    for line in result.stdout.splitlines():
        fields = line.split(None, 2)
        if len(fields) != 3 or not fields[0].isdigit() or not fields[2].isdigit():
            continue
        pid, command, rss_kb = int(fields[0]), fields[1], int(fields[2])
        rows.append((rss_kb, pid, command))
        if command in {"cargo", "rustc"}:
            build_running = True
    rows.sort(reverse=True)
    consumers = [f"{command}[{pid}] {rss_kb // 1024} MiB" for rss_kb, pid, command in rows[:5]]
    return consumers, build_running


def pressure_snapshot():
    mem = read_meminfo()
    consumers, build_running = read_process_snapshot()
    return {
        "available_mb": mem.get("MemAvailable", 0) // (1024 * 1024),
        "swap_free_mb": mem.get("SwapFree", 0) // (1024 * 1024),
        "consumers": consumers,
        "build_running": build_running,
    }


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"pressured": False, "breaches": 0, "since": 0}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def send_alert(subject, text):
    try:
        with open(RESEND_KEY_FILE) as f:
            key = f.read().strip()
    except Exception as e:
        return False, f"no resend key: {e}"
    payload = json.dumps({"from": ALERT_FROM, "to": [ALERT_TO], "subject": subject, "text": text}).encode()
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            return response.status in (200, 201), f"HTTP {response.status}: {response.read(300).decode('utf-8', 'replace')[:200]}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read(300).decode('utf-8', 'replace')[:200]}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def utc(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))


def main(snapshot_fn=None):
    snapshot = (snapshot_fn or pressure_snapshot)()
    state = load_state()
    now = int(time.time())
    pressured = (
        snapshot["available_mb"] < AVAILABLE_LIMIT_MB
        and snapshot["swap_free_mb"] < SWAP_FREE_LIMIT_MB
    )

    if not pressured:
        was_pressured = state.get("pressured", False)
        state["breaches"] = 0
        state["pressured"] = False
        state["since"] = now
        if was_pressured:
            sent, result = send_alert(
                "[filament] memory pressure RECOVERED",
                f"Memory pressure recovered at {utc(now)}.\n\n{snapshot}\n",
            )
            print(f"RESTORED alert sent={sent} {result}", file=sys.stderr)
        save_state(state)
        print(f"OK memory available={snapshot['available_mb']} MiB swap free={snapshot['swap_free_mb']} MiB")
        return 0

    state["breaches"] = state.get("breaches", 0) + 1
    if state.get("pressured", False) or state["breaches"] < PRESSURE_THRESHOLD:
        state["since"] = state.get("since", now) or now
        save_state(state)
        print(f"PRESSURE ({state['breaches']}/{PRESSURE_THRESHOLD}) available={snapshot['available_mb']} MiB swap free={snapshot['swap_free_mb']} MiB")
        return 0

    state["pressured"] = True
    state["since"] = state.get("since", now) or now
    build = "cargo/rustc detected" if snapshot["build_running"] else "no cargo/rustc detected"
    sent, result = send_alert(
        "[filament] sustained memory pressure",
        f"Host memory pressure detected at {utc(now)} after {state['breaches']} consecutive checks.\n"
        f"MemAvailable={snapshot['available_mb']} MiB (limit {AVAILABLE_LIMIT_MB}), "
        f"SwapFree={snapshot['swap_free_mb']} MiB (limit {SWAP_FREE_LIMIT_MB}).\n"
        f"Build status: {build}.\nTop RSS consumers: {', '.join(snapshot['consumers']) or 'unavailable'}.\n"
        "No process was killed or modified; choose an operator action.\n",
    )
    print(f"PRESSURE alert sent={sent} {result}", file=sys.stderr)
    save_state(state)
    print(f"PRESSURE sustained available={snapshot['available_mb']} MiB swap free={snapshot['swap_free_mb']} MiB")
    return 1


if __name__ == "__main__":
    sys.exit(main())
