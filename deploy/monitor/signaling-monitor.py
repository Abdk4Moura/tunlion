#!/usr/bin/env python3
"""Filament signaling monitor.

Polls the signaling server's liveness endpoint and emails an alert (via Resend)
when it transitions DOWN or recovers. Driven every few minutes by
filament-monitor.timer, which must be INSTALLED on the host by
`deploy/monitor/install-timers.sh` before any of that is true.

That sentence used to say "Run by a systemd timer (see the .timer / .service in
this directory)" with no installer and no check. On 2026-08-04 the host was
inspected for the first time and no such timer existed: no unit under
/etc/systemd/system, nothing in `systemctl list-timers`, no cron entry. The
state file below had last been written by a hand-run on 2026-07-31, and that run
had recorded a real DOWN and recovery. The monitor worked; nothing ran it.
Confirm with `deploy/monitor/install-timers.sh verify` rather than by reading
this comment.

Why /api/health and not / : `GET /` on the api returns 503 by design (the SPA
fallback route, since the React build is served by Cloudflare Pages, not this
container). `/api/health` is the real liveness route and returns {"ok": true}.
Monitoring the wrong path is exactly what cost time during the 2026-06-27
incident, so this is the canonical check.

Debounced: a single transient failure does not alert; the server must miss
FAIL_THRESHOLD consecutive checks before it is declared DOWN, so a momentary
blip or a deploy restart stays quiet. State persists between runs in STATE_FILE.

All knobs are env-overridable; defaults target the production deployment.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

SERVER = os.environ.get("FILAMENT_SERVER", "https://api.filament.autumated.com")
HEALTH_URL = SERVER.rstrip("/") + "/api/health"
STATE_FILE = os.environ.get(
    "MONITOR_STATE", os.path.expanduser("~/.cache/filament-signaling-monitor.json")
)
ALERT_TO = os.environ.get("MONITOR_ALERT_TO", "pro.kaiserlautern@gmail.com")
ALERT_FROM = os.environ.get("MONITOR_ALERT_FROM", "Filament Monitor <monitor@send.autumated.com>")
RESEND_KEY_FILE = os.environ.get("RESEND_KEY_FILE", os.path.expanduser("~/secret_keys/resend_api_key"))
# Consecutive failed checks before declaring DOWN (debounce transient blips).
FAIL_THRESHOLD = int(os.environ.get("MONITOR_FAIL_THRESHOLD", "2"))
TIMEOUT = int(os.environ.get("MONITOR_TIMEOUT", "12"))


def check_health():
    """(ok: bool, detail: str) for one probe of the liveness endpoint."""
    try:
        req = urllib.request.Request(HEALTH_URL, headers={"User-Agent": "filament-monitor/1"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read(2048).decode("utf-8", "replace")
            ok = r.status == 200 and '"ok"' in body and "true" in body.lower()
            return ok, f"HTTP {r.status}: {body[:200]}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read(300).decode('utf-8', 'replace')[:200]}"
    except Exception as e:  # timeout, DNS, connection refused, ...
        return False, f"{type(e).__name__}: {e}"


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        # healthy=None means "no prior observation": the first run never alerts.
        return {"healthy": None, "fails": 0, "since": 0, "down_since": 0}


def save_state(st):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
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
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            # Required. Without an explicit User-Agent, urllib sends
            # "Python-urllib/3.x", which Cloudflare rejects in front of the
            # Resend API with a 403 (error 1010) before the request ever
            # reaches Resend. Every alert this monitor tried to send was
            # dropped there. check_health already sets one, which is why
            # probing worked while alerting silently did not.
            "User-Agent": "filament-monitor/1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status in (200, 201), f"HTTP {r.status}: {r.read(300).decode('utf-8', 'replace')[:200]}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read(300).decode('utf-8', 'replace')[:200]}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def utc(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))


def main():
    ok, detail = check_health()
    st = load_state()
    now = int(time.time())
    prev = st.get("healthy")

    if ok:
        st["fails"] = 0
        # Recovery: only alert if we had previously CONFIRMED a down state.
        if prev is False:
            down_for = now - st.get("down_since", now)
            sent, sres = send_alert(
                "[filament] signaling RECOVERED",
                f"{HEALTH_URL} is healthy again ({detail}).\n"
                f"Was down for ~{down_for // 60}m{down_for % 60}s.\nRecovered at {utc(now)}.",
            )
            print(f"recovery alert sent={sent} {sres}", file=sys.stderr)
        st["healthy"] = True
        st["since"] = now
        save_state(st)
        print(f"OK  {detail}")
        return 0

    # Failed this probe. Count it; only declare DOWN past the threshold.
    st["fails"] = st.get("fails", 0) + 1
    if st["fails"] >= FAIL_THRESHOLD and prev is not False:
        # Transition into a CONFIRMED down state -> alert once.
        st["healthy"] = False
        st["since"] = now
        st["down_since"] = now
        sent, sres = send_alert(
            "[filament] signaling DOWN",
            f"{HEALTH_URL} failed {st['fails']} consecutive checks.\n\n"
            f"Last error: {detail}\n\nDetected at {utc(now)}.\n\n"
            "Note: GET / returns 503 by design (SPA fallback); check /api/health "
            "and /socket.io/?EIO=4&transport=polling on the origin.",
        )
        print(f"DOWN alert sent={sent} {sres}", file=sys.stderr)
    save_state(st)
    print(f"FAIL ({st['fails']}/{FAIL_THRESHOLD})  {detail}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
