#!/usr/bin/env python3
"""Production OOM-shield monitor.

Runs `deploy/assert-oom-shield.sh` on a timer and alerts (via Resend) when the
shield is not in effect. Companion to signaling-monitor.py; same alert path,
same state-file debounce shape, deliberately different debounce RULES (see
below).

WHY A TIMER AND NOT JUST THE ASSERTION SCRIPT

The assertion landed in cd6d75c and made the shield's absence *observable*. It
did not make it *observed*. Nothing ran it. On 2026-08-03 all four production
containers sat at oom_score_adj=0 for hours while docker-compose.yml said -800,
and the only reason anyone noticed was an unrelated memory check. An assertion
that no one runs is a document, not a guard. This is the thing that runs it.

The drift is created by container RECREATION: compose applies oom_score_adj at
creation time, so a container started before the compose change, or recreated by
a path that does not use that compose file, comes up unshielded and silent. That
is a deploy-time event, hence a few-minute cadence rather than daily.

WHY IT AUTO-FIXES, AND WHY IT STILL ALERTS

An unshielded production API on this 4-core/8GB box is a live risk: a concurrent
rustc has OOM-killed processes here before. Waiting for a human costs more than
applying -800. So it fixes.

But the fix is NOT the resolution. `echo -800 > /proc/PID/oom_score_adj` lasts
exactly as long as that process does; the next recreation brings the drift back.
The question the alert exists to raise is "why was it missing", not "is it back".
So every fix alerts, and the alert says so. A monitor that silently repaired this
would restore precisely the silence cd6d75c was written to end.

WHY EXIT 1 IS NOT DEBOUNCED AND EXIT 2 IS

Debouncing filters transient FALSE readings. The two failure exits differ in
kind, so they get different rules:

  exit 2 UNVERIFIABLE  containers not running / cgroup unreadable. Normal and
                       transient during a deploy or a restart. Debounced.
  exit 1 UNSHIELDED    a live process in a running container reports
                       oom_score_adj != -800. That is read straight off /proc.
                       It is a fact, not a flaky probe, and there is no reading
                       of it that becomes false by waiting. Alerts on the first
                       occurrence.

Treating exit 2 as OK would be the original defect in a new place: an
unverifiable shield is not a shield.

Env knobs mirror signaling-monitor.py so both can be pointed at a test target.
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ASSERT = os.environ.get("OOM_ASSERT_SCRIPT", os.path.join(HERE, "..", "assert-oom-shield.sh"))
STATE_FILE = os.environ.get(
    "OOM_MONITOR_STATE", os.path.expanduser("~/.cache/filament-oom-shield-monitor.json")
)
ALERT_TO = os.environ.get("MONITOR_ALERT_TO", "cadaynstudio@gmail.com")
ALERT_FROM = os.environ.get("MONITOR_ALERT_FROM", "Filament Monitor <monitor@send.autumated.com>")
RESEND_KEY_FILE = os.environ.get("RESEND_KEY_FILE", os.path.expanduser("~/secret_keys/resend_api_key"))
TIMEOUT = int(os.environ.get("MONITOR_TIMEOUT", "10"))
# Consecutive UNVERIFIABLE checks before alerting. Deploys and restarts routinely
# produce one; a run of them means the containers are not coming back.
UNVERIFIABLE_THRESHOLD = int(os.environ.get("OOM_UNVERIFIABLE_THRESHOLD", "3"))


def run_assert(fix=False):
    """(exit_code, combined_output) for one run of the assertion script."""
    cmd = ["bash", ASSERT] + (["--fix"] if fix else [])
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return 2, "assert-oom-shield.sh timed out after 60s"
    except Exception as e:
        return 2, f"could not run {ASSERT}: {type(e).__name__}: {e}"


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        # shielded=None means "no prior observation".
        return {"shielded": None, "unverifiable": 0, "since": 0}


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
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
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
    code, detail = run_assert()
    st = load_state()
    now = int(time.time())

    if code == 0:
        st["unverifiable"] = 0
        if st.get("shielded") is False:
            sent, sres = send_alert(
                "[filament] OOM shield RESTORED",
                f"Production is shielded again at {utc(now)}.\n\n{detail}\n",
            )
            # Print the send result here for the same reason the other two
            # branches do: an alert that failed to send must not be silent.
            print(f"RESTORED alert sent={sent} {sres}", file=sys.stderr)
        st["shielded"] = True
        st["since"] = now
        save_state(st)
        print(f"OK  {detail}")
        return 0

    if code == 2:
        st["unverifiable"] = st.get("unverifiable", 0) + 1
        n = st["unverifiable"]
        if n == UNVERIFIABLE_THRESHOLD:
            sent, sres = send_alert(
                "[filament] OOM shield UNVERIFIABLE",
                f"assert-oom-shield.sh could not determine the shield state on "
                f"{n} consecutive checks, ending {utc(now)}.\n\n{detail}\n\n"
                "This is NOT the same as shielded. Either the production "
                "containers are down (check `docker ps`), or the cgroup layout "
                "changed and the assertion needs updating. Both are worth "
                "looking at; neither is safe to read as OK.\n",
            )
            print(f"UNVERIFIABLE alert sent={sent} {sres}", file=sys.stderr)
        save_state(st)
        print(f"UNVERIFIABLE ({n}/{UNVERIFIABLE_THRESHOLD})  {detail}")
        return 2

    # code == 1: at least one live process is unshielded. Not debounced.
    st["unverifiable"] = 0
    before = detail
    fix_code, fix_detail = run_assert(fix=True)
    after_code, after_detail = run_assert()
    remedied = after_code == 0

    sent, sres = send_alert(
        "[filament] OOM shield WAS MISSING" + ("" if remedied else " and could NOT be restored"),
        f"Detected at {utc(now)}: production was running WITHOUT the OOM shield.\n\n"
        f"--- before ---\n{before}\n\n"
        f"--- fix attempt (exit {fix_code}) ---\n{fix_detail}\n\n"
        f"--- after (exit {after_code}) ---\n{after_detail}\n\n"
        + (
            "The shield is back in effect, but only for the processes running "
            "right now. `echo -800 > /proc/PID/oom_score_adj` dies with the "
            "process; the next container recreation brings the drift back. The "
            "open question is why it was missing: a container created outside "
            "deploy/docker-compose.yml, or created before its oom_score_adj was "
            "added. Find that, or this alert repeats.\n"
            if remedied
            else "THE FIX DID NOT TAKE. Production is still unshielded and can "
            "be OOM-killed ahead of a build. Check that this ran as root and "
            "that the processes still exist.\n"
        ),
    )
    print(f"UNSHIELDED alert sent={sent} {sres}", file=sys.stderr)

    st["shielded"] = False
    st["since"] = now
    save_state(st)
    print(f"UNSHIELDED (remedied={remedied})  {before}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
