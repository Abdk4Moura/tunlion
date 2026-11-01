"""Real-device acceptance: the Android app paired with a separate desktop identity.

Run the instrumentation test on a phone that has the debug APK installed, with a
tunlion binary for this machine. The desktop identity is created in a temporary
directory and is never the machine's own identity.

Required environment/arguments:
  --adb      path to adb
  --device   adb serial (for example 100.64.0.1:5555)
  --desktop  path to this machine's tunlion executable

This is deliberately not part of CI: it pairs two real devices.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument("--adb", required=True)
parser.add_argument("--device", required=True)
parser.add_argument("--desktop", required=True)
args = parser.parse_args()

root = Path(__file__).parent / ("cli-phone-acceptance-" + str(int(time.time())))
root.mkdir()
inbox = root / "inbox"
inbox.mkdir()
environment = os.environ.copy()
environment["TUNLION_CONFIG_DIR"] = str(root / "desktop")
environment["TUNLION_NO_IMPLICIT_INIT"] = "1"
desktop = [args.desktop, "--no-interactive", "--color", "never", "--name-as", "acceptance-desktop"]
adb = [args.adb, "-s", args.device]
started = []


def log(message):
    print(message, flush=True)


def host(command, timeout=90, check=True):
    result = subprocess.run(desktop + command, env=environment, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"Desktop {command[0]} failed ({result.returncode}): {result.stdout}\n{result.stderr}")
    return result


def wait_for_daemon(timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            snapshot = json.loads(host(["status", "--json"]).stdout)
        except Exception:
            snapshot = {}
        if snapshot.get("running"):
            return
        time.sleep(1)
    raise RuntimeError("The desktop daemon did not start")


class Captured:
    """Start a process that stays up while the phone phase runs, capturing its output."""

    def __init__(self, command):
        self.process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.lines = []
        self.events = queue.Queue()
        started.append(self.process)
        threading.Thread(target=self.read, daemon=True).start()

    def read(self):
        for line in self.process.stdout:
            self.lines.append(line)
            self.events.put(line)

    def until(self, predicate, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = predicate(self.events.get(timeout=1))
                if value:
                    return value
            except queue.Empty:
                if self.process.poll() is not None:
                    break
        raise RuntimeError("Expected phase was not reached:\n" + "".join(self.lines))


def file_code(line):
    try:
        event = json.loads(line)
        return event.get("code") if event.get("event") == "code" else None
    except (ValueError, AttributeError):
        return None


try:
    log("1/6 desktop identity")
    host(["init", "--name", "acceptance-desktop", "--no-background",
          "--recovery-file", str(root / "recovery.txt"), "--yes", "--json"])
    log("2/6 desktop receiver")
    host(["up", "--userspace", "--detach", "--dir", str(inbox)], check=False)
    if not json.loads(host(["status", "--json"]).stdout).get("running"):
        Captured(desktop + ["up", "--userspace", "--dir", str(inbox)])
    wait_for_daemon()

    log("3/6 mint a pairing code")
    pairing = Captured(desktop + ["add", "--for", "device", "--name", "acceptance-phone",
                                  "--word", "instrument copper glacier", "--yes"])
    code = pairing.until(lambda line: (match.group(0) if (match := re.search(r"instrument-copper-glacier-[0-9]{4}", line)) else None))
    log(f"    code {code}")

    log("4/6 a receive-by-code file")
    code_file = root / "code-proof.txt"
    code_file.write_text("code-to-phone verified proof\n")
    sending = Captured(desktop + ["send", str(code_file), "--code", "--timeout", "300", "--json"])
    receive_code = sending.until(file_code)

    background_file = root / ("desktop-proof-" + str(int(time.time())) + ".txt")
    background_file.write_text("desktop-to-phone verified proof\n")

    log("5/6 phone pairing, transfer and availability checks")
    test = Captured(adb + ["shell", "am", "instrument", "-w", "-r",
        "-e", "class", "com.tunlion.android.CliAndroidAcceptanceTest",
        "-e", "deviceCode", code,
        "-e", "fileCode", receive_code,
        "-e", "backgroundFile", background_file.name,
        "-e", "desktopName", "acceptance-desktop",
        "com.tunlion.android.test/androidx.test.runner.AndroidJUnitRunner"])
    test.until(lambda line: "BACKGROUND_READY" in line, timeout=180)

    listed = json.loads(host(["devices", "--json"]).stdout)["data"]["devices"]
    assert listed, "The desktop did not list the phone"
    phone = next((item["name"] for item in listed if "phone" in item["name"]), listed[0]["name"])
    log(f"    the desktop lists {phone}")
    host(["send", str(background_file), "--to", phone, "--json"], timeout=90)

    log("6/6 background receive, saved bytes and availability off")
    test.until(lambda line: "CLI_ACCEPTANCE_PASSED" in line, timeout=120)
    assert test.process.wait(timeout=30) == 0
    assert sending.process.wait(timeout=30) == 0
    assert pairing.process.wait(timeout=30) == 0

    received = list(inbox.glob("phone-proof*.txt"))
    assert received and received[0].read_text() == "phone-to-desktop verified proof\n", \
        "The desktop's received bytes do not match"

    print("PASS: code pairing, real phone-to-desktop file, receive by code, "
          "background desktop-to-phone file, public Downloads bytes, daemon reaped, notifications removed")
    print("Evidence directory:", root)
except Exception:
    if "test" in globals():
        print("".join(test.lines))
    raise
finally:
    host(["down", "--yes"], timeout=20, check=False)
    for process in started:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
