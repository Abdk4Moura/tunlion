#!/usr/bin/env python3
"""Real isolated enrollment, offer approval, process restart and delivery.

Run only on the leased worker. Never uses the installed binary/config/daemon.
No identities, certificates, pair secrets or approvals are fabricated here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", required=True, type=Path)
    parser.add_argument("--python", required=True)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--fault-hooks", action="store_true")
    args = parser.parse_args()
    binary = args.bin.resolve()
    if binary == (Path.home() / ".local/bin/tunlion").resolve():
        raise SystemExit("refusing the installed daemon executable; pass an isolated test build")
    work = args.evidence.resolve()
    if work.exists() and any(work.iterdir()):
        raise SystemExit("evidence directory must be new or empty")
    work.mkdir(parents=True, exist_ok=True)
    repo = Path(__file__).resolve().parents[1]
    processes = []
    logs = []
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = f"http://127.0.0.1:{port}"
    owner, guest, inbox = work / "owner", work / "guest", work / "inbox"
    for path in (owner, guest, inbox):
        path.mkdir()

    def env(config, extra=None):
        return {**os.environ, "TUNLION_CONFIG_DIR": str(config),
                "TUNLION_NONINTERACTIVE": "1", **(extra or {})}

    def run(config, *argv, timeout=60, success=True):
        command = [str(binary), "--server", server, *map(str, argv)]
        result = subprocess.run(command, env=env(config), stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=timeout)
        # Keep command output locally as evidence, never render invitation data.
        index = len(logs)
        logs.append({"args": list(map(str, argv)), "rc": result.returncode})
        (work / f"command-{index}.log").write_text(result.stdout + result.stderr)
        if success and result.returncode:
            raise AssertionError(f"command {index} failed, rc={result.returncode}; see its evidence log")
        return result

    def spawn(config, label, *argv, extra=None):
        log = (work / f"{label}.log").open("w")
        child = subprocess.Popen([str(binary), "--server", server, *map(str, argv)],
                                 env=env(config, extra), stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=subprocess.STDOUT)
        processes.append(child)
        return child

    def stop(child):
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=12)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)

    def wait_for(predicate, description, seconds=30):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            if predicate():
                return
            time.sleep(0.25)
        raise AssertionError(f"timed out waiting for {description}")

    def state():
        path = owner / "transfer-requests/requests.json"
        return json.loads(path.read_text()) if path.exists() else {"requests": []}

    def json_result(result):
        return json.loads(result.stdout.strip().splitlines()[-1])

    try:
        backend_log = (work / "backend.log").open("w")
        backend = subprocess.Popen([args.python, "app.py"], cwd=repo / "backend",
            env={**os.environ, "PORT": str(port), "FIL_ASYNC_MODE": "eventlet",
                 "FIL_SELF_MONKEYPATCH": "1", "FIL_CLAIM_LIMIT": "1000000"},
            stdout=backend_log, stderr=subprocess.STDOUT)
        processes.append(backend)

        def healthy():
            try:
                with urllib.request.urlopen(server + "/api/health", timeout=1) as response:
                    return response.status == 200
            except Exception:
                return False
        wait_for(healthy, "isolated backend")
        run(owner, "init", "--name", "alpha", "--recovery-file", owner / "recovery", "--yes")
        run(owner, "config", "dir", inbox)
        receiver = spawn(owner, "receiver-first", "up", "--dir", inbox)
        time.sleep(2)
        invitation = work / "invitation"
        run(owner, "add", "--for", "guest", "--allow", "transfer", "--out", invitation, "--yes")
        run(guest, "join", "--invite-file", invitation, "--name", "guest", "--no-interactive")
        invitation.unlink()

        payload = work / "original.bin"
        original = b"durable transfer exact bytes\n" * 8192
        payload.write_bytes(original)
        queued = json_result(run(guest, "--json", "send", "--defer", "--to", "alpha",
                                 "--timeout", "15", payload))
        assert queued["state"] == "waiting" and queued["delivered"] is False, queued
        offer_id = queued["offers"][0]["id"]
        wait_for(lambda: len(state()["requests"]) == 1, "one durable pending offer")
        request = state()["requests"][0]
        assert request["state"] == "pending", request
        assert not list(inbox.iterdir()), "bytes/staging arrived before approval"
        print("PASS: proven restricted sender created one offer and no unsolicited bytes", flush=True)

        stop(receiver)
        listing = run(owner, "requests").stdout
        # Rendering may use stderr on a terminal; the archived evidence has both.
        assert state()["requests"][0]["state"] == "pending"
        run(owner, "requests", "accept", request["id"])
        approved = state()["requests"][0]
        assert approved["state"] == "approved"
        assert Path(approved["destination"]).parent.resolve() == inbox.resolve()
        assert not list(inbox.iterdir()), "approval itself must not deliver bytes"
        payload.write_bytes(b"the original source changed after the retained snapshot")
        receiver = spawn(owner, "receiver-restarted", "up", "--dir", inbox)
        time.sleep(2)
        delivered = json_result(run(guest, "--json", "send", "--resume", offer_id, "--timeout", "20"))
        assert delivered["state"] == "delivered" and delivered["delivered"] is True, delivered
        target = Path(approved["destination"])
        assert target.read_bytes() == original
        assert state()["requests"][0]["state"] == "fulfilled"
        print("PASS: offline approval and process restart delivered the retained exact snapshot", flush=True)

        # A completed sender retry cannot create another incoming request/file.
        before = sorted(path.name for path in inbox.iterdir())
        run(guest, "--json", "send", "--resume", offer_id, "--timeout", "10", success=False)
        assert sorted(path.name for path in inbox.iterdir()) == before
        assert len(state()["requests"]) == 1
        print("PASS: completed retry did not create a second request or duplicate delivery", flush=True)

        declined_source = work / "decline.bin"
        declined_source.write_bytes(b"never approved")
        queued = json_result(run(guest, "--json", "send", "--defer", "--to", "alpha",
                                 "--timeout", "15", declined_source))
        declined_id = queued["offers"][0]["id"]
        pending = next(item for item in state()["requests"] if item["state"] == "pending")
        run(owner, "requests", "decline", pending["id"])
        run(guest, "--json", "send", "--resume", declined_id, "--timeout", "15", success=False)
        assert not (inbox / "decline.bin").exists()
        print("PASS: a recorded decline never delivered bytes", flush=True)

        # Actual sender-daemon scheduling, not a simulated retry loop.
        automatic_source = work / "automatic.bin"
        automatic_source.write_bytes(b"scheduled by the existing sender daemon")
        queued = json_result(run(guest, "--json", "send", "--defer", "--to", "alpha",
                                 "--timeout", "15", automatic_source))
        automatic_id = queued["offers"][0]["id"]
        pending = next(item for item in state()["requests"] if item["state"] == "pending")
        run(owner, "requests", "accept", pending["id"])
        guest_inbox = work / "guest-inbox"
        guest_inbox.mkdir()
        sender_daemon = spawn(guest, "sender-daemon", "up", "--dir", guest_inbox)
        wait_for(lambda: any(item["id"] == pending["id"] and item["state"] == "fulfilled"
                             for item in state()["requests"]), "daemon scheduled retry", seconds=90)
        wait_for(lambda: any(item["id"] == automatic_id and item["state"] == "delivered"
                             for item in json.loads((guest / "retained-sends/retained-sends.json").read_text())["sends"]),
                 "sender's verified delivery receipt", seconds=15)
        stop(sender_daemon)
        assert Path(next(item for item in state()["requests"] if item["id"] == pending["id"])["destination"]).read_bytes() == automatic_source.read_bytes()
        print("PASS: the sender daemon retried a retained offer and reaped its attempt", flush=True)

        # Offline receiver: persistence is sender-local, no cloud mailbox.
        stop(receiver)
        offline_source = work / "offline.bin"
        offline_source.write_bytes(b"retained while the receiver was offline")
        queued = json_result(run(guest, "--json", "send", "--defer", "--to", "alpha",
                                 "--timeout", "3", offline_source))
        offline_id = queued["offers"][0]["id"]
        assert queued["state"] == "waiting" and queued["delivered"] is False
        receiver = spawn(owner, "receiver-after-offline", "up", "--dir", inbox)
        time.sleep(2)
        run(guest, "--json", "send", "--resume", offline_id, "--timeout", "15")
        pending = next(item for item in state()["requests"] if item["state"] == "pending")
        run(owner, "requests", "accept", pending["id"])
        delivered = json_result(run(guest, "--json", "send", "--resume", offline_id, "--timeout", "15"))
        assert delivered["delivered"] is True
        print("PASS: offline receiver did not lose the sender-retained offer", flush=True)

        if args.fault_hooks:
            # The real receiver commits then drops the link at the ack boundary.
            # Its retry must re-ack the receipt, not choose another destination.
            receipt_source = work / "receipt.bin"
            receipt_source.write_bytes(b"one delivery despite a lost acknowledgement")
            queued = json_result(run(guest, "--json", "send", "--defer", "--to", "alpha",
                                     "--timeout", "15", receipt_source))
            receipt_id = queued["offers"][0]["id"]
            pending = next(item for item in state()["requests"] if item["state"] == "pending")
            run(owner, "requests", "accept", pending["id"])
            stop(receiver)
            receiver = spawn(owner, "receiver-ack-loss", "up", "--dir", inbox,
                             extra={"TUNLION_TEST_PREMATURE_CLOSE": "once"})
            time.sleep(2)
            run(guest, "--json", "send", "--resume", receipt_id, "--timeout", "15", timeout=110)
            wait_for(lambda: any(item["id"] == pending["id"] and item["state"] == "fulfilled"
                                 for item in state()["requests"]), "committed receiver receipt")
            stop(receiver)
            receiver = spawn(owner, "receiver-after-ack-loss", "up", "--dir", inbox)
            time.sleep(2)
            delivered = json_result(run(guest, "--json", "send", "--resume", receipt_id, "--timeout", "15"))
            assert delivered["delivered"] is True
            assert len(list(inbox.glob("receipt*"))) == 1
            assert (inbox / "receipt.bin").read_bytes() == receipt_source.read_bytes()
            print("PASS: committed receipt survived ack loss and restart without duplicate placement", flush=True)

        # Revocation stays authoritative after review and receiver restart.
        revoked_source = work / "revoked.bin"
        revoked_source.write_bytes(b"revoked before delivery")
        queued = json_result(run(guest, "--json", "send", "--defer", "--to", "alpha",
                                 "--timeout", "15", revoked_source))
        revoked_id = queued["offers"][0]["id"]
        pending = next(item for item in state()["requests"] if item["state"] == "pending")
        run(owner, "requests", "accept", pending["id"])
        run(owner, "--yes", "revoke", "guest", "--certificate")
        run(guest, "--json", "send", "--resume", revoked_id, "--timeout", "15", success=False)
        assert not (inbox / "revoked.bin").exists()
        print("PASS: fresh revocation defeated a prior exact approval", flush=True)
        (work / "summary.json").write_text(json.dumps({"ok": True,
            "sha256": hashlib.sha256(original).hexdigest(), "commands": logs}, indent=2))
    finally:
        for child in reversed(processes):
            stop(child)


if __name__ == "__main__":
    main()
