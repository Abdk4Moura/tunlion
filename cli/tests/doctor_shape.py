"""Print the shape of a `tunlion doctor --json` document, never its content.

The lan-discovery gate calls this only after its wg/p2p-class check failed.
The document can carry the configured server URL and other free text, so
every printed value is either a fixed allowlisted constant from the doctor's
schema or an opaque placeholder. Nothing read from the input is echoed.

    doctor_shape.py < doctor.out     the shape lines
    doctor_shape.py --self-test      adversarial cases; exit 1 on any leak
"""
import json
import sys

# Top-level keys of the preflight document and of an error envelope.
KEYS = {
    "identity", "role", "kind", "server", "signaling", "ice", "interfaces",
    "sshd_ca", "history", "daemon", "lan", "ok", "verb", "error",
}
KINDS = {"tunlion-doctor-preflight", "tunlion-doctor-probe", "tunlion-doctor-repeat"}
CODES = {
    "error", "usage", "unknown_device", "denied", "still_relayed", "unreachable",
    "network", "partial", "no_identity", "local_resource", "tls_certificate",
    "interrupted",
}
EXITS = {1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 130, 143}
SIGNALS = {"SIGINT", "SIGTERM"}
CLASSES = {"shared", "p2p", "loopback"}


def pick(value, allowed):
    """The value itself only when it is one of the allowed constants."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "<bool>"
    try:
        if value in allowed:
            return str(value)
    except TypeError:
        pass
    return "<other>"


def shape(text):
    try:
        v = json.loads(text)
    except Exception:
        return ["doctor stdout: not one JSON document"]
    if not isinstance(v, dict):
        return ["doctor stdout: a JSON value that is not an object"]
    keys = sorted(k for k in v if k in KEYS)
    other = sum(1 for k in v if k not in KEYS)
    lines = ["doctor keys: %s, %d other" % (keys, other),
             "doctor kind: %s" % pick(v.get("kind"), KINDS)]
    lan = v.get("lan")
    if "lan" not in v:
        lines.append("doctor lan: absent")
    elif not isinstance(lan, dict) or not isinstance(lan.get("interfaces"), list):
        lines.append("doctor lan: present, no interfaces list")
    else:
        ifs = [i for i in lan["interfaces"] if isinstance(i, dict)]
        wg = [pick(i.get("class"), CLASSES) for i in ifs if i.get("name") == "wg0"]
        lines.append("doctor lan: %d interfaces, wg0 classes %s" % (len(ifs), wg))
    e = v.get("error")
    if isinstance(e, dict):
        lines.append("doctor error: code %s exit %s signal %s" % (
            pick(e.get("code"), CODES), pick(e.get("exit"), EXITS), pick(e.get("signal"), SIGNALS)))
    elif "error" in v:
        lines.append("doctor error: present, not an object")
    return lines


def self_test():
    secrets = ["s3cr3tTok3nAbc", "8675309421"]
    a, n = secrets
    cases = [
        '{"kind":"%s","%s":1,"server":"https://u:%s@h/?t=%s"}' % (a, a, a, n),
        '{"kind":%s,"lan":{"interfaces":[{"name":"wg0","class":"%s"}]}}' % (n, a),
        '{"lan":{"interfaces":[{"name":"wg0","class":%s}]},"%s":%s}' % (n, n, n),
        '{"ok":false,"error":{"code":"%s","exit":%s,"signal":"%s","message":"%s"}}' % (a, n, a, a),
        '{"error":{"code":%s,"exit":"%s","signal":%s}}' % (n, a, n),
        '{"error":"%s %s"}' % (a, n),
        '{"kind": "%s", ' % a,
        "%s %s not json" % (a, n),
        '["%s", %s]' % (a, n),
        "",
    ]
    fails = 0
    for c in cases:
        out = "\n".join(shape(c))
        leaked = [s for s in secrets if s in out]
        print("%s %s" % ("LEAK" if leaked else "ok", out.replace("\n", " | ")))
        fails += bool(leaked)
    good = '{"kind":"tunlion-doctor-preflight","lan":{"interfaces":[{"name":"wg0","class":"p2p"}]}}'
    want = "doctor lan: 1 interfaces, wg0 classes ['p2p']"
    if want not in shape(good):
        print("MISMATCH known-good document: %s" % shape(good))
        fails += 1
    print("RESULT doctor-shape %s" % ("PASS" if fails == 0 else "FAIL %d" % fails))
    return 1 if fails else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    try:
        for line in shape(sys.stdin.read())[:6]:
            print("  " + line)
    except Exception:
        print("  doctor shape: could not be read")
