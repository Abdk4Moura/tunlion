import os, pty, select, time, sys

# Spawn opencode in a bare PTY, do NOT answer any queries, capture what it writes.
argv = ["/root/.opencode/bin/opencode"]
env = dict(os.environ)
env["TERM"] = "xterm-256color"
# no COLORTERM, mimic current cli/src/l2.rs

pid, fd = pty.fork()
if pid == 0:
    os.execvpe(argv[0], argv, env)
    os._exit(1)

# set a sane window size
import fcntl, termios, struct
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))

out = bytearray()
start = time.time()
while time.time() - start < 4.0:
    r, _, _ = select.select([fd], [], [], 0.3)
    if fd in r:
        try:
            d = os.read(fd, 65536)
        except OSError:
            break
        if not d:
            break
        out += d

try:
    os.kill(pid, 9)
except Exception:
    pass

sys.stdout.buffer.write(b"=== RAW (repr) ===\n")
sys.stdout.buffer.write(repr(bytes(out)).encode() + b"\n")
sys.stdout.buffer.write(b"=== len: %d ===\n" % len(out))
