# ptydrive.py LOG CODEFILE -- argv... : run argv in a pty, log its output
# (ANSI stripped), write the first pairing code seen to CODEFILE, and press
# Enter whenever the output asks a question. Exits with the child's status.
import os, pty, re, select, sys, time
log, codefile = sys.argv[1], sys.argv[2]
argv = sys.argv[sys.argv.index('--') + 1:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(argv[0], argv)
buf = ''
ansi = re.compile(r'\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07')
code_done = False
answered = set()
with open(log, 'w') as lf:
    while True:
        r, _, _ = select.select([fd], [], [], 0.5)
        if fd in r:
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            text = ansi.sub('', data.decode('utf8', 'replace'))
            lf.write(text); lf.flush()
            buf += text
            if not code_done:
                m = re.search(r'\b([a-z]+(?:-[a-z]+)+-[0-9]{3,5})\b', buf, re.I)
                if m:
                    open(codefile, 'w').write(m.group(1).lower()); code_done = True
            menu_key = os.environ.get('PTY_MENU_KEY', '1')
            n_menus = len(re.findall(r'pick · esc', buf))
            if n_menus > len([a for a in answered if a.startswith('menu#')]):
                answered.add(f'menu#{n_menus}'); lf.write(f'\n[ptydrive] menu: pressing {menu_key}\n'); lf.flush()
                time.sleep(0.3); os.write(fd, menu_key.encode())
            for q in re.findall(r'[^\n\r]*\?[^\n\r]*', buf):
                if q not in answered:
                    answered.add(q); lf.write(f'\n[ptydrive] answering Enter to: {q}\n'); lf.flush()
                    time.sleep(0.3); os.write(fd, b'\r')
        try:
            wpid, st = os.waitpid(pid, os.WNOHANG)
            if wpid:
                sys.exit(os.waitstatus_to_exitcode(st))
        except ChildProcessError:
            break
_, st = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(st))
