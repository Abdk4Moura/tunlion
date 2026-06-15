// Throwaway isolation harness bridge: PTY <-> websocket, plus a tiny static file
// server. This is NOT part of the shipped app. It exists only to run opencode in
// the SAME xterm.js (6.0.0) + fit (0.11.0) the web shell uses, wired to a real
// node-pty, so we can observe whether opencode renders in plain xterm.js.
const http = require('http')
const fs = require('fs')
const path = require('path')
const { WebSocketServer } = require('ws')
const pty = require('node-pty')

const ROOT = __dirname
const MIME = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css' }

const server = http.createServer((req, res) => {
  let p = req.url.split('?')[0]
  if (p === '/') p = '/index.html'
  const fp = path.join(ROOT, p)
  if (!fp.startsWith(ROOT)) { res.writeHead(403); res.end(); return }
  fs.readFile(fp, (err, data) => {
    if (err) { res.writeHead(404); res.end('not found'); return }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(fp)] || 'application/octet-stream' })
    res.end(data)
  })
})

const wss = new WebSocketServer({ server })

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://x')
  const cols = parseInt(url.searchParams.get('cols') || '120', 10)
  const rows = parseInt(url.searchParams.get('rows') || '40', 10)
  const cmd = url.searchParams.get('cmd') || 'opencode'
  const colorterm = url.searchParams.get('colorterm') === '1'

  const argv = cmd === 'opencode' ? ['/root/.opencode/bin/opencode'] : [cmd]
  const env = Object.assign({}, process.env, { TERM: 'xterm-256color' })
  if (colorterm) env.COLORTERM = 'truecolor'
  else delete env.COLORTERM

  // Log every byte the PTY emits (probe bytes) and every byte the client sends
  // back (xterm.js query responses), so we can see the handshake precisely.
  const ptyLog = fs.createWriteStream(path.join(ROOT, 'pty-out.log'))
  const inLog = fs.createWriteStream(path.join(ROOT, 'pty-in.log'))

  const term = pty.spawn(argv[0], argv.slice(1), {
    name: 'xterm-256color', cols, rows, cwd: process.env.HOME, env,
  })

  term.onData((d) => {
    // node-pty hands us a JS string; send it as a BINARY frame (Buffer) so the
    // browser gets an ArrayBuffer it feeds straight to term.write, and so a byte
    // is never mis-parsed as a control JSON message. Use latin1/binary so the raw
    // bytes round-trip (node-pty already decoded UTF-8 to a string; re-encoding as
    // utf8 would also work, but opencode emits valid UTF-8 so utf8 is safe).
    const buf = Buffer.from(d, 'utf8')
    try { ptyLog.write(buf) } catch (e) {}
    try { ws.send(buf, { binary: true }) } catch (e) {}
  })
  term.onExit(({ exitCode }) => {
    try { ws.send(JSON.stringify({ __exit: exitCode })) } catch (e) {}
    try { ws.close() } catch (e) {}
  })

  ws.on('message', (msg, isBinary) => {
    // Control messages (resize) arrive as JSON text; everything else is raw input.
    if (!isBinary) {
      const s = msg.toString()
      if (s.startsWith('{')) {
        try {
          const o = JSON.parse(s)
          if (o.resize) { term.resize(o.cols, o.rows); return }
        } catch (e) {}
      }
    }
    try { inLog.write(msg) } catch (e) {}
    term.write(isBinary ? msg : msg.toString())
  })

  ws.on('close', () => { try { term.kill() } catch (e) {} ; try { ptyLog.end() } catch (e) {}; try { inLog.end() } catch (e) {} })
})

const PORT = process.env.PORT || 8799
server.listen(PORT, () => console.log('harness on http://127.0.0.1:' + PORT))
