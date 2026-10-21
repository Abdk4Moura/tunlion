// NDJSON bridge to a real VT emulator. Install @xterm/headless@6.0.0 in the
// remote worker's tools directory; NODE_PATH points there, not into the repo.
const { Terminal } = require('@xterm/headless');
const readline = require('node:readline');
const terminal = new Terminal({ cols: Number(process.argv[2]), rows: Number(process.argv[3]), allowProposedApi: true });
const replies = [];
terminal.onData(data => replies.push(Buffer.from(data).toString('base64')));
function snapshot() {
  const buffer = terminal.buffer.active;
  const lines = Array.from({ length: terminal.rows }, (_, y) =>
    buffer.getLine(buffer.baseY + y)?.translateToString(true) || '');
  const inputCell = buffer.getLine(buffer.baseY + buffer.cursorY)?.getCell(2);
  return { lines, baseY: buffer.baseY, cursorX: buffer.cursorX, cursorY: buffer.cursorY,
    inputCell: inputCell && { text: inputCell.getChars(), foreground: inputCell.getFgColor(), bold: inputCell.isBold() },
    replies: replies.splice(0) };
}
// Await writes in order: callers receive a snapshot only after parsing completes.
let pending = Promise.resolve();
readline.createInterface({ input: process.stdin }).on('line', line => {
  pending = pending.then(async () => {
    const message = JSON.parse(line);
    if (message.resize) terminal.resize(...message.resize);
    if (message.data) await new Promise(resolve => terminal.write(Buffer.from(message.data, 'base64'), resolve));
    process.stdout.write(JSON.stringify(snapshot()) + '\n');
  }).catch(error => { console.error(error); process.exit(1); });
});
