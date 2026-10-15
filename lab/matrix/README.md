# Launch matrix

Every relationship pair and every feature, on real machines and real browsers,
against the production server. One cell is one user-visible behaviour with its
assertions; a cell passes only when all of them hold, and nothing is retried
into a pass.

| Pair | Where it runs |
|---|---|
| CLI-CLI | fresh Debian containers on a lab host with docker (a Codespace), one of them a hostile machine (read-only root, 192 MB, C locale, `TERM=dumb`) |
| browser-CLI | real Chromium here, desktop and phone (Pixel 7) viewports, against a container on the lab host |
| browser-browser | two Chromium contexts here |

The page is served under `https://tunlion.autumated.com` from a local build
(the production API refuses other origins) and talks to the production API.

## Run

```bash
# a static Linux build of the CLI (rbuild output) and a built frontend
LAB_HOST="gh codespace ssh -c <codespace> --" CODESPACE=<codespace> \
PLAYWRIGHT=<path to the playwright package> FRONTEND_DIST=<frontend/dist> \
  lab/matrix/run.sh <tunlion-binary> <outdir> [cli|browser|all] [cell-regex]
```

Results: `<outdir>/matrix.md`, `<outdir>/matrix.json`, evidence (logs,
screenshots, received files) under `<outdir>/ev/`.

## Files

- `box.sh`: build the container image with a given binary; start and remove machines.
- `cli-cells.sh`: the CLI-CLI cells (runs on the lab host; tmux gives real TTYs).
- `browser/cells.cjs`: the browser-CLI and browser-browser cells (Playwright).
- `render.py`: merges the results into the matrix.

A cell that does not apply where it runs (mount needs `/dev/fuse`; member to
member links when the CLI says they are not in this release) is recorded as
`n/a` with the reason in its log, never as a pass.
