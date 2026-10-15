# Launch matrix results, 0.9.0

Latest run: https://github.com/Abdk4Moura/tunlion/actions/runs/38768306726 on main 08d483a4
(GitHub runner, `.github/workflows/matrix.yml`). Signaling: production API. C20 (forced relay)
ran against a local backend and a local coturn on the runner.

**49 pass, 0 fail, 2 n/a** of 51 cells (C13: member-to-member links are not in this release;
C15: no `/dev/fuse` in the containers). The browser pairing cells (B03 B04 B05 B08 B12 BB1) ran
four more rounds in the same run: **23 of 24 pass**. The one failure (B03, round 3) was the page
never reaching the production signaling server ("offline, reconnecting" in the page text), not a
pairing fault.

Known, with evidence:

- With `signaling=local` the CLI-CLI cell C24 (invitation `--expires` cuts live sessions) ends the
  live exec on time (116 to 117 s, within the 135 s bound) but as a dead link (exit 6) rather than
  the "access expired" refusal (exit 4). It does the same on the commit before the latest backend
  change, and passes with production signaling, so it is not a regression. The exit reason is a
  race between the expiry closing the link and the session's own cut message.
- Production coturn still allows only 41 relay ports (49160-49200). The repo's config now uses
  49152-65535 (#457); production needs that deployed and the firewall opened.

The previous all-pass run (38737947532, main eda56186) had the same totals and 24 of 24 pairing rounds.
Per-cell results from it follow; the latest run matched them cell for cell.

| Cell | Pair | Feature | Result | Seconds | Evidence |
|---|---|---|---|---|---|
| C01 | cli-cli | pair: invitation file (device) | pass | 5 | ev/C01.log |
| C02 | cli-cli | pair: spoken code at a TTY | pass | 16 | ev/C02.log |
| C03 | cli-cli | send --to a known device (5 MB, sha256) | pass | 1 | ev/C03.log |
| C04 | cli-cli | send by code / receive | pass | 15 | ev/C04.log |
| C05 | cli-cli | two concurrent code sends | pass | 13 | ev/C05.log |
| C06 | cli-cli | receive at a TTY returns; Ctrl-C is 130 | pass | 17 | ev/C06.log |
| C07 | cli-cli | sync, then sync --delete | pass | 1 | ev/C07.log |
| C08 | cli-cli | exec refused before grant (exit 4) | pass | 0 | ev/C08.log |
| C09 | cli-cli | exec argv, --shell, exit status, cwd/env | pass | 2 | ev/C09.log |
| C10 | cli-cli | shell (pty) | pass | 3 | ev/C10.log |
| C11 | cli-cli | forward a port | pass | 7 | ev/C11.log |
| C12 | cli-cli | expose, reach <dev>.mesh via proxy | pass | 13 | ev/C12.log |
| C13 | cli-cli | member to member reach and send | n/a | 0 | ev/C13.log |
| C14 | cli-cli | overlay address | pass | 0 | ev/C14.log |
| C15 | cli-cli | mount | n/a | 2 | ev/C15.log |
| C16 | cli-cli | reach and doctor --json | pass | 0 | ev/C16.log |
| C17 | cli-cli | status/devices --json, error envelope | pass | 0 | ev/C17.log |
| C18 | cli-cli | exit codes 3 2 9 11 7 6 | pass | 16 | ev/C18.log |
| C19 | cli-cli | skill install | pass | 0 | ev/C19.log |
| C20 | cli-cli | forced relay: send and exec | pass | 22 | ev/C20.log |
| C21 | cli-cli | revoke a capability | pass | 0 | ev/C21.log |
| C22 | cli-cli | devices revoke, then restore | pass | 13 | ev/C22.log |
| C23 | cli-cli | devices forget, then re-add | pass | 13 | ev/C23.log |
| C24 | cli-cli | invitation --expires cuts live sessions | pass | 123 | ev/C24.log |
| C25 | cli-cli | hostile machines: code, invite, send | pass | 22 | ev/C25.log |
| C26 | cli-cli | default ceiling: no shell, remedy named | pass | 0 | ev/C26.log |
| C27 | cli-cli | shell survives a 10 s network drop | pass | 17 | ev/C27.log |
| C28 | cli-cli | a person invitee is EXTERNAL, not FLEET | pass | 4 | ev/C28.log |
| C29 | cli | tunlion demo --auto plays to the end | pass | 2 | ev/C29.log |
| C30 | cli | tunlion demo without a TTY: exit 2 | pass | 0 | ev/C30.log |
| B01 | browser-cli | receive by code (desktop) | pass | 25 | ev/B01.log |
| B02 | browser-cli | receive by code (phone) | pass | 24 | ev/B02.log |
| B03 | browser-cli | browser code, CLI receive, browser sends | pass | 41 | ev/B03.log |
| B04 | browser-cli | CLI joins a browser "Remember a device" code | pass | 12 | ev/B04.log |
| B05 | browser-cli | browser claims a CLI `add` code, both remember | pass | 21 | ev/B05.log |
| B06 | browser-cli | browser sends to the remembered vps after reload | pass | 21 | ev/B06.log |
| B07 | browser-cli | shell: refused before grant, works after (desktop) | pass | 53 | ev/B07.log |
| B08 | browser-cli | shell on a phone viewport against the vps | pass | 28 | ev/B08.log |
| B11 | browser-cli | browser shell survives a 10 s network cut | pass | 32 | ev/B11.log |
| B09 | browser-cli | revoke shell cuts the browser off | pass | 39 | ev/B09.log |
| B10 | browser-cli | CLI sends --to the remembered browser | pass | 3 | ev/B10.log |
| B12 | browser-cli | pairing with a bystander browser on the same network, 3 times | pass | 39 | ev/B12.log |
| BB1 | browser-browser | code, then send (desktop to phone) | pass | 9 | ev/BB1.log |
| BB2 | browser-browser | remember each other, reload, send | pass | 25 | ev/BB2.log |
| D01 | dashboard | sign in once with the printed link; a second use is refused | pass | 0 | ev/D01.log |
| D02 | dashboard | make an invitation, another machine joins it | pass | 6 | ev/D02.log |
| D04 | dashboard | cut off, then restore | pass | 6 | ev/D04.log |
| D05 | dashboard | a pairing code from the dashboard, joined from a terminal | pass | 4 | ev/D05.log |
| D03 | dashboard | grant shell (confirmed), then remove it (device paired by code) | pass | 3 | ev/D03.log |
| D06 | dashboard | approve an ask from the Asks screen | pass | 8 | ev/D06.log |
| D07 | dashboard | the dashboard closes when the background service stops | pass | 7 | ev/D07.log |

## Notes

- **n/a:** C13, member-to-member links are not in this release (the CLI says so); C15, the
  containers have no `/dev/fuse`.
- **C20 and production TURN.** The relay path passes against a local coturn. Production coturn
  allows only 41 relay ports (49160-49200 in `/opt/filament/deploy/coturn/turnserver.conf`) and
  ran out during earlier runs, so forced relay against production can fail until that range is
  widened (and the firewall opened) on the server. That is a production change for the operator.
- **Harness fixes in this run, none weakens an assertion:** wait up to 30 s for a newly created
  code instead of reading the page once after 3 s; `Connect` matched by exact name (peer tiles
  labelled "<name>, connecting" also matched); the app's Home button instead of the terminal key
  bar's Home key; the ended terminal from the shell cells is closed before B10 goes Home (the
  click used to miss silently); a code sender left from a failed cell is stopped by pid.
