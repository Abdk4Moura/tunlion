# Launch matrix

Binary sha256 `f41225dba056 (main 173b9853)`. 45 pass, 3 fail, 2 n/a.

| Cell | Pair | Feature | Result | Seconds | Evidence |
|---|---|---|---|---|---|
| C01 | cli-cli | pair: invitation file (device) | pass | 7 | ev/C01.log |
| C02 | cli-cli | pair: spoken code at a TTY | pass | 18 | ev/C02.log |
| C03 | cli-cli | send --to a known device (5 MB, sha256) | pass | 2 | ev/C03.log |
| C04 | cli-cli | send by code / receive | pass | 16 | ev/C04.log |
| C05 | cli-cli | two concurrent code sends | pass | 15 | ev/C05.log |
| C06 | cli-cli | receive at a TTY returns; Ctrl-C is 130 | pass | 18 | ev/C06.log |
| C07 | cli-cli | sync, then sync --delete | pass | 2 | ev/C07.log |
| C08 | cli-cli | exec refused before grant (exit 4) | pass | 1 | ev/C08.log |
| C09 | cli-cli | exec argv, --shell, exit status, cwd/env | pass | 5 | ev/C09.log |
| C10 | cli-cli | shell (pty) | pass | 4 | ev/C10.log |
| C11 | cli-cli | forward a port | pass | 7 | ev/C11.log |
| C12 | cli-cli | expose, reach <dev>.mesh via proxy | pass | 13 | ev/C12.log |
| C13 | cli-cli | member to member reach and send | n/a | 0 | ev/C13.log |
| C14 | cli-cli | overlay address | pass | 0 | ev/C14.log |
| C15 | cli-cli | mount | n/a | 2 | ev/C15.log |
| C16 | cli-cli | reach and doctor --json | pass | 1 | ev/C16.log |
| C17 | cli-cli | status/devices --json, error envelope | pass | 0 | ev/C17.log |
| C18 | cli-cli | exit codes 3 2 9 11 7 6 | pass | 17 | ev/C18.log |
| C19 | cli-cli | skill install | pass | 0 | ev/C19.log |
| C20 | cli-cli | forced relay: send and exec | **FAIL** | 62 | ev/C20.log |
| C21 | cli-cli | revoke a capability | pass | 1 | ev/C21.log |
| C22 | cli-cli | devices revoke, then restore | pass | 6 | ev/C22.log |
| C23 | cli-cli | devices forget, then re-add | pass | 14 | ev/C23.log |
| C24 | cli-cli | invitation --expires cuts live sessions | pass | 125 | ev/C24.log |
| C25 | cli-cli | hostile machines: code, invite, send | pass | 24 | ev/C25.log |
| C26 | cli-cli | default ceiling: no shell, remedy named | pass | 1 | ev/C26.log |
| C27 | cli-cli | shell survives a 10 s network drop | pass | 18 | ev/C27.log |
| C28 | cli-cli | a person invitee is EXTERNAL, not FLEET | pass | 6 | ev/C28.log |
| C29 | cli | tunlion demo --auto plays to the end | pass | 2 | ev/C29.log |
| C30 | cli | tunlion demo without a TTY: exit 2 | pass | 0 | ev/C30.log |
| B01 | browser-cli | receive by code (desktop) | pass | 30 | ev/B01.log |
| B02 | browser-cli | receive by code (phone) | pass | 31 | ev/B02.log |
| B03 | browser-cli | browser code, CLI receive, browser sends | pass | 52 | ev/B03.log |
| B04 | browser-cli | CLI joins a browser "Remember a device" code | pass | 27 | ev/B04.log |
| B05 | browser-cli | browser claims a CLI `add` code, both remember | pass | 31 | ev/B05.log |
| B06 | browser-cli | browser sends to the remembered vps after reload | pass | 22 | ev/B06.log |
| B07 | browser-cli | shell: refused before grant, works after (desktop) | pass | 71 | ev/B07.log |
| B08 | browser-cli | shell on a phone viewport against the vps | pass | 51 | ev/B08.log |
| B11 | browser-cli | browser shell survives a 10 s network cut | pass | 32 | ev/B11.log |
| B09 | browser-cli | revoke shell cuts the browser off | pass | 43 | ev/B09.log |
| B10 | browser-cli | CLI sends --to the remembered browser | **FAIL** | 67 | ev/B10.log |
| BB1 | browser-browser | code, then send (desktop to phone) | pass | 12 | ev/BB1.log |
| BB2 | browser-browser | remember each other, reload, send | **FAIL** | 69 | ev/BB2.log |
| D01 | dashboard | sign in once with the printed link; a second use is refused | pass | 2 | ev/D01.log |
| D02 | dashboard | make an invitation, another machine joins it | pass | 13 | ev/D02.log |
| D04 | dashboard | cut off, then restore | pass | 13 | ev/D04.log |
| D05 | dashboard | a pairing code from the dashboard, joined from a terminal | pass | 9 | ev/D05.log |
| D03 | dashboard | grant shell (confirmed), then remove it (device paired by code) | pass | 11 | ev/D03.log |
| D06 | dashboard | approve an ask from the Asks screen | pass | 23 | ev/D06.log |
| D07 | dashboard | the dashboard closes when the background service stops | pass | 16 | ev/D07.log |
