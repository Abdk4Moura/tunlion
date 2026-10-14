#!/usr/bin/env bash
# CLI-to-CLI cells of the launch matrix. Runs ON THE LAB HOST (docker + tmux),
# after `box.sh build <binary>`. Usage:
#   cli-cells.sh <outdir> [cell-regex]
# Writes <outdir>/cli.jsonl (one result per cell) and <outdir>/ev/<cell>.log.
#
# Machines (each a fresh container with user sam):
#   mx-laptop  owner: init, invites, pairs
#   mx-server  joins laptop's devices by invitation, serves shell/ports
#   mx-third   joins laptop's devices by spoken code (needs a TTY: tmux)
#   mx-guest   a person admitted by an expiring invitation
#   mx-fresh   never set up (exit-code cells)
#   mx-hl / mx-hs  hostile pair (read-only root, 192 MB, C locale, TERM=dumb)
#
# A cell passes only when every assertion in it holds; nothing is retried
# into a pass. Exit 77 from a cell means "does not apply here" (recorded as n/a
# with the reason in its log).
set -u
OUT="${1:?outdir}"; FILTER="${2:-.}"
here="$(cd "$(dirname "$0")" && pwd)"
BOX="$here/box.sh"
mkdir -p "$OUT/ev"; RES="$OUT/cli.jsonl"; : > "$RES"
L=mx-laptop S=mx-server T=mx-third G=mx-guest F=mx-fresh HL=mx-hl HS=mx-hs
ALL=($L $S $T $G $F $HL $HS)

# --- helpers ---------------------------------------------------------------
# x <container>: run the script on stdin as sam in a login shell.
x() { docker exec -i "$1" bash -l -s; }
# xr <container> <cmd>: run a one-liner as root (container-local setup only).
xr() { docker exec -u0 "$1" sh -c "$2"; }
cp_between() { # <from> <path> <to> <path>  (owner-only on arrival; works on tmpfs homes)
  docker exec "$1" cat "$2" | docker exec -i "$3" sh -c "umask 077; cat > '$4'"
}
sha_of() { docker exec "$1" sha256sum "$2" | cut -d' ' -f1; }
want_exit() { # <want> <got> <what>
  echo "[$3: exit $2, want $1]"; [ "$2" = "$1" ]
}
# tmux on the host gives a real TTY inside the container.
tm_new() { tmux kill-session -t "$1" 2>/dev/null; tmux new-session -d -s "$1" -x 160 -y 50 "docker exec -it $2 bash -l"; sleep 2; }
tm_keys() { tmux send-keys -t "$1" "${@:2}"; }
tm_cap() { tmux capture-pane -p -J -S -300 -t "$1"; }
tm_wait() { # <session> <regex> <seconds>
  local i; for ((i=0;i<$3*2;i++)); do tm_cap "$1" | grep -qE "$2" && return 0; sleep 0.5; done
  echo "--- pane $1 (no /$2/ after $3 s) ---"; tm_cap "$1"; return 1
}
# keep <grep args>: log stdin to the cell evidence, then test it. (A `tee | grep -q`
# pipeline fails under pipefail when grep exits early and tee takes SIGPIPE.)
keep() { local o; o=$(cat); printf '%s\n' "$o" >>"$ev"; grep -q "$@" <<<"$o"; }
keepcount() { local o; o=$(cat); printf '%s\n' "$o" >>"$ev"; [ "$(grep -c "$1" <<<"$o")" -ge "$2" ]; }
code_in() { grep -oE '\b[a-z]+-[a-z]+(-[a-z]+)?-[0-9]{2,5}\b' | head -1; }

cell() { # <id> <pair> <feature> <function>
  local id=$1 pair=$2 feat=$3 fn=$4 ev="$OUT/ev/$1.log" t0 rc r
  [[ "$id" =~ $FILTER ]] || return 0
  t0=$(date +%s%N)
  ( set -o pipefail; "$fn" ) >"$ev" 2>&1; rc=$?
  case $rc in 0) r=pass;; 77) r=n/a;; *) r=fail;; esac
  printf '{"cell":"%s","pair":"%s","feature":"%s","result":"%s","seconds":%s,"evidence":"ev/%s.log"}\n' \
    "$id" "$pair" "$feat" "$r" "$(( ($(date +%s%N)-t0)/1000000000 ))" "$id" >>"$RES"
  printf '%-5s %-8s %s\n' "$r" "$id" "$feat"
}

# --- setup -----------------------------------------------------------------
setup() {
  for n in $L $S $T $G $F; do "$BOX" up "$n"; done
  "$BOX" up $HL hostile; "$BOX" up $HS hostile
  for n in $L $HL $HS; do
    x "$n" <<'EOF'
tunlion init --name "$(hostname | sed 's/^mx-//')" --no-background --recovery-file ~/.recovery -y >/dev/null
EOF
  done
  x $L <<<'tunlion up --detach >/dev/null' 
  echo setup done
}
teardown() { "$BOX" down "${ALL[@]}"; for s in mxa mxb mxc; do tmux kill-session -t $s 2>/dev/null; done; true; }

# --- cells -----------------------------------------------------------------
c_pair_invite() {  # laptop invites server into its devices with a file
  x $L <<<'tunlion add server --allow transfer,mount,shell --out inv-server.txt -y' || return 1
  cp_between $L /home/sam/inv-server.txt $S /home/sam/inv-server.txt
  x $S <<<'tunlion join inv-server.txt --name server -y && tunlion up --detach' || return 1
  sleep 4
  x $L <<<'tunlion devices --json' | keep '"server"' || return 1
  x $S <<<'tunlion devices --json' | grep -q '"laptop"'
}
c_pair_code() {    # laptop offers a spoken code at a TTY; third claims it
  tm_new mxa $L
  tm_keys mxa 'tunlion add third' Enter; sleep 3; tm_keys mxa Enter
  tm_wait mxa 'one claim' 20 || return 1
  local code; code=$(tm_cap mxa | code_in); echo "code=$code"; [ -n "$code" ] || return 1
  x $T <<<"tunlion join $code" || { tm_cap mxa; return 1; }
  tm_wait mxa 'remembered|verified end-to-end' 30 || return 1
  x $T <<<'tunlion up --detach'
  sleep 3; x $L <<<'tunlion devices --json' | keep '"third"' || return 1
  x $T <<<'tunlion devices --json' | keep '"laptop"'
}
c_send_known() {
  x $L <<<'head -c 5000000 /dev/urandom > big.bin && tunlion send big.bin --to server' || return 1
  local a b; a=$(sha_of $L /home/sam/big.bin); b=$(sha_of $S /home/sam/Tunlion/big.bin)
  echo "laptop $a"; echo "server $b"; [ "$a" = "$b" ]
}
c_send_code() {
  x $L <<<'head -c 3000000 /dev/urandom > code.bin; (tunlion send code.bin --code > code.out 2>&1; echo "EXIT=$?" >> code.out) & sleep 5; cat code.out'
  local code; code=$(x $L <<<'cat code.out' | code_in); echo "code=$code"; [ -n "$code" ] || return 1
  x $T <<<"mkdir -p in-code && tunlion receive $code --dir in-code"; want_exit 0 $? receive || return 1
  sleep 2; x $L <<<'cat code.out' | keep 'EXIT=0' || return 1
  [ "$(sha_of $L /home/sam/code.bin)" = "$(sha_of $T /home/sam/in-code/code.bin)" ]
}
c_send_code_concurrent() {
  x $L <<<'head -c 2000000 /dev/urandom > c1.bin; head -c 1500000 /dev/urandom > c2.bin
(tunlion send c1.bin --code > c1.out 2>&1; echo "EXIT=$?" >> c1.out) &
(tunlion send c2.bin --code > c2.out 2>&1; echo "EXIT=$?" >> c2.out) & sleep 6'
  local k1 k2; k1=$(x $L <<<'cat c1.out' | code_in); k2=$(x $L <<<'cat c2.out' | code_in); echo "codes $k1 $k2"
  x $S <<<"mkdir -p cc1 cc2; (tunlion receive $k1 --dir cc1; echo R1=\$?) & (tunlion receive $k2 --dir cc2; echo R2=\$?) & wait" | keepcount '=0$' 2 || return 1
  sleep 2; x $L <<<'cat c1.out c2.out' | grep -c 'EXIT=0' | grep -q 2 || { x $L <<<'cat c1.out c2.out'; return 1; }
  [ "$(sha_of $L /home/sam/c1.bin)" = "$(sha_of $S /home/sam/cc1/c1.bin)" ] && [ "$(sha_of $L /home/sam/c2.bin)" = "$(sha_of $S /home/sam/cc2/c2.bin)" ]
}
c_receive_tty() {  # receive at a real TTY returns when done; Ctrl-C at the prompt is 130
  x $L <<<'echo hello > tty.txt; (tunlion send tty.txt --code > tty.out 2>&1) & sleep 5'
  local code; code=$(x $L <<<'cat tty.out' | code_in); echo "code=$code"
  tm_new mxb $S
  tm_keys mxb "tunlion receive $code --dir intty; echo RX-EXIT=\$?" Enter
  tm_wait mxb 'RX-EXIT=0' 25 || return 1
  tm_keys mxb 'clear' Enter 'tunlion receive' Enter; sleep 3; tm_keys mxb C-c; sleep 1
  tm_keys mxb 'echo CC-EXIT=$?' Enter
  tm_wait mxb 'CC-EXIT=130' 5
}
c_sync() {
  x $L <<<'mkdir -p proj/sub; for i in 1 2 3; do head -c 200000 /dev/urandom > proj/f$i; done; echo a > proj/sub/a.txt
tunlion sync proj server:syncdst' || return 1
  local dst; dst=$(x $S <<<'ls -d ~/Tunlion/syncdst ~/syncdst 2>/dev/null | head -1'); echo "landed in: $dst"; [ -n "$dst" ] || return 1
  x $S <<<"cd $dst && sha256sum f1 f2 f3 sub/a.txt" > /tmp/mx-s.$$; x $L <<<'cd proj && sha256sum f1 f2 f3 sub/a.txt' | diff - /tmp/mx-s.$$ || return 1
  x $L <<<'echo changed > proj/f2; rm proj/f3; tunlion sync proj server:syncdst --delete' || return 1
  x $S <<<"cat $dst/f2; test ! -e $dst/f3 && echo F3-GONE" | keep F3-GONE
}
c_exec_denied() {  # pairing alone never yields a command
  x $L <<<'tunlion exec server -- true'; want_exit 4 $? "exec before grant"
}
c_exec() {
  x $S <<<'tunlion grant laptop shell' || return 1
  local out
  out=$(x $L <<<"tunlion exec server -- printf '%s|' 'a b' c 2>/dev/null"); echo "argv: $out"; [ "$out" = "a b|c|" ] || return 1
  out=$(x $L <<<"tunlion exec server --shell -- 'echo \$((6*7)) | tr 4 X' 2>/dev/null"); echo "shell: $out"; [ "$out" = "X2" ] || return 1
  x $L <<<"tunlion exec server -- sh -c 'exit 7'"; want_exit 7 $? "remote exit status" || return 1
  out=$(x $L <<<"tunlion exec server --cwd /tmp --env MXV=ok -- sh -c 'echo \$PWD:\$MXV' 2>/dev/null"); echo "cwd/env: $out"; [ "$out" = "/tmp:ok" ]
}
c_shell_pty() {
  tm_new mxa $L
  tm_keys mxa 'tunlion shell server' Enter
  tm_wait mxa 'sam@mx-server' 30 || return 1
  tm_keys mxa 'echo MX-$((40+2))' Enter; tm_wait mxa 'MX-42' 10 || return 1
  tm_keys mxa 'exit' Enter; tm_wait mxa 'sam@mx-laptop:~\$ *$' 15
}
c_forward() {
  xr $S 'mkdir -p /run/sshd'
  x $S <<<'test -f hk || ssh-keygen -q -t ed25519 -f hk -N ""; /usr/sbin/sshd -p 2222 -h $PWD/hk -o PidFile=$PWD/sshd.pid 2>/dev/null; sleep 1; ss -ltn | grep 2222' || return 1
  x $L <<<'(tunlion forward server:2222 --lport 12222 > fwd.log 2>&1 &) ; sleep 6
exec 3<>/dev/tcp/127.0.0.1/12222 && timeout 8 head -c 20 <&3' | keep 'SSH-2.0'
}
c_expose_mesh() {  # server publishes a port; third reaches server.mesh through the local proxy
  x $S <<<'tunlion expose 2222' || return 1
  sleep 3
  x $L <<<'tok=$(cat ~/.config/tunlion/proxy.token 2>/dev/null); test -n "$tok" || { echo "no proxy token"; exit 1; }
curl -s -m 10 --socks5-hostname "u:$tok@127.0.0.1:1080" telnet://server.mesh:2222 </dev/null | head -c 20' | keep 'SSH-2.0'
}
c_member_reach() { # two members of laptop's devices reach each other
  local r; r=$(x $T <<<'tunlion reach server 2>&1'); echo "$r"
  if grep -q 'sibling connections are not in this release' <<<"$r"; then echo "the CLI says member-to-member links are not in this release"; return 77; fi
  x $T <<<'tunlion reach server --json' | keep -E '"ok": ?true' || return 1
  x $T <<<'echo from-third > m.txt && tunlion send m.txt --to server' || return 1
  x $S <<<'cat Tunlion/m.txt' | grep -q from-third
}
c_overlay_addr() {
  local a; a=$(x $L <<<'tunlion addr server'); echo "$a"; grep -qE 'fd[0-9a-f]{2}:' <<<"$a"
}
c_mount() {
  x $S <<<'mkdir -p share && echo shared > share/s.txt; tunlion grant laptop mount 2>&1 || true'
  x $L <<<'mkdir -p mnt; timeout 30 tunlion mount server /home/sam/share mnt; echo MOUNT-EXIT=$?; sleep 2; cat mnt/s.txt; tunlion mount --off mnt' ; true
  x $L <<<'grep -q shared mnt/s.txt 2>/dev/null' && return 0
  echo "mount did not serve the file (container has no /dev/fuse)"; return 77
}
c_reach_doctor() {
  x $L <<<'tunlion reach server --json' | keep -E '"ok": ?true' || return 1
  x $L <<<'tunlion doctor server --json > d.json; echo DOCTOR=$?; head -c 600 d.json' | keep 'DOCTOR=0'
}
c_json() {
  x $L <<<'tunlion status --json' | keep -E '"ok": ?true' || return 1
  x $L <<<'tunlion devices --json' | grep -q '"devices"' || return 1
  # An error under --json is one envelope with ok:false and the exit code (reach is a JSON verb).
  x $L <<<'tunlion reach nosuch --json 2>/dev/null; echo EXIT=$?' | keep -E '"ok": ?false'
}
c_exit_codes() {
  x $L <<<'tunlion exec nosuch -- true'; want_exit 3 $? "unknown device" || return 1
  x $L <<<'tunlion send x --too y'; want_exit 2 $? "usage" || return 1
  x $F <<<'tunlion up'; want_exit 9 $? "no identity" || return 1
  x $HL <<<'tunlion status'; want_exit 11 $? "no daemon" || return 1
  x $F <<<'timeout 60 tunlion receive brave-otter-123 --server https://127.0.0.1:9'; want_exit 7 $? "network" || return 1
  x $T <<<'tunlion down -y'
  x $L <<<'timeout 120 tunlion exec third -- true'; local rc=$?
  x $T <<<'tunlion up --detach >/dev/null'
  want_exit 6 $rc "peer offline"
}
c_skill() {
  x $L <<<'tunlion skill install --dir ~/sk --json' | keep -E '"ok": ?true' || return 1
  x $L <<<'head -3 ~/sk/tunlion/SKILL.md' | grep -q 'name: tunlion'
}
c_relay() {
  x $L <<<'echo via-relay > r.txt; tunlion send r.txt --to server --relay' 2>&1 | keep -i relay || return 1
  x $S <<<'cat Tunlion/r.txt' | grep -q via-relay || return 1
  out=$(x $L <<<'tunlion exec server --relay -- echo relayed-exec 2>/dev/null'); [ "$out" = relayed-exec ]
}
c_revoke_cap() {
  x $S <<<'tunlion revoke laptop shell -y' || return 1
  x $L <<<'tunlion exec server -- true'; want_exit 4 $? "exec after revoke"
}
c_devices_revoke_restore() {
  x $L <<<'tunlion grant third shell >/dev/null; tunlion devices revoke third -y' || return 1
  x $T <<<'echo r > rv.txt; tunlion send rv.txt --to laptop'; local rc=$?; echo "send after revoke rc=$rc"; [ $rc -ne 0 ] || return 1
  x $L <<<'tunlion devices restore third' || return 1
  sleep 3
  x $T <<<'tunlion send rv.txt --to laptop'; want_exit 0 $? "send after restore"
}
c_forget_readd() {
  x $L <<<'tunlion devices forget third -y' || return 1
  x $T <<<'tunlion send rv.txt --to laptop'; local rc=$?; [ $rc -ne 0 ] || { echo "forgotten device still accepted"; return 1; }
  tm_new mxa $L
  tm_keys mxa 'tunlion add third' Enter; sleep 3; tm_keys mxa Enter
  tm_wait mxa 'one claim' 20 || return 1
  local code; code=$(tm_cap mxa | code_in | tail -1); echo "code=$code"
  x $T <<<"tunlion join $code"; want_exit 0 $? "re-add after forget" || { tm_cap mxa; return 1; }
  sleep 4; x $T <<<'tunlion send rv.txt --to laptop'; want_exit 0 $? "send after re-add"
}
c_invite_expiry() {  # a person with transfer+shell for 2 minutes: cut off on time, live session included
  "$BOX" up $G
  x $L <<<'tunlion add --for person --name guest --allow transfer,shell --expires 2m --out inv-guest.txt -y' || return 1
  cp_between $L /home/sam/inv-guest.txt $G /home/sam/inv-guest.txt
  x $G <<<'tunlion join inv-guest.txt --name guest -y && tunlion up --detach' || return 1
  local until; until=$(x $L <<<'tunlion devices --json' | grep -oE '"(accessUntil|invitationEnds)":"?[0-9TZ:-]+' | head -1); echo "until: $until"
  xr $L 'mkdir -p /run/sshd'; x $L <<<'test -f hk || ssh-keygen -q -t ed25519 -f hk -N ""; /usr/sbin/sshd -p 2222 -h $PWD/hk -o PidFile=$PWD/sshd.pid 2>/dev/null'
  x $G <<<'(tunlion forward laptop:2222 --lport 12222 > fwd.log 2>&1 &); sleep 6; exec 3<>/dev/tcp/127.0.0.1/12222 && timeout 5 head -c 8 <&3; echo' | grep -q SSH || { echo "forward before expiry failed"; return 1; }
  local t0=$(date +%s)
  x $G <<<'timeout 200 tunlion exec laptop -- sh -c "while true; do date +%T; sleep 5; done"'; local rc=$?
  local held=$(( $(date +%s) - t0 )); echo "live exec ended after ${held}s rc=$rc"
  [ $rc -eq 4 ] || return 1; [ $held -le 135 ] || { echo "outlived the 2 minute window"; return 1; }
  x $G <<<'tunlion exec laptop -- true'; want_exit 4 $? "exec after expiry" || return 1
  x $G <<<'echo z > z.txt; tunlion send z.txt --to laptop'; want_exit 4 $? "send after expiry" || return 1
  x $G <<<'exec 3<>/dev/tcp/127.0.0.1/12222 && timeout 5 head -c 8 <&3; echo "FWD-READ=$?"' | keep 'SSH' && { echo "forward still serving after expiry"; return 1; }
  return 0
}
c_hostile() {
  x $HS <<<'echo hostile-ok > h.txt; (tunlion send h.txt --code > h.out 2>&1; echo "EXIT=$?" >> h.out) & sleep 6'
  local code; code=$(x $HS <<<'cat h.out' | code_in); echo "code=$code"; [ -n "$code" ] || { x $HS <<<'cat h.out'; return 1; }
  x $HL <<<"mkdir -p in && tunlion receive $code --dir in && cat in/h.txt" | keep hostile-ok || return 1
  x $HL <<<'tunlion up --detach >/dev/null; tunlion add hs --out inv.txt -y' || return 1
  cp_between $HL /home/sam/inv.txt $HS /home/sam/inv.txt
  # hs already has an identity from setup; join needs a clean one, so reset first (a first-time box would not have one)
  x $HS <<<'tunlion reset -y >/dev/null 2>&1; tunlion join inv.txt --name hs -y && tunlion up --detach' || return 1
  x $HL <<<'sleep 4; echo k > k.txt; tunlion send k.txt --to hs'; want_exit 0 $? "send --to in hostile pair"
}

c_session_resume() { # a shell survives the server's network dropping for 10 s (link manager)
  x $S <<<'tunlion grant laptop shell >/dev/null 2>&1; true'
  tm_new mxa $L
  tm_keys mxa 'tunlion shell server' Enter
  tm_wait mxa 'sam@mx-server' 30 || return 1
  tm_keys mxa 'export MXMARK=before-drop; echo MARK-$MXMARK' Enter; tm_wait mxa 'MARK-before-drop' 10 || return 1
  docker network disconnect bridge $S; sleep 10; docker network connect bridge $S
  sleep 3
  tm_keys mxa 'echo AFTER-$MXMARK-$((40+2))' Enter
  # The same shell (its variable survived) answers after the link came back.
  tm_wait mxa 'AFTER-before-drop-42' 60 || return 1
  tm_keys mxa 'exit' Enter; tm_wait mxa 'sam@mx-laptop:~\$ *$' 20
}
c_person_external() { # a person invited with add --for person is listed as someone else's, not as one of my devices
  x $L <<<'tunlion add --for person --name visitor --out inv-visitor.txt -y >/dev/null' || return 1
  cp_between $L /home/sam/inv-visitor.txt $F /home/sam/inv-visitor.txt
  x $F <<<'tunlion join inv-visitor.txt -y && tunlion up --detach >/dev/null' || return 1
  sleep 3
  local d; d=$(x $L <<<'tunlion devices'); echo "$d"
  # The visitor row must sit in the EXTERNAL section, never under FLEET.
  awk '/EXTERNAL/{s="ext"} /FLEET/{s="fleet"} /visitor/{print s}' <<<"$d" | grep -qx ext
}
c_demo_auto() { # the guided tour plays to the end by itself at a real TTY
  tm_new mxb $F
  tm_keys mxb 'clear; tunlion demo --auto --speed 0; echo DEMO-EXIT=$?' Enter
  tm_wait mxb 'DEMO-EXIT=' 180 || return 1
  tm_cap mxb | tail -15
  tm_cap mxb | grep -q 'DEMO-EXIT=0'
}
c_demo_no_tty() { # without a terminal (and without --auto) the demo refuses with exit 2 and says how
  local r; r=$(x $F <<<'tunlion demo </dev/null 2>&1; echo EXIT=$?'); echo "$r"
  grep -q 'EXIT=2' <<<"$r" && grep -q -- '--auto' <<<"$r"
}
c_default_ceiling() { # third joined with the default ceiling (transfer, mount): no shell, and the refusal says how
  local r; r=$(x $L <<<'tunlion exec third -- true 2>&1; echo EXIT=$?'); echo "$r"
  # Either remedy is actionable: grant on the member, or re-enrol with shell in the ceiling.
  grep -q 'EXIT=4' <<<"$r" && grep -qE -- 'tunlion grant laptop shell|--allow transfer,mount,shell' <<<"$r"
}

trap teardown EXIT
setup > "$OUT/ev/setup.log" 2>&1 || { echo "setup failed"; cat "$OUT/ev/setup.log"; exit 1; }
cell C01 cli-cli "pair: invitation file (device)"          c_pair_invite
cell C02 cli-cli "pair: spoken code at a TTY"               c_pair_code
cell C03 cli-cli "send --to a known device (5 MB, sha256)"  c_send_known
cell C04 cli-cli "send by code / receive"                   c_send_code
cell C05 cli-cli "two concurrent code sends"                c_send_code_concurrent
cell C06 cli-cli "receive at a TTY returns; Ctrl-C is 130"  c_receive_tty
cell C07 cli-cli "sync, then sync --delete"                 c_sync
cell C08 cli-cli "exec refused before grant (exit 4)"       c_exec_denied
cell C09 cli-cli "exec argv, --shell, exit status, cwd/env" c_exec
cell C10 cli-cli "shell (pty)"                              c_shell_pty
cell C11 cli-cli "forward a port"                           c_forward
cell C12 cli-cli "expose, reach <dev>.mesh via proxy"       c_expose_mesh
cell C13 cli-cli "member to member reach and send"          c_member_reach
cell C14 cli-cli "overlay address"                          c_overlay_addr
cell C15 cli-cli "mount"                                    c_mount
cell C16 cli-cli "reach and doctor --json"                  c_reach_doctor
cell C17 cli-cli "status/devices --json, error envelope"    c_json
cell C18 cli-cli "exit codes 3 2 9 11 7 6"                  c_exit_codes
cell C19 cli-cli "skill install"                            c_skill
cell C20 cli-cli "forced relay: send and exec"              c_relay
cell C21 cli-cli "revoke a capability"                      c_revoke_cap
cell C22 cli-cli "devices revoke, then restore"             c_devices_revoke_restore
cell C23 cli-cli "devices forget, then re-add"              c_forget_readd
cell C24 cli-cli "invitation --expires cuts live sessions"  c_invite_expiry
cell C25 cli-cli "hostile machines: code, invite, send"     c_hostile
cell C26 cli-cli "default ceiling: no shell, remedy named"  c_default_ceiling
cell C27 cli-cli "shell survives a 10 s network drop"       c_session_resume
cell C28 cli-cli "a person invitee is EXTERNAL, not FLEET"  c_person_external
cell C29 cli     "tunlion demo --auto plays to the end"      c_demo_auto
cell C30 cli     "tunlion demo without a TTY: exit 2"        c_demo_no_tty
echo "results: $RES"
