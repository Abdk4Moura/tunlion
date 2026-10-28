#!/bin/sh
# Start coturn with the TURN secret in a config file, never in argv.
#
# `--static-auth-secret=...` on the command line is readable by every user on
# the host through `ps` and /proc/PID/cmdline, and it shows in `docker inspect`
# as the container's Cmd. Here compose hands the secret in as a file
# (/run/secrets/turn_secret, from FIL_TURN_SECRET in .env, so it still lives in
# exactly one place and stays equal to the backend's), and this script renders
# the static config plus that one line into a mode 600 file on a tmpfs, so the
# secret is never in argv, in the container's environment, or on disk.
#
# Everything after the script name (realm, IPs) is passed through to
# turnserver as before: those are not secret.
set -eu

src=/etc/coturn/turnserver.conf
secret_file=${TURN_SECRET_FILE:-/run/secrets/turn_secret}
out_dir=${TURN_CONF_DIR:-/run/coturn}
out=$out_dir/turnserver.conf

if [ ! -r "$secret_file" ]; then
  echo "coturn: $secret_file is missing or unreadable (set FIL_TURN_SECRET in .env)" >&2
  exit 1
fi
secret=$(cat "$secret_file")
if [ -z "$secret" ]; then
  echo "coturn: $secret_file is empty (set FIL_TURN_SECRET in .env)" >&2
  exit 1
fi
case $secret in
  *[!A-Za-z0-9._~+/=-]*)
    # A newline or space would end the config value early or inject a second
    # option; refuse rather than start with a secret the backend does not hold.
    echo "coturn: FIL_TURN_SECRET has characters a config line cannot carry" >&2
    exit 1
    ;;
esac

umask 077
mkdir -p "$out_dir"
tmp=$out.tmp.$$
{
  cat "$src"
  printf '\n# Rendered at container start from /run/secrets/turn_secret.\n'
  printf 'static-auth-secret=%s\n' "$secret"
} > "$tmp"
chmod 600 "$tmp"
mv -f "$tmp" "$out"
unset secret

exec turnserver -c "$out" "$@"
