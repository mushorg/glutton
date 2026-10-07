#!/bin/bash
# Server-side helper: replace the Glutton binary and restart the "glutton" screen session.
# Expects a new binary at /tmp/glutton.new (scp there from the workstation).
# Fails loudly if the old process cannot be stopped or the new one does not stay up.
set -euo pipefail

OPT_DIR=/opt/glutton
BIN="$OPT_DIR/glutton"
NEW=/tmp/glutton.new
SCREEN_NAME=glutton
STOP_TIMEOUT=20 # seconds to wait for a graceful exit before SIGKILL
START_WAIT=5    # seconds the new process must survive

if [[ ! -f "$NEW" ]]; then
	echo "missing $NEW; scp the binary there first" >&2
	exit 1
fi

chmod 755 "$NEW"
NEW_VERSION=$("$NEW" --version 2>&1 | grep -m1 "version v" || true)
echo "new binary: ${NEW_VERSION:-unknown}"

# Stop every running glutton, not just the one in a matching screen session.
screen -ls 2>/dev/null | awk -v n="\\\\.$SCREEN_NAME[[:space:]]" '$1 ~ n {print $1}' | while read -r s; do
	screen -S "$s" -X quit 2>/dev/null || true
done
pkill -TERM -x glutton 2>/dev/null || true

for ((i = 0; i < STOP_TIMEOUT; i++)); do
	pgrep -x glutton >/dev/null || break
	sleep 1
done
if pgrep -x glutton >/dev/null; then
	echo "glutton still running after ${STOP_TIMEOUT}s; sending SIGKILL" >&2
	pkill -KILL -x glutton || true
	sleep 1
fi
if pgrep -x glutton >/dev/null; then
	echo "failed to stop the old glutton process" >&2
	exit 1
fi
screen -wipe >/dev/null 2>&1 || true

install -m 755 "$NEW" "$BIN"
rm -f "$NEW"

cd "$OPT_DIR"
screen -dmS "$SCREEN_NAME" ./glutton -i ens2 -c .

sleep "$START_WAIT"
PID=$(pgrep -x glutton | head -n 1 || true)
if [[ -z "$PID" ]]; then
	echo "glutton exited within ${START_WAIT}s of starting; check config and ports (run ./glutton -i ens2 -c . by hand)" >&2
	exit 1
fi

echo "redeployed: pid $PID, started $(ps -o lstart= -p "$PID"), binary ${NEW_VERSION:-unknown}"
screen -ls || true
