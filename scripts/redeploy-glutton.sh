#!/bin/bash
# Server-side helper: replace the Glutton binary and restart the "glutton" screen session.
# Expects a new binary at /tmp/glutton.new (scp there from the workstation).
set -euo pipefail

OPT_DIR=/opt/glutton
BIN="$OPT_DIR/glutton"
NEW=/tmp/glutton.new
SCREEN_NAME=glutton

if [[ ! -f "$NEW" ]]; then
	echo "missing $NEW; scp the binary there first" >&2
	exit 1
fi

install -m 755 "$NEW" "$BIN"
rm -f "$NEW"

screen -S "$SCREEN_NAME" -X quit 2>/dev/null || true
sleep 1

cd "$OPT_DIR"
screen -dmS "$SCREEN_NAME" ./glutton -i ens2 -c .

echo "redeployed; screen sessions:"
screen -ls || true
