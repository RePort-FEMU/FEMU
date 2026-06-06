#!/bin/sh
set -e

python -m femu --binaries /femu/binaries "$@" &
PID=$!

_forward() {
    kill -INT $PID
}
trap _forward TERM INT

wait $PID
EXIT=$?

if [ -n "$PUID" ] && [ -n "$PGID" ]; then
    chown -R "$PUID:$PGID" /output
fi

exit $EXIT
