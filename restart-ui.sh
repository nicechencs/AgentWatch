#!/usr/bin/env bash
# Restart the local preview UI on macOS or Linux.
#
# Drops agentwatchd.stop into the data directory and waits for the daemon to
# exit on its own, then runs start-ui.sh. Does not kill the process, and does
# not touch the certificate store or the system proxy.

set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
data_dir="$root/.aw-preview/data"
url="http://127.0.0.1:7456/health"

healthy() {
    curl -fsS --max-time 3 "$url" >/dev/null 2>&1
}

if healthy; then
    mkdir -p "$data_dir"
    # The daemon polls this file every 50ms and shuts itself down.
    : >"$data_dir/agentwatchd.stop"
    echo "asked the daemon to stop, waiting for the port..."
    deadline=$((SECONDS + 20))
    while (( SECONDS < deadline )); do
        sleep 0.5
        if ! healthy; then
            break
        fi
    done
    if healthy; then
        echo "daemon did not exit within 20s. log: $data_dir/agentwatchd.log"
        exit 1
    fi
else
    echo "nothing is answering on 7456, starting."
fi

exec "$root/start-ui.sh"
