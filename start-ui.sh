#!/usr/bin/env bash
# Start the local preview UI on macOS or Linux.
#
# Builds target/release/agentwatchd when it is missing, starts it in the
# background when nothing answers on port 7456, then opens the browser.
# The preview config is generated on first run and is not committed: it holds
# this machine's data directory. debug.preview_ui must stay on for the page to
# get past the sign-in screen. Stop with ./restart-ui.sh, or create
# .aw-preview/data/agentwatchd.stop.

set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
config="$root/.aw-preview/agentwatchd.toml"
data_dir="$root/.aw-preview/data"
exe="$root/target/release/agentwatchd"
url="http://127.0.0.1:7456/"

if [[ ! -f "$config" ]]; then
    mkdir -p "$(dirname "$config")"
    cat >"$config" <<EOF
[storage]
data_dir = "$data_dir"

[debug]
# Local preview only. GET / then issues a one-time ticket so the browser
# can pass the sign-in screen. Do not enable this in a real deployment.
preview_ui = true
EOF
    echo "wrote $config"
fi

if [[ ! -x "$exe" ]]; then
    echo "release daemon is missing, building (the first build takes a while)..."
    (cd "$root" && cargo build -p aw-daemon --release --bin agentwatchd)
fi

healthy() {
    curl -fsS --max-time 3 "$url/health" >/dev/null 2>&1
}

if ! healthy; then
    mkdir -p "$data_dir"
    # A leftover stop file makes the new process exit immediately.
    rm -f "$data_dir/agentwatchd.stop"
    echo "starting daemon..."
    nohup "$exe" --foreground --config "$config" >/dev/null 2>&1 &
    disown || true
    deadline=$((SECONDS + 30))
    while (( SECONDS < deadline )); do
        sleep 0.5
        if healthy; then
            break
        fi
    done
fi

if ! healthy; then
    echo "daemon did not answer within 30s. log: $data_dir/agentwatchd.log"
    exit 1
fi

echo "opening $url"
if command -v open >/dev/null 2>&1; then
    open "$url"
elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 &
    disown || true
else
    echo "no opener found. open $url yourself."
fi
