#!/usr/bin/env bash
# Keep the daemon's clippy ban executable: run a deliberate violation in a
# disposable source tree, never in the checkout or a system socket directory.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
probe_root=$(mktemp -d)
trap 'rm -rf "$probe_root"' EXIT
mkdir "$probe_root/repo"
tar -C "$repo_root" --exclude=.git --exclude=target --exclude=ui/node_modules -cf - . |
    tar -C "$probe_root/repo" -xf -

cat >> "$probe_root/repo/crates/aw-daemon/src/main.rs" <<'EOF'

#[allow(dead_code, clippy::items_after_test_module)]
fn daemon_current_user_lint_probe() {
    let _ = aw_platform::IdentifiedCaller::current_user();
}
EOF

log="$probe_root/clippy.log"
probe_target_dir=${PROBE_TARGET_DIR:-"$probe_root/target"}
if (
    cd "$probe_root/repo"
    CARGO_TARGET_DIR="$probe_target_dir" cargo clippy -p aw-daemon --bin agentwatchd --locked -- -D warnings
) >"$log" 2>&1; then
    cat "$log" >&2
    echo "expected aw-daemon current_user probe to fail clippy" >&2
    exit 1
fi

if ! grep -q 'clippy::disallowed_methods' "$log"; then
    cat "$log" >&2
    echo "probe failed, but not because of clippy::disallowed_methods" >&2
    exit 1
fi

if grep -E '^(error|warning):' "$log" |
    grep -Ev '^(error|warning): (could not compile|aborting)' |
    grep -Ev 'disallowed method'; then
    cat "$log" >&2
    echo "probe failed with an unexpected clippy error or warning" >&2
    exit 1
fi

echo "aw-daemon current_user clippy guard passed"
