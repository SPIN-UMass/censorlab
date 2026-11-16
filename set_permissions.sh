#!/bin/sh
# Grant CAP_NET_ADMIN and CAP_NET_RAW to every built censorlab binary.
# Paths are resolved relative to this script, not the caller's cwd.
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
TARGET="${CARGO_TARGET_DIR:-$ROOT/target}"

found=0
for profile in debug release; do
    bin="$TARGET/$profile/censorlab"
    [ -f "$bin" ] || continue
    found=1
    if ! setcap CAP_NET_ADMIN,CAP_NET_RAW+eip "$bin"; then
        echo "set_permissions: setcap failed on $bin (are you root?)" >&2
        exit 1
    fi
    echo "set_permissions: $bin"
done

if [ "$found" = 0 ]; then
    echo "set_permissions: no censorlab binary in $TARGET/{debug,release}; run cargo build first" >&2
    exit 1
fi
