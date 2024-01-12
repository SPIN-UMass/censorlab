#!/bin/sh
set -eu

setcap CAP_NET_ADMIN,CAP_NET_RAW+eip target/debug/censorlab || true
setcap CAP_NET_ADMIN,CAP_NET_RAW+eip target/release/censorlab || true
