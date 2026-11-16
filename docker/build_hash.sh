#!/usr/bin/env bash
# build_hash.sh — fingerprint of the sources that go into docker/Dockerfile.
# Sourced by docker/censorlab.sh and experiments/scripts/run_all_docker.sh.
#
# NOTE: DOCKERFILE_SOURCES must match the COPY sources in docker/Dockerfile.
# If the Dockerfile's COPY paths change, update the list here too.
# Result directories are written by the experiments themselves and are not
# build inputs, so they are excluded (otherwise every run forces a rebuild).
#
# DOCKERFILE_SOURCES_NO_EXPERIMENTS is for callers that bind-mount
# experiments/ over the image copy; it keeps experiments/tools/opengfw/,
# which the flake's experiments shell builds from at image build time.
DOCKERFILE_SOURCES_NO_EXPERIMENTS=(
    docker/ flake.nix flake.lock Cargo.toml Cargo.lock build.rs
    src/ demos/ website/ .gitmodules experiments/tools/opengfw/
)
DOCKERFILE_SOURCES=(
    "${DOCKERFILE_SOURCES_NO_EXPERIMENTS[@]}" experiments/
    ':(exclude,glob)experiments/**/results/**'
)

# compute_build_hash <repo_root> <pathspec>...
#   Hashes HEAD, uncommitted changes to tracked files, and the names and
#   contents of untracked, non-ignored files under the given pathspecs.
#   Prints "unknown" if git is unavailable (forcing a rebuild).
compute_build_hash() {
    local root="$1"; shift
    (cd "$root" && {
        git rev-parse HEAD
        git diff HEAD -- "$@"
        git ls-files --others --exclude-standard -- "$@"
        git ls-files -z --others --exclude-standard -- "$@" \
            | xargs -0 -r git hash-object --
        git submodule status
    } 2>/dev/null | git hash-object --stdin 2>/dev/null) || echo "unknown"
}
